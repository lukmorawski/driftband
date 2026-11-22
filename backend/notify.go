package main

// Notification channels: where alerts are delivered (Telegram, Slack,
// Microsoft Teams, email over SMTP with password or OAuth 2.0). A channel's
// settings and secrets are sealed at rest (only its name and kind are stored
// in clear) and the secrets are never returned by the API. Webhook-style targets must be
// HTTPS on public addresses (checked on every connection, so DNS rebinding
// cannot reach internal services).

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var channelKinds = map[string]bool{"telegram": true, "slack": true, "teams": true, "email": true}

// channelConfig is the part of a channel the API shows to the organization
// (stored sealed, together with the secrets).
type channelConfig struct {
	ChatID string `json:"chat_id,omitempty"` // telegram

	Host          string   `json:"host,omitempty"` // email
	Port          int      `json:"port,omitempty"`
	Security      string   `json:"security,omitempty"` // starttls | tls | none
	From          string   `json:"from,omitempty"`
	To            []string `json:"to,omitempty"`
	Auth          string   `json:"auth,omitempty"` // none | password | oauth2
	Username      string   `json:"username,omitempty"`
	OAuthProvider string   `json:"oauth_provider,omitempty"` // microsoft | custom
	TenantID      string   `json:"tenant_id,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	TokenURL      string   `json:"token_url,omitempty"`
	Scope         string   `json:"scope,omitempty"`
}

// channelSecrets is never returned by the API.
type channelSecrets struct {
	BotToken     string `json:"bot_token,omitempty"`
	WebhookURL   string `json:"webhook_url,omitempty"`
	Password     string `json:"password,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

type channel struct {
	ID      int64
	OrgID   int64
	Name    string
	Kind    string
	Enabled bool
	Config  channelConfig
	Secrets channelSecrets
}

var (
	telegramTokenRe = regexp.MustCompile(`^\d{3,15}:[A-Za-z0-9_-]{20,100}$`)
	telegramChatRe  = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z0-9_]{4,64})$`)
	hostnameRe      = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	tenantRe        = regexp.MustCompile(`^[A-Za-z0-9.-]{1,100}$`)
)

// validate checks a channel, merging secrets left empty from prev (an
// update that does not resend a secret keeps the stored one).
func (a *App) validateChannel(c *channel, prev *channelSecrets) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 100 {
		return errors.New("name is required (max 100 characters)")
	}
	if !channelKinds[c.Kind] {
		return errors.New("kind must be telegram, slack, teams or email")
	}
	keep := func(cur *string, old string) {
		if strings.TrimSpace(*cur) == "" {
			*cur = old
		}
		*cur = strings.TrimSpace(*cur)
	}
	if prev == nil {
		prev = &channelSecrets{}
	}
	keep(&c.Secrets.BotToken, prev.BotToken)
	keep(&c.Secrets.WebhookURL, prev.WebhookURL)
	keep(&c.Secrets.Password, prev.Password)
	keep(&c.Secrets.ClientSecret, prev.ClientSecret)
	cfg := &c.Config
	switch c.Kind {
	case "telegram":
		cfg.ChatID = strings.TrimSpace(cfg.ChatID)
		if !telegramTokenRe.MatchString(c.Secrets.BotToken) {
			return errors.New("bot token looks invalid (expected 123456789:ABC...)")
		}
		if !telegramChatRe.MatchString(cfg.ChatID) {
			return errors.New("chat id must be numeric (e.g. -1001234567890) or @channelname")
		}
		*c = channel{ID: c.ID, OrgID: c.OrgID, Name: c.Name, Kind: c.Kind, Enabled: c.Enabled,
			Config: channelConfig{ChatID: cfg.ChatID}, Secrets: channelSecrets{BotToken: c.Secrets.BotToken}}
	case "slack", "teams":
		if err := a.checkPublicURL(c.Secrets.WebhookURL); err != nil {
			return fmt.Errorf("webhook URL: %w", err)
		}
		*c = channel{ID: c.ID, OrgID: c.OrgID, Name: c.Name, Kind: c.Kind, Enabled: c.Enabled,
			Secrets: channelSecrets{WebhookURL: c.Secrets.WebhookURL}}
	case "email":
		cfg.Host = strings.TrimSpace(cfg.Host)
		if !hostnameRe.MatchString(cfg.Host) {
			return errors.New("SMTP host is required")
		}
		if cfg.Port == 0 {
			cfg.Port = 587
		}
		if cfg.Port < 1 || cfg.Port > 65535 {
			return errors.New("SMTP port must be 1-65535")
		}
		if cfg.Security == "" {
			cfg.Security = "starttls"
		}
		if cfg.Security != "starttls" && cfg.Security != "tls" && cfg.Security != "none" {
			return errors.New("security must be starttls, tls or none")
		}
		if _, err := mail.ParseAddress(cfg.From); err != nil {
			return errors.New("from must be a valid email address")
		}
		var to []string
		for _, t := range cfg.To {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			if _, err := mail.ParseAddress(t); err != nil || strings.ContainsAny(t, "\r\n") {
				return fmt.Errorf("invalid recipient %q", t)
			}
			to = append(to, t)
		}
		if len(to) == 0 || len(to) > 20 {
			return errors.New("1 to 20 recipients are required")
		}
		cfg.To = to
		cfg.Username = strings.TrimSpace(cfg.Username)
		switch cfg.Auth {
		case "", "none":
			cfg.Auth = "none"
			cfg.Username, c.Secrets.Password, c.Secrets.ClientSecret = "", "", ""
		case "password":
			if cfg.Username == "" || c.Secrets.Password == "" {
				return errors.New("username and password are required")
			}
			if cfg.Security == "none" {
				return errors.New("password authentication requires TLS or STARTTLS")
			}
			c.Secrets.ClientSecret = ""
		case "oauth2":
			if cfg.Username == "" || cfg.ClientID == "" || c.Secrets.ClientSecret == "" {
				return errors.New("username (mailbox), client id and client secret are required")
			}
			if cfg.Security == "none" {
				return errors.New("OAuth 2.0 requires TLS or STARTTLS")
			}
			switch cfg.OAuthProvider {
			case "", "microsoft":
				cfg.OAuthProvider = "microsoft"
				if !tenantRe.MatchString(cfg.TenantID) {
					return errors.New("tenant id is required for Microsoft 365")
				}
				cfg.TokenURL = "https://login.microsoftonline.com/" + cfg.TenantID + "/oauth2/v2.0/token"
				if cfg.Scope == "" {
					cfg.Scope = "https://outlook.office365.com/.default"
				}
			case "custom":
				if err := a.checkPublicURL(cfg.TokenURL); err != nil {
					return fmt.Errorf("token URL: %w", err)
				}
			default:
				return errors.New("oauth provider must be microsoft or custom")
			}
			c.Secrets.Password = ""
		default:
			return errors.New("auth must be none, password or oauth2")
		}
		if cfg.Auth != "oauth2" {
			cfg.OAuthProvider, cfg.TenantID, cfg.ClientID, cfg.TokenURL, cfg.Scope = "", "", "", "", ""
		}
		cfg.ChatID = ""
		c.Secrets.BotToken, c.Secrets.WebhookURL = "", ""
	}
	return nil
}

// ----- outbound HTTP with SSRF protection -----

// checkPublicURL accepts https URLs whose host resolves only to public
// addresses (connections are checked again when dialing).
func (a *App) checkPublicURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("not a valid URL")
	}
	if u.Scheme != "https" && !(a.allowPrivateTargets && u.Scheme == "http") {
		return errors.New("must use https")
	}
	if u.User != nil {
		return errors.New("must not contain credentials")
	}
	if a.allowPrivateTargets {
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), u.Hostname())
	if err != nil || len(ips) == 0 {
		return errors.New("host does not resolve")
	}
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			return errors.New("host resolves to a private or reserved address")
		}
	}
	return nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, c := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96"} {
		if _, n, _ := net.ParseCIDR(c); n.Contains(ip) {
			return false
		}
	}
	return true
}

func (a *App) httpClient() *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if !a.allowPrivateTargets {
				if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || !isPublicIP(tcp.IP) {
					conn.Close()
					return nil, errors.New("refusing to connect to a private address")
				}
			}
			return conn, nil
		},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") }}
}

func (a *App) postJSON(ctx context.Context, target string, body any) error {
	j, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.httpClient().Do(req)
	if err != nil {
		return redactURL(err, target)
	}
	defer res.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	if res.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// redactURL keeps webhook URLs and bot tokens (both secrets) out of errors
// that end up in the delivery log.
func redactURL(err error, target string) error {
	s := err.Error()
	if u, perr := url.Parse(target); perr == nil {
		s = strings.ReplaceAll(s, target, u.Scheme+"://"+u.Host+"/...")
	}
	return errors.New(s)
}

// ----- messages and delivery -----

// alertMessage is one notification, rendered per channel.
type alertMessage struct {
	Event   string // firing | resolved | reminder | flapping | flapping_end | test
	Title   string // one line, plain text
	Lines   []string
	Link    string
	Firing  bool // colour hint
	Neutral bool
}

func (m alertMessage) text() string {
	s := m.Title + "\n" + strings.Join(m.Lines, "\n")
	if m.Link != "" {
		s += "\n" + m.Link
	}
	return s
}

func (a *App) deliver(ctx context.Context, c *channel, m alertMessage) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch c.Kind {
	case "telegram":
		var b strings.Builder
		b.WriteString("<b>" + html.EscapeString(m.Title) + "</b>")
		for _, l := range m.Lines {
			b.WriteString("\n" + html.EscapeString(l))
		}
		if m.Link != "" {
			b.WriteString("\n" + html.EscapeString(m.Link))
		}
		target := a.telegramAPI + "/bot" + c.Secrets.BotToken + "/sendMessage"
		err := a.postJSON(ctx, target, map[string]any{
			"chat_id": c.Config.ChatID, "text": b.String(), "parse_mode": "HTML", "disable_web_page_preview": true,
		})
		if err != nil {
			return errors.New(strings.ReplaceAll(err.Error(), c.Secrets.BotToken, "<token>"))
		}
		return nil
	case "slack":
		text := "*" + slackEscape(m.Title) + "*"
		for _, l := range m.Lines {
			text += "\n" + slackEscape(l)
		}
		if m.Link != "" {
			text += "\n<" + m.Link + "|Open in Driftband>"
		}
		return a.postJSON(ctx, c.Secrets.WebhookURL, map[string]any{"text": text})
	case "teams":
		return a.postJSON(ctx, c.Secrets.WebhookURL, teamsCard(m))
	case "email":
		return a.sendMail(ctx, c, m)
	}
	return fmt.Errorf("unknown channel kind %q", c.Kind)
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// teamsCard is an Adaptive Card message, the payload Microsoft Teams
// "Workflows" webhooks (Post to a channel when a webhook request is received)
// expect.
func teamsCard(m alertMessage) map[string]any {
	color := "Good"
	if m.Firing {
		color = "Attention"
	} else if m.Neutral {
		color = "Warning"
	}
	body := []any{map[string]any{"type": "TextBlock", "text": m.Title, "weight": "Bolder", "size": "Medium", "color": color, "wrap": true}}
	for _, l := range m.Lines {
		body = append(body, map[string]any{"type": "TextBlock", "text": l, "wrap": true, "spacing": "Small"})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
	if m.Link != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open in Driftband", "url": m.Link}}
	}
	return map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}
}

// ----- email -----

func (a *App) sendMail(ctx context.Context, c *channel, m alertMessage) error {
	cfg := c.Config
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	deadline, _ := ctx.Deadline()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(deadline)
	cl, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if err := cl.Hello("driftband"); err != nil {
		return err
	}
	if cfg.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	switch cfg.Auth {
	case "password":
		if err := cl.Auth(loginOrPlainAuth{user: cfg.Username, pass: c.Secrets.Password}); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	case "oauth2":
		tok, err := a.oauthToken(ctx, cfg, c.Secrets.ClientSecret)
		if err != nil {
			return fmt.Errorf("oauth2 token: %w", err)
		}
		if err := cl.Auth(xoauth2{user: cfg.Username, token: tok}); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}
	from, _ := mail.ParseAddress(cfg.From)
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	for _, t := range cfg.To {
		addr, _ := mail.ParseAddress(t)
		if err := cl.Rcpt(addr.Address); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	var msg bytes.Buffer
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Title)
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\nAuto-Submitted: auto-generated\r\n\r\n",
		from.String(), strings.Join(cfg.To, ", "), mime(subject), time.Now().Format(time.RFC1123Z))
	msg.WriteString(strings.ReplaceAll(m.text(), "\n", "\r\n") + "\r\n") // the DATA writer dot-stuffs
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// mime encodes a header value as RFC 2047 when it is not plain ASCII.
func mime(s string) string {
	for _, r := range s {
		if r > 126 {
			return "=?utf-8?B?" + b64(s) + "?="
		}
	}
	return s
}

// loginOrPlainAuth uses PLAIN, falling back to LOGIN for servers (like some
// Exchange setups) that only offer it. Only used over TLS.
type loginOrPlainAuth struct{ user, pass string }

func (a loginOrPlainAuth) Start(si *smtp.ServerInfo) (string, []byte, error) {
	for _, m := range si.Auth {
		if m == "PLAIN" {
			return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
		}
	}
	return "LOGIN", nil, nil
}

func (a loginOrPlainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected server challenge")
}

// xoauth2 is the SASL XOAUTH2 mechanism used by Microsoft 365 and Gmail.
type xoauth2 struct{ user, token string }

func (a xoauth2) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "XOAUTH2", []byte("user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a xoauth2) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil // server sent an error challenge; finish to get the failure
	}
	return nil, nil
}

// oauthToken runs the OAuth 2.0 client-credentials grant.
func (a *App) oauthToken(ctx context.Context, cfg channelConfig, secret string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cfg.ClientID}, "client_secret": {secret}, "scope": {cfg.Scope}}
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := a.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&out)
	if res.StatusCode != 200 || out.AccessToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s: %s", out.Error, firstLine(out.Description))
		}
		return "", fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return out.AccessToken, nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// ----- storage -----

// channelPayload is everything about a channel that is stored sealed: the
// settings (addresses, account names, recipients) and the secrets.
type channelPayload struct {
	Config  channelConfig  `json:"config"`
	Secrets channelSecrets `json:"secrets"`
}

// channelContext binds a sealed channel to its organization.
func channelContext(orgID int64) string {
	return "notify_channel:org:" + strconv.FormatInt(orgID, 10)
}

func (a *App) loadChannel(ctx context.Context, orgID, id int64) (*channel, error) {
	var c channel
	var cfg, sealed []byte
	var ver int
	err := a.db.QueryRow(ctx, `SELECT id, org_id, name, kind, enabled, config, secret, enc_version FROM notify_channels WHERE id = $1 AND org_id = $2`, id, orgID).
		Scan(&c.ID, &c.OrgID, &c.Name, &c.Kind, &c.Enabled, &cfg, &sealed, &ver)
	if err != nil {
		return nil, err
	}
	if err := a.openChannel(&c, cfg, sealed, ver); err != nil {
		return nil, err
	}
	return &c, nil
}

// openChannel fills c.Config and c.Secrets from the stored row. Version 2
// rows hold both sealed in secret; older rows have the settings in clear in
// config and only the secrets sealed (see migrateChannelSecrets).
func (a *App) openChannel(c *channel, cfg, sealed []byte, ver int) error {
	errKey := errors.New("cannot decrypt the channel (was SECRET_KEY changed?)")
	if ver >= 2 {
		plain, err := a.sealer.openFor(channelContext(c.OrgID), sealed)
		if err != nil {
			return errKey
		}
		var p channelPayload
		if err := json.Unmarshal(plain, &p); err != nil {
			return errKey
		}
		c.Config, c.Secrets = p.Config, p.Secrets
		return nil
	}
	_ = json.Unmarshal(cfg, &c.Config)
	if len(sealed) > 0 {
		plain, err := a.sealer.open(sealed)
		if err != nil {
			return errKey
		}
		_ = json.Unmarshal(plain, &c.Secrets)
	}
	return nil
}

// sealChannel encrypts a channel's settings and secrets for storage.
func (a *App) sealChannel(c *channel) ([]byte, error) {
	j, _ := json.Marshal(channelPayload{Config: c.Config, Secrets: c.Secrets}) // #nosec G117 -- sealed with AES-256-GCM on the next line, never stored or returned in clear
	return a.sealer.sealFor(channelContext(c.OrgID), j)
}

// migrateChannelSecrets re-seals channels stored by older versions (settings
// in clear, secrets sealed without a salt) in the current format. A row that
// cannot be opened (SECRET_KEY changed) is left as it is and reported.
func (a *App) migrateChannelSecrets(ctx context.Context) {
	rows, err := a.db.Query(ctx, `SELECT id, org_id, config, secret, enc_version FROM notify_channels WHERE enc_version < 2`)
	if err != nil {
		log.Printf("secrets: cannot list channels to re-seal: %v", err)
		return
	}
	type old struct {
		c           channel
		cfg, sealed []byte
		ver         int
	}
	var todo []old
	for rows.Next() {
		var o old
		if rows.Scan(&o.c.ID, &o.c.OrgID, &o.cfg, &o.sealed, &o.ver) == nil {
			todo = append(todo, o)
		}
	}
	rows.Close()
	done := 0
	for _, o := range todo {
		if err := a.openChannel(&o.c, o.cfg, o.sealed, o.ver); err != nil {
			log.Printf("secrets: channel %d left as it is: %v", o.c.ID, err)
			continue
		}
		sealed, err := a.sealChannel(&o.c)
		if err != nil {
			continue
		}
		if _, err := a.db.Exec(ctx, `UPDATE notify_channels SET config = '{}', secret = $1, enc_version = 2 WHERE id = $2 AND enc_version < 2`,
			sealed, o.c.ID); err == nil {
			done++
		}
	}
	if done > 0 {
		log.Printf("secrets: re-sealed %d notification channel(s) with salted encryption", done)
	}
}

// channelView is what the API returns: config plus which secrets are set.
func channelView(c *channel) map[string]any {
	set := map[string]bool{}
	if c.Secrets.BotToken != "" {
		set["bot_token"] = true
	}
	if c.Secrets.WebhookURL != "" {
		set["webhook_url"] = true
	}
	if c.Secrets.Password != "" {
		set["password"] = true
	}
	if c.Secrets.ClientSecret != "" {
		set["client_secret"] = true
	}
	return map[string]any{"id": c.ID, "name": c.Name, "kind": c.Kind, "enabled": c.Enabled, "config": c.Config, "secrets_set": set}
}

// ----- handlers -----

type channelInput struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	Enabled *bool          `json:"enabled"`
	Config  channelConfig  `json:"config"`
	Secrets channelSecrets `json:"secrets"`
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request, action string) bool {
	if u := userFrom(r); u.Role == "member" {
		a.deny(w, r, action, "only owners and admins can manage notifications")
		return false
	}
	return true
}

func (a *App) handleListChannels(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := a.db.Query(r.Context(), `SELECT id FROM notify_channels WHERE org_id = $1 ORDER BY name, id`, u.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	out := []map[string]any{}
	for _, id := range ids {
		if c, err := a.loadChannel(r.Context(), u.OrgID, id); err == nil {
			out = append(out, channelView(c))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.channel_create") {
		return
	}
	u := userFrom(r)
	var in channelInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	c := &channel{OrgID: u.OrgID, Name: in.Name, Kind: in.Kind, Enabled: in.Enabled == nil || *in.Enabled, Config: in.Config, Secrets: in.Secrets}
	if err := a.validateChannel(c, nil); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sealed, err := a.sealChannel(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	ctx := r.Context()
	if err := a.db.QueryRow(ctx, `INSERT INTO notify_channels (org_id, name, kind, secret, enc_version, enabled) VALUES ($1,$2,$3,$4,2,$5) RETURNING id`,
		u.OrgID, c.Name, c.Kind, sealed, c.Enabled).Scan(&c.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "notify.channel_create", c.Kind+" "+c.Name)
	writeJSON(w, http.StatusOK, channelView(c))
}

func (a *App) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.channel_update") {
		return
	}
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in channelInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	prev, err := a.loadChannel(ctx, u.OrgID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	enabled := prev.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	c := &channel{ID: id, OrgID: u.OrgID, Name: in.Name, Kind: prev.Kind, Enabled: enabled, Config: in.Config, Secrets: in.Secrets}
	if in.Kind != "" && in.Kind != prev.Kind {
		writeErr(w, http.StatusBadRequest, "the kind of a channel cannot be changed")
		return
	}
	if err := a.validateChannel(c, &prev.Secrets); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sealed, err := a.sealChannel(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	if _, err := a.db.Exec(ctx, `UPDATE notify_channels SET name=$1, config='{}', secret=$2, enc_version=2, enabled=$3 WHERE id=$4 AND org_id=$5`,
		c.Name, sealed, c.Enabled, id, u.OrgID); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	a.audit(ctx, u, clientIP(r), "notify.channel_update", c.Kind+" "+c.Name+map[bool]string{true: "", false: " (disabled)"}[c.Enabled])
	writeJSON(w, http.StatusOK, channelView(c))
}

func (a *App) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.channel_delete") {
		return
	}
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	var name, kind string
	if err := a.db.QueryRow(ctx, `DELETE FROM notify_channels WHERE id=$1 AND org_id=$2 RETURNING name, kind`, id, u.OrgID).Scan(&name, &kind); err != nil {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	_, _ = a.db.Exec(ctx, `UPDATE alert_rules SET channel_ids = array_remove(channel_ids, $1) WHERE org_id = $2`, id, u.OrgID)
	a.audit(ctx, u, clientIP(r), "notify.channel_delete", kind+" "+name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r, "notify.channel_test") {
		return
	}
	u := userFrom(r)
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	c, err := a.loadChannel(ctx, u.OrgID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	m := alertMessage{Event: "test", Title: "Driftband test notification", Neutral: true,
		Lines: []string{"Channel \"" + c.Name + "\" works.", "Sent by " + u.Email + "."}, Link: a.appURL}
	derr := a.deliver(ctx, c, m)
	a.logDelivery(ctx, u.OrgID, 0, 0, c.ID, "test", m, derr)
	a.audit(ctx, u, clientIP(r), "notify.channel_test", c.Kind+" "+c.Name+map[bool]string{true: ", delivered", false: ", failed"}[derr == nil])
	if derr != nil {
		writeErr(w, http.StatusBadGateway, "delivery failed: "+derr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) logDelivery(ctx context.Context, orgID, ruleID, hostID, channelID int64, event string, m alertMessage, derr error) {
	var errText *string
	if derr != nil {
		s := derr.Error()
		if len(s) > 500 {
			s = s[:500]
		}
		errText = &s
	}
	nz := func(v int64) any {
		if v == 0 {
			return nil
		}
		return v
	}
	_, _ = a.db.Exec(ctx, `INSERT INTO notify_log (org_id, rule_id, host_id, channel_id, event, message, ok, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		orgID, nz(ruleID), nz(hostID), nz(channelID), event, m.Title, derr == nil, errText)
}
