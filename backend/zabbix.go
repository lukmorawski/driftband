package main

// Zabbix as a notification channel. Driftband pushes one value per change
// of an alert's state to a trapper item of a host in Zabbix, through the
// Zabbix API (history.push, Zabbix 7.0 and later, an API token over HTTPS).
// The template in docs/zabbix turns the values into problems that open when
// a rule starts alerting for a host and close when it recovers.
//
// Unlike the message channels, Zabbix follows the state itself: it gets
// every "alerting" and every "recovered", also from rules that send no
// recovery notice and while a host is flapping, and no reminders. A problem
// in Zabbix therefore mirrors the alert here.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// zabbixItemKey is the key of the trapper item the template defines.
const zabbixItemKey = "driftband.alert"

var (
	zabbixHostRe  = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,128}$`)
	zabbixTokenRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{16,512}$`)
)

// zabbixValue is the value of the item: one JSON object per line of history.
// The template reads event, alert, metric and summary with regular
// expressions, so those four never contain a double quote or a backslash.
type zabbixValue struct {
	Event        string   `json:"event"`  // problem | resolved | test
	Alert        string   `json:"alert"`  // the same for the problem and its recovery
	Metric       string   `json:"metric"` // loss | latency | test
	Summary      string   `json:"summary"`
	Host         string   `json:"host,omitempty"`
	Address      string   `json:"address,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Value        *float64 `json:"value,omitempty"`
	Threshold    *float64 `json:"threshold,omitempty"`
	Unit         string   `json:"unit,omitempty"`
	URL          string   `json:"url,omitempty"`
}

// zabbixAPIURL accepts the address of the Zabbix frontend or of its API
// and returns the API endpoint.
func zabbixAPIURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("not a valid URL")
	}
	if !strings.HasSuffix(u.Path, "/api_jsonrpc.php") {
		u.Path = strings.TrimRight(u.Path, "/") + "/api_jsonrpc.php"
	}
	return u.String(), nil
}

// plainText makes s safe for the fields the template reads with regular
// expressions and for a one-line problem name.
func plainText(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '"':
			return '\''
		case r == '\\':
			return '/'
		case r < 0x20 || r == 0x7f:
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return strings.TrimSpace(s)
}

// zabbixEvent renders a message as an item value. ok is false for events
// that are not a change of state.
func zabbixEvent(m alertMessage) (v zabbixValue, ok bool) {
	if m.Event == "test" {
		return zabbixValue{Event: "test", Alert: "test", Metric: "test", Summary: plainText(m.Title), URL: m.Link}, true
	}
	d := m.Alert
	if d == nil || (m.Event != "firing" && m.Event != "resolved") {
		return v, false
	}
	what, unit := "packet loss", "%"
	if d.Metric == "latency" {
		what, unit = "median latency", "ms"
	}
	host := d.Host
	if d.Address != "" && d.Address != d.Host {
		host += " (" + d.Address + ")"
	}
	v = zabbixValue{Event: "problem", Alert: "r" + strconv.FormatInt(d.RuleID, 10) + "-h" + strconv.FormatInt(d.HostID, 10),
		Metric: d.Metric, Host: d.Host, Address: d.Address, Rule: d.Rule, Organization: d.Org,
		Value: &d.Value, Threshold: &d.Threshold, Unit: unit, URL: m.Link}
	val := strconv.FormatFloat(d.Value, 'f', 1, 64) + " " + unit
	if m.Event == "resolved" {
		v.Event = "resolved"
		v.Summary = plainText(fmt.Sprintf("%s: %s back to %s", host, what, val))
	} else {
		v.Summary = plainText(fmt.Sprintf("%s: %s %s", host, what, val))
	}
	return v, true
}

// pushZabbix sends one value with history.push.
func (a *App) pushZabbix(ctx context.Context, c *channel, m alertMessage) error {
	v, ok := zabbixEvent(m)
	if !ok {
		return nil
	}
	var value bytes.Buffer
	enc := json.NewEncoder(&value)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	now := time.Now()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "history.push", "id": 1,
		"params": []any{map[string]any{"host": c.Config.ZabbixHost, "key": zabbixItemKey,
			"value": strings.TrimSpace(value.String()), "clock": now.Unix(), "ns": now.Nanosecond()}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.ZabbixURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json-rpc")
	req.Header.Set("Authorization", "Bearer "+c.Secrets.APIToken)
	clean := func(s string) string {
		s = strings.ReplaceAll(firstLine(strings.TrimSpace(s)), c.Secrets.APIToken, "<token>")
		if len(s) > 300 {
			s = s[:300]
		}
		return s
	}
	res, err := a.httpClient().Do(req)
	if err != nil {
		return errors.New(clean(err.Error()))
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from the Zabbix API", res.StatusCode)
	}
	var out struct {
		Result *struct {
			Data []struct {
				Error string `json:"error"`
			} `json:"data"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &out) != nil || (out.Result == nil && out.Error == nil) {
		return errors.New("the address did not answer like a Zabbix API (expected the frontend URL of Zabbix 7.0 or later)")
	}
	if out.Error != nil {
		return errors.New(clean("Zabbix API: " + strings.TrimSpace(out.Error.Message+" "+out.Error.Data)))
	}
	if len(out.Result.Data) != 1 {
		return errors.New("Zabbix API: unexpected answer to history.push")
	}
	if e := out.Result.Data[0].Error; e != "" {
		return errors.New(clean("Zabbix did not take the value for item " + zabbixItemKey + " of host " + c.Config.ZabbixHost + ": " + e))
	}
	return nil
}
