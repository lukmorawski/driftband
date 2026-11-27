import { h, clear } from "../ui.js";

// Band swatch opacities (lightest -> darkest, toward the median). Theme-aware
// via color-mix on --accent, matching the chart's smoke bands.
const BANDS = [
  ["p25-75", 46, "Middle 50% of pings (interquartile range). The most likely latency - darkest band."],
  ["p10-90", 28, "Middle 80% of pings."],
  ["p2.5-97.5", 18, "Middle 95% of pings."],
  ["min-max", 11, "Full range, from the fastest to the slowest ping in the cycle - lightest band."],
];
const LOSS_GRADIENT = "linear-gradient(90deg, rgb(74,222,128) 0%, rgb(163,230,53) 5%, rgb(250,204,21) 20%, rgb(251,146,60) 50%, rgb(248,113,113) 100%)";

function swatch(pct) {
  return h("span.sw", { style: `display:inline-block;width:26px;height:13px;border-radius:3px;background:color-mix(in srgb, var(--accent) ${pct}%, transparent)` });
}

function defRow(term, desc) {
  return h("tr", h("td", { style: "white-space:nowrap;color:var(--text)" }, term), h("td", desc));
}

// A numbered how-to: steps(title, ["...", ...], note).
function steps(title, list, note) {
  return h("div.howto",
    h("h3", title),
    h("ol", ...list.map((t) => h("li", t))),
    note ? h("p.hint", note) : null);
}
const ui = (t) => h("b", t);        // a label in Driftband's own interface
const code = (t) => h("code", t);   // something to type or copy

function card(title, sub, ...body) {
  return h("div.card", h("h2", title), sub ? h("p.sub", sub) : null, ...body);
}

export function renderFaq(mount) {
  clear(mount);
  mount.append(
    h("div.section-title", h("h2", "FAQ")),
    h("div.stack",

      card("Reading the smoke graph",
        "Each probe cycle sends several pings. Driftband plots the whole distribution of round-trip times, not just an average. A solid median line runs through shaded percentile bands that widen with jitter, and the line's colour encodes packet loss. The wider and darker the smoke, the more variable the latency."),

      card("Median RTT", "Statistics over the currently visible window.",
        h("div.legend", { style: "border:0;margin:0;padding:0" },
          h("div.lg-line", { style: "color:var(--text-dim)" },
            h("span.lab", { style: "min-width:92px;color:var(--text-mute)" }, "Median RTT"),
            " avg ", h("b", "2.2"), " · max ", h("b", "13.9"), " · min ", h("b", "1.3"), " · now ", h("b", "2.2"), " ms · sd ", h("b", "0.1"))),
        h("table.tbl", { style: "margin-top:14px" }, h("tbody",
          defRow("avg", "Average of the per-cycle median latencies across the window."),
          defRow("max", "Highest latency observed in the window (the slowest single ping)."),
          defRow("min", "Lowest latency observed in the window (the fastest single ping)."),
          defRow("now", "Median latency of the most recent cycle."),
          defRow("sd", "Standard deviation of the medians - a measure of jitter. Higher means less stable."),
        ))),

      card("Packet loss", "How many pings did not come back.",
        h("div.legend", { style: "border:0;margin:0;padding:0" },
          h("div.lg-line", { style: "color:var(--text-dim)" },
            h("span.lab", { style: "min-width:92px;color:var(--text-mute)" }, "Packet loss"),
            " avg ", h("b", "0.00%"), " · max ", h("b", "0%"), " · cycles with loss ", h("b", "0"), "/54")),
        h("table.tbl", { style: "margin-top:14px" }, h("tbody",
          defRow("avg", "Total lost packets divided by total packets sent across the window."),
          defRow("max", "Worst single-cycle loss percentage in the window."),
          defRow("cycles with loss", "Number of cycles that lost at least one packet, out of the total cycles shown."),
        ))),

      card("Percentile bands (the smoke)",
        "Symmetric bands around the median. Opacity increases toward the median, so the most likely latencies look darkest - that density is the smoke.",
        h("table.tbl", { style: "margin-top:6px" }, h("tbody",
          ...BANDS.map(([label, pct, desc]) => h("tr",
            h("td", { style: "white-space:nowrap" }, swatch(pct), h("span", { style: "margin-left:10px;color:var(--text)" }, label)),
            h("td", desc)))))),

      card("Loss colour",
        "The median line is coloured by the cycle's packet loss: green = no loss, ramping through yellow and orange to red = total loss. A thin strip along the bottom of the chart marks cycles with loss, and the health dot next to each host uses the same scale.",
        h("div.lg-loss", { style: "margin-top:8px" },
          h("span.lab", "loss"),
          h("div.lg-loss-wrap",
            h("div.bar", { style: `width:240px;background:${LOSS_GRADIENT}` }),
            h("div.ticks", { style: "width:240px" }, h("span", "0%"), h("span", "20%"), h("span", "50%"), h("span", "100%"))))),

      card("Probe profiles",
        "Sampling presets you attach to hosts. Manage them under Settings, Probe profiles.",
        h("table.tbl", h("tbody",
          defRow("Interval", "Seconds between probe cycles. Shorter means finer time resolution and more data points."),
          defRow("Pings per cycle", "How many pings form one cycle. More pings give a richer distribution (smoother smoke) and finer loss steps."),
          defRow("Packet size", "ICMP payload size in bytes, 12 to 1472 (a 1500-byte Ethernet frame minus the 20-byte IPv4 and 8-byte ICMP headers). Larger packets exercise the path differently."),
          defRow("Limits", "Pings per cycle can never exceed the interval in seconds, so every cycle finishes before the next one starts. Test instances also require an interval of 60 s or more and packets of at most 56 bytes."),
          defRow("Default", "New hosts attach the default profile automatically. You can choose a different profile per host; deleting a profile makes its hosts fall back to the default."),
        )),
        h("p.sub", { style: "margin:18px 0 8px" }, "Built-in presets"),
        h("table.tbl",
          h("thead", h("tr", h("th", "Name"), h("th", "Interval"), h("th", "Pings"), h("th", "Packet"))),
          h("tbody",
            h("tr", h("td", "Standard "), h("td", "60 s"), h("td", "20"), h("td", "56 B")),
            h("tr", h("td", "Fast"), h("td", "30 s"), h("td", "20"), h("td", "56 B")),
            h("tr", h("td", "Coarse"), h("td", "300 s"), h("td", "20"), h("td", "56 B")),
            h("tr", h("td", "Large packet"), h("td", "60 s"), h("td", "15"), h("td", "1400 B")),
          ))),

      card("Single sign-on",
        "Shown when the operator of this instance has turned on signing in with Google or Microsoft.",
        steps("Connect your account", [
          ["Open ", ui("Settings"), ", ", ui("Account"), " and find ", ui("Single sign-on"), "."],
          ["Press ", ui("Connect"), " next to the provider and confirm with your password."],
          ["Choose the account at the provider. You are sent back here and the connection is shown as ", ui("connected"), "."],
          ["From then on use ", ui("Sign in with Google"), " or ", ui("Sign in with Microsoft"), " on the sign-in page."],
        ], "Your password keeps working, and Disconnect removes the connection at any time."),
        h("table.tbl", h("tbody",
          defRow("Second factor", "Single sign-on replaces the password only. If your account has two-factor sign-in, you are still asked for the code, security key or passkey."),
          defRow("\"No account here is connected\"", "The account you chose at the provider has not been connected to an account here. Accounts are never matched by email address: sign in with your password and connect it first."),
          defRow("New people", "Joining an organization still goes through an invitation link and a password. Single sign-on can be connected afterwards."),
        ))),

      card("Notifications",
        "Settings, Notifications. Owners and admins add channels (Telegram, Slack, Microsoft Teams, email, Zabbix) and alert rules; members can see them.",
        h("table.tbl", h("tbody",
          defRow("Condition", "Packet loss (%) or median latency (ms), measured over the last few probe cycles of each host, so a single bad cycle never alerts on its own."),
          defRow("for N minutes", "The condition must hold continuously for this long before the alert fires."),
          defRow("Recovery", "A lower threshold that must hold for its own duration before the alert resolves (hysteresis), so a link hovering at the threshold does not ping-pong. The recovery notice is optional."),
          defRow("Flap guard", "If the alert changes state too often within the window, you get one \"flapping\" notice and nothing more until the link has been stable for half the window."),
          defRow("Reminder", "Optionally repeats the alert every N minutes while it is still firing."),
          defRow("Scope", "All hosts, a folder (and everything below it) or one host."),
        ))),
      card("Setting up notification channels",
        "Owners and admins add channels under Settings, Notifications, Add channel. Every channel has a \"Send test\" button: use it before you attach the channel to an alert rule. Addresses, accounts, tokens and passwords are stored encrypted, and secrets are never shown again; leave a secret field empty when editing to keep the stored one.",

        steps("Telegram", [
          ["In Telegram, open a chat with ", code("@BotFather"), ", send ", code("/newbot"), " and follow the questions. BotFather answers with the bot token, which looks like ", code("123456789:AAE..."), "."],
          ["Add the bot to the group or channel that should receive alerts (in a channel it must be an administrator). For a private chat, open the bot and press Start."],
          ["Find the chat id. A public channel can be addressed as ", code("@channelname"), ". For a group or a private chat, send any message there and open ", code("https://api.telegram.org/bot<token>/getUpdates"), " in a browser: the id is the ", code("chat.id"), " value (group ids are negative, supergroups and channels start with ", code("-100"), ")."],
          ["In Driftband choose ", ui("Telegram"), ", paste the ", ui("Bot token"), " and the ", ui("Chat id"), ", save and press ", ui("Send test"), "."],
        ], "If the test fails with \"chat not found\", the bot is not a member of that chat or the id is missing its minus sign."),

        steps("Slack", [
          ["Open ", code("https://api.slack.com/apps"), ", create an app (From scratch) in your workspace."],
          ["In the app, open Incoming Webhooks, switch them on and press Add New Webhook to Workspace. Pick the channel for the alerts."],
          ["Copy the webhook URL (", code("https://hooks.slack.com/services/..."), ")."],
          ["In Driftband choose ", ui("Slack"), ", paste it into ", ui("Webhook URL"), ", save and press ", ui("Send test"), "."],
        ], "One webhook posts to one channel. For another channel add another webhook and another Driftband channel."),

        steps("Microsoft Teams", [
          ["In Teams, open the channel, choose the three dots next to its name, then Workflows."],
          ["Pick the template \"Post to a channel when a webhook request is received\", confirm the team and channel, and create it."],
          ["Copy the URL the workflow shows (it starts with ", code("https://"), " and contains ", code("/workflows/"), ")."],
          ["In Driftband choose ", ui("Microsoft Teams"), ", paste it into ", ui("Webhook URL"), ", save and press ", ui("Send test"), "."],
        ], "Driftband sends an Adaptive Card, which is what Workflows webhooks expect. The older Office 365 connector webhooks are being retired by Microsoft; use Workflows."),

        steps("Email with a username and password", [
          ["Choose ", ui("Email"), " and enter the ", ui("SMTP host"), " of your mail server, the ", ui("Port"), " and the ", ui("Security"), ": 587 with STARTTLS for most servers, 465 with TLS (implicit) for the others."],
          ["Fill ", ui("From"), " (an address the server lets this account send as, for example ", code("Driftband <alerts@example.com>"), ") and ", ui("To"), " (up to 20 recipients, comma-separated)."],
          ["Set ", ui("Authentication"), " to ", ui("Username and password"), ". Where the provider has two-step sign-in (Gmail, iCloud, many hosted mailboxes), create an app password and use that, not the account's own password."],
          ["Save and press ", ui("Send test"), "."],
        ], "A relay on your own network that accepts mail without signing in works with \"No authentication\". A password is only sent over TLS or STARTTLS."),

        steps("Email through Microsoft 365 with OAuth 2.0", [
          ["In the Microsoft Entra admin center, register an application (App registrations, New registration). Note its Application (client) ID and the Directory (tenant) ID."],
          ["Under API permissions add the application permission ", code("SMTP.SendAsApp"), " (APIs my organization uses, Office 365 Exchange Online) and grant admin consent."],
          ["Under Certificates & secrets create a client secret and copy its value."],
          ["In Exchange Online PowerShell, register the application as a service principal and let it use the mailbox: ", code("New-ServicePrincipal -AppId <client id> -ObjectId <enterprise application object id>"), ", then ", code("Add-MailboxPermission -Identity alerts@example.com -User <service principal id> -AccessRights FullAccess"), ". Make sure authenticated SMTP is enabled for that mailbox."],
          ["In Driftband choose ", ui("Email"), ", host ", code("smtp.office365.com"), ", port 587, STARTTLS, ", ui("Authentication"), ": ", ui("OAuth 2.0 (client credentials)"), ", provider ", ui("Microsoft 365"), ". Enter the mailbox as ", ui("Mailbox (username)"), " and as ", ui("From"), ", the ", ui("Tenant"), ", the ", ui("Client id"), " and the ", ui("Client secret"), "."],
          ["Save and press ", ui("Send test"), "."],
        ], "With another provider choose \"Other provider\" and enter its token URL and scope; Driftband uses the client credentials grant and signs in to SMTP with XOAUTH2."),

        steps("Zabbix", [
          ["You need Zabbix 7.0 or later, reachable from this Driftband over HTTPS. Download the template ", code("template_driftband.yaml"), " from ", h("a", { href: "https://github.com/lukmorawski/driftband/tree/main/docs/zabbix", target: "_blank", rel: "noopener" }, "docs/zabbix"), " in the Driftband repository; the page there describes every step in detail."],
          ["In Zabbix, import the template (Data collection, Templates, Import) and create a host for the alerts, for example ", code("Driftband"), ", linked to the template \"Driftband by Zabbix trapper\". The host needs no interface."],
          ["Create a user role of type User whose only allowed API method is ", code("history.push"), ", a user with that role and read permission on the host's group, and an API token for that user (Users, API tokens)."],
          ["In Driftband choose ", ui("Zabbix"), ", enter the ", ui("Zabbix URL"), " (the address of the Zabbix frontend), the ", ui("Host in Zabbix"), " (its technical host name) and the ", ui("API token"), ", save and press ", ui("Send test"), "."],
          ["The test value appears in Zabbix under Monitoring, Latest data. Add the channel to your alert rules: a rule that starts alerting for a host opens a problem in Zabbix, and the problem closes when the host recovers."],
        ], "Zabbix follows the state of an alert: it gets every change, also from rules without a recovery notice, and no reminders. A problem can also be closed by hand in Zabbix."),

        h("p.sub", { style: "margin:18px 0 8px" }, "When a test fails"),
        h("table.tbl", h("tbody",
          defRow("Webhook URL refused", "Webhook, token and Zabbix URLs must be HTTPS and must point to a public address. Addresses of an internal network are refused unless the operator of this instance has allowed them."),
          defRow("Zabbix did not take the value", "The host name must be the technical name of a host linked to the template, the user needs read permission on its host group, and the user's role must allow the API method history.push."),
          defRow("Authentication failed", "Check the username, use an app password where the provider requires one, and for Microsoft 365 check the admin consent and the mailbox permission."),
          defRow("No STARTTLS offered", "The server speaks implicit TLS on that port (use TLS, usually port 465) or no encryption at all."),
          defRow("Where to look", "Recent notifications (Settings, Notifications, or Active Alerts in the top bar) lists every delivery with the error the service returned."),
        ))),

      card("Tips",
        null,
        h("table.tbl", h("tbody",
          defRow("Zoom", "Drag horizontally across a chart to zoom into a time range."),
          defRow("Reset", "Double-click a chart to reset back to the selected range."),
          defRow("Ranges", "The 1h / 6h / 24h / 7d / max buttons control the main chart. Selecting a single host also shows fixed 1h, 6h and 24h graphs."),
          defRow("Live", "The live button toggles 15-second auto-refresh (off by default)."),
          defRow("Health dot", "The dot beside a host shows its latest status: green = ok, ramping to red on loss, grey if stale or not yet probed."),
        ))),
    ),
  );
}
