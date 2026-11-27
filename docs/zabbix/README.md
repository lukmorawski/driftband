# Driftband alerts in Zabbix

Driftband can report its alerts to Zabbix. An alert rule that starts
alerting for a host opens a problem in Zabbix; when the host recovers, the
problem closes. Zabbix then handles it like any other problem: dashboards,
escalations, maintenance, acknowledgements.

- [`template_driftband.yaml`](template_driftband.yaml): the template to
  import into Zabbix, "Driftband by Zabbix trapper".

Driftband pushes the values through the Zabbix API (`history.push`) over
HTTPS, authenticated with an API token. Nothing is installed on the Zabbix
server and Zabbix needs no access to Driftband.

## Requirements

- Zabbix 7.0 or later (`history.push` appeared in 7.0). The template and
  the steps below were tested with Zabbix 7.0 and 8.0.
- The Zabbix frontend is reachable from Driftband over HTTPS with a
  certificate Driftband trusts.
- If Zabbix has a private address, the operator of the Driftband instance
  has allowed that: `NOTIFY_PRIVATE_TARGETS=yes`
  (see [Configuration](../CONFIGURATION.md#notifications-to-internal-systems),
  also for certificates of a private certificate authority).

## Setup in Zabbix

1. **Import the template.** Data collection, Templates, Import, choose
   `template_driftband.yaml`.
2. **Create a host for the alerts.** Data collection, Hosts, Create host:
   any name (for example `Driftband`), a host group of its own (for example
   `Driftband`), template "Driftband by Zabbix trapper". The host needs no
   interface. Its *host name* (the technical name, not the visible name) is
   what you enter in Driftband.
3. **Create a role that can only push values.** Users, User roles, Create
   user role: user type "User", access to UI elements, modules and actions
   off, API access on, API methods "Allow list" with the single method
   `history.push`. Zabbix 8.0 does not let the built-in user role call
   that method, so the role is needed there; on 7.0 it keeps the token
   from doing anything else.
4. **Create a user for Driftband.** Users, User groups, Create user group
   with **read** permission on the host group from step 2; then Users,
   Create user with that group and the role from step 3. Read permission
   is enough to push values.
5. **Create an API token.** Users, API tokens, Create API token for that
   user. Copy the token: Zabbix shows it once.

## Setup in Driftband

Settings, Notifications, Add channel, type **Zabbix**:

| Field | Value |
|---|---|
| Zabbix URL | the address of the Zabbix frontend, for example `https://zabbix.example.com` or `https://example.com/zabbix` |
| Host in Zabbix | the host name from step 2 |
| API token | the token from step 5 |

Save and press **Send test**. The test value appears in Zabbix under
Monitoring, Latest data for that host (item "Driftband: alert event"); it
opens no problem. Then add the channel to your alert rules.

## How problems behave

- One problem per alert rule and host. The problem's name carries the host,
  its address, and the measured value, for example
  `Driftband: core-sw1 (192.0.2.7): packet loss 61.3 %`.
- Packet loss rules open problems of severity *High*, latency rules of
  severity *Warning*. Change the severities in the template's triggers if
  you rate them differently.
- Zabbix follows the state of the alert, not the messages Driftband sends
  to people. It gets every "alerting" and every "recovered", also from a
  rule with recovery notices turned off and while a host is flapping;
  reminders are not sent.
- Problems carry the tags `source: driftband`, `scope: availability` or
  `scope: performance`, and `alert` with the rule and the host. A recovery
  closes the problem with the same `alert` tag.
- A problem can be closed by hand. That is the way out when its recovery
  could not be delivered (Zabbix was down for longer than Driftband
  retries), or when the rule or the host was deleted in Driftband while
  alerting.

## What Zabbix receives

One value of the item `driftband.alert` per change of state, a JSON object:

```json
{"event":"problem","alert":"r7-h42","metric":"loss","summary":"core-sw1 (192.0.2.7): packet loss 61.3 %","host":"core-sw1","address":"192.0.2.7","rule":"Core links: packet loss","organization":"Acme","value":61.3,"threshold":50,"unit":"%","url":"https://latency.example.org"}
```

| Field | Meaning |
|---|---|
| `event` | `problem`, `resolved`, or `test` (the Send test button) |
| `alert` | identifies the rule and the host; the same in a problem and its recovery |
| `metric` | `loss` (packet loss, %) or `latency` (median round-trip time, ms) |
| `summary` | one line for the problem's name |
| `host`, `address` | the host as named in Driftband, and what is probed |
| `rule`, `organization` | the alert rule and the organization it belongs to |
| `value`, `threshold`, `unit` | the measurement that changed the state and the rule's threshold |
| `url` | the address of the Driftband instance |

The history of the item keeps the values for 90 days, so you can build
your own triggers, dashboards or reports on them.

## Restricting who may send values

The template macro `{$DRIFTBAND.ALLOWED_HOSTS}` is the item's "Allowed
hosts" list. Its default accepts every address; the API token and the
permissions of its user are what protect the item. To restrict it further,
set the macro on the host to the addresses of **both** the Zabbix frontend
and Driftband, comma-separated: Zabbix checks the address the API call
came from and the address of the frontend that passes the value on.

## When the test fails

| Message | Cause |
|---|---|
| `Zabbix URL: must use https` | the channel needs the HTTPS address of the frontend |
| `Zabbix URL: host resolves to a private or reserved address` | Zabbix has a private address and the instance does not allow such targets (`NOTIFY_PRIVATE_TARGETS`) |
| `certificate signed by unknown authority` | Driftband does not trust the frontend's certificate (see Configuration, private certificate authority) |
| `Zabbix API: ... Not authorized.` | the API token is wrong, expired or disabled |
| `Zabbix API: ... No permissions to call "history.push".` | the user's role does not allow the method (step 3) |
| `No permissions to referred object or it does not exist.` | the host name is not the technical host name, the template is not linked to it, or the user group has no read permission on its host group |
| `... is not in item's allowed hosts list.` | the `{$DRIFTBAND.ALLOWED_HOSTS}` macro leaves out the address of Driftband or of the Zabbix frontend |
| `the address did not answer like a Zabbix API` | the URL is not the frontend of Zabbix 7.0 or later |

A host or template created a moment ago is known to the Zabbix server only
after its next configuration reload (a few seconds); the same goes for
changed permissions.
