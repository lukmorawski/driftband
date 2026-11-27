// Thin fetch wrapper around the JSON API.

async function req(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (!res.ok) {
    const msg = (data && data.error) || `request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// query({a: 1, b: ""}) -> "?a=1" (empty and null values are left out)
function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v != null && v !== "") q.set(k, v);
  const s = q.toString();
  return s ? "?" + s : "";
}

export const api = {
  get:   (p)    => req("GET", p),
  post:  (p, b) => req("POST", p, b),
  patch: (p, b) => req("PATCH", p, b),
  del:   (p)    => req("DELETE", p),

  me:            ()        => req("GET", "/api/me"),
  registerOrg:   (b)       => req("POST", "/api/auth/register-org", b),
  login:         (b)       => req("POST", "/api/auth/login", b),
  logout:        ()        => req("POST", "/api/auth/logout"),
  inviteInfo:    (token)   => req("GET", "/api/auth/invite-info?token=" + encodeURIComponent(token)),
  // what the sign-in page needs before anyone is signed in:
  // { registration_open, turnstile_site_key, sso: [{ id, name }] }
  authConfig:    ()        => req("GET", "/api/auth/config"),
  // single sign-on: the provider's answer, then (if asked) the second factor
  ssoFinish:     (b)       => req("POST", "/api/auth/sso/finish", b),
  acceptInvite:  (b)       => req("POST", "/api/auth/accept-invite", b),

  changePassword:(b)       => req("POST", "/api/account/password", b),
  changeEmail:   (b)       => req("POST", "/api/account/email", b),
  changeName:    (b)       => req("POST", "/api/account/name", b),
  totpSetup:     (b)       => req("POST", "/api/account/2fa/setup", b),
  totpEnable:    (b)       => req("POST", "/api/account/2fa/enable", b),
  totpDisable:   (b)       => req("POST", "/api/account/2fa/disable", b),
  webauthnList:  ()        => req("GET", "/api/account/webauthn"),
  webauthnBegin: (b)       => req("POST", "/api/account/webauthn/register/begin", b),
  webauthnFinish:(b)       => req("POST", "/api/account/webauthn/register/finish", b),
  webauthnRemove:(id, password) => req("POST", `/api/account/webauthn/${id}/delete`, { password }),
  ssoList:       ()        => req("GET", "/api/account/sso"),
  ssoLink:       (provider, password) => req("POST", "/api/account/sso/link", { provider, password }),
  ssoLinkFinish: (b)       => req("POST", "/api/account/sso/finish", b),
  ssoUnlink:     (provider, password) => req("POST", `/api/account/sso/${provider}/unlink`, { password }),
  // type: the file's media type; data: the file, base64-encoded
  setAvatar:     (type, data) => req("POST", "/api/account/avatar", { type, data }),
  removeAvatar:  ()        => req("DELETE", "/api/account/avatar"),
  setRetention:  (years)   => req("POST", "/api/settings/retention", { years }),

  users:         ()        => req("GET", "/api/users"),
  removeUser:    (id)      => req("DELETE", "/api/users/" + id),
  changeRole:    (id, role) => req("PATCH", `/api/users/${id}/role`, { role }),

  notifyChannels: ()       => req("GET", "/api/notify/channels"),
  createChannel: (b)       => req("POST", "/api/notify/channels", b),
  updateChannel: (id, b)   => req("PATCH", "/api/notify/channels/" + id, b),
  deleteChannel: (id)      => req("DELETE", "/api/notify/channels/" + id),
  testChannel:   (id)      => req("POST", `/api/notify/channels/${id}/test`),
  notifyRules:   ()        => req("GET", "/api/notify/rules"),
  createRule:    (b)       => req("POST", "/api/notify/rules", b),
  updateRule:    (id, b)   => req("PATCH", "/api/notify/rules/" + id, b),
  deleteRule:    (id)      => req("DELETE", "/api/notify/rules/" + id),
  // page: { limit, offset } of the delivery history (active alerts always come whole)
  notifyEvents:  (page)    => req("GET", "/api/notify/events" + query(page)),
  invites:       ()        => req("GET", "/api/invites"),
  createInvite:  (role)    => req("POST", "/api/invites", { role }),
  revokeInvite:  (token)   => req("DELETE", "/api/invites/" + encodeURIComponent(token)),

  profiles:      ()        => req("GET", "/api/profiles"),
  createProfile: (b)       => req("POST", "/api/profiles", b),
  updateProfile: (id, b)   => req("PATCH", "/api/profiles/" + id, b),
  deleteProfile: (id)      => req("DELETE", "/api/profiles/" + id),

  tree:          ()        => req("GET", "/api/tree"),
  createNode:    (b)       => req("POST", "/api/nodes", b),
  updateNode:    (id, b)   => req("PATCH", "/api/nodes/" + id, b),
  moveNode:      (id, parent_id, position) => req("POST", `/api/nodes/${id}/move`, { parent_id, position }),
  deleteNode:    (id)      => req("DELETE", "/api/nodes/" + id),
  importSmokeping: (config) => req("POST", "/api/import/smokeping", { config }),

  // opts: { points, step, since } - see handleSeries in backend/series.go
  series:        (host, from, to, opts = {}) => {
    const q = new URLSearchParams({ host, from, to });
    for (const [k, v] of Object.entries(opts)) if (v != null) q.set(k, v);
    return req("GET", "/api/series?" + q);
  },
  status:        ()        => req("GET", "/api/status"),
  audit:         (page)    => req("GET", "/api/audit" + query(page)),

  // platform administration (superadmins)
  adminOrgs:         ()            => req("GET", "/api/admin/orgs"),
  adminOrgUsers:     (id)          => req("GET", `/api/admin/orgs/${id}/users`),
  adminBlockOrg:     (id, blocked) => req("POST", `/api/admin/orgs/${id}/block`, { blocked }),
  adminSetLimits:    (id, host_limit, exempt_limits) => req("PATCH", `/api/admin/orgs/${id}/limits`, { host_limit, exempt_limits }),
  adminOrgHosts:     (id)          => req("GET", `/api/admin/orgs/${id}/hosts`),
  adminDeleteOrg:    (id, password, name) => req("POST", `/api/admin/orgs/${id}/delete`, { password, name }),
  usage:             ()            => req("GET", "/api/usage"),
  adminBlockUser:    (id, blocked) => req("POST", `/api/admin/users/${id}/block`, { blocked }),
  adminResetPassword:(id, reset_2fa) => req("POST", `/api/admin/users/${id}/reset-password`, { reset_2fa }),
  adminDeleteUser:   (id)          => req("DELETE", `/api/admin/users/${id}`),
  adminStats:        ()            => req("GET", "/api/admin/stats"),
  adminSettings:     ()            => req("GET", "/api/admin/settings"),
  adminSetSettings:  (b)           => req("PATCH", "/api/admin/settings", b),
  adminAudit:        (params)      => req("GET", "/api/admin/audit" + query(params)),
};
