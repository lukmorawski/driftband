// Browser side of security keys and passkeys (WebAuthn). The server sends
// its options as JSON with base64url strings; navigator.credentials wants
// binary buffers and answers with buffers. These helpers convert both ways.

const enc = (buf) => {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

// Needs HTTPS (or localhost) and a browser with WebAuthn.
export const webauthnSupported = () =>
  !!(window.isSecureContext && window.PublicKeyCredential && navigator.credentials);

function common(cred) {
  return {
    id: cred.id, rawId: enc(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

// Enrollment: options is the "options" object of /register/begin.
export async function createCredential(options) {
  const pk = { ...options.publicKey };
  pk.challenge = dec(pk.challenge);
  pk.user = { ...pk.user, id: dec(pk.user.id) };
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: pk });
  const r = cred.response;
  return {
    ...common(cred),
    response: {
      clientDataJSON: enc(r.clientDataJSON),
      attestationObject: enc(r.attestationObject),
      transports: r.getTransports ? r.getTransports() : [],
    },
  };
}

// Sign-in: options is the "options" object sent with the login challenge.
export async function getAssertion(options) {
  const pk = { ...options.publicKey };
  pk.challenge = dec(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
  const cred = await navigator.credentials.get({ publicKey: pk });
  const r = cred.response;
  return {
    ...common(cred),
    response: {
      clientDataJSON: enc(r.clientDataJSON),
      authenticatorData: enc(r.authenticatorData),
      signature: enc(r.signature),
      userHandle: r.userHandle && r.userHandle.byteLength ? enc(r.userHandle) : undefined,
    },
  };
}

// What went wrong, in words a person can act on.
export function webauthnError(e) {
  switch (e && e.name) {
    case "NotAllowedError": return "The request was cancelled or timed out. Try again.";
    case "InvalidStateError": return "This key or device is already enrolled for your account.";
    case "SecurityError": return "Security keys and passkeys work only on Driftband's own HTTPS address.";
    case "NotSupportedError": return "This device or browser cannot create that kind of key.";
    case "AbortError": return "The request was cancelled.";
  }
  return (e && e.message) || "The key did not answer.";
}
