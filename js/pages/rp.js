// Demo relying party: implicit flow with state + nonce, verifies the ID token in the browser.
import { randomToken, verifyIdToken } from "../oidc.js";
import { $, el } from "../ui.js";

const KEY = "demo-rp-pending";
const SETTINGS = "demo-rp-settings";
const redirectUri = location.origin + location.pathname;
const store = {
  get(k) { try { return JSON.parse(sessionStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del(k) { try { sessionStorage.removeItem(k); } catch {} },
};

const saved = store.get(SETTINGS) || {};
$("#issuer").value = saved.issuer || new URL("..", location.href).href.replace(/\/$/, "");
$("#client").value = saved.client || "demo-rp";
$("#scope").value = saved.scope || "openid profile";

const fail = (msg) => { $("#error-msg").textContent = msg; $("#error").hidden = false; };
const getJson = async (url) => {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url} returned ${r.status}`);
  return r.json();
};

$("#signin").addEventListener("click", async () => {
  $("#error").hidden = true;
  const issuer = $("#issuer").value.replace(/\/+$/, "");
  const client = $("#client").value.trim();
  const scope = $("#scope").value.trim();
  store.set(SETTINGS, { issuer, client, scope });
  try {
    const disco = await getJson(`${issuer}/.well-known/openid-configuration`);
    if (disco.issuer !== issuer) throw new Error(`Discovery says the issuer is ${disco.issuer}, not ${issuer}.`);
    const state = randomToken(), nonce = randomToken();
    store.set(KEY, { state, nonce, issuer, client, jwks_uri: disco.jwks_uri });
    const url = new URL(disco.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: client, redirect_uri: redirectUri, response_type: "id_token", response_mode: "fragment",
      scope, state, nonce,
    });
    location.assign(url);
  } catch (e) {
    fail(`Could not reach the sign-in service: ${e.message}`);
  }
});

$("#signout").addEventListener("click", () => {
  $("#signed-in").hidden = true;
  $("#signed-out").hidden = false;
});

// ---------------------------------------------------------------- callback
const frag = new URLSearchParams(location.hash.slice(1));
if (frag.has("id_token") || frag.has("error")) {
  history.replaceState(null, "", location.pathname + location.search); // drop the token from the address bar
  const pending = store.get(KEY);
  store.del(KEY);
  try {
    if (!pending || frag.get("state") !== pending.state) throw new Error("This response doesn't match a sign-in started here (state mismatch). Start again.");
    if (frag.has("error")) throw new Error(`The sign-in service returned ${frag.get("error")}: ${frag.get("error_description") || "no details"}`);
    const token = frag.get("id_token");
    const jwks = await getJson(pending.jwks_uri);
    const { header, claims } = await verifyIdToken(token, jwks, { issuer: pending.issuer, audience: pending.client, nonce: pending.nonce });

    $("#hello").textContent = `Signed in as ${claims.name || claims.preferred_username || claims.sub}`;
    const fact = (k, v) => el("li", {}, el("span", { class: "k" }, k), el("span", { class: "v" }, v));
    $("#checks").replaceChildren(
      fact("Signature", `ES256, key ${header.kid} from the published JWKS`),
      fact("Issuer", claims.iss),
      fact("Audience", claims.aud),
      fact("Nonce", "matches this sign-in"),
      fact("Expires", new Date(claims.exp * 1000).toLocaleTimeString()),
    );
    $("#claims").replaceChildren(...Object.entries(claims).map(([k, v]) => fact(k, String(v))));
    $("#raw").textContent = token;
    $("#signed-out").hidden = true;
    $("#signed-in").hidden = false;
  } catch (e) {
    fail(e.message);
  }
}
