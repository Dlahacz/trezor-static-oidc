import { parseAuthRequest, authResponse, sendAuthResponse, AuthError } from "../oidc.js";
import { signIdToken } from "../flows.js";
import { $, el, renderDevice, setSteps, connectTrezor, explainError, LOCK_ICON } from "../ui.js";

const show = (id) => ["loading", "fatal", "consent"].forEach((s) => ($("#" + s).hidden = s !== id));
const load = async (path) => {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path} could not be loaded (${r.status}).`);
  return r.json();
};
const fatal = (msg) => { $("#fatal-msg").textContent = msg; show("fatal"); };

/** Load config and validate the request; returns null when the page must stop. */
async function boot() {
  // Refuse to run inside a frame: a hidden frame could ask for device confirmations.
  if (window.top !== window.self) {
    document.body.textContent = "This sign-in page can't be shown inside another page.";
    return null;
  }
  let config, clients, req;
  try {
    [config, clients] = await Promise.all([load("idp-config.json"), load("clients.json")]);
    $("#issuer").append(LOCK_ICON(), el("span", {}, new URL(config.issuer).host));
    req = parseAuthRequest(new URLSearchParams(location.search), clients);
  } catch (e) {
    if (e instanceof AuthError && !e.fatal && e.req) {
      sendAuthResponse(document, authResponse(e.req, { error: e.error, error_description: e.message }));
    } else {
      fatal(e.message);
    }
    return null;
  }
  if (!config.accounts?.length) {
    fatal("No accounts are set up yet. Open setup.html on this site to register a Trezor.");
    return null;
  }
  return { config, req };
}

const ctx = await boot();
if (ctx) startConsent(ctx);

function startConsent({ config, req }) {
  const appName = req.client.name || req.clientId;
  const returnHost = new URL(req.redirectUri).host;
  $("#title").textContent = `Sign in to ${appName}`;
  $("#lede").textContent = `${appName} wants to confirm who you are. Your Trezor signs a short-lived ID token; nothing else leaves the device.`;
  $("#step-return").textContent = `Return to ${appName}`;
  const shares = ["your account ID"];
  if (req.scope.includes("profile")) shares.push("your name and username");
  $("#facts").append(
    el("li", {}, el("span", { class: "k" }, "Returns to"), el("span", { class: "v" }, returnHost)),
    el("li", {}, el("span", { class: "k" }, "Shares"), el("span", { class: "v" }, shares.join(" and "))),
    el("li", {}, el("span", { class: "k" }, "Valid for"), el("span", { class: "v" }, `${Math.round((config.token_ttl || 300) / 60)} minutes`)),
  );

  const select = $("#account");
  config.accounts.forEach((a, i) => select.append(el("option", { value: i }, a.name ? `${a.name} (${a.sub})` : a.sub)));
  if (req.loginHint) {
    const i = config.accounts.findIndex((a) => a.sub === req.loginHint || a.identity.user === req.loginHint);
    if (i >= 0) select.value = String(i);
  }
  $("#account-field").hidden = config.accounts.length < 2;
  const account = () => config.accounts[Number(select.value) || 0];
  const visual = `Sign in to ${appName}`.slice(0, 64);
  const paint = () => renderDevice($("#device"), { identity: account().identity, visual });
  select.addEventListener("change", paint);
  paint();
  show("consent");

  // ---------------------------------------------------------------- actions
  $("#cancel").addEventListener("click", () =>
    sendAuthResponse(document, authResponse(req, { error: "access_denied", error_description: "The user cancelled sign-in." })),
  );

  const steps = $("#steps");
  async function signIn(forcePicker) {
    const btn = $("#go");
    btn.disabled = true;
    $("#error").hidden = true;
    setSteps(steps, 0);
    let transport;
    try {
      const conn = await connectTrezor({
        forcePicker,
        onButton: () => { setSteps(steps, 1); $("#device").classList.add("device--active"); },
      });
      transport = conn.transport;
      const { idToken } = await signIdToken(conn.client, { config, account: account(), req });
      $("#device").classList.remove("device--active");
      setSteps(steps, 2);
      await transport.close();
      transport = null;
      sendAuthResponse(document, authResponse(req, { id_token: idToken }));
    } catch (e) {
      console.error(e);
      $("#device").classList.remove("device--active");
      setSteps(steps, -1);
      $("#error-msg").textContent = explainError(e);
      $("#error").hidden = false;
      btn.disabled = false;
    } finally {
      if (transport) await transport.close();
    }
  }
  $("#go").addEventListener("click", () => signIn(false));
  $("#other-device").addEventListener("click", (e) => { e.preventDefault(); signIn(true); });
}
