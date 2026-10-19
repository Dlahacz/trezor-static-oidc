import { slip13Identity } from "../oidc.js";
import { enrollAccount } from "../flows.js";
import { $, el, renderDevice, connectTrezor, explainError } from "../ui.js";

const load = async (path) => {
  try {
    const r = await fetch(path, { cache: "no-store" });
    return r.ok ? await r.json() : null;
  } catch { return null; }
};
const deployed = await load("idp-config.json");

// The deployed config knows the real issuer; fall back to this page's folder when running unbuilt.
$("#issuer").value = deployed?.issuer || new URL(".", location.href).href.replace(/\/$/, "");

const paint = () => {
  try {
    const identity = slip13Identity($("#issuer").value, $("#user").value || "user", Number($("#index").value) || 0);
    renderDevice($("#device"), { identity, visual: "Set up sign-in key" });
  } catch { /* invalid URL while typing */ }
};
["issuer", "user", "index"].forEach((id) => $("#" + id).addEventListener("input", paint));
paint();

/** For *.github.io sites, guess the repository so we can link straight to the file editor. */
function githubEditUrl(issuer) {
  const u = new URL(issuer);
  if (!u.hostname.endsWith(".github.io")) return null;
  const owner = u.hostname.slice(0, -".github.io".length);
  const repo = u.pathname.split("/").filter(Boolean)[0] || u.hostname;
  return `https://github.com/${owner}/${repo}/edit/main/config/accounts.json`;
}

function fileBlock(path, body) {
  const text = JSON.stringify(body, null, 2) + "\n";
  const name = path.split("/").pop();
  const copy = el("button", { type: "button", class: "quiet" }, "Copy");
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(text);
    copy.textContent = "Copied";
    setTimeout(() => (copy.textContent = "Copy"), 1500);
  });
  const dl = el("a", { class: "button quiet", download: name, href: URL.createObjectURL(new Blob([text], { type: "application/json" })) }, "Download");
  return el("div", { class: "file" },
    el("header", {}, el("code", {}, path), el("span", { class: "row" }, copy, dl)),
    el("pre", {}, text),
  );
}

$("#form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("#go");
  btn.disabled = true;
  $("#error").hidden = true;
  let transport;
  try {
    const issuer = $("#issuer").value.replace(/\/+$/, "");
    new URL(issuer);
    const user = $("#user").value.trim();
    const conn = await connectTrezor({ onButton: () => $("#device").classList.add("device--active") });
    transport = conn.transport;
    const { account } = await enrollAccount(conn.client, {
      issuer, user, name: $("#name").value.trim(), index: Number($("#index").value) || 0,
    });

    // Merge with the accounts already published for this issuer, replacing one with the same username.
    const published = deployed && deployed.issuer === issuer ? deployed.accounts : [];
    const accounts = [...published.filter((a) => a.sub !== account.sub), account];

    const replaced = published.some((a) => a.sub === account.sub);
    $("#ok-msg").textContent =
      `${replaced ? "Updated" : "Registered"} ${account.sub} with key ${account.kid}. ` +
      "The Trezor's test signature verified as a standard ES256 JWT.";
    $("#files").replaceChildren(fileBlock("config/accounts.json", accounts));
    const edit = githubEditUrl(issuer);
    $("#edit-link").hidden = !edit;
    if (edit) $("#edit-link a").href = edit;
    $("#result").hidden = false;
    $("#result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  } catch (e) {
    console.error(e);
    $("#error-msg").textContent = explainError(e);
    $("#error").hidden = false;
  } finally {
    $("#device").classList.remove("device--active");
    btn.disabled = false;
    if (transport) await transport.close();
  }
});
