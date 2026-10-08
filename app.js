import qrcode from "./vendor/qrcode.mjs";
import {
  base32,
  createSecret,
  enrollmentUri,
  importKey,
  matchingCounters,
  validateLabel,
  verifyNextCode,
} from "./totp.js";

const $ = (id) => document.getElementById(id);
let secret = null;
let key = null;
let label = "";
let firstCounters = [];
let busy = false;
let generation = 0;

function showPanel(name, step, focusId) {
  for (const panel of document.querySelectorAll(".panel"))
    panel.hidden = panel.id !== `${name}-panel`;
  for (let i = 1; i <= 3; i++) {
    const item = $(`step-${i}`);
    item.classList.toggle("complete", i < step);
    if (i === step) item.setAttribute("aria-current", "step");
    else item.removeAttribute("aria-current");
  }
  if (focusId) $(focusId).focus();
}

function resetVerification() {
  firstCounters = [];
  $("verification-code").value = "";
  $("code-label").textContent = "First code";
  $("verify-button").textContent = "Check first code →";
  $("verify-status").textContent = "";
  $("verify-error").textContent = "";
  $("first-check").classList.remove("checked");
  $("second-check").classList.remove("checked");
  $("restart-check").hidden = true;
}

function clearSecret() {
  generation++;
  secret?.fill(0);
  secret = null;
  key = null;
  label = "";
  $("qr-code").replaceChildren();
  $("manual-key").textContent = "";
  $("enroll-label").textContent = "";
  $("success-label").textContent = "";
  $("copy-status").textContent = "";
  $("manual-details").open = false;
  $("token-label").value = "";
  resetVerification();
}

if (!window.isSecureContext || !globalThis.crypto?.subtle) {
  $("create-button").disabled = true;
  $("create-error").textContent =
    "Please open this page over HTTPS in a browser that supports Web Crypto.";
}

$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  $("create-error").textContent = "";
  try {
    label = validateLabel($("token-label").value);
  } catch (error) {
    $("create-error").textContent = error.message;
    return;
  }
  busy = true;
  $("create-button").disabled = true;
  const activeGeneration = generation;
  try {
    secret = createSecret();
    const imported = await importKey(secret);
    if (activeGeneration !== generation) return;
    key = imported;
    const qr = qrcode(0, "M");
    qr.addData(enrollmentUri(secret, label), "Byte");
    qr.make();
    // The library renders only QR geometry. Labels are never interpreted as HTML.
    $("qr-code").innerHTML = qr.createSvgTag({
      cellSize: 4,
      margin: 16,
      scalable: true,
    });
    $("manual-key").textContent = base32(secret);
    $("enroll-label").textContent = label;
    showPanel("enroll", 2, "enroll-title");
  } catch {
    clearSecret();
    $("create-error").textContent =
      "Could not create your token. Please try again in an up-to-date browser over HTTPS.";
  } finally {
    busy = false;
    $("create-button").disabled = false;
  }
});

$("copy-key").addEventListener("click", async () => {
  const activeGeneration = generation;
  try {
    await navigator.clipboard.writeText($("manual-key").textContent);
    if (activeGeneration === generation)
      $("copy-status").textContent =
        "Copied. Your clipboard now contains the secret; clear it after importing.";
  } catch {
    if (activeGeneration === generation)
      $("copy-status").textContent =
        "Copy was unavailable. Select the setup key above and copy it manually.";
  }
});

function beginVerification() {
  resetVerification();
  showPanel("verify", 3, "verification-code");
}
$("begin-verify").addEventListener("click", beginVerification);
$("check-another").addEventListener("click", beginVerification);
$("restart-check").addEventListener("click", () => {
  if (!busy) beginVerification();
});
for (const id of ["back-to-qr", "show-qr"]) {
  $(id).addEventListener("click", () => {
    if (busy) return;
    resetVerification();
    showPanel("enroll", 2, "enroll-title");
  });
}

$("verify-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !key) return;
  const code = $("verification-code").value.trim();
  if (!/^\d{6}$/.test(code)) {
    $("verify-error").textContent =
      "Enter all six digits from your authenticator app.";
    return;
  }
  busy = true;
  $("verify-button").disabled = true;
  $("verify-error").textContent = "";
  const activeGeneration = generation;
  try {
    if (!firstCounters.length) {
      const matches = await matchingCounters(key, code);
      if (activeGeneration !== generation) return;
      if (!matches.length) {
        $("verify-error").textContent =
          "That code didn’t match. Check the token name and enable automatic date and time on both devices, then try the current code.";
        return;
      }
      firstCounters = matches;
      $("first-check").classList.add("checked");
      $("code-label").textContent = "Next code";
      $("verify-button").textContent = "Confirm next code →";
      $("verify-status").textContent =
        "First code matched. Wait for the code in your app to change, then enter the very next one.";
      $("restart-check").hidden = false;
      $("verification-code").value = "";
      $("verification-code").focus();
    } else {
      const valid = await verifyNextCode(key, code, firstCounters);
      if (activeGeneration !== generation) return;
      if (!valid) {
        $("verify-error").textContent =
          "That isn’t the next code yet, or it has expired. Wait for your app to change. If you missed the next code, restart the two-code check.";
        return;
      }
      $("second-check").classList.add("checked");
      $("verification-code").value = "";
      $("success-label").textContent = label;
      showPanel("success", 4, "success-title");
    }
  } catch {
    if (activeGeneration === generation)
      $("verify-error").textContent =
        "Could not check the code. Please try again.";
  } finally {
    busy = false;
    $("verify-button").disabled = false;
  }
});

$("finish").addEventListener("click", () => {
  clearSecret();
  showPanel("finished", 4, "finished-title");
});
$("new-token").addEventListener("click", () =>
  showPanel("create", 1, "token-label"),
);
// Avoid retaining an enrollment in the back/forward cache.
window.addEventListener("pagehide", () => {
  clearSecret();
  showPanel("create", 1);
});
