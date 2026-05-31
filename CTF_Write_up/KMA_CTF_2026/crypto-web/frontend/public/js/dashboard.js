const $ = (id) => document.getElementById(id);

const initialAppState = {
  material: null,
  login: null,
  expired: false,
  debug: null,
};

const appState = {
  ...initialAppState,
};

let toastTimer = null;

function showToast(message = "Copied") {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.remove("show");
  void toast.offsetWidth;
  toast.classList.add("show");

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 1400);
}

function flash(el) {
  el.classList.remove("flash");
  void el.offsetWidth;
  el.classList.add("flash");
}

function markInvalid(field, message) {
  const row = field.closest(".form-row");
  row.classList.add("invalid", "shake");
  const error = row.querySelector(".field-error");
  if (error && message) error.textContent = message;
  setTimeout(() => row.classList.remove("shake"), 420);
}

function clearInvalid(field) {
  const row = field.closest(".form-row");
  row.classList.remove("invalid");
}

function clearRegisterInvalid() {
  ["regEmail", "regUsername", "regAccountId", "regDeviceId"].forEach((id) => {
    const field = $(id);
    if (field) clearInvalid(field);
  });
}

function clearRegisterFields() {
  ["regEmail", "regUsername", "regAccountId", "regDeviceId"].forEach((id) => {
    const field = $(id);
    if (!field) return;
    field.value = "";
    clearInvalid(field);
  });
}

function markRegisterError(message) {
  const errorText = String(message || "").toLowerCase();
  clearRegisterInvalid();

  if (errorText.startsWith("username")) {
    markInvalid($("regUsername"), message);
    return;
  }
  if (errorText.startsWith("email")) {
    markInvalid($("regEmail"), message);
    return;
  }
  if (errorText.startsWith("account_id")) {
    markInvalid($("regAccountId"), message);
    return;
  }
  if (errorText.startsWith("device_id")) {
    markInvalid($("regDeviceId"), message);
    return;
  }

  if (errorText.includes("account_id")) {
    markInvalid($("regAccountId"), message);
  } else if (errorText.includes("device_id")) {
    markInvalid($("regDeviceId"), message);
  } else if (errorText.includes("email")) {
    markInvalid($("regEmail"), message);
  } else if (errorText.includes("username")) {
    markInvalid($("regUsername"), message);
  }
}

function validateFields(ids) {
  let ok = true;
  ids.forEach((id) => {
    const field = $(id);
    const value = field.value.trim();
    if (!value) {
      markInvalid(field);
      ok = false;
    } else {
      clearInvalid(field);
    }
  });
  return ok;
}

function wireValidation() {
  document.querySelectorAll("[data-required='true']").forEach((field) => {
    field.addEventListener("input", () => {
      if (field.value.trim()) clearInvalid(field);
    });
  });
}

function setResponse(obj, ok = true) {
  const box = $("responseBox");
  if (!box) {
    if (!ok) {
      const message = typeof obj === "string" ? obj : (obj.error || obj.status || "Request failed.");
      showToast(message);
    }
    return;
  }
  box.textContent = typeof obj === "string" ? obj : prettyJson(obj);
  box.className = ok ? "terminal response ok" : "terminal response bad";
  flash(box);
}

function setLoginResult(obj, ok = true) {
  const box = $("loginResult");
  if (!box) return;
  box.textContent = typeof obj === "string" ? obj : prettyJson(obj);
  box.className = `terminal response ${ok ? "ok" : "bad"}`;
  box.classList.remove("hidden");
  flash(box);
}

function clearLoginResult() {
  const box = $("loginResult");
  if (!box) return;
  box.textContent = "";
  box.className = "terminal response hidden";
}

function hideReceiptPanel() {
  const panel = $("receiptPanel");
  if (panel) panel.classList.add("hidden");
}

function showReceiptPanel() {
  const panel = $("receiptPanel");
  if (panel) panel.classList.remove("hidden");
}

function showLoginActions() {
  const actions = $("loginActions");
  if (actions) actions.classList.remove("hidden");
}

function hideLoginActions() {
  const actions = $("loginActions");
  if (actions) actions.classList.add("hidden");
}

function updateDebugAction(data) {
  const debug = data && typeof data === "object" ? data.debug : null;
  const button = $("copyDebugBtn");
  appState.debug = debug || null;
  if (!button) return;
  if (debug) {
    button.classList.remove("hidden");
    button.disabled = false;
  } else {
    button.classList.add("hidden");
    button.disabled = true;
  }
}

function setAccountExpired(expired) {
  appState.expired = expired;
  [
    "waitLoginBtn",
    "submitLoginBtn",
    "resetFormBtn",
    "loginUsername",
    "loginAccountId",
    "loginDeviceId",
    "submitUsername",
    "loginId",
    "masterKeyEnc",
    "shareKeyEnc",
    "shareKeyTag",
  ].forEach((id) => {
    const field = $(id);
    if (field) field.disabled = expired;
  });

  const notice = $("expiredNotice");
  if (notice) notice.classList.toggle("hidden", !expired);
}

function showRegisterSuccess(message) {
  const panel = $("registerPanel");
  const note = $("registerSuccess");
  if (!panel || !note) return;
  note.textContent = message;
  note.classList.add("show");
  panel.classList.remove("registered");
  void panel.offsetWidth;
  panel.classList.add("registered");
}

function clearRegisterSuccess() {
  const panel = $("registerPanel");
  const note = $("registerSuccess");
  if (!panel || !note) return;
  note.textContent = "";
  note.classList.remove("show");
  panel.classList.remove("registered");
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const toggle = $("themeToggle");
  if (!toggle) return;
  toggle.setAttribute("aria-pressed", theme === "dark");
  const label = toggle.querySelector(".theme-toggle__label");
  if (label) label.textContent = theme === "dark" ? "Dark" : "Light";
}

function getInitialTheme() {
  const stored = localStorage.getItem("theme");
  if (stored === "light" || stored === "dark") {
    return stored;
  }
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  return prefersDark ? "dark" : "light";
}

function initThemeToggle() {
  const toggle = $("themeToggle");
  if (!toggle) return;
  applyTheme(getInitialTheme());
  toggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem("theme", next);
    applyTheme(next);
  });
}

function renderValueRow(label, value, options = {}) {
  const row = document.createElement("div");
  row.className = options.expanded ? "value-row expanded-value" : "value-row";

  const meta = document.createElement("div");
  meta.className = "value-meta";

  const name = document.createElement("div");
  name.className = "value-name";
  name.textContent = label;

  const preview = document.createElement("code");
  preview.textContent = options.compact ? compactHex(value) : String(value);

  meta.appendChild(name);
  meta.appendChild(preview);

  const button = document.createElement("button");
  button.className = "copy-btn";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    const copied = await copyText(value);
    button.textContent = copied ? "Copied" : "Manual";
    row.classList.add("copied");
    flash(row);
    showToast(copied ? `${label} copied` : `Copy ${label} manually`);
    setTimeout(() => {
      button.textContent = "Copy";
      row.classList.remove("copied");
    }, 900);
  });

  row.appendChild(meta);
  row.appendChild(button);
  return row;
}

function renderReceipt(material) {
  showReceiptPanel();
  const container = $("receiptOutput");
  container.innerHTML = "";
  container.className = "receipt-card";

  const user = document.createElement("div");
  user.className = "receipt-user";

  const username = document.createElement("strong");
  username.textContent = material.user.username;
  const email = document.createElement("span");
  email.textContent = material.user.email;
  const accountId = document.createElement("span");
  accountId.textContent = `account_id: ${material.user.account_id}`;
  const deviceId = document.createElement("span");
  deviceId.textContent = `device_id: ${material.user.device_id}`;

  user.appendChild(username);
  user.appendChild(email);
  user.appendChild(accountId);
  user.appendChild(deviceId);
  container.appendChild(user);

  const n = material.share_key_pub[0];
  const e = material.share_key_pub[1];

  if (material.login_id) {
    container.appendChild(renderValueRow("login_id", material.login_id));
  }
  container.appendChild(renderValueRow("n", n, { expanded: true }));
  container.appendChild(renderValueRow("e", e));
  container.appendChild(renderValueRow("auth_key_hashed", material.auth_key_hashed, { compact: true }));
  container.appendChild(renderValueRow("master_key_enc", material.master_key_enc, { compact: true }));
  container.appendChild(renderValueRow("share_key_nonce", material.share_key_nonce, { compact: true }));
  container.appendChild(renderValueRow("share_key_enc", material.share_key_enc, { expanded: true }));
  container.appendChild(renderValueRow("tag", material.tag, { compact: true }));

  const note = document.createElement("p");
  note.className = "muted receipt-note";
  container.appendChild(note);
  flash(container);
}

function renderLogin(data) {
  appState.login = data;
  const box = $("loginOutput");
  box.textContent = prettyJson({
    login_id: data.login_id,
    encrypted_flag: data.encrypted_flag,
    iv: data.iv,
  });
  box.className = "terminal mini ok";
  flash(box);
}

async function handleRegister() {
  if (!validateFields(["regEmail", "regUsername", "regAccountId", "regDeviceId"])) {
    showToast("Fill required fields");
    clearRegisterSuccess();
    return;
  }

  const data = await apiPost("/api/register", {
    email: $("regEmail").value.trim(),
    username: $("regUsername").value.trim(),
    account_id: $("regAccountId").value.trim(),
    device_id: $("regDeviceId").value.trim(),
  });

  if (!data.ok) {
    setResponse(data, false);
    markRegisterError(data.error);
    clearRegisterSuccess();
    return;
  }

  appState.material = null;
  clearRegisterInvalid();
  setAccountExpired(false);
  appState.login = null;
  ["loginUsername", "loginAccountId", "loginDeviceId", "submitUsername", "loginId", "masterKeyEnc", "shareKeyEnc", "shareKeyTag"].forEach((id) => {
    const field = $(id);
    if (!field) return;
    field.value = "";
    clearInvalid(field);
  });
  clearLoginResult();
  hideLoginActions();
  updateDebugAction(null);
  const loginOutput = $("loginOutput");
  if (loginOutput) {
    loginOutput.textContent = "No active login.";
    loginOutput.className = "terminal mini";
  }
  clearReceipt();
  const successMessage = data.message || "Registration successful. You can log in now.";
  showRegisterSuccess(successMessage);
  setResponse(
    {
      status: data.message,
      next: "Registration successful. You can log in now.",
      hint: "Use the Login section to get a login_id.",
    },
    true
  );
}

async function handleWaitLogin() {
  if (!validateFields(["loginUsername", "loginAccountId", "loginDeviceId"])) {
    showToast("Fill required fields");
    return;
  }

  const username = $("loginUsername").value.trim();
  const data = await apiPost("/api/wait_login", {
    username,
    account_id: $("loginAccountId").value.trim(),
    device_id: $("loginDeviceId").value.trim(),
  });

  if (!data.ok) {
    $("loginOutput").textContent = prettyJson(data);
    $("loginOutput").className = "terminal mini bad";
    flash($("loginOutput"));
    clearReceipt();
    return;
  }

  renderLogin(data);
  appState.material = data.registration_receipt;
  renderReceipt(data.registration_receipt);
}

async function handleSubmitLogin() {
  const required = ["submitUsername", "loginId", "masterKeyEnc", "shareKeyEnc", "shareKeyTag"];
  if (!validateFields(required)) {
    setLoginResult({ error: "Missing required login material." }, false);
    showToast("Missing fields");
    return;
  }

  const data = await apiPost("/api/send_login", {
    username: $("submitUsername").value.trim(),
    login_id: $("loginId").value.trim(),
    master_key_enc: $("masterKeyEnc").value.trim(),
    share_key_enc: $("shareKeyEnc").value.trim(),
    tag: $("shareKeyTag").value.trim(),
  });

  setLoginResult(data, data.ok !== false);
  showLoginActions();
  updateDebugAction(data);
  clearRegisterFields();
  setAccountExpired(true);
}

function resetForm() {
  ["submitUsername", "loginId", "masterKeyEnc", "shareKeyEnc", "shareKeyTag"].forEach((id) => {
    $(id).value = "";
    clearInvalid($(id));
  });
  clearLoginResult();
}

function clearReceipt() {
  appState.material = null;
  showReceiptPanel();
  const container = $("receiptOutput");
  container.className = "receipt-empty";
  container.textContent = "Login with username, account_id, and device_id to reveal the registration receipt.";
  flash(container);
}

function logoutAndResetPage() {
  appState.material = initialAppState.material;
  appState.login = initialAppState.login;
  appState.expired = initialAppState.expired;
  appState.debug = initialAppState.debug;

  [
    "regEmail",
    "regUsername",
    "regAccountId",
    "regDeviceId",
    "loginUsername",
    "loginAccountId",
    "loginDeviceId",
    "submitUsername",
    "loginId",
    "masterKeyEnc",
    "shareKeyEnc",
    "shareKeyTag",
  ].forEach((id) => {
    const field = $(id);
    if (!field) return;
    field.value = "";
    clearInvalid(field);
  });

  clearRegisterSuccess();
  clearLoginResult();
  hideLoginActions();
  updateDebugAction(null);
  setAccountExpired(false);

  const loginOutput = $("loginOutput");
  if (loginOutput) {
    loginOutput.textContent = "No active login.";
    loginOutput.className = "terminal mini";
  }

  clearReceipt();
  showReceiptPanel();

  const registerPanel = $("registerPanel");
  if (registerPanel) {
    registerPanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  const regEmail = $("regEmail");
  if (regEmail) regEmail.focus();
}

window.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  wireValidation();
  $("registerBtn").addEventListener("click", handleRegister);
  $("waitLoginBtn").addEventListener("click", handleWaitLogin);
  $("submitLoginBtn").addEventListener("click", handleSubmitLogin);
  $("resetFormBtn").addEventListener("click", resetForm);
  $("clearReceiptBtn").addEventListener("click", clearReceipt);
  $("resetPageBtn").addEventListener("click", logoutAndResetPage);
  $("copyDebugBtn").addEventListener("click", async () => {
    if (!appState.debug) return;
    const copied = await copyText(appState.debug);
    showToast(copied ? "Debug copied" : "Copy debug manually");
  });
});
