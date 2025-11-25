// ======================================================
// GLOBAL STATE
// ======================================================

let csrfToken = null;
let currentUsername = null;
let selectedEntry = null;
let entryCache = [];   // For local search filtering


// ======================================================
// UTILITIES
// ======================================================

function setStatus(elId, msg, ok = false) {
  const el = document.getElementById(elId);
  el.textContent = msg || "";
  el.className = "status " + (msg ? (ok ? "ok" : "error") : "");
}

function copy(text) {
  navigator.clipboard.writeText(text).catch(() => alert("Copy failed"));
}

function generatePassword(length = 20) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}


// ======================================================
// AUTHENTICATION
// ======================================================

document.getElementById("reg-submit").onclick = register;
document.getElementById("login-submit").onclick = login;
document.getElementById("logout-btn").onclick = logout;

async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;

  setStatus("reg-status", "");

  if (!username || !password) {
    setStatus("reg-status", "Username and password required");
    return;
  }

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username, master_password: password}),
    });

    const data = await res.json();

    if (!res.ok) {
      setStatus("reg-status", data.detail || data.message || "Error");
      return;
    }

    setStatus("reg-status", "User created. You can log in now.", true);

  } catch {
    setStatus("reg-status", "Network error");
  }
}


async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  setStatus("login-status", "");

  if (!username || !password) {
    setStatus("login-status", "Username and password required");
    return;
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username, master_password: password}),
    });

    const data = await res.json();

    if (!res.ok) {
      setStatus("login-status", data.detail || data.message || "Error");
      return;
    }

    currentUsername = data.username;
    csrfToken = data.csrf_token;

    document.getElementById("user-pill").textContent =
      "Logged in as " + currentUsername;

    // Switch UI
    document.getElementById("auth-card").classList.add("hidden");
    document.getElementById("app-card").classList.remove("hidden");

    loadEntries();

  } catch {
    setStatus("login-status", "Network error");
  }
}


async function logout() {
  try {
    const headers = {};
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

    await fetch("/logout", {method: "POST", headers});
  } catch {}

  currentUsername = null;
  csrfToken = null;
  selectedEntry = null;
  entryCache = [];

  // Reset UI back to login screen
  document.getElementById("auth-card").classList.remove("hidden");
  document.getElementById("app-card").classList.add("hidden");

  document.getElementById("entries-tbody").innerHTML = "";
  document.getElementById("selected-entry").textContent =
    "Click an entry in the table to view username, password, and notes.";
}


// ======================================================
// ENTRIES
// ======================================================

document.getElementById("entry-save-btn").onclick = addEntry;
document.getElementById("password-generate-btn").onclick = function () {
  const newPass = generatePassword();
  document.getElementById("entry-password").value = newPass;
};


async function addEntry() {
  const name = document.getElementById("entry-name").value.trim();
  const username = document.getElementById("entry-username").value.trim();
  const password = document.getElementById("entry-password").value;
  const url = document.getElementById("entry-url").value.trim();
  const notes = document.getElementById("entry-notes").value;

  setStatus("entry-status", "");

  if (!name || !password) {
    setStatus("entry-status", "Name and password required");
    return;
  }

  try {
    const headers = {"Content-Type": "application/json"};
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

    const res = await fetch("/entries", {
      method: "POST",
      headers,
      body: JSON.stringify({name, username, password, url, notes}),
    });

    const data = await res.json();

    if (!res.ok) {
      if (res.status === 403)
        return setStatus("entry-status", "CSRF error. Log in again.");
      if (res.status === 401) return logout();

      return setStatus("entry-status", data.detail || "Error");
    }

    setStatus("entry-status", "Saved.", true);

    // Reset the password field for safety
    document.getElementById("entry-password").value = "";

    loadEntries();

  } catch {
    setStatus("entry-status", "Network error");
  }
}


async function loadEntries() {
  try {
    const res = await fetch("/entries");

    if (res.status === 401) return logout();

    const items = await res.json();
    entryCache = items;

    document.getElementById("entry-count").textContent =
      `${items.length} entries`;

    renderEntries(items);

  } catch {}
}


// ✅ CSP-SAFE: no inline onclick, use addEventListener
function renderEntries(list) {
  const tbody = document.getElementById("entries-tbody");
  tbody.innerHTML = "";

  for (const e of list) {
    const tr = document.createElement("tr");

    const tdId = document.createElement("td");
    tdId.textContent = e.id;

    const tdName = document.createElement("td");
    tdName.textContent = e.name;

    const tdUser = document.createElement("td");
    tdUser.textContent = e.username || "";

    const tdUrl = document.createElement("td");
    tdUrl.textContent = e.url || "";

    const tdActions = document.createElement("td");
    tdActions.className = "actions-cell";

    const viewBtn = document.createElement("button");
    viewBtn.className = "btn btn-ghost";
    viewBtn.textContent = "View";
    viewBtn.addEventListener("click", () => viewEntry(e.id));

    const delBtn = document.createElement("button");
    delBtn.className = "btn btn-danger";
    delBtn.textContent = "Del";
    delBtn.addEventListener("click", () => deleteEntry(e.id));

    tdActions.appendChild(viewBtn);
    tdActions.appendChild(delBtn);

    tr.appendChild(tdId);
    tr.appendChild(tdName);
    tr.appendChild(tdUser);
    tr.appendChild(tdUrl);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  }
}


async function viewEntry(id) {
  try {
    const res = await fetch(`/entries/${id}`);

    if (!res.ok) {
      if (res.status === 401) return logout();
      return;
    }

    const e = await res.json();
    selectedEntry = e;

    const box = document.getElementById("selected-entry");

    box.textContent =
      `Name: ${e.name}\n` +
      `Username: ${e.username || ""}\n` +
      `Password: ${e.password}\n` +
      `URL: ${e.url || ""}\n\n` +
      `Notes:\n${e.notes || ""}`;

  } catch {}
}


async function deleteEntry(id) {
  if (!confirm("Delete entry " + id + "?")) return;

  try {
    const headers = {};
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

    const res = await fetch(`/entries/${id}`, {
      method: "DELETE",
      headers,
    });

    if (res.status === 204) {
      loadEntries();
      document.getElementById("selected-entry").textContent =
        "Deleted entry " + id;
    } else if (res.status === 403) {
      alert("CSRF error. Log in again.");
    } else if (res.status === 401) {
      logout();
    }

  } catch {}
}


// ======================================================
// SEARCH FILTER
// ======================================================

document.getElementById("search-input").oninput = function (e) {
  const q = e.target.value.toLowerCase();

  const filtered = entryCache.filter((e) =>
    e.name.toLowerCase().includes(q) ||
    (e.username || "").toLowerCase().includes(q)
  );

  renderEntries(filtered);
};


// ======================================================
// COPY BUTTONS
// ======================================================

document.getElementById("copy-username-btn").onclick = function () {
  if (!selectedEntry || !selectedEntry.username)
    return alert("No username available");
  copy(selectedEntry.username);
};

document.getElementById("copy-password-btn").onclick = function () {
  if (!selectedEntry || !selectedEntry.password)
    return alert("No password available");
  copy(selectedEntry.password);
};
