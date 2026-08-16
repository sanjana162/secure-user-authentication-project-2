/*
 * SafePass is intentionally dependency-free. It is a front-end , so user
 * records live in this browser only. A real app must validate on a server and
 * store password hashes in a database with a server-side password algorithm.
 */
const STORAGE_USERS = "safepass_users_v1";
const STORAGE_SESSION = "safepass_session_v1";

const form = document.querySelector("#authForm");
const modeButtons = document.querySelectorAll(".mode-button");
const nameField = document.querySelector(".name-field");
const confirmField = document.querySelector(".confirm-field");
const registerHelp = document.querySelector(".register-help");
const forgotButton = document.querySelector("#forgotButton");
const formTitle = document.querySelector("#formTitle");
const formSubtitle = document.querySelector("#formSubtitle");
const submitButton = document.querySelector("#submitButton");
const formMessage = document.querySelector("#formMessage");
const termsText = document.querySelector("#termsText");
const authView = document.querySelector("#authView");
const dashboardView = document.querySelector("#dashboardView");
const passwordInput = document.querySelector("#password");
let mode = "login";

function getUsers() {
  try { return JSON.parse(localStorage.getItem(STORAGE_USERS)) || []; }
  catch { return []; }
}

function setUsers(users) { localStorage.setItem(STORAGE_USERS, JSON.stringify(users)); }

async function hashPassword(password, salt) {
  const bytes = new TextEncoder().encode(`${salt}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function createSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function setMessage(message = "", success = false) {
  formMessage.textContent = message;
  formMessage.classList.toggle("success", success);
}

function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === "register";
  modeButtons.forEach(button => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", selected);
  });
  nameField.classList.toggle("hidden", !registering);
  confirmField.classList.toggle("hidden", !registering);
  registerHelp.classList.toggle("hidden", !registering);
  forgotButton.classList.toggle("hidden", registering);
  termsText.classList.toggle("hidden", !registering);
  formTitle.textContent = registering ? "Create your account" : "Welcome back";
  formSubtitle.textContent = registering ? "A protected space is just a minute away." : "Sign in to continue to your account.";
  submitButton.innerHTML = registering ? "Create account <span aria-hidden=\"true\">→</span>" : "Sign in <span aria-hidden=\"true\">→</span>";
  passwordInput.autocomplete = registering ? "new-password" : "current-password";
  form.reset();
  setMessage();
}

function validatePassword(password) {
  return password.length >= 8 && /\d/.test(password) && /[^A-Za-z0-9]/.test(password);
}

function setLoading(loading) {
  submitButton.disabled = loading;
  submitButton.dataset.label ||= submitButton.innerHTML;
  if (loading) submitButton.textContent = "Please wait…";
  else submitButton.innerHTML = submitButton.dataset.label;
}

function startSession(user) {
  localStorage.setItem(STORAGE_SESSION, JSON.stringify({ id: user.id, startedAt: Date.now() }));
  showDashboard(user);
}

function getCurrentUser() {
  try {
    const session = JSON.parse(localStorage.getItem(STORAGE_SESSION));
    return session && getUsers().find(user => user.id === session.id);
  } catch { return null; }
}

function showDashboard(user) {
  document.querySelector("#userName").textContent = user.name;
  document.querySelector("#userEmail").textContent = user.email;
  document.querySelector("#userRole").textContent = `${user.role === "admin" ? "Administrator" : "Member"} account`;
  document.querySelector("#accessLevel").textContent = user.role === "admin" ? "Administrator" : "Member";
  document.querySelector("#avatar").textContent = user.name.trim().charAt(0).toUpperCase();
  authView.classList.add("hidden");
  dashboardView.classList.remove("hidden");
}

function showAuth() {
  dashboardView.classList.add("hidden");
  authView.classList.remove("hidden");
  setMode("login");
}

modeButtons.forEach(button => button.addEventListener("click", () => setMode(button.dataset.mode)));

document.querySelector(".password-toggle").addEventListener("click", event => {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  event.currentTarget.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
  event.currentTarget.title = isHidden ? "Hide password" : "Show password";
});

forgotButton.addEventListener("click", () => setMessage("For this local, create a new account if you no longer remember your password."));

form.addEventListener("submit", async event => {
  event.preventDefault();
  const name = form.name.value.trim();
  const email = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const confirmPassword = form.confirmPassword.value;
  if (!email || !password || (mode === "register" && !name)) return setMessage("Please complete all required fields.");
  if (!/^\S+@\S+\.\S+$/.test(email)) return setMessage("Please enter a valid email address.");
  if (mode === "register") {
    if (!validatePassword(password)) return setMessage("Use at least 8 characters, including a number and a symbol.");
    if (password !== confirmPassword) return setMessage("Your passwords do not match.");
  }
  setLoading(true);
  try {
    const users = getUsers();
    if (mode === "register") {
      if (users.some(user => user.email === email)) return setMessage("An account with this email already exists. Please sign in.");
      const salt = createSalt();
      const user = { id: crypto.randomUUID(), name, email, salt, passwordHash: await hashPassword(password, salt), role: "user", createdAt: new Date().toISOString() };
      setUsers([...users, user]);
      setMessage("Account created. Signing you in…", true);
      window.setTimeout(() => startSession(user), 450);
    } else {
      const user = users.find(item => item.email === email);
      if (!user || (await hashPassword(password, user.salt)) !== user.passwordHash) return setMessage("Incorrect email or password.");
      startSession(user);
    }
  } catch {
    setMessage("Something went wrong. Please try again.");
  } finally { setLoading(false); }
});

document.querySelector("#logoutButton").addEventListener("click", () => { localStorage.removeItem(STORAGE_SESSION); showAuth(); });

document.querySelector("#deleteAccountButton").addEventListener("click", () => {
  const user = getCurrentUser();
  if (!user || !confirm("Delete this browser-only account? This cannot be undone.")) return;
  setUsers(getUsers().filter(item => item.id !== user.id));
  localStorage.removeItem(STORAGE_SESSION);
  showAuth();
});

const activeUser = getCurrentUser();
if (activeUser) showDashboard(activeUser);
