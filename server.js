// ═══════════════════════════════════════════════════
//  FB Downloader Pro — Login-Based License Server v2
//  Node.js + Express | Deploy: Render (free)
// ═══════════════════════════════════════════════════

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── CONFIG ───────────────────────────────────────
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || "Dark@@@x3@xrt";
const CURRENT_VERSION = process.env.CURRENT_VERSION || "3.1.0";
const MIN_VERSION     = process.env.MIN_VERSION     || "3.1.0";
const TOKEN_SECRET    = process.env.TOKEN_SECRET    || "FBDLTokenSecret2026XYZ";
const APP_NAME        = "FB Downloader Pro";

// ── DATABASE ─────────────────────────────────────
const DATA_DIR   = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

function loadUsers() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(USERS_FILE)) return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch(e) {}
  return {};
}

function saveUsers(db) {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2)); } catch(e) {}
}

// ── TOKEN ────────────────────────────────────────
function generateToken(username) {
  const ts  = Date.now();
  const sig = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${username}:${ts}`).digest("hex").slice(0, 16);
  return Buffer.from(`${username}:${ts}:${sig}`).toString("base64");
}

function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, "base64").toString("utf8");
    const [username, ts, sig] = decoded.split(":");
    const expected = crypto.createHmac("sha256", TOKEN_SECRET)
      .update(`${username}:${ts}`).digest("hex").slice(0, 16);
    if (sig !== expected) return null;
    if (Date.now() - parseInt(ts) > 30 * 24 * 60 * 60 * 1000) return null;
    return username;
  } catch(e) { return null; }
}

// ── PLAN HELPERS ─────────────────────────────────
const PLAN_DAYS = { monthly:30, quarterly:90, halfyearly:180, yearly:365, lifetime:99999 };

function calcExpiry(plan) {
  if (plan === "lifetime") return null;
  const d = new Date();
  d.setDate(d.getDate() + (PLAN_DAYS[plan] || 30));
  return d.toISOString().split("T")[0];
}

function daysLeft(expiry) {
  if (!expiry) return 99999;
  return Math.max(0, Math.floor((new Date(expiry) - new Date()) / 86400000));
}

function hashPassword(pwd) {
  return crypto.createHash("sha256").update(pwd + TOKEN_SECRET).digest("hex");
}

// ── MIDDLEWARE ───────────────────────────────────
function adminAuth(req, res, next) {
  const pwd = req.headers["x-admin-password"] || req.body?.adminPassword;
  if (pwd !== ADMIN_PASSWORD) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function compareVersions(a, b) {
  const pa = (a||"0").split(".").map(Number);
  const pb = (b||"0").split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i]||0) < (pb[i]||0)) return -1;
    if ((pa[i]||0) > (pb[i]||0)) return  1;
  }
  return 0;
}

// ════════════════════════════════════════════════
//  PUBLIC API
// ════════════════════════════════════════════════

app.get("/", (req, res) => {
  res.json({ app: APP_NAME, version: CURRENT_VERSION, status: "online", time: new Date().toISOString() });
});

// ── REGISTER
app.post("/api/register", (req, res) => {
  let { username, password, email } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required" });

  username = username.trim();
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.json({ success: false, message: "Username: 3-20 chars, letters/numbers/_ only" });
  if (password.length < 6)
    return res.json({ success: false, message: "Password must be at least 6 characters" });

  const db  = loadUsers();
  const key = username.toLowerCase();
  if (db[key]) return res.json({ success: false, message: "Username already taken" });

  db[key] = {
    username,
    email:        email || "",
    passwordHash: hashPassword(password),
    approved:     false,
    blocked:      false,
    plan:         null,
    expiry:       null,
    approvedAt:   null,
    registeredAt: new Date().toISOString(),
    lastLogin:    null,
    loginCount:   0,
    device:       req.body.device || "",
    lastVersion:  "",
  };
  saveUsers(db);

  res.json({ success: true, message: "Account created! Waiting for admin approval. Contact us on WhatsApp/Telegram." });
});

// ── LOGIN
app.post("/api/login", (req, res) => {
  const { username, password, version, device } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required" });

  const db   = loadUsers();
  const key  = username.toLowerCase().trim();
  const user = db[key];

  if (!user)   return res.json({ success: false, message: "Account not found. Please register first." });
  if (user.blocked) return res.json({ success: false, message: "Account blocked. Contact support." });

  if (hashPassword(password) !== user.passwordHash)
    return res.json({ success: false, message: "Wrong password." });

  if (!user.approved)
    return res.json({ success: false, pending: true, message: "Account pending approval. Contact us on WhatsApp/Telegram." });

  const dl = daysLeft(user.expiry);
  if (user.plan !== "lifetime" && dl <= 0)
    return res.json({ success: false, expired: true, message: `License expired on ${user.expiry}. Please renew.` });

  if (version && compareVersions(version, MIN_VERSION) < 0)
    return res.json({ success: false, forceUpdate: true, message: `Please update to v${CURRENT_VERSION}.` });

  // Update stats
  db[key].lastLogin   = new Date().toISOString();
  db[key].loginCount  = (user.loginCount || 0) + 1;
  db[key].device      = device || user.device || "";
  db[key].lastVersion = version || "";
  saveUsers(db);

  const token = generateToken(key);
  res.json({
    success:    true,
    token,
    username:   user.username,
    plan:       user.plan,
    expiry:     user.expiry || null,
    daysLeft:   dl,
    isLifetime: user.plan === "lifetime",
    message:    `Welcome ${user.username}! ${user.plan === "lifetime" ? "Lifetime access" : `${dl} days left`}`
  });
});

// ── TOKEN VERIFY (app startup)
app.post("/api/verify", (req, res) => {
  const { token, version } = req.body;
  if (!token) return res.json({ valid: false, message: "No token" });

  const username = verifyToken(token);
  if (!username) return res.json({ valid: false, message: "Session expired. Please login again." });

  const db   = loadUsers();
  const user = db[username];
  if (!user)        return res.json({ valid: false, message: "Account not found" });
  if (user.blocked) return res.json({ valid: false, message: "Account blocked" });
  if (!user.approved) return res.json({ valid: false, message: "Account not approved" });

  const dl = daysLeft(user.expiry);
  if (user.plan !== "lifetime" && dl <= 0)
    return res.json({ valid: false, expired: true, message: "License expired. Please renew." });

  if (version && compareVersions(version, MIN_VERSION) < 0)
    return res.json({ valid: false, forceUpdate: true, message: `Update to v${CURRENT_VERSION}` });

  res.json({
    valid:      true,
    username:   user.username,
    plan:       user.plan,
    expiry:     user.expiry,
    daysLeft:   dl,
    isLifetime: user.plan === "lifetime",
  });
});

// ════════════════════════════════════════════════
//  ADMIN API
// ════════════════════════════════════════════════

app.get("/api/admin/stats", adminAuth, (req, res) => {
  const db    = loadUsers();
  const users = Object.values(db);
  const today = new Date().toISOString().split("T")[0];
  res.json({
    total:      users.length,
    approved:   users.filter(u => u.approved && !u.blocked).length,
    pending:    users.filter(u => !u.approved && !u.blocked).length,
    blocked:    users.filter(u => u.blocked).length,
    loginToday: users.filter(u => u.lastLogin?.startsWith(today)).length,
    plans: {
      monthly:    users.filter(u => u.plan === "monthly").length,
      quarterly:  users.filter(u => u.plan === "quarterly").length,
      halfyearly: users.filter(u => u.plan === "halfyearly").length,
      yearly:     users.filter(u => u.plan === "yearly").length,
      lifetime:   users.filter(u => u.plan === "lifetime").length,
    },
    appVersion: CURRENT_VERSION,
    minVersion: MIN_VERSION,
  });
});

app.get("/api/admin/users", adminAuth, (req, res) => {
  const db = loadUsers();
  const users = Object.values(db).map(u => ({
    username:     u.username,
    email:        u.email || "",
    approved:     u.approved,
    blocked:      u.blocked || false,
    plan:         u.plan || "none",
    expiry:       u.expiry || "N/A",
    daysLeft:     u.expiry ? daysLeft(u.expiry) : (u.plan === "lifetime" ? 99999 : 0),
    registeredAt: u.registeredAt,
    lastLogin:    u.lastLogin || "never",
    loginCount:   u.loginCount || 0,
    device:       u.device || "",
    lastVersion:  u.lastVersion || "",
  }));
  res.json({ total: users.length, users });
});

app.post("/api/admin/approve", adminAuth, (req, res) => {
  const { username, plan } = req.body;
  if (!username || !plan) return res.status(400).json({ error: "username and plan required" });
  const validPlans = Object.keys(PLAN_DAYS);
  if (!validPlans.includes(plan)) return res.status(400).json({ error: `Invalid plan` });

  const db  = loadUsers();
  const key = username.toLowerCase();
  if (!db[key]) return res.status(404).json({ error: "User not found" });

  db[key].approved   = true;
  db[key].blocked    = false;
  db[key].plan       = plan;
  db[key].approvedAt = new Date().toISOString();
  db[key].expiry     = calcExpiry(plan);
  saveUsers(db);

  res.json({ success: true, message: `${username} approved — ${plan}`, expiry: db[key].expiry || "Lifetime" });
});

app.post("/api/admin/block", adminAuth, (req, res) => {
  const { username, reason } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });
  const db  = loadUsers();
  const key = username.toLowerCase();
  if (!db[key]) return res.status(404).json({ error: "User not found" });
  db[key].blocked     = true;
  db[key].blockReason = reason || "Blocked by admin";
  db[key].blockedAt   = new Date().toISOString();
  saveUsers(db);
  res.json({ success: true, message: `${username} blocked` });
});

app.post("/api/admin/unblock", adminAuth, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });
  const db  = loadUsers();
  const key = username.toLowerCase();
  if (!db[key]) return res.status(404).json({ error: "User not found" });
  db[key].blocked = false;
  delete db[key].blockReason;
  saveUsers(db);
  res.json({ success: true, message: `${username} unblocked` });
});

app.post("/api/admin/plan", adminAuth, (req, res) => {
  const { username, plan } = req.body;
  if (!username || !plan) return res.status(400).json({ error: "username and plan required" });
  const db  = loadUsers();
  const key = username.toLowerCase();
  if (!db[key]) return res.status(404).json({ error: "User not found" });
  db[key].plan   = plan;
  db[key].expiry = calcExpiry(plan);
  saveUsers(db);
  res.json({ success: true, message: `${username} plan changed to ${plan}`, expiry: db[key].expiry || "Lifetime" });
});

app.delete("/api/admin/user/:username", adminAuth, (req, res) => {
  const db  = loadUsers();
  const key = req.params.username.toLowerCase();
  if (!db[key]) return res.status(404).json({ error: "User not found" });
  delete db[key];
  saveUsers(db);
  res.json({ success: true, message: `${key} deleted` });
});

// ── START ────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ${APP_NAME} Server v2 on port ${PORT}`);
  console.log(`   Version: ${CURRENT_VERSION} | Min: ${MIN_VERSION}`);
});
