// ═══════════════════════════════════════════════════
//  FB Downloader Pro — Server v3 (MongoDB Atlas)
//  Node.js + Express | Deploy: Render (free)
// ═══════════════════════════════════════════════════

const express  = require("express");
const crypto   = require("crypto");
const path     = require("path");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── CONFIG ───────────────────────────────────────
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || "Dark@@@x3@xrt";
const CURRENT_VERSION = process.env.CURRENT_VERSION || "3.1.0";
const MIN_VERSION     = process.env.MIN_VERSION     || "3.1.0";
const TOKEN_SECRET    = process.env.TOKEN_SECRET    || "FBDLTokenSecret2026XYZ";
const MONGODB_URI     = process.env.MONGODB_URI     || "";
const APP_NAME        = "FB Downloader Pro";

// ── MONGODB ──────────────────────────────────────
let db = null;

async function connectDB() {
  if (!MONGODB_URI) {
    console.error("❌ MONGODB_URI not set in environment variables!");
    return;
  }
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db("fbdl");
    // Create indexes
    await db.collection("users").createIndex({ username: 1 }, { unique: true });
    console.log("✅ MongoDB connected!");
  } catch(e) {
    console.error("❌ MongoDB connection failed:", e.message);
  }
}

function getUsers() {
  return db.collection("users");
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
    // Token kabhi expire nahi hoga — sirf license expiry matter karti hai
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

function compareVersions(a, b) {
  const pa = (a||"0").split(".").map(Number);
  const pb = (b||"0").split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i]||0) < (pb[i]||0)) return -1;
    if ((pa[i]||0) > (pb[i]||0)) return  1;
  }
  return 0;
}

// ── MIDDLEWARE ───────────────────────────────────
function adminAuth(req, res, next) {
  const pwd = req.headers["x-admin-password"] || req.body?.adminPassword;
  if (pwd !== ADMIN_PASSWORD) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function dbCheck(req, res, next) {
  if (!db) return res.status(503).json({ success: false, message: "Database not connected" });
  next();
}

// ════════════════════════════════════════════════
//  PUBLIC API
// ════════════════════════════════════════════════

app.get("/", (req, res) => {
  res.json({ app: APP_NAME, version: CURRENT_VERSION, status: "online", time: new Date().toISOString() });
});

// ── REGISTER ─────────────────────────────────────
app.post("/api/register", dbCheck, async (req, res) => {
  let { username, password, email, device } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required" });

  username = username.trim();
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.json({ success: false, message: "Username: 3-20 chars, letters/numbers/_ only" });
  if (password.length < 6)
    return res.json({ success: false, message: "Password must be at least 6 characters" });

  try {
    const existing = await getUsers().findOne({ username: username.toLowerCase() });
    if (existing) return res.json({ success: false, message: "Username already taken" });

    await getUsers().insertOne({
      username:     username.toLowerCase(),
      displayName:  username,
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
      device:       device || "",
      lastVersion:  "",
    });

    res.json({ success: true, message: "Account created! Contact admin on Telegram/Facebook to activate." });
  } catch(e) {
    if (e.code === 11000) return res.json({ success: false, message: "Username already taken" });
    res.json({ success: false, message: "Server error" });
  }
});

// ── LOGIN ─────────────────────────────────────────
app.post("/api/login", dbCheck, async (req, res) => {
  const { username, password, version, device } = req.body;
  if (!username || !password)
    return res.json({ success: false, message: "Username and password required" });

  const user = await getUsers().findOne({ username: username.toLowerCase().trim() });

  if (!user)   return res.json({ success: false, message: "Account not found. Please register first." });
  if (user.blocked) return res.json({ success: false, message: "Account blocked. Contact support." });

  if (hashPassword(password) !== user.passwordHash)
    return res.json({ success: false, message: "Wrong password." });

  if (!user.approved)
    return res.json({ success: false, pending: true, message: "Account pending approval. Contact us on Telegram/Facebook." });

  const dl = daysLeft(user.expiry);
  if (user.plan !== "lifetime" && dl <= 0)
    return res.json({ success: false, expired: true, message: `License expired on ${user.expiry}. Please renew.` });

  if (version && compareVersions(version, MIN_VERSION) < 0)
    return res.json({ success: false, forceUpdate: true, message: `Please update to v${CURRENT_VERSION}.` });

  // Update stats
  await getUsers().updateOne(
    { username: user.username },
    { $set: {
      lastLogin:   new Date().toISOString(),
      loginCount:  (user.loginCount || 0) + 1,
      device:      device || user.device || "",
      lastVersion: version || "",
    }}
  );

  const token = generateToken(user.username);
  res.json({
    success:    true,
    token,
    username:   user.displayName || user.username,
    plan:       user.plan,
    expiry:     user.expiry || null,
    daysLeft:   dl,
    isLifetime: user.plan === "lifetime",
    message:    `Welcome ${user.displayName || user.username}! ${user.plan === "lifetime" ? "Lifetime access" : `${dl} days left`}`
  });
});

// ── TOKEN VERIFY ──────────────────────────────────
app.post("/api/verify", dbCheck, async (req, res) => {
  const { token, version } = req.body;
  if (!token) return res.json({ valid: false, message: "No token" });

  const username = verifyToken(token);
  if (!username) return res.json({ valid: false, message: "Invalid session. Please login again." });

  const user = await getUsers().findOne({ username });
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
    username:   user.displayName || user.username,
    plan:       user.plan,
    expiry:     user.expiry,
    daysLeft:   dl,
    isLifetime: user.plan === "lifetime",
  });
});

// ════════════════════════════════════════════════
//  ADMIN API
// ════════════════════════════════════════════════

app.get("/api/admin/stats", adminAuth, dbCheck, async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  const [total, approved, pending, blocked, loginToday, plans] = await Promise.all([
    getUsers().countDocuments(),
    getUsers().countDocuments({ approved: true, blocked: false }),
    getUsers().countDocuments({ approved: false, blocked: false }),
    getUsers().countDocuments({ blocked: true }),
    getUsers().countDocuments({ lastLogin: { $regex: `^${today}` } }),
    getUsers().aggregate([{ $group: { _id: "$plan", count: { $sum: 1 } } }]).toArray(),
  ]);

  const planMap = {};
  plans.forEach(p => { if(p._id) planMap[p._id] = p.count; });

  res.json({
    total, approved, pending, blocked, loginToday,
    plans: {
      monthly:    planMap.monthly    || 0,
      quarterly:  planMap.quarterly  || 0,
      halfyearly: planMap.halfyearly || 0,
      yearly:     planMap.yearly     || 0,
      lifetime:   planMap.lifetime   || 0,
    },
    appVersion: CURRENT_VERSION,
    minVersion: MIN_VERSION,
  });
});

app.get("/api/admin/users", adminAuth, dbCheck, async (req, res) => {
  const users = await getUsers().find().sort({ registeredAt: -1 }).toArray();
  res.json({
    total: users.length,
    users: users.map(u => ({
      username:     u.displayName || u.username,
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
    }))
  });
});

app.post("/api/admin/approve", adminAuth, dbCheck, async (req, res) => {
  const { username, plan } = req.body;
  if (!username || !plan) return res.status(400).json({ error: "username and plan required" });
  if (!PLAN_DAYS[plan])   return res.status(400).json({ error: "Invalid plan" });

  const result = await getUsers().updateOne(
    { username: username.toLowerCase() },
    { $set: {
      approved:   true,
      blocked:    false,
      plan,
      approvedAt: new Date().toISOString(),
      expiry:     calcExpiry(plan),
    }}
  );

  if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });

  const user = await getUsers().findOne({ username: username.toLowerCase() });
  res.json({ success: true, message: `${username} approved — ${plan}`, expiry: user.expiry || "Lifetime" });
});

app.post("/api/admin/block", adminAuth, dbCheck, async (req, res) => {
  const { username, reason } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });

  const result = await getUsers().updateOne(
    { username: username.toLowerCase() },
    { $set: { blocked: true, blockReason: reason || "Blocked by admin", blockedAt: new Date().toISOString() }}
  );
  if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
  res.json({ success: true, message: `${username} blocked` });
});

app.post("/api/admin/unblock", adminAuth, dbCheck, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username required" });

  const result = await getUsers().updateOne(
    { username: username.toLowerCase() },
    { $set: { blocked: false }, $unset: { blockReason: "" }}
  );
  if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
  res.json({ success: true, message: `${username} unblocked` });
});

app.post("/api/admin/plan", adminAuth, dbCheck, async (req, res) => {
  const { username, plan } = req.body;
  if (!username || !plan) return res.status(400).json({ error: "username and plan required" });

  const result = await getUsers().updateOne(
    { username: username.toLowerCase() },
    { $set: { plan, expiry: calcExpiry(plan) }}
  );
  if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });

  const user = await getUsers().findOne({ username: username.toLowerCase() });
  res.json({ success: true, message: `${username} → ${plan}`, expiry: user.expiry || "Lifetime" });
});

app.delete("/api/admin/user/:username", adminAuth, dbCheck, async (req, res) => {
  const result = await getUsers().deleteOne({ username: req.params.username.toLowerCase() });
  if (result.deletedCount === 0) return res.status(404).json({ error: "User not found" });
  res.json({ success: true, message: `${req.params.username} deleted` });
});

// ── START ────────────────────────────────────────
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ ${APP_NAME} Server v3 (MongoDB) on port ${PORT}`);
    console.log(`   Version: ${CURRENT_VERSION} | Min: ${MIN_VERSION}`);
  });
});
