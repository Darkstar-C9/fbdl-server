// ═══════════════════════════════════════════════════
//  FB Downloader Pro — License Server
//  Node.js + Express
//  Deploy on: Render / Railway (Free)
// ═══════════════════════════════════════════════════

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");

const app  = express();
app.use(express.json());

// ─────────────────────────────────────────────
//  CONFIG — Change these!
// ─────────────────────────────────────────────
const MASTER_SECRET   = process.env.MASTER_SECRET   || "FBDLPRO_CHANGE_THIS_TO_SOMETHING_UNIQUE_2025";
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || "admin123_change_this";
const CURRENT_VERSION = process.env.CURRENT_VERSION || "3.1.0";
const MIN_VERSION     = process.env.MIN_VERSION     || "3.1.0";  // Below this = FORCE UPDATE
const APP_NAME        = "FB Downloader Pro";

// ─────────────────────────────────────────────
//  DATABASE (JSON file — simple & free)
//  On Render: use environment variable for data
//  or upgrade to MongoDB Atlas (also free)
// ─────────────────────────────────────────────
const DB_FILE = path.join(__dirname, "data", "keys.json");

function loadDB() {
  try {
    if (!fs.existsSync(path.dirname(DB_FILE))) {
      fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
    }
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    }
  } catch (e) {}
  return {};
}

function saveDB(db) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (e) {}
}

// ─────────────────────────────────────────────
//  KEY ENGINE (same logic as Python)
// ─────────────────────────────────────────────
const MONTH_DEC = { A:1,B:2,C:3,D:4,E:5,F:6,G:7,H:8,I:9,J:10,K:11,L:12 };
const PLAN_DEC  = { M:"monthly",Q:"quarterly",H:"halfyearly",Y:"yearly",L:"lifetime" };

function decodeDate(enc) {
  if (enc === "X000000") return null;
  const month = MONTH_DEC[enc[0]];
  const day   = parseInt(enc.slice(1,3));
  const year  = parseInt(enc.slice(3).split("").reverse().join(""));
  if (!month || !day || !year) return null;
  return new Date(year, month - 1, day);
}

function verifySignature(planCode, dateEnc, cid) {
  const payload = `${planCode}${dateEnc}${cid}`;
  return crypto.createHmac("sha256", MASTER_SECRET)
    .update(payload).digest("hex").slice(0,8).toUpperCase();
}

function validateKeyLogic(key) {
  key = key.trim().toUpperCase();
  const parts = key.split("-");
  if (parts.length !== 4 || parts[0] !== "FBPRO") {
    return { valid: false, message: "Invalid key format" };
  }
  const [, dataPart, cid, sigGiven] = parts;
  if (dataPart.length !== 9) {
    return { valid: false, message: "Invalid key length" };
  }
  const planCode = dataPart[0];
  const dateEnc  = dataPart.slice(1);
  const sigExp   = verifySignature(planCode, dateEnc, cid);

  if (sigGiven !== sigExp) {
    return { valid: false, message: "Invalid key — signature mismatch" };
  }

  const plan = PLAN_DEC[planCode];
  if (!plan) return { valid: false, message: "Unknown plan" };

  const expDate = decodeDate(dateEnc);
  if (!expDate) {
    return { valid: true, plan: "lifetime", expiry: null, daysLeft: 99999, cid };
  }

  const today    = new Date();
  today.setHours(0,0,0,0);
  const daysLeft = Math.floor((expDate - today) / 86400000);

  if (daysLeft < 0) {
    return { valid: false, message: `License expired on ${expDate.toDateString()}` };
  }

  return {
    valid: true,
    plan,
    expiry:   expDate.toISOString().split("T")[0],
    daysLeft,
    cid
  };
}

// ─────────────────────────────────────────────
//  MIDDLEWARE — Admin auth
// ─────────────────────────────────────────────
function adminAuth(req, res, next) {
  const pwd = req.headers["x-admin-password"] || req.body?.adminPassword;
  if (pwd !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ─────────────────────────────────────────────
//  ROUTES
// ─────────────────────────────────────────────

// Health check
app.get("/", (req, res) => {
  res.json({
    app:     APP_NAME,
    version: CURRENT_VERSION,
    status:  "online",
    time:    new Date().toISOString()
  });
});

app.get("/api/version", (req, res) => {
  res.json({
    current: process.env.CURRENT_VERSION,
    min: process.env.MIN_VERSION
  });
});

// ── 1. VERSION CHECK ─────────────────────────
// Called by tool on startup to check for updates
app.post("/api/version", (req, res) => {
  const { version, app: appName } = req.body;

  if (!version) {
    return res.status(400).json({ error: "version required" });
  }

  const isOutdated     = compareVersions(version, CURRENT_VERSION) < 0;
  const isForcedUpdate = compareVersions(version, MIN_VERSION) < 0;

  res.json({
    currentVersion: CURRENT_VERSION,
    minVersion:     MIN_VERSION,
    isOutdated,
    isForcedUpdate,
    // Message shown to user in app
    message: isForcedUpdate
      ? `⛔ Version ${version} is no longer supported. Please update to v${CURRENT_VERSION}.`
      : isOutdated
      ? `🔔 New version v${CURRENT_VERSION} is available! Please update.`
      : null,
    // Download link for update
    downloadUrl: isForcedUpdate || isOutdated
      ? "https://t.me/YourTelegramChannel"  // Change this!
      : null
  });
});

// ── 2. KEY VALIDATE ──────────────────────────
// Called by tool when user enters a key
app.post("/api/validate", (req, res) => {
  const { key, version, app: appName } = req.body;

  if (!key) {
    return res.status(400).json({ valid: false, message: "Key required" });
  }

  // First: validate key signature (offline logic)
  const result = validateKeyLogic(key);
  if (!result.valid) {
    return res.json({ valid: false, message: result.message });
  }

  // Second: check if key is revoked in DB
  const db      = loadDB();
  const keyData = db[key.toUpperCase()];

  if (keyData?.revoked) {
    return res.json({
      valid: false,
      message: `❌ License revoked: ${keyData.revokeReason || "Contact support"}`
    });
  }

  // Log activation/validation
  if (!keyData) {
    // First time this key is seen online — register it
    db[key.toUpperCase()] = {
      plan:        result.plan,
      expiry:      result.expiry,
      cid:         result.cid,
      firstSeen:   new Date().toISOString(),
      lastSeen:    new Date().toISOString(),
      activations: 1,
      revoked:     false,
    };
  } else {
    db[key.toUpperCase()].lastSeen    = new Date().toISOString();
    db[key.toUpperCase()].activations = (keyData.activations || 0) + 1;
  }
  saveDB(db);

  res.json({
    valid:    true,
    plan:     result.plan,
    expiry:   result.expiry,
    daysLeft: result.daysLeft,
    cid:      result.cid,
    message:  `✅ Valid | ${result.plan.toUpperCase()} | ${result.expiry ? `Expires: ${result.expiry} (${result.daysLeft}d left)` : "Lifetime"}`
  });
});

// ── 3. REVOKE KEY (admin) ────────────────────
app.post("/api/admin/revoke", adminAuth, (req, res) => {
  const { key, reason } = req.body;
  if (!key) return res.status(400).json({ error: "key required" });

  const db  = loadDB();
  const k   = key.toUpperCase();
  db[k]     = db[k] || {};
  db[k].revoked      = true;
  db[k].revokeReason = reason || "Revoked by admin";
  db[k].revokedAt    = new Date().toISOString();
  saveDB(db);

  res.json({ success: true, message: `Key ${k} revoked` });
});

// ── 4. UNREVOKE KEY (admin) ──────────────────
app.post("/api/admin/unrevoke", adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: "key required" });

  const db = loadDB();
  const k  = key.toUpperCase();
  if (db[k]) {
    db[k].revoked = false;
    delete db[k].revokeReason;
    saveDB(db);
  }
  res.json({ success: true, message: `Key ${k} unrevoked` });
});

// ── 5. SET VERSION (admin) ───────────────────
// Change MIN_VERSION to force all old users to update
app.post("/api/admin/version", adminAuth, (req, res) => {
  const { current, minimum } = req.body;
  // On Render: you'd update env vars, here we just acknowledge
  // In production: store in DB or env
  res.json({
    success: true,
    message: `To force update: set MIN_VERSION=${minimum || MIN_VERSION} in your Render environment variables`,
    current: CURRENT_VERSION,
    minimum: MIN_VERSION,
  });
});

// ── 6. LIST KEYS (admin) ─────────────────────
app.get("/api/admin/keys", adminAuth, (req, res) => {
  const db = loadDB();
  const summary = Object.entries(db).map(([key, v]) => ({
    key,
    plan:        v.plan,
    expiry:      v.expiry || "Lifetime",
    cid:         v.cid,
    revoked:     v.revoked || false,
    activations: v.activations || 0,
    lastSeen:    v.lastSeen || "never",
  }));
  res.json({ total: summary.length, keys: summary });
});

// ── 7. STATS (admin) ─────────────────────────
app.get("/api/admin/stats", adminAuth, (req, res) => {
  const db      = loadDB();
  const keys    = Object.values(db);
  const active  = keys.filter(k => !k.revoked).length;
  const revoked = keys.filter(k => k.revoked).length;
  const today   = new Date().toISOString().split("T")[0];
  const seenToday = keys.filter(k => k.lastSeen?.startsWith(today)).length;

  res.json({
    totalKeys:   keys.length,
    activeKeys:  active,
    revokedKeys: revoked,
    seenToday,
    appVersion:  CURRENT_VERSION,
    minVersion:  MIN_VERSION,
  });
});

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i]||0) < (pb[i]||0)) return -1;
    if ((pa[i]||0) > (pb[i]||0)) return  1;
  }
  return 0;
}

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ${APP_NAME} License Server running on port ${PORT}`);
  console.log(`   Version: ${CURRENT_VERSION} | Min: ${MIN_VERSION}`);
});
