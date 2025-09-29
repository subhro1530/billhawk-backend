/**
 *  ____  _ _ _ _   _            _
 * | __ )(_) | (_) | | __ ___   / \   _ __ _____  ___   _
 * |  _ \| | | | | | |/ _` \ \ / / | | '__/ _ \ \/ / | | |
 * | |_) | | | | | | | (_| |\ V /| |_| | |  __/>  <| |_| |
 * |____/|_|_|_|_| |_|\__,_| \_/  \__,_|  \___/_/\_\\__, |
 *                                                  |___/
 * BillHawk MVP Backend - Postgres (Neon) Edition
 *
 * Full server.js with:
 *  - defensive reminder scheduling
 *  - get specific reminder route
 *  - admin routes to manage users (list, get, update, delete, disable)
 *  - admin routes to inspect user bills & reminders
 *
 * NOTE: set NEON_DATABASE_URL, JWT_SECRET and optionally ADMIN_CODE in env.
 */

require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const morgan = require("morgan");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

// ----------------------- Config & Environment -----------------------
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const APP_ENV = process.env.APP_ENV || "development";
const NEON_DATABASE_URL = process.env.NEON_DATABASE_URL;
const ADMIN_CODE = process.env.ADMIN_CODE || "admin123";

//--------------------- Passport Google OAuth2 setup

const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_me_session_secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Configure Google OAuth

const { google } = require("googleapis");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: [
        "profile",
        "email",
        "https://www.googleapis.com/auth/calendar.events.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
      ],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Extract email
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("No email found"));

        // Check if user exists, otherwise create
        let user = await one(
          `SELECT * FROM users WHERE LOWER(email)=LOWER($1)`,
          [email]
        );
        if (!user) {
          const id = uuid();
          const profileData = {
            reminderOffsetDays: 2,
            notifications: { push: true },
          };
          await q(
            `INSERT INTO users (id,email,password_hash,plan,profile) VALUES ($1,$2,$3,'free',$4::jsonb)`,
            [id, email, "", JSON.stringify(profileData)]
          );
          user = await one(`SELECT * FROM users WHERE id=$1`, [id]);
        }

        // Attach Google tokens to user object for later API calls
        user.googleAccessToken = accessToken;
        user.googleRefreshToken = refreshToken;

        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await one(`SELECT * FROM users WHERE id=$1`, [id]);
  done(null, user || null);
});

// ----------------------- DB (Neon / Postgres) -----------------------
if (!NEON_DATABASE_URL) {
  console.error("NEON_DATABASE_URL missing in environment");
  process.exit(1);
}

const pool = new Pool({
  connectionString: NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Basic query helpers
const q = (text, params) => pool.query(text, params);
const one = async (text, params) => {
  const r = await q(text, params);
  return r.rows[0] || null;
};
const many = async (text, params) => {
  const r = await q(text, params);
  return r.rows;
};
async function tx(run) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const res = await run(client);
    await client.query("COMMIT");
    return res;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

// Schema init (idempotent)
async function ensureSchema() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT NOT NULL,
      profile JSONB NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS bills (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      amount NUMERIC,
      due_date TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL,
      source_type TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS reminders (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      bill_id UUID REFERENCES bills(id) ON DELETE CASCADE,
      due_date TIMESTAMPTZ NOT NULL,
      remind_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL,
      channel TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti UUID PRIMARY KEY,
      revoked_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(
    `CREATE INDEX IF NOT EXISTS idx_bills_user_due ON bills(user_id,due_date);`
  );
  await q(
    `CREATE INDEX IF NOT EXISTS idx_reminders_user_remind ON reminders(user_id,remind_at);`
  );
  await q(`
    CREATE TABLE IF NOT EXISTS categories (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      color TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS bill_history (
      id UUID PRIMARY KEY,
      bill_id UUID REFERENCES bills(id) ON DELETE CASCADE,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      data JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS recurring_rules (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      amount NUMERIC,
      interval TEXT NOT NULL,
      next_occurrence TIMESTAMPTZ NOT NULL,
      category_id UUID,
      meta JSONB,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS reminder_templates (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      offset_days INT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'push',
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      meta JSONB,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      label TEXT,
      last_used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS export_jobs (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      type TEXT NOT NULL,
      params JSONB,
      file_path TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      completed_at TIMESTAMPTZ
    );
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS user_activity (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id UUID,
      meta JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await q(
    `CREATE INDEX IF NOT EXISTS idx_bill_history_bill ON bill_history(bill_id);`
  );
  await q(
    `CREATE INDEX IF NOT EXISTS idx_recurring_rules_next ON recurring_rules(user_id,next_occurrence);`
  );
  await q(
    `CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id,created_at DESC);`
  );
}

// ----------------------- Middleware -----------------------
app.use(
  cors({
    origin: "*",
    methods: "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    allowedHeaders:
      "Origin, X-Requested-With, Content-Type, Accept, Authorization",
    exposedHeaders: "X-Correlation-Id",
  })
);
app.options("*", cors());

// FIX: Body parsers (missing previously -> req.body was undefined)
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));

// Lightweight request log (path + method)
app.use((req, res, next) => {
  console.log("[REQ]", req.method, req.path);
  next();
});

// Legacy path rewrite (allow calling /bills instead of /api/v1/bills)
const LEGACY_ROOT_REGEX =
  /^\/(auth|bills|reminders|categories|notifications|analytics|user|premium|admin)\b/;
app.use((req, res, next) => {
  if (!req.path.startsWith("/api/") && LEGACY_ROOT_REGEX.test(req.path)) {
    req.url = "/api/v1" + req.url;
  }
  next();
});

// ----------------------- Utility Helpers -----------------------
function safeUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    email: u.email,
    plan: u.plan,
    role: u.role,
    profile: u.profile,
    createdAt: u.created_at,
  };
}

function json(res, status, payload) {
  return res.status(status).json({ success: status < 400, ...payload });
}

function parseDate(val) {
  const d = new Date(val);
  if (isNaN(d.getTime())) throw new Error("Invalid date");
  return d;
}

// ----------------------- Reminder Logic (Fixed) -----------------------
async function createAutoReminderForBill(billRow, userRow, client = pool) {
  if (!billRow) throw new Error("Bill row missing for reminder generation");
  // Skip auto reminder for ephemeral admin (no DB user row)
  if (userRow && userRow.id === "admin") {
    console.warn("[AutoReminder] Skipping auto reminder for admin user.");
    return null;
  }

  // ensure profile fallback
  const offsetDays = userRow?.profile?.reminderOffsetDays ?? 2;
  const due = new Date(billRow.due_date);
  let remindAt = new Date(due.getTime() - offsetDays * 24 * 60 * 60 * 1000);
  if (remindAt < new Date()) {
    remindAt = new Date(Date.now() + 60 * 60 * 1000);
  }

  const reminderId = uuid();
  try {
    await client.query(
      `INSERT INTO reminders (id, user_id, bill_id, due_date, remind_at, status, channel)
       VALUES ($1,$2,$3,$4,$5,'scheduled','push')`,
      [
        reminderId,
        billRow.user_id,
        billRow.id,
        billRow.due_date,
        remindAt.toISOString(),
      ]
    );
  } catch (e) {
    console.error("[AutoReminder][InsertFailed]", {
      billId: billRow.id,
      userId: billRow.user_id,
      err: e && e.message,
    });
    return null;
  }

  const reminder = await one(`SELECT * FROM reminders WHERE id=$1`, [
    reminderId,
  ]);
  if (!reminder) {
    console.error("[AutoReminder][MissingAfterInsert]", {
      reminderId,
      billId: billRow.id,
    });
    return null;
  }

  // Defensive scheduling - won't throw when reminder is null
  try {
    scheduleReminderDispatch(reminder);
  } catch (e) {
    console.error("[AutoReminder][ScheduleFailed]", { reminderId, err: e });
  }
  return reminder;
}

function scheduleReminderDispatch(reminder) {
  if (!reminder) {
    console.warn("[scheduleReminderDispatch] called with null reminder");
    return;
  }
  // defensive properties check
  const rid = reminder.id || "<no-id>";
  const rtime = reminder.remind_at || reminder.remindAt || "<no-time>";
  const uid = reminder.user_id || "<no-user>";
  console.log("[ReminderScheduled]", {
    reminderId: rid,
    remindAt: rtime,
    userId: uid,
  });

  // Actual dispatch wiring (push / whatsapp) should be implemented here.
  // For now we just log; do not attempt to access reminder.id without checks.
}

// ----------------------- Auth Middleware -----------------------
async function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return json(res, 401, { error: "Missing or invalid Authorization header" });
  }
  const token = header.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const revoked = await one(`SELECT jti FROM revoked_tokens WHERE jti=$1`, [
      payload.jti,
    ]);
    if (revoked) return json(res, 401, { error: "Token revoked" });

    // Ephemeral admin user (code-based login)
    if (payload.sub === "admin" && payload.role === "admin") {
      req.user = {
        id: "admin",
        email: "admin@local",
        plan: "infinite",
        role: "admin",
        profile: { reminderOffsetDays: 2, notifications: { push: true } },
        created_at: new Date().toISOString(),
      };
      return next();
    }

    const user = await one(`SELECT * FROM users WHERE id=$1`, [payload.sub]);
    if (!user) return json(res, 401, { error: "User not found" });
    req.user = user;
    next();
  } catch (err) {
    return json(res, 401, { error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user) return json(res, 401, { error: "Unauthorized" });
  if (req.user.role !== "admin")
    return json(res, 403, { error: "Admin required" });
  next();
}

async function planGuard(req, res, next) {
  if (!req.user) return json(res, 401, { error: "Unauthorized" });
  if (req.user.plan === "free") {
    const r = await one(
      `SELECT COUNT(*)::int AS count FROM bills WHERE user_id=$1 AND status!='deleted'`,
      [req.user.id]
    );
    if (r.count >= 2) {
      return json(res, 403, {
        error: "Free plan limit reached (2 active bills). Upgrade required.",
      });
    }
  }
  next();
}

// ----------------------- JWT Issue -----------------------
function issueToken(userLike) {
  const jti = uuid();
  const token = jwt.sign(
    {
      sub: userLike.id,
      jti,
      plan: userLike.plan,
      role: userLike.role || "user",
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
  return { token, jti };
}

// ----------------------- Routes -----------------------
const API_PREFIX = "/api/v1";

// Endpoint index (quick discovery)
app.get(`${API_PREFIX}/_endpoints`, (req, res) => {
  res.json({
    success: true,
    data: [
      "GET /api/v1/health",
      "POST /api/v1/auth/register",
      "POST /api/v1/auth/login",
      "POST /api/v1/auth/admin-login",
      "GET /api/v1/user/me",
      "PUT /api/v1/user/me",
      "PATCH /api/v1/user/security",
      "GET /api/v1/user/api-keys",
      "POST /api/v1/user/api-keys",
      "DELETE /api/v1/user/api-keys/:id",
      "POST /api/v1/user/export",
      "GET /api/v1/user/export/:jobId/status",
      "GET /api/v1/user/export/:jobId/download",
      "GET /api/v1/user/activity",
      "POST /api/v1/bills",
      "GET /api/v1/bills",
      "GET /api/v1/bills/:id",
      "PUT /api/v1/bills/:id",
      "DELETE /api/v1/bills/:id",
      "POST /api/v1/bills/import/sms",
      "POST /api/v1/bills/import/email",
      "POST /api/v1/bills/import/manual",
      "POST /api/v1/bills/recurring",
      "GET /api/v1/bills/recurring",
      "POST /api/v1/bills/:id/settle",
      "GET /api/v1/bills/:id/history",
      "PATCH /api/v1/bills/:id/category",
      "GET /api/v1/bills/search",
      "GET /api/v1/bills/export",
      "POST /api/v1/reminders",
      "GET /api/v1/reminders",
      "GET /api/v1/reminders/:id",
      "DELETE /api/v1/reminders/:id",
      "POST /api/v1/reminders/bulk",
      "GET /api/v1/reminders/upcoming",
      "GET /api/v1/reminders/templates",
      "POST /api/v1/reminders/templates",
      "GET /api/v1/categories",
      "POST /api/v1/categories",
      "GET /api/v1/notifications",
      "POST /api/v1/notifications/:id/read",
      "POST /api/v1/notifications/read-all",
      "GET /api/v1/notifications/stream",
      "GET /api/v1/analytics/overview",
      "GET /api/v1/analytics/cashflow",
      "GET /api/v1/analytics/aging",
      "GET /api/v1/analytics/category-breakdown",
      "GET /api/v1/analytics/monthly-trend",
      "GET /api/v1/analytics/top-counterparties",
      "POST /api/v1/premium/subscribe",
      "POST /api/v1/premium/unsubscribe",
      "GET /api/v1/premium/status",
      "GET /api/v1/admin/users",
      "GET /api/v1/admin/users/:id",
      "PUT /api/v1/admin/users/:id",
      "DELETE /api/v1/admin/users/:id",
      "POST /api/v1/admin/users/:id/disable",
      "GET /api/v1/admin/users/:id/bills",
      "GET /api/v1/admin/users/:id/reminders",
    ],
  });
});

// Health
app.get("/", (req, res) => res.send("BillHawk Backend Running"));
app.get(`${API_PREFIX}/health`, (req, res) =>
  json(res, 200, { data: { status: "ok", time: new Date().toISOString() } })
);

// -------- Auth --------
app.post(`${API_PREFIX}/auth/register`, async (req, res) => {
  try {
    const emailRaw = req.body?.email;
    const passwordRaw = req.body?.password;
    const email = typeof emailRaw === "string" ? emailRaw.trim() : "";
    const password = typeof passwordRaw === "string" ? passwordRaw : "";
    if (!email || !password)
      return json(res, 400, { error: "Email & password required" });
    const existing = await one(
      `SELECT id FROM users WHERE LOWER(email)=LOWER($1)`,
      [email]
    );
    if (existing) return json(res, 409, { error: "Email already registered" });
    const hash = await bcrypt.hash(password, 10);
    const id = uuid();
    const profile = {
      reminderOffsetDays: 2,
      notifications: { push: true, whatsapp: false },
    };
    await q(
      `INSERT INTO users (id,email,password_hash,plan,profile)
       VALUES ($1,LOWER($2),$3,'free',$4::jsonb)`,
      [id, email, hash, JSON.stringify(profile)]
    );
    const user = await one(`SELECT * FROM users WHERE id=$1`, [id]);
    const { token } = issueToken(user);
    json(res, 201, { data: { user: safeUser(user), token } });
  } catch (e) {
    console.error(e);
    json(res, 500, { error: "Registration failed" });
  }
});

app.post(`${API_PREFIX}/auth/login`, async (req, res) => {
  const emailRaw = req.body?.email;
  const passwordRaw = req.body?.password;
  const email = typeof emailRaw === "string" ? emailRaw.trim() : "";
  const password = typeof passwordRaw === "string" ? passwordRaw : "";
  if (!email || !password)
    return json(res, 400, { error: "Email & password required" });
  const user = await one(`SELECT * FROM users WHERE email=LOWER($1)`, [email]);
  if (!user) return json(res, 401, { error: "Invalid credentials" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return json(res, 401, { error: "Invalid credentials" });
  const { token } = issueToken(user);
  json(res, 200, { data: { user: safeUser(user), token } });
});

// Optional: admin login to mint ephemeral admin token for dev/testing
app.post(`${API_PREFIX}/auth/admin-login`, async (req, res) => {
  const { code } = req.body || {};
  if (!code) return json(res, 400, { error: "admin code required" });
  if (code !== ADMIN_CODE)
    return json(res, 401, { error: "Invalid admin code" });
  const adminLike = { id: "admin", plan: "infinite", role: "admin" };
  const { token } = issueToken(adminLike);
  json(res, 200, { data: { token, message: "Admin token (ephemeral)" } });
});

app.post(`${API_PREFIX}/auth/logout`, auth, async (req, res) => {
  try {
    const header = req.headers.authorization;
    const token = header.split(" ")[1];
    const payload = jwt.decode(token);
    if (payload?.jti) {
      await q(
        `INSERT INTO revoked_tokens (jti) VALUES ($1) ON CONFLICT DO NOTHING`,
        [payload.jti]
      );
    }
  } catch (_) {}
  json(res, 200, { data: { message: "Logged out" } });
});

// -------- User Profile --------
app.get(`${API_PREFIX}/user/me`, auth, (req, res) => {
  json(res, 200, { data: { user: safeUser(req.user) } });
});

app.put(`${API_PREFIX}/user/me`, auth, async (req, res) => {
  const { reminderOffsetDays, notifications, displayName } = req.body || {};
  const profile = { ...req.user.profile };
  if (reminderOffsetDays !== undefined) {
    if (
      typeof reminderOffsetDays !== "number" ||
      reminderOffsetDays < 0 ||
      reminderOffsetDays > 30
    ) {
      return json(res, 400, { error: "Invalid reminderOffsetDays" });
    }
    profile.reminderOffsetDays = reminderOffsetDays;
  }
  if (notifications) {
    profile.notifications = { ...profile.notifications, ...notifications };
  }
  if (displayName) profile.displayName = String(displayName).slice(0, 80);
  await q(`UPDATE users SET profile=$2::jsonb WHERE id=$1`, [
    req.user.id,
    JSON.stringify(profile),
  ]);
  const updated = await one(`SELECT * FROM users WHERE id=$1`, [req.user.id]);
  json(res, 200, { data: { user: safeUser(updated) } });
});

// Start OAuth flow
app.get(`${API_PREFIX}/auth/google`, passport.authenticate("google"));

// Callback URL
app.get(
  `${API_PREFIX}/auth/google/callback`,
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Issue JWT for our app
    const { token } = issueToken(req.user);
    res.json({ success: true, user: safeUser(req.user), token });
  }
);

// Logout
app.get(`${API_PREFIX}/auth/google/logout`, (req, res) => {
  req.logout(() => {});
  res.json({ success: true });
});

async function fetchGmailMessages(user) {
  if (!user.googleAccessToken) return [];
  const oauth2Client = new google.auth.OAuth2();
  oauth2Client.setCredentials({ access_token: user.googleAccessToken });

  const gmail = google.gmail({ version: "v1", auth: oauth2Client });
  const res = await gmail.users.messages.list({ userId: "me", maxResults: 10 });
  const messages = res.data.messages || [];
  return messages;
}

async function fetchCalendarEvents(user) {
  if (!user.googleAccessToken) return [];
  const oauth2Client = new google.auth.OAuth2();
  oauth2Client.setCredentials({ access_token: user.googleAccessToken });

  const calendar = google.calendar({ version: "v3", auth: oauth2Client });
  const res = await calendar.events.list({
    calendarId: "primary",
    maxResults: 10,
    singleEvents: true,
    orderBy: "startTime",
  });
  return res.data.items || [];
}

// Route to fetch Gmail & Calendar events
app.get(`${API_PREFIX}/auth/google/fetch`, auth, async (req, res) => {
  try {
    const emails = await fetchGmailMessages(req.user);
    const events = await fetchCalendarEvents(req.user);
    res.json({ success: true, emails, events });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to fetch data" });
  }
});

// -------- Bills CRUD --------
// Create bill — expects { name, amount, dueDate } where dueDate is camelCase (as requested)
app.post(`${API_PREFIX}/bills`, auth, planGuard, async (req, res) => {
  try {
    const { name, amount, dueDate } = req.body || {};
    if (!name || !dueDate)
      return json(res, 400, { error: "Name & dueDate required" });
    const parsedDue = parseDate(dueDate);

    const result = await tx(async (client) => {
      const billRow = await client
        .query(
          `INSERT INTO bills (id,user_id,name,amount,due_date,status,source_type,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,'active','manual',NOW(),NOW())
         RETURNING *`,
          [
            uuid(),
            req.user.id,
            name.trim(),
            amount ?? null,
            parsedDue.toISOString(),
          ]
        )
        .then((r) => r.rows[0]);

      if (!billRow) throw new Error("Bill creation failed");

      // createAutoReminderForBill may return null; that's fine
      const autoReminder = await createAutoReminderForBill(
        billRow,
        req.user,
        client
      );
      return { bill: billRow, autoReminder };
    });

    json(res, 201, { data: result });
  } catch (err) {
    console.error("BillCreateError", { cid: req.cid, err });
    json(res, 400, { error: err.message || "Invalid bill data" });
  }
});

// List bills for authenticated user
app.get(`${API_PREFIX}/bills`, auth, async (req, res) => {
  const bills = await many(
    `SELECT * FROM bills WHERE user_id=$1 AND status!='deleted' ORDER BY due_date ASC`,
    [req.user.id]
  );
  json(res, 200, { data: { bills } });
});

// Get single bill (owner or admin)
app.get(`${API_PREFIX}/bills/:id`, auth, async (req, res) => {
  const bill = await one(`SELECT * FROM bills WHERE id=$1`, [req.params.id]);
  if (!bill || bill.status === "deleted")
    return json(res, 404, { error: "Bill not found" });

  // owner or admin
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });

  json(res, 200, { data: { bill } });
});

// Update bill (owner only)
app.put(`${API_PREFIX}/bills/:id`, auth, async (req, res) => {
  const bill = await one(`SELECT * FROM bills WHERE id=$1`, [req.params.id]);
  if (!bill || bill.status === "deleted")
    return json(res, 404, { error: "Bill not found" });
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });

  const { name, amount, dueDate } = req.body || {};
  let newDue = bill.due_date;
  if (dueDate) {
    try {
      newDue = parseDate(dueDate).toISOString();
    } catch {
      return json(res, 400, { error: "Invalid dueDate" });
    }
  }
  await q(
    `UPDATE bills SET name=COALESCE($3,name), amount=$4, due_date=$5, updated_at=NOW() WHERE id=$1`,
    [
      bill.id,
      /* $2 unused */ null,
      name ? name.trim() : null,
      amount ?? bill.amount,
      newDue,
    ]
  );
  const updated = await one(`SELECT * FROM bills WHERE id=$1`, [bill.id]);
  json(res, 200, { data: { bill: updated } });
});

// Soft-delete bill (owner or admin)
app.delete(`${API_PREFIX}/bills/:id`, auth, async (req, res) => {
  const bill = await one(`SELECT * FROM bills WHERE id=$1`, [req.params.id]);
  if (!bill || bill.status === "deleted")
    return json(res, 404, { error: "Bill not found" });
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });

  await q(`UPDATE bills SET status='deleted', updated_at=NOW() WHERE id=$1`, [
    bill.id,
  ]);
  json(res, 200, { data: { message: "Bill deleted" } });
});

// -------- Bill Sources (Imports) --------
app.post(
  `${API_PREFIX}/bills/import/sms`,
  auth,
  planGuard,
  async (req, res) => {
    const { messages } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
      return json(res, 400, { error: "messages array required" });
    }
    const created = [];
    await tx(async (client) => {
      for (const m of messages) {
        if (!m.parsed?.name || !m.parsed?.dueDate) continue;
        try {
          const due = parseDate(m.parsed.dueDate);
          const id = uuid();
          await client.query(
            `INSERT INTO bills (id,user_id,name,amount,due_date,status,source_type,created_at,updated_at)
           VALUES ($1,$2,$3,$4,$5,'active','sms',NOW(),NOW())`,
            [
              id,
              req.user.id,
              m.parsed.name,
              typeof m.parsed.amount === "number" ? m.parsed.amount : null,
              due.toISOString(),
            ]
          );
          const billRow = await client
            .query(`SELECT * FROM bills WHERE id=$1`, [id])
            .then((r) => r.rows[0]);
          const reminder = await createAutoReminderForBill(
            billRow,
            req.user,
            client
          );
          created.push({ bill: billRow, reminder });
        } catch (e) {
          // skip invalid, log for debugging
          console.warn("[ImportSMS][Skip]", { err: e && e.message, item: m });
        }
      }
    });
    json(res, 201, { data: { imported: created.length, items: created } });
  }
);

app.post(
  `${API_PREFIX}/bills/import/email`,
  auth,
  planGuard,
  async (req, res) => {
    const { emails } = req.body || {};
    if (!Array.isArray(emails) || emails.length === 0) {
      return json(res, 400, { error: "emails array required" });
    }
    const created = [];
    await tx(async (client) => {
      for (const e of emails) {
        if (!e.parsed?.name || !e.parsed?.dueDate) continue;
        try {
          const due = parseDate(e.parsed.dueDate);
          const id = uuid();
          await client.query(
            `INSERT INTO bills (id,user_id,name,amount,due_date,status,source_type,created_at,updated_at)
           VALUES ($1,$2,$3,$4,$5,'active','email',NOW(),NOW())`,
            [
              id,
              req.user.id,
              e.parsed.name,
              typeof e.parsed.amount === "number" ? e.parsed.amount : null,
              due.toISOString(),
            ]
          );
          const billRow = await client
            .query(`SELECT * FROM bills WHERE id=$1`, [id])
            .then((r) => r.rows[0]);
          const reminder = await createAutoReminderForBill(
            billRow,
            req.user,
            client
          );
          created.push({ bill: billRow, reminder });
        } catch (err) {
          // skip invalid
          console.warn("[ImportEmail][Skip]", {
            err: err && err.message,
            item: e,
          });
        }
      }
    });
    json(res, 201, { data: { imported: created.length, items: created } });
  }
);

// -------- Reminders --------
// Create manual reminder
app.post(`${API_PREFIX}/reminders`, auth, async (req, res) => {
  const { billId, remindAt } = req.body || {};
  if (!billId || !remindAt)
    return json(res, 400, { error: "billId & remindAt required" });
  const bill = await one(
    `SELECT * FROM bills WHERE id=$1 AND status!='deleted'`,
    [billId]
  );
  if (!bill) return json(res, 404, { error: "Bill not found" });

  // only owner or admin can create reminder for a bill
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });

  let scheduled;
  try {
    scheduled = parseDate(remindAt);
  } catch {
    return json(res, 400, { error: "Invalid remindAt" });
  }
  const id = uuid();
  await q(
    `INSERT INTO reminders (id,user_id,bill_id,due_date,remind_at,status,channel)
     VALUES ($1,$2,$3,$4,$5,'scheduled','push')`,
    [id, bill.user_id, bill.id, bill.due_date, scheduled.toISOString()]
  );
  const reminder = await one(`SELECT * FROM reminders WHERE id=$1`, [id]);
  if (reminder) {
    try {
      scheduleReminderDispatch(reminder);
    } catch (e) {
      console.error("[ReminderCreate][ScheduleError]", { id, err: e });
    }
  }
  json(res, 201, { data: { reminder } });
});

// List reminders for authenticated user
app.get(`${API_PREFIX}/reminders`, auth, async (req, res) => {
  const reminders = await many(
    `SELECT * FROM reminders WHERE user_id=$1 ORDER BY remind_at ASC`,
    [req.user.id]
  );
  json(res, 200, { data: { reminders } });
});

// Get specific reminder (owner or admin)
app.get(`${API_PREFIX}/reminders/:id`, auth, async (req, res) => {
  const rem = await one(`SELECT * FROM reminders WHERE id=$1`, [req.params.id]);
  if (!rem) return json(res, 404, { error: "Reminder not found" });
  if (rem.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });
  json(res, 200, { data: { reminder: rem } });
});

// Delete a reminder (owner or admin)
app.delete(`${API_PREFIX}/reminders/:id`, auth, async (req, res) => {
  const rem = await one(`SELECT * FROM reminders WHERE id=$1`, [req.params.id]);
  if (!rem) return json(res, 404, { error: "Reminder not found" });
  if (rem.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });
  await q(`DELETE FROM reminders WHERE id=$1`, [rem.id]);
  json(res, 200, { data: { message: "Reminder deleted" } });
});

// -------- Premium / Payments (Stub) --------
app.post(`${API_PREFIX}/premium/subscribe`, auth, async (req, res) => {
  await q(`UPDATE users SET plan='premium' WHERE id=$1`, [req.user.id]);
  const updated = await one(`SELECT * FROM users WHERE id=$1`, [req.user.id]);
  json(res, 200, {
    data: { plan: updated.plan, message: "Subscription upgraded (stub)." },
  });
});

// NEW: Unsubscribe (downgrade to free)
app.post(`${API_PREFIX}/premium/unsubscribe`, auth, async (req, res) => {
  if (req.user.plan === "free") {
    return json(res, 200, {
      data: { plan: "free", message: "Already on free plan." },
    });
  }
  await q(`UPDATE users SET plan='free' WHERE id=$1`, [req.user.id]);
  const updated = await one(`SELECT * FROM users WHERE id=$1`, [req.user.id]);
  json(res, 200, {
    data: {
      plan: updated.plan,
      message: "Subscription canceled. Reverted to free plan.",
    },
  });
});

app.get(`${API_PREFIX}/premium/status`, auth, (req, res) => {
  json(res, 200, { data: { plan: req.user.plan } });
});

// ----------------------- Admin Routes -----------------------
// List users (admin only) — supports simple pagination via ?limit=&offset=
app.get(`${API_PREFIX}/admin/users`, auth, requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "50", 10) || 50, 200);
  const offset = Math.max(parseInt(req.query.offset || "0", 10) || 0, 0);
  const rows = await many(
    `SELECT id,email,plan,role,profile,created_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  json(res, 200, { data: { users: rows } });
});

// Get a single user (admin)
app.get(
  `${API_PREFIX}/admin/users/:id`,
  auth,
  requireAdmin,
  async (req, res) => {
    const user = await one(
      `SELECT id,email,plan,role,profile,created_at FROM users WHERE id=$1`,
      [req.params.id]
    );
    if (!user) return json(res, 404, { error: "User not found" });
    json(res, 200, { data: { user } });
  }
);

// Update a user (admin) - allow plan/role/profile updates
app.put(
  `${API_PREFIX}/admin/users/:id`,
  auth,
  requireAdmin,
  async (req, res) => {
    const { plan, role, profile } = req.body || {};
    const target = await one(`SELECT * FROM users WHERE id=$1`, [
      req.params.id,
    ]);
    if (!target) return json(res, 404, { error: "User not found" });

    // Basic validation
    const allowedPlans = ["free", "premium", "disabled"];
    const allowedRoles = ["user", "admin"];
    if (plan && !allowedPlans.includes(plan))
      return json(res, 400, { error: "Invalid plan" });
    if (role && !allowedRoles.includes(role))
      return json(res, 400, { error: "Invalid role" });

    const newProfile = profile
      ? JSON.stringify({ ...target.profile, ...profile })
      : JSON.stringify(target.profile);

    await q(
      `UPDATE users SET plan=COALESCE($2,plan), role=COALESCE($3,role), profile=$4::jsonb WHERE id=$1`,
      [req.params.id, plan || null, role || null, newProfile]
    );
    const updated = await one(
      `SELECT id,email,plan,role,profile,created_at FROM users WHERE id=$1`,
      [req.params.id]
    );
    json(res, 200, { data: { user: updated } });
  }
);

// Delete a user (admin) - cascades to bills & reminders
app.delete(
  `${API_PREFIX}/admin/users/:id`,
  auth,
  requireAdmin,
  async (req, res) => {
    const target = await one(`SELECT id FROM users WHERE id=$1`, [
      req.params.id,
    ]);
    if (!target) return json(res, 404, { error: "User not found" });
    await q(`DELETE FROM users WHERE id=$1`, [req.params.id]);
    json(res, 200, { data: { message: "User deleted" } });
  }
);

// Disable membership (admin) - set plan to 'disabled'
app.post(
  `${API_PREFIX}/admin/users/:id/disable`,
  auth,
  requireAdmin,
  async (req, res) => {
    const target = await one(`SELECT id FROM users WHERE id=$1`, [
      req.params.id,
    ]);
    if (!target) return json(res, 404, { error: "User not found" });
    await q(`UPDATE users SET plan='disabled' WHERE id=$1`, [req.params.id]);
    json(res, 200, {
      data: { message: "User disabled (plan set to 'disabled')" },
    });
  }
);

// Admin: list user's bills
app.get(
  `${API_PREFIX}/admin/users/:id/bills`,
  auth,
  requireAdmin,
  async (req, res) => {
    const bills = await many(
      `SELECT * FROM bills WHERE user_id=$1 AND status!='deleted' ORDER BY due_date ASC`,
      [req.params.id]
    );
    json(res, 200, { data: { bills } });
  }
);

// Admin: list user's reminders
app.get(
  `${API_PREFIX}/admin/users/:id/reminders`,
  auth,
  requireAdmin,
  async (req, res) => {
    const reminders = await many(
      `SELECT * FROM reminders WHERE user_id=$1 ORDER BY remind_at ASC`,
      [req.params.id]
    );
    json(res, 200, { data: { reminders } });
  }
);

// ----------------------- Not Found & Error Handling -----------------------
app.use((req, res) => json(res, 404, { error: "Route not found" }));
app.use((err, req, res, next) => {
  console.error("[UnhandledError]", err);
  json(res, 500, { error: "Internal server error" });
});

// ----------------------- Start Server -----------------------
(async () => {
  try {
    await ensureSchema();
    app.listen(PORT, () =>
      console.log(`BillHawk backend listening on ${PORT} (env=${APP_ENV})`)
    );
  } catch (e) {
    console.error("Startup failed", e);
    process.exit(1);
  }
})();

// ---------- Helpers (History / Activity / Notifications / Recurring / Maintenance) ----------
async function addHistory(billId, userId, eventType, data = {}) {
  await q(
    `INSERT INTO bill_history (id,bill_id,user_id,event_type,data) VALUES ($1,$2,$3,$4,$5::jsonb)`,
    [uuid(), billId, userId, eventType, JSON.stringify(data)]
  );
}
async function logActivity(userId, action, entityType, entityId, meta = {}) {
  await q(
    `INSERT INTO user_activity (id,user_id,action,entity_type,entity_id,meta) VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [uuid(), userId, action, entityType, entityId, JSON.stringify(meta)]
  );
}
async function issueNotification(userId, type, title, body, meta = {}) {
  await q(
    `INSERT INTO notifications (id,user_id,type,title,body,meta)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [uuid(), userId, type, title, body || null, JSON.stringify(meta)]
  );
}
function advanceNextOccurrence(interval, date) {
  const d = new Date(date);
  switch (interval) {
    case "daily":
      d.setDate(d.getDate() + 1);
      break;
    case "weekly":
      d.setDate(d.getDate() + 7);
      break;
    case "monthly":
      d.setMonth(d.getMonth() + 1);
      break;
    default:
      d.setMonth(d.getMonth() + 1);
  }
  return d.toISOString();
}
async function processRecurring(now) {
  const dueRules = await many(
    `SELECT * FROM recurring_rules WHERE active=true AND next_occurrence <= $1`,
    [now.toISOString()]
  );
  for (const rule of dueRules) {
    const billId = uuid();
    try {
      await tx(async (client) => {
        const billRow = await client
          .query(
            `INSERT INTO bills (id,user_id,name,amount,due_date,status,source_type,created_at,updated_at)
           VALUES ($1,$2,$3,$4,$5,'active','recurring',NOW(),NOW()) RETURNING *`,
            [billId, rule.user_id, rule.name, rule.amount, rule.next_occurrence]
          )
          .then((r) => r.rows[0]);
        await addHistory(billRow.id, rule.user_id, "generated", {
          ruleId: rule.id,
        });
        await logActivity(rule.user_id, "bill_generated", "bill", billRow.id, {
          ruleId: rule.id,
        });
        await q(
          `UPDATE recurring_rules SET next_occurrence=$2, updated_at=NOW() WHERE id=$1`,
          [rule.id, advanceNextOccurrence(rule.interval, rule.next_occurrence)]
        );
        // auto reminder
        const user = await one(`SELECT * FROM users WHERE id=$1`, [
          rule.user_id,
        ]);
        await createAutoReminderForBill(billRow, user);
      });
    } catch (e) {
      console.error("[RecurringGenerateError]", e.message);
    }
  }
}
async function expireOldBills(now) {
  await tx(async (client) => {
    const expired = await client
      .query(
        `UPDATE bills
       SET status='expired', updated_at=NOW()
       WHERE status='active' AND due_date < (NOW() - INTERVAL '15 days')
       RETURNING id,user_id,name,due_date`
      )
      .then((r) => r.rows);
    for (const b of expired) {
      await addHistory(b.id, b.user_id, "expired", { due_date: b.due_date });
      await issueNotification(
        b.user_id,
        "bill.expired",
        `Bill expired: ${b.name}`,
        `Bill due on ${b.due_date} auto-marked expired.`,
        { billId: b.id }
      );
      await logActivity(b.user_id, "bill_expired", "bill", b.id, {});
    }
  });
}
async function purgeOldReminders() {
  await q(
    `DELETE FROM reminders WHERE remind_at < (NOW() - INTERVAL '15 days')`
  );
}
let lastMaintenance = 0;
async function runMaintenance() {
  const now = new Date();
  if (now.getTime() - lastMaintenance < 60000) return; // throttle to 60s
  lastMaintenance = now.getTime();
  try {
    await processRecurring(now);
    await expireOldBills(now);
    await purgeOldReminders();
  } catch (e) {
    console.error("[MaintenanceError]", e.message);
  }
}
setInterval(runMaintenance, 60000);
// Inject lazy maintenance
app.use((req, res, next) => {
  runMaintenance().finally(() => {});
  next();
});

// ---------------- Additional Routes (Bills Domain Extensions) ----------------

// Create recurring rule
app.post(`${API_PREFIX}/bills/recurring`, auth, async (req, res) => {
  const {
    name,
    amount,
    interval = "monthly",
    nextOccurrence,
    categoryId,
    meta,
  } = req.body || {};
  if (!name || !nextOccurrence)
    return json(res, 400, { error: "name & nextOccurrence required" });
  const allowed = ["daily", "weekly", "monthly"];
  if (!allowed.includes(interval))
    return json(res, 400, { error: "invalid interval" });
  let n;
  try {
    n = parseDate(nextOccurrence);
  } catch {
    return json(res, 400, { error: "invalid nextOccurrence" });
  }
  const id = uuid();
  await q(
    `INSERT INTO recurring_rules (id,user_id,name,amount,interval,next_occurrence,category_id,meta)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
    [
      id,
      req.user.id,
      name.trim(),
      amount ?? null,
      interval,
      n.toISOString(),
      categoryId || null,
      JSON.stringify(meta || {}),
    ]
  );
  json(res, 201, { data: { ruleId: id } });
});

app.get(`${API_PREFIX}/bills/recurring`, auth, async (req, res) => {
  const rules = await many(
    `SELECT * FROM recurring_rules WHERE user_id=$1 ORDER BY next_occurrence ASC`,
    [req.user.id]
  );
  json(res, 200, { data: { rules } });
});

// Settle bill
app.post(`${API_PREFIX}/bills/:id/settle`, auth, async (req, res) => {
  const { note, amount } = req.body || {};
  const bill = await one(
    `SELECT * FROM bills WHERE id=$1 AND status!='deleted'`,
    [req.params.id]
  );
  if (!bill) return json(res, 404, { error: "Bill not found" });
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });
  await q(`UPDATE bills SET status='settled', updated_at=NOW() WHERE id=$1`, [
    bill.id,
  ]);
  await addHistory(bill.id, req.user.id, "settled", {
    note: note || null,
    amount: amount ?? bill.amount,
  });
  await logActivity(req.user.id, "bill_settled", "bill", bill.id, {});
  json(res, 200, { data: { message: "Bill settled" } });
});

// Bill history
app.get(`${API_PREFIX}/bills/:id/history`, auth, async (req, res) => {
  const bill = await one(`SELECT user_id,status FROM bills WHERE id=$1`, [
    req.params.id,
  ]);
  if (!bill) return json(res, 404, { error: "Bill not found" });
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });
  const history = await many(
    `SELECT event_type,data,created_at FROM bill_history WHERE bill_id=$1 ORDER BY created_at ASC`,
    [req.params.id]
  );
  json(res, 200, { data: { history } });
});

// Patch category
app.patch(`${API_PREFIX}/bills/:id/category`, auth, async (req, res) => {
  const { categoryId } = req.body || {};
  const bill = await one(`SELECT * FROM bills WHERE id=$1`, [req.params.id]);
  if (!bill) return json(res, 404, { error: "Bill not found" });
  if (bill.user_id !== req.user.id && req.user.role !== "admin")
    return json(res, 403, { error: "Forbidden" });
  await q(`UPDATE bills SET updated_at=NOW() WHERE id=$1`, [bill.id]); // placeholder (no dedicated column yet)
  await addHistory(bill.id, req.user.id, "category_set", { categoryId });
  await logActivity(req.user.id, "bill_category_set", "bill", bill.id, {
    categoryId,
  });
  json(res, 200, { data: { message: "Category assigned" } });
});

// Categories
app.get(`${API_PREFIX}/categories`, auth, async (req, res) => {
  const cats = await many(
    `SELECT * FROM categories WHERE user_id=$1 ORDER BY name ASC`,
    [req.user.id]
  );
  json(res, 200, { data: { categories: cats } });
});
app.post(`${API_PREFIX}/categories`, auth, async (req, res) => {
  const { name, color } = req.body || {};
  if (!name) return json(res, 400, { error: "name required" });
  const id = uuid();
  await q(
    `INSERT INTO categories (id,user_id,name,color) VALUES ($1,$2,$3,$4)`,
    [id, req.user.id, name.trim(), color || null]
  );
  json(res, 201, { data: { categoryId: id } });
});

// Search bills
app.get(`${API_PREFIX}/bills/search`, auth, async (req, res) => {
  const qterm = (req.query.q || "").trim();
  if (!qterm) return json(res, 400, { error: "q required" });
  const rows = await many(
    `SELECT * FROM bills WHERE user_id=$1 AND status!='deleted' AND (name ILIKE $2) ORDER BY due_date ASC LIMIT 50`,
    [req.user.id, `%${qterm}%`]
  );
  json(res, 200, { data: { bills: rows } });
});

// Export CSV
app.get(`${API_PREFIX}/bills/export`, auth, async (req, res) => {
  const format = (req.query.format || "csv").toLowerCase();
  if (format !== "csv") return json(res, 400, { error: "only csv supported" });
  const rows = await many(
    `SELECT name,amount,due_date,status FROM bills WHERE user_id=$1 AND status!='deleted' ORDER BY due_date ASC`,
    [req.user.id]
  );
  const header = "name,amount,due_date,status";
  const lines = rows.map((r) =>
    [JSON.stringify(r.name), r.amount ?? "", r.due_date, r.status].join(",")
  );
  const csv = [header, ...lines].join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", 'attachment; filename="bills.csv"');
  res.send(csv);
});

// Manual bulk import
app.post(
  `${API_PREFIX}/bills/import/manual`,
  auth,
  planGuard,
  async (req, res) => {
    const { items } = req.body || {};
    if (!Array.isArray(items) || !items.length)
      return json(res, 400, { error: "items array required" });
    let created = 0;
    await tx(async (client) => {
      for (const it of items) {
        if (!it.name || !it.dueDate) continue;
        try {
          const due = parseDate(it.dueDate);
          const billRow = await client
            .query(
              `INSERT INTO bills (id,user_id,name,amount,due_date,status,source_type,created_at,updated_at)
           VALUES ($1,$2,$3,$4,$5,'active','manual',NOW(),NOW()) RETURNING *`,
              [
                uuid(),
                req.user.id,
                it.name.trim(),
                it.amount ?? null,
                due.toISOString(),
              ]
            )
            .then((r) => r.rows[0]);
          created++;
          await createAutoReminderForBill(billRow, req.user, client);
          await addHistory(billRow.id, req.user.id, "imported", {
            source: "manual_bulk",
          });
        } catch {}
      }
    });
    json(res, 201, { data: { imported: created } });
  }
);

// ---------------- Reminders Extensions ----------------
app.post(`${API_PREFIX}/reminders/bulk`, auth, async (req, res) => {
  const { reminders } = req.body || {};
  if (!Array.isArray(reminders) || !reminders.length)
    return json(res, 400, { error: "reminders array required" });
  const created = [];
  await tx(async (client) => {
    for (const r of reminders) {
      if (!r.billId || !r.remindAt) continue;
      const bill = await client
        .query(
          `SELECT * FROM bills WHERE id=$1 AND user_id=$2 AND status!='deleted'`,
          [r.billId, req.user.id]
        )
        .then((x) => x.rows[0]);
      if (!bill) continue;
      let ra;
      try {
        ra = parseDate(r.remindAt);
      } catch {
        continue;
      }
      const id = uuid();
      await client.query(
        `INSERT INTO reminders (id,user_id,bill_id,due_date,remind_at,status,channel)
         VALUES ($1,$2,$3,$4,$5,'scheduled',$6)`,
        [
          id,
          req.user.id,
          bill.id,
          bill.due_date,
          ra.toISOString(),
          r.channel || "push",
        ]
      );
      created.push(id);
    }
  });
  json(res, 201, { data: { created } });
});

app.get(`${API_PREFIX}/reminders/upcoming`, auth, async (req, res) => {
  const days = Math.min(parseInt(req.query.days || "30", 10) || 30, 180);
  const rows = await many(
    `SELECT * FROM reminders WHERE user_id=$1 AND remind_at BETWEEN NOW() AND (NOW() + ($2||' days')::interval)
     ORDER BY remind_at ASC`,
    [req.user.id, days]
  );
  json(res, 200, { data: { reminders: rows } });
});

app.get(`${API_PREFIX}/reminders/templates`, auth, async (req, res) => {
  const t = await many(
    `SELECT * FROM reminder_templates WHERE user_id=$1 AND active=true ORDER BY created_at ASC`,
    [req.user.id]
  );
  json(res, 200, { data: { templates: t } });
});
app.post(`${API_PREFIX}/reminders/templates`, auth, async (req, res) => {
  const { name, offsetDays, channel = "push" } = req.body || {};
  if (!name || offsetDays == null)
    return json(res, 400, { error: "name & offsetDays required" });
  if (typeof offsetDays !== "number" || offsetDays < 0 || offsetDays > 90)
    return json(res, 400, { error: "invalid offsetDays" });
  const id = uuid();
  await q(
    `INSERT INTO reminder_templates (id,user_id,name,offset_days,channel) VALUES ($1,$2,$3,$4,$5)`,
    [id, req.user.id, name.trim(), offsetDays, channel]
  );
  json(res, 201, { data: { templateId: id } });
});

// ---------------- Notifications ----------------
app.get(`${API_PREFIX}/notifications`, auth, async (req, res) => {
  const unread = req.query.unread === "1";
  const rows = await many(
    unread
      ? `SELECT * FROM notifications WHERE user_id=$1 AND read_at IS NULL ORDER BY created_at DESC LIMIT 100`
      : `SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200`,
    [req.user.id]
  );
  json(res, 200, { data: { notifications: rows } });
});

app.post(`${API_PREFIX}/notifications/:id/read`, auth, async (req, res) => {
  await q(
    `UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2 AND read_at IS NULL`,
    [req.params.id, req.user.id]
  );
  json(res, 200, { data: { message: "marked read" } });
});

app.post(`${API_PREFIX}/notifications/read-all`, auth, async (req, res) => {
  await q(
    `UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL`,
    [req.user.id]
  );
  json(res, 200, { data: { message: "all read" } });
});

// SSE stream (simple polling fallback)
app.get(`${API_PREFIX}/notifications/stream`, auth, async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.flushHeaders();
  const send = async () => {
    const latest = await many(
      `SELECT id,title,body,type,created_at FROM notifications WHERE user_id=$1 AND created_at > (NOW() - INTERVAL '5 minutes') ORDER BY created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.write(`data: ${JSON.stringify(latest)}\n\n`);
  };
  const interval = setInterval(send, 15000);
  req.on("close", () => clearInterval(interval));
  send();
});

// ---------------- Analytics ----------------
app.get(`${API_PREFIX}/analytics/overview`, auth, async (req, res) => {
  const row = await one(
    `
    SELECT
      (SELECT COUNT(*)::int FROM bills WHERE user_id=$1 AND status!='deleted') as bills_total,
      (SELECT COUNT(*)::int FROM bills WHERE user_id=$1 AND status='active') as bills_active,
      (SELECT COUNT(*)::int FROM bills WHERE user_id=$1 AND status='expired') as bills_expired,
      (SELECT COUNT(*)::int FROM reminders WHERE user_id=$1) as reminders_total
  `,
    [req.user.id]
  );
  json(res, 200, { data: { overview: row } });
});

app.get(`${API_PREFIX}/analytics/cashflow`, auth, async (req, res) => {
  // Basic YTD sum of amounts by month for settled bills
  const rows = await many(
    `SELECT date_trunc('month', due_date) AS month, SUM(COALESCE(amount,0))::float AS total
     FROM bills
     WHERE user_id=$1 AND status='settled' AND date_part('year',due_date)=date_part('year',NOW())
     GROUP BY 1 ORDER BY 1`,
    [req.user.id]
  );
  json(res, 200, { data: { cashflow: rows } });
});

app.get(`${API_PREFIX}/analytics/aging`, auth, async (req, res) => {
  const rows = await many(
    `SELECT
       SUM(CASE WHEN due_date >= NOW() THEN 1 ELSE 0 END)::int AS current,
       SUM(CASE WHEN due_date < NOW() AND due_date >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0 END)::int AS past_due_0_30,
       SUM(CASE WHEN due_date < NOW() - INTERVAL '30 days' AND due_date >= NOW() - INTERVAL '60 days' THEN 1 ELSE 0 END)::int AS past_due_31_60,
       SUM(CASE WHEN due_date < NOW() - INTERVAL '60 days' THEN 1 ELSE 0 END)::int AS past_due_60_plus
     FROM bills WHERE user_id=$1 AND status IN ('active','expired')`,
    [req.user.id]
  );
  json(res, 200, { data: { aging: rows[0] } });
});

app.get(
  `${API_PREFIX}/analytics/category-breakdown`,
  auth,
  async (req, res) => {
    const rows = await many(
      `SELECT b.status, c.name AS category, COUNT(*)::int AS count, SUM(COALESCE(b.amount,0))::float AS total
     FROM bills b
     LEFT JOIN categories c ON c.id = NULL  -- placeholder (no category_id column stored yet)
     WHERE b.user_id=$1
     GROUP BY b.status, c.name
     ORDER BY total DESC NULLS LAST`,
      [req.user.id]
    );
    json(res, 200, { data: { breakdown: rows } });
  }
);

app.get(`${API_PREFIX}/analytics/monthly-trend`, auth, async (req, res) => {
  const rows = await many(
    `SELECT date_trunc('month', due_date) AS month,
            SUM(COALESCE(amount,0))::float AS total
     FROM bills
     WHERE user_id=$1 AND status!='deleted'
     GROUP BY 1
     ORDER BY 1`,
    [req.user.id]
  );
  json(res, 200, { data: { trend: rows } });
});

app.get(
  `${API_PREFIX}/analytics/top-counterparties`,
  auth,
  async (req, res) => {
    const rows = await many(
      `SELECT name AS counterparty, COUNT(*)::int AS count, SUM(COALESCE(amount,0))::float AS total
     FROM bills WHERE user_id=$1 AND status!='deleted'
     GROUP BY name ORDER BY total DESC NULLS LAST LIMIT 10`,
      [req.user.id]
    );
    json(res, 200, { data: { top: rows } });
  }
);

// ---------------- User Security & API Keys / Export / Activity ----------------
app.patch(`${API_PREFIX}/user/security`, auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword) return json(res, 400, { error: "newPassword required" });
  const user = await one(`SELECT * FROM users WHERE id=$1`, [req.user.id]);
  if (!user) return json(res, 404, { error: "User not found" });
  if (user.password_hash && currentPassword) {
    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) return json(res, 400, { error: "currentPassword invalid" });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await q(`UPDATE users SET password_hash=$2 WHERE id=$1`, [user.id, hash]);
  await logActivity(user.id, "password_changed", "user", user.id, {});
  json(res, 200, { data: { message: "Password updated" } });
});

function hashApiKey(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}
app.get(`${API_PREFIX}/user/api-keys`, auth, async (req, res) => {
  const keys = await many(
    `SELECT id,label,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=$1 ORDER BY created_at DESC`,
    [req.user.id]
  );
  json(res, 200, { data: { apiKeys: keys } });
});
app.post(`${API_PREFIX}/user/api-keys`, auth, async (req, res) => {
  const { label } = req.body || {};
  const raw = crypto.randomBytes(24).toString("hex");
  const id = uuid();
  await q(
    `INSERT INTO api_keys (id,user_id,token_hash,label)
     VALUES ($1,$2,$3,$4)`,
    [id, req.user.id, hashApiKey(raw), label || null]
  );
  json(res, 201, { data: { apiKey: { id, label }, token: raw } });
});
app.delete(`${API_PREFIX}/user/api-keys/:id`, auth, async (req, res) => {
  await q(
    `UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`,
    [req.params.id, req.user.id]
  );
  json(res, 200, { data: { message: "API key revoked" } });
});

// Export job (stub async)
app.post(`${API_PREFIX}/user/export`, auth, async (req, res) => {
  const jobId = uuid();
  await q(
    `INSERT INTO export_jobs (id,user_id,status,type,params)
     VALUES ($1,$2,'pending','full',$3::jsonb)`,
    [jobId, req.user.id, JSON.stringify({})]
  );
  setTimeout(async () => {
    await q(
      `UPDATE export_jobs
       SET status='completed', completed_at=NOW(), updated_at=NOW()
       WHERE id=$1`,
      [jobId]
    );
  }, 500);
  json(res, 202, { data: { jobId } });
});
app.get(`${API_PREFIX}/user/export/:jobId/status`, auth, async (req, res) => {
  const job = await one(
    `SELECT * FROM export_jobs WHERE id=$1 AND user_id=$2`,
    [req.params.jobId, req.user.id]
  );
  if (!job) return json(res, 404, { error: "Job not found" });
  json(res, 200, { data: { job } });
});
app.get(`${API_PREFIX}/user/export/:jobId/download`, auth, async (req, res) => {
  const job = await one(
    `SELECT * FROM export_jobs WHERE id=$1 AND user_id=$2`,
    [req.params.jobId, req.user.id]
  );
  if (!job) return json(res, 404, { error: "Job not found" });
  if (job.status !== "completed")
    return json(res, 400, { error: "Job not completed" });
  res.setHeader("Content-Type", "application/json");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="export_${job.id}.json"`
  );
  // minimal export dataset
  const bills = await many(`SELECT * FROM bills WHERE user_id=$1`, [
    req.user.id,
  ]);
  res.end(JSON.stringify({ bills }));
});

app.get(`${API_PREFIX}/user/activity`, auth, async (req, res) => {
  const rows = await many(
    `SELECT action,entity_type,entity_id,meta,created_at
     FROM user_activity WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.user.id]
  );
  json(res, 200, { data: { activity: rows } });
});
