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

// ----------------------- Config & Environment -----------------------
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const APP_ENV = process.env.APP_ENV || "development";
const NEON_DATABASE_URL = process.env.NEON_DATABASE_URL;
const ADMIN_CODE = process.env.ADMIN_CODE || "admin123";

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
}

// ----------------------- Middleware -----------------------
app.use(cors());
app.use(express.json({ limit: "256kb" }));
app.use(morgan(APP_ENV === "development" ? "dev" : "combined"));

// Simple correlation ID for tracing
app.use((req, res, next) => {
  req.cid = uuid();
  res.setHeader("X-Correlation-Id", req.cid);
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

// Health
app.get("/", (req, res) => res.send("BillHawk Backend Running"));
app.get(`${API_PREFIX}/health`, (req, res) =>
  json(res, 200, { data: { status: "ok", time: new Date().toISOString() } })
);

// -------- Auth --------
app.post(`${API_PREFIX}/auth/register`, async (req, res) => {
  try {
    const { email, password } = req.body || {};
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
  const { email, password } = req.body || {};
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
