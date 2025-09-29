# BillHawk Backend (MVP)

A lightweight Express-based backend designed for rapid iteration toward a cross-platform bill tracking app. This MVP intentionally keeps logic in-memory and centralized (single `server.js`) while sketching how it will evolve into an Azure-native, serverless-friendly architecture.

## Core Concepts

1. Authentication

   - Email + password registration with bcrypt hashing.
   - JWT-based stateless auth (access token only for now).
   - Logout is a soft blacklist (in-memory set) for rapid MVP; to replace with token versioning or short TTL + rotation.

2. Data Model (In-Memory for MVP)

   - Users: { id, email, passwordHash, plan, profile:{ reminderOffsetDays, notifications }, createdAt }
   - Bills: { id, userId, name, amount, dueDate, status, sourceType, createdAt, updatedAt }
   - Reminders: { id, userId, billId, remindAt, dueDate, status, channel }
   - Tokens (blacklist): Set of revoked JWT jti values (placeholder).
   - All to migrate to Azure Table Storage (partition strategy below).

3. Premium / Plan Enforcement

   - Free plan limited to 2 active bills (status !== deleted).
   - Premium removes limit (stub subscribe endpoint flips plan).
   - Future: family plan, seat sharing, usage metrics.

4. Automatic Reminder Generation

   - On bill creation: create a reminder 2 days before due date (configurable per user later).
   - If due date < (now + offset) fallback to 1 hour from now (still ensures a trigger).
   - Additional channels (WhatsApp / Push) will layer on a notification dispatcher queue.

5. Import Pipelines

   - SMS / Email import endpoints accept already-parsed metadata (MVP assumes device/app parser).
   - Future: Azure Functions bound to Communication Services / Gmail API ingestion -> push normalized events to queue/topic.

6. Lifecycle of a Typical Request

   - Client includes Authorization: Bearer <token>.
   - Auth middleware verifies JWT -> attaches req.user.
   - Business middleware (e.g. planGuard) optionally enforces constraints.
   - Handler executes, persists (currently in memory).
   - Response serialized as JSON with consistent envelope: { success, data?, error? }.

7. Error Strategy

   - Centralized error handler standardizes output.
   - Validation errors use 400; unauthorized 401; forbidden 403; not found 404.
   - Unexpected server errors collapse to 500 with generic message (stack hidden unless APP_ENV=development).

8. Azure Evolution Path (Planned)

   - Azure Table Storage
     - PartitionKey: userId (for multi-tenant isolation / horizontal scalability).
     - RowKey: entity id (UUID).
     - Tables: Users, Bills, Reminders, Subscriptions.
   - Replace in-memory arrays with thin repository adapter pattern.
   - Move heavy operations (reminder scheduling / notifications) to Azure Functions (Timer + Queue Trigger).
   - Eventually emit domain events (bill.created, reminder.due) -> Service Bus / Event Grid.

9. Notifications (Future)

   - MVP stub only logs scheduling intent.
   - Real flow: reminder due -> enqueue job -> channel fan-out (Push via FCM, WhatsApp via ACS, Email optional).
   - Idempotency key: reminderId + channel.

10. Security Notes

    - Secrets via environment (.env not committed).
    - Strengthen password policies + rate limiting later.
    - Add refresh token rotation for mobile resilience.
    - Consider per-user encryption of sensitive metadata (not needed for plain bill fields initially).

11. Scaling Strategy

    - Stateless containers (Docker) fronted by Azure Container Apps or App Service.
    - Promote long-running tasks to async workers.
    - Observability: add structured logging + correlation ID middleware.

12. Local Development

    - Install deps: npm install
    - Run: node server.js (or nodemon if added)
    - Test with curl / Postman.
    - Data resets on restart (intentional MVP simplification).

13. Environment Variables

    - PORT=4000 (default)
    - JWT_SECRET=change_me
    - APP_ENV=development
    - AZURE_TABLE_ACCOUNT=your_account (future)
    - AZURE_TABLE_KEY=your_key (future)

14. Future Enhancements (Shortlist)

    - Category classification (ML / rule-based).
    - Recurring bill inference (detect cadence from past instances).
    - Natural language queries (“What’s due next week?”).
    - Calendar export (ICS feed / Google Calendar API).
    - Family workspace membership & roles.

15. Code Philosophy
    - Start scrappy, keep refactor seams (helper sections in `server.js`).
    - Migrate to modular folders only when complexity justifies it.
    - Favor explicitness over magic in first iteration.

## Quick Start

1. Create `.env` with:
   JWT_SECRET=dev_secret
2. npm install
3. node server.js
4. Register, then authenticate subsequent requests with returned token.

## Persistence (Neon/PostgreSQL Migration)

The backend now uses Neon (PostgreSQL) instead of in-memory arrays.

Tables (auto-created on startup if missing):

- users (id UUID PK, email UNIQUE, password_hash, plan, profile JSONB, created_at)
- bills (id, user_id FK, name, amount NUMERIC, due_date, status, source_type, created_at, updated_at)
- reminders (id, user_id, bill_id, due_date, remind_at, status, channel, created_at)
- revoked_tokens (jti PRIMARY KEY, revoked_at)

Active bill limit (free plan) enforced via COUNT query.

Automatic reminders inserted transactionally when a bill is created/imported.

## Environment (Updated)

Add NEON_DATABASE_URL to `.env`:
NEON_DATABASE_URL=postgresql://... (Neon provided)
JWT_SECRET=change_me

## Local Setup (Updated)

1. cp .env (edit secrets)
2. npm install pg bcrypt jsonwebtoken express cors morgan dotenv uuid
3. node server.js

## Future (Data Layer)

- Replace ad-hoc SQL with repository modules.
- Add indexes (bills(user_id,due_date), reminders(remind_at)).
- Add soft-deletion timestamp columns later instead of status flag.

## Admin & Payments (New)

Admin access:

- Login with POST /api/v1/admin/login { code } where code matches ADMIN_CODE env.
- Admin JWT contains role=admin.
- Admin routes:
  - GET /api/v1/admin/users/:email (fetch any user by email)
  - PATCH /api/v1/admin/users/:id/plan { plan } (e.g. premium)
  - GET /api/v1/admin/users?q=partial (search)

Payment simulation:

- POST /api/v1/premium/subscribe { paymentReference } (upgrade)
- POST /api/v1/premium/unsubscribe (downgrade to free, idempotent)
- POST /api/v1/payments/confirm { provider, reference } (alt upgrade flow)

Security note: Replace ADMIN_CODE before production and move real payment verification server-side (webhooks).

Profile:

- Users can update reminderOffsetDays, notifications, and displayName.

## Environment Additions

ADMIN_CODE=admin123 (change in real deployments)

## Dashboard (New)

High-level aggregated data (for user home screen):
GET /api/v1/dashboard/summary
Returns:

- counts: { billsActive, remindersScheduled }
- nextDueBill
- recentBills (last 5 by created_at)
- upcomingReminders (next 5 by remind_at)

Use this to hydrate a single dashboard view without multiple round trips.

## Disclaimer

Not production-hardened. No persistence, no rate limiting, no audit logging yet.

Enjoy iterating—this is the launch pad, not the skyscraper.
