import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import crypto from "node:crypto";
import { promisify } from "node:util";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import session from "express-session";
import Database from "better-sqlite3";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || process.env.SITE_URL || "").replace(/\/+$/, "");
const ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || "";
const PUBLIC_KEY = process.env.MP_PUBLIC_KEY || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const DOCUSIGN_INTEGRATION_KEY = process.env.DOCUSIGN_INTEGRATION_KEY || "";
const DOCUSIGN_USER_ID = process.env.DOCUSIGN_USER_ID || "";
const DOCUSIGN_ACCOUNT_ID = process.env.DOCUSIGN_ACCOUNT_ID || "";
const DOCUSIGN_TEMPLATE_ID = process.env.DOCUSIGN_TEMPLATE_ID || "";
const DOCUSIGN_ROLE_NAME = process.env.DOCUSIGN_ROLE_NAME || "Signer";
const DOCUSIGN_AUTH_HOST = process.env.DOCUSIGN_AUTH_HOST || "account-d.docusign.com";
const DOCUSIGN_BASE_URI = (process.env.DOCUSIGN_BASE_URI || "").replace(/\/+$/, "");
const DOCUSIGN_PRIVATE_KEY_PATH = process.env.DOCUSIGN_PRIVATE_KEY_PATH || "";
const DATA_DIR = fileURLToPath(new URL("./data/", import.meta.url));
const DATABASE_PATH = path.join(DATA_DIR, "k11fit.sqlite");
const scrypt = promisify(crypto.scrypt);

app.disable("x-powered-by");
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));

mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(DATABASE_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    external_reference TEXT NOT NULL UNIQUE,
    preference_id TEXT,
    payment_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS signature_intents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    envelope_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'creating',
    order_id TEXT REFERENCES orders(id),
    checkout_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expires INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS orders_user_created ON orders(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS signatures_user_created ON signature_intents(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
`);

class SQLiteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.database = database;
    this.getStatement = database.prepare("SELECT sess, expires FROM sessions WHERE sid = ?");
    this.setStatement = database.prepare(`
      INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires
    `);
    this.touchStatement = database.prepare("UPDATE sessions SET expires = ? WHERE sid = ?");
    this.deleteStatement = database.prepare("DELETE FROM sessions WHERE sid = ?");
  }

  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid);
      if (!row) return callback(null, null);
      if (row.expires <= Date.now()) {
        this.deleteStatement.run(sid);
        return callback(null, null);
      }
      return callback(null, JSON.parse(row.sess));
    } catch (error) {
      return callback(error);
    }
  }

  set(sid, sess, callback) {
    try {
      const expires = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + 1000 * 60 * 60 * 24;
      this.setStatement.run(sid, JSON.stringify(sess), expires);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else this.emit("disconnect", error);
    }
  }

  touch(sid, sess, callback) {
    try {
      const expires = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + 1000 * 60 * 60 * 24;
      this.touchStatement.run(expires, sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else this.emit("disconnect", error);
    }
  }

  destroy(sid, callback) {
    try {
      this.deleteStatement.run(sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
      else this.emit("disconnect", error);
    }
  }
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("Configure SESSION_SECRET com pelo menos 32 caracteres no arquivo .env.");
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ADMIN_EMAIL) ||
    ADMIN_PASSWORD.length < 12 || ADMIN_PASSWORD.length > 128) {
  throw new Error("Configure ADMIN_EMAIL e ADMIN_PASSWORD (mínimo de 12 caracteres) no arquivo .env.");
}

app.use(session({
  name: "k11fit.sid",
  secret: SESSION_SECRET,
  store: new SQLiteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
db.prepare("DELETE FROM sessions WHERE expires <= ?").run(Date.now());

const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde alguns minutos e tente novamente." }
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60_000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitos cadastros deste endereço. Tente novamente mais tarde." }
});

function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (!origin) return res.status(403).json({ error: "Origem da solicitação não autorizada." });
  try {
    const expectedOrigin = BASE_URL
      ? new URL(BASE_URL).origin
      : `${req.protocol}://${req.get("host")}`;
    if (new URL(origin).origin !== expectedOrigin) {
      return res.status(403).json({ error: "Origem da solicitação não autorizada." });
    }
  } catch {
    return res.status(403).json({ error: "Origem da solicitação não autorizada." });
  }
  return next();
}

function requireUser(req, res, next) {
  const user = req.session.userId
    ? db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(req.session.userId)
    : null;
  if (!user) return res.status(401).json({ error: "Faça login para continuar." });
  req.user = user;
  return next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.sendStatus(403);
  return next();
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

async function ensureAdminAccount() {
  const passwordHash = await hashPassword(ADMIN_PASSWORD);
  db.transaction(() => {
    db.prepare("UPDATE users SET role = 'student' WHERE role = 'admin' AND email != ?").run(ADMIN_EMAIL);
    db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role)
      VALUES (?, 'Administrador', ?, ?, 'admin')
      ON CONFLICT(email) DO UPDATE SET
        password_hash = excluded.password_hash,
        role = 'admin'
    `).run(crypto.randomUUID(), ADMIN_EMAIL, passwordHash);
  })();
}

async function verifyPassword(password, storedHash) {
  const [saltHex, hashHex] = storedHash.split(":");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function establishSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => {
      if (error) return reject(error);
      req.session.userId = user.id;
      return req.session.save(saveError => saveError ? reject(saveError) : resolve());
    });
  });
}

function priceInCents(centsVariable, reaisVariable) {
  const cents = process.env[centsVariable];
  if (cents !== undefined) return Number(cents);
  const reais = Number(process.env[reaisVariable] || 0);
  return Number.isFinite(reais) ? Math.round(reais * 100) : 0;
}
const planConfig = {
  mensal: {
    title: "Plano Mensal K11Fit",
    price: priceInCents("PLAN_MENSAL_CENTAVOS", "PRICE_MENSAL")
  },
  trimestral: {
    title: "Plano Trimestral K11Fit",
    price: priceInCents("PLAN_TRIMESTRAL_CENTAVOS", "PRICE_TRIMESTRAL")
  },
  anual: {
    title: "Plano Anual K11Fit",
    price: priceInCents("PLAN_ANUAL_CENTAVOS", "PRICE_ANUAL")
  },
};

function configReady() {
  if (!BASE_URL || !ACCESS_TOKEN || !WEBHOOK_SECRET) return false;
  try {
    const url = new URL(BASE_URL);
    if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) return false;
    const localDevelopment = process.env.NODE_ENV !== "production" &&
      ["localhost", "127.0.0.1"].includes(url.hostname);
    return url.protocol === "https:" || (localDevelopment && url.protocol === "http:");
  } catch {
    return false;
  }
}

function docusignReady() {
  if (!DOCUSIGN_INTEGRATION_KEY || !DOCUSIGN_USER_ID || !DOCUSIGN_ACCOUNT_ID ||
      !DOCUSIGN_TEMPLATE_ID || !DOCUSIGN_PRIVATE_KEY_PATH ||
      !existsSync(path.resolve(DOCUSIGN_PRIVATE_KEY_PATH)) ||
      !["account-d.docusign.com", "account.docusign.com"].includes(DOCUSIGN_AUTH_HOST)) {
    return false;
  }
  try {
    const url = new URL(DOCUSIGN_BASE_URI);
    return url.protocol === "https:" &&
      (url.hostname.endsWith(".docusign.net") || url.hostname.endsWith(".docusign.com")) &&
      url.pathname.endsWith("/restapi") &&
      !url.search && !url.hash && !url.username && !url.password;
  } catch {
    return false;
  }
}

let docuSignTokenCache;
async function getDocuSignAccessToken() {
  if (docuSignTokenCache && docuSignTokenCache.expiresAt > Date.now() + 60_000) {
    return docuSignTokenCache.accessToken;
  }
  const privateKey = readFileSync(path.resolve(DOCUSIGN_PRIVATE_KEY_PATH), "utf8");
  const now = Math.floor(Date.now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
  const unsigned = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({
    iss: DOCUSIGN_INTEGRATION_KEY,
    sub: DOCUSIGN_USER_ID,
    aud: DOCUSIGN_AUTH_HOST,
    iat: now,
    exp: now + 3600,
    scope: "signature impersonation"
  })}`;
  const assertion = `${unsigned}.${crypto.sign("RSA-SHA256", Buffer.from(unsigned), privateKey).toString("base64url")}`;
  const response = await fetch(`https://${DOCUSIGN_AUTH_HOST}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const body = await response.json();
  if (!response.ok || typeof body.access_token !== "string") {
    const error = new Error(
      body.error === "consent_required"
        ? "O usuário de integração ainda precisa autorizar os escopos signature e impersonation no DocuSign."
        : "Não foi possível autenticar no DocuSign. Confira as configurações e a autorização JWT."
    );
    error.status = response.status;
    throw error;
  }
  docuSignTokenCache = {
    accessToken: body.access_token,
    expiresAt: Date.now() + Number(body.expires_in || 3600) * 1000
  };
  return docuSignTokenCache.accessToken;
}

async function docusignRequest(endpoint, options = {}) {
  const accessToken = await getDocuSignAccessToken();
  const response = await fetch(`${DOCUSIGN_BASE_URI}/v2.1/accounts/${encodeURIComponent(DOCUSIGN_ACCOUNT_ID)}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      ...options.headers
    }
  });
  const body = await response.json();
  if (!response.ok) {
    const error = new Error("O DocuSign não concluiu a solicitação. Confira o template, a função do assinante e as permissões da API.");
    error.status = response.status;
    throw error;
  }
  return body;
}

async function createMercadoPagoPreference({ planKey, plan, userId, orderId }) {
  const externalReference = `k11fit-${userId}-${orderId}`;
  db.prepare(`
    INSERT INTO orders (id, user_id, plan, amount_cents, status, external_reference)
    VALUES (?, ?, ?, ?, 'pending', ?)
    ON CONFLICT(id) DO UPDATE SET status = 'pending', updated_at = CURRENT_TIMESTAMP
  `).run(orderId, userId, planKey, plan.price, externalReference);
  try {
    const client = new MercadoPagoConfig({ accessToken: ACCESS_TOKEN });
    const preferenceApi = new Preference(client);
    const preference = await preferenceApi.create({
      body: {
        items: [{
          id: planKey,
          title: plan.title,
          quantity: 1,
          currency_id: "BRL",
          unit_price: Number((plan.price / 100).toFixed(2))
        }],
        payment_methods: {
          excluded_payment_types: [{ id: "ticket" }]
        },
        back_urls: {
          success: `${BASE_URL}/pagamento-retorno.html?status=success`,
          pending: `${BASE_URL}/pagamento-retorno.html?status=pending`,
          failure: `${BASE_URL}/pagamento-retorno.html?status=failure`
        },
        auto_return: "approved",
        notification_url: `${BASE_URL}/api/mercadopago-webhook`,
        statement_descriptor: "K11FIT ACADEMIA",
        external_reference: externalReference
      }
    });
    if (!preference.init_point) throw new Error("O Mercado Pago não retornou o link de checkout.");
    db.prepare("UPDATE orders SET preference_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run(preference.id || null, orderId);
    return preference.init_point;
  } catch (error) {
    db.prepare("UPDATE orders SET status = 'checkout_error', updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run(orderId);
    throw error;
  }
}

app.post("/api/auth/register", sameOrigin, registerLimiter, async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (name.length < 2 || name.length > 100 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
      password.length < 10 || password.length > 128) {
    return res.status(400).json({ error: "Informe nome, e-mail válido e senha entre 10 e 128 caracteres." });
  }

  let accountCreated = false;
  try {
    const user = { id: crypto.randomUUID(), name, email, role: "student" };
    const passwordHash = await hashPassword(password);
    db.prepare("INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'student')")
      .run(user.id, user.name, user.email, passwordHash);
    accountCreated = true;
    await establishSession(req, user);
    return res.status(201).json({ user });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Já existe uma conta com esse e-mail." });
    }
    console.error("Falha ao criar conta:", error?.message || error);
    return res.status(500).json({
      error: accountCreated
        ? "Conta criada, mas não foi possível iniciar a sessão. Entre usando seu e-mail e senha."
        : "Não foi possível criar a conta."
    });
  }
});

app.post("/api/auth/login", sameOrigin, loginLimiter, async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const userRecord = db.prepare("SELECT id, name, email, role, password_hash FROM users WHERE email = ?")
    .get(email);
  const valid = userRecord
    ? await verifyPassword(password, userRecord.password_hash)
    : await verifyPassword(password, "00000000000000000000000000000000:" + "00".repeat(64));
  if (!valid) return res.status(401).json({ error: "E-mail ou senha incorretos." });

  const user = { id: userRecord.id, name: userRecord.name, email: userRecord.email, role: userRecord.role };
  try {
    await establishSession(req, user);
    return res.json({ user });
  } catch (error) {
    console.error("Falha ao iniciar sessão:", error?.message || error);
    return res.status(500).json({ error: "Não foi possível iniciar a sessão." });
  }
});

app.get("/api/auth/me", (req, res) => {
  const user = req.session.userId
    ? db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(req.session.userId)
    : null;
  if (!user) return res.status(401).json({ error: "Faça login para continuar." });
  return res.json({ user });
});

app.post("/api/auth/logout", sameOrigin, (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie("k11fit.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    return res.sendStatus(204);
  });
});

app.get("/api/account/orders", requireUser, (req, res) => {
  const orders = db.prepare(`
    SELECT id, plan, amount_cents AS amountCents, status, created_at AS createdAt
    FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 100
  `).all(req.user.id);
  return res.json({ orders });
});

app.get("/api/admin/users", requireUser, requireAdmin, (_req, res) => {
  const users = db.prepare(`
    SELECT users.id, users.name, users.email, users.role, users.created_at AS createdAt,
      orders.plan, orders.amount_cents AS amountCents, orders.status AS paymentStatus,
      orders.created_at AS paymentCreatedAt
    FROM users LEFT JOIN orders ON orders.user_id = users.id
    ORDER BY users.created_at DESC, orders.created_at DESC LIMIT 500
  `).all();
  return res.json({ users });
});

app.get("/api/config", (_req, res) => {
  const checkoutAvailable = configReady() && docusignReady();
  res.json({
    publicKey: PUBLIC_KEY || null,
    plans: Object.fromEntries(Object.entries(planConfig).map(([key, plan]) => [
      key, {
        title: plan.title,
        priceCents: plan.price > 0 ? plan.price : null,
        checkoutAvailable
      }
    ])),
    ready: checkoutAvailable
  });
});

app.post("/api/signatures", sameOrigin, requireUser, async (req, res) => {
  const planKey = req.body?.plan;
  const plan = planConfig[planKey];
  if (!plan || !Number.isSafeInteger(plan.price) || plan.price <= 0) {
    return res.status(400).json({ error: "Plano inválido ou preço ainda não configurado." });
  }

  if (!configReady() || !docusignReady()) {
    return res.status(503).json({ error: "Configure o Mercado Pago, o webhook e a integração/template DocuSign no .env." });
  }

  db.prepare(`
    UPDATE signature_intents SET status = 'superseded', updated_at = CURRENT_TIMESTAMP
    WHERE user_id = ? AND status IN ('creating', 'sent', 'signed_checkout_error')
  `).run(req.user.id);
  const signatureId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO signature_intents (id, user_id, plan, amount_cents, status)
    VALUES (?, ?, ?, ?, 'creating')
  `).run(signatureId, req.user.id, planKey, plan.price);

  try {
    const envelope = await docusignRequest("/envelopes", {
      method: "POST",
      body: JSON.stringify({
        templateId: DOCUSIGN_TEMPLATE_ID,
        templateRoles: [{
          email: req.user.email,
          name: req.user.name,
          roleName: DOCUSIGN_ROLE_NAME,
          clientUserId: signatureId
        }],
        status: "sent"
      })
    });
    if (typeof envelope.envelopeId !== "string") {
      throw new Error("O DocuSign não retornou o identificador do envelope.");
    }
    db.prepare(`
      UPDATE signature_intents
      SET envelope_id = ?, status = 'sent', updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(envelope.envelopeId, signatureId);
    const recipients = await docusignRequest(`/envelopes/${encodeURIComponent(envelope.envelopeId)}/recipients`);
    const signer = (recipients.signers || []).find(recipient =>
      recipient.clientUserId === signatureId &&
      String(recipient.email || "").toLowerCase() === req.user.email.toLowerCase()
    );
    if (!signer?.recipientId) {
      throw new Error("O assinante da conta não foi encontrado no template do DocuSign.");
    }
    const recipientView = await docusignRequest(`/envelopes/${encodeURIComponent(envelope.envelopeId)}/views/recipient`, {
      method: "POST",
      body: JSON.stringify({
        returnUrl: `${BASE_URL}/assinatura-retorno.html?signatureId=${encodeURIComponent(signatureId)}`,
        authenticationMethod: "none",
        email: req.user.email,
        userName: req.user.name,
        clientUserId: signatureId,
        recipientId: String(signer.recipientId)
      })
    });
    if (typeof recipientView.url !== "string" || !recipientView.url.startsWith("https://")) {
      throw new Error("O DocuSign não retornou uma URL segura de assinatura.");
    }
    return res.json({ signingUrl: recipientView.url });
  } catch (error) {
    db.prepare("UPDATE signature_intents SET status = 'signing_error', updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run(signatureId);
    console.error("Falha ao iniciar assinatura DocuSign:", error?.message || error);
    return res.status(502).json({
      error: error.message.includes("autorizar os escopos")
        ? error.message
        : "Não foi possível abrir a assinatura. Confira o template e a configuração do DocuSign."
    });
  }
});

app.post("/api/signatures/:id/complete", sameOrigin, requireUser, async (req, res) => {
  const intent = db.prepare(`
    SELECT id, user_id, plan, amount_cents, envelope_id, status, order_id, checkout_url
    FROM signature_intents WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.id);
  if (!intent || !intent.envelope_id || ["superseded", "signing_error"].includes(intent.status)) {
    return res.status(404).json({ error: "Assinatura não encontrada. Selecione um plano para começar novamente." });
  }
  if (intent.checkout_url) return res.json({ checkoutUrl: intent.checkout_url });
  if (!configReady()) {
    return res.status(503).json({ error: "O Mercado Pago ainda não está configurado no servidor." });
  }

  try {
    const envelope = await docusignRequest(`/envelopes/${encodeURIComponent(intent.envelope_id)}`);
    if (envelope.status !== "completed") {
      return res.status(409).json({ error: "O DocuSign ainda não confirmou que o contrato foi assinado." });
    }
    db.prepare(`
      UPDATE signature_intents SET status = 'signed', updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(intent.id);
    const orderId = intent.order_id || crypto.randomUUID();
    const checkoutUrl = await createMercadoPagoPreference({
      planKey: intent.plan,
      plan: { ...planConfig[intent.plan], price: intent.amount_cents },
      userId: intent.user_id,
      orderId
    });
    db.prepare(`
      UPDATE signature_intents
      SET status = 'checkout_ready', order_id = ?, checkout_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(orderId, checkoutUrl, intent.id);
    return res.json({ checkoutUrl });
  } catch (error) {
    db.prepare(`
      UPDATE signature_intents SET status = 'signed_checkout_error', updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(intent.id);
    console.error("Falha ao confirmar assinatura ou criar checkout Mercado Pago:", error?.message || error);
    return res.status(502).json({
      error: error.status === 401 || error.status === 403
        ? "Não foi possível verificar a assinatura no DocuSign. Confira as credenciais da integração."
        : "Não foi possível preparar o pagamento após a assinatura. Tente novamente."
    });
  }
});

// Valida a assinatura de webhook conforme o esquema HMAC documentado pelo Mercado Pago.
// A confirmação do pagamento deve ser feita consultando a API com o ID recebido, nunca
// confiando apenas no redirecionamento do navegador.
function validWebhookSignature(req) {
  if (!WEBHOOK_SECRET) return false;
  const signature = req.get("x-signature") || "";
  const requestId = req.get("x-request-id") || "";
  const dataId = String(req.query["data.id"] || req.body?.data?.id || "").toLowerCase();
  const ts = signature.match(/(?:^|,)ts=([^,]+)/)?.[1];
  const v1 = signature.match(/(?:^|,)v1=([^,]+)/)?.[1];
  if (!ts || !v1 || !requestId || !dataId) return false;
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET).update(manifest).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(v1, "hex"));
  } catch {
    return false;
  }
}

app.post("/api/mercadopago-webhook", async (req, res) => {
  if (!validWebhookSignature(req)) return res.sendStatus(401);
  const topic = req.query.type || req.body?.type;
  const paymentId = req.query["data.id"] || req.body?.data?.id;
  if (topic === "payment" && paymentId) {
    try {
      const client = new MercadoPagoConfig({ accessToken: ACCESS_TOKEN });
      const paymentApi = new Payment(client);
      const payment = await paymentApi.get({ id: String(paymentId) });
      if (typeof payment.external_reference !== "string") {
        console.error("Notificação Mercado Pago sem referência de pedido:", String(paymentId));
        return res.sendStatus(400);
      }
      const order = db.prepare("SELECT id, amount_cents FROM orders WHERE external_reference = ?")
        .get(payment.external_reference);
      if (!order ||
          payment.currency_id !== "BRL" ||
          Math.round(Number(payment.transaction_amount) * 100) !== order.amount_cents) {
        console.error("Notificação Mercado Pago não corresponde a um pedido válido:", String(paymentId));
        return res.sendStatus(400);
      }
      db.prepare(`
        UPDATE orders
        SET status = ?, payment_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(payment.status || "unknown", String(payment.id), order.id);
    } catch (error) {
      console.error("Não foi possível consultar pagamento notificado:", error?.message || error);
      return res.sendStatus(500);
    }
  }
  return res.sendStatus(200);
});

app.use("/data", (_req, res) => res.sendStatus(404));
app.use(express.static(fileURLToPath(new URL(".", import.meta.url))));

await ensureAdminAccount();
app.listen(PORT, () => {
  console.log(`K11Fit site disponível na porta ${PORT}`);
  if (!configReady()) console.warn("Checkout indisponível: configure as credenciais do Mercado Pago, o segredo do webhook e a URL do site no arquivo .env.");
});
