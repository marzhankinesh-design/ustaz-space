
require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.error('DATABASE_URL және SESSION_SECRET .env ішінде міндетті түрде көрсетілуі керек.');
  process.exit(1);
}
if (isProduction) app.set('trust proxy', 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  }
}));
app.use(express.json({ limit: '20kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false }));

app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'ustazspace.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Алдымен жүйеге кіріңіз.' });
  next();
}
function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function publicUser(row) {
  return { id: row.id, firstName: row.first_name, lastName: row.last_name, subject: row.subject, email: row.email };
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, subject, email, password } = req.body || {};
    if (![firstName, lastName, subject].every(v => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= 100)) {
      return res.status(400).json({ error: 'Атыңызды, тегіңізді және пәніңізді дұрыс енгізіңіз.' });
    }
    if (!validEmail(email)) return res.status(400).json({ error: 'Электрондық пошта пішімін тексеріңіз.' });
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: 'Құпиясөз кемінде 8 таңбадан тұруы керек.' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, subject, email, password_hash)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, first_name, last_name, subject, email`,
      [firstName.trim(), lastName.trim(), subject.trim(), email.trim().toLowerCase(), passwordHash]
    );
    req.session.userId = result.rows[0].id;
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Қауіпсіз сессияны бастау мүмкін болмады.' });
      req.session.userId = result.rows[0].id;
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({ error: 'Сессияны сақтау мүмкін болмады.' });
        res.status(201).json({ user: publicUser(result.rows[0]) });
      });
    });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Бұл электрондық пошта бұрын тіркелген. «Кіру» бөлімін таңдаңыз.' });
    console.error('register error:', err.message);
    res.status(500).json({ error: 'Тіркелу кезінде сервер қатесі пайда болды.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!validEmail(email) || typeof password !== 'string') return res.status(400).json({ error: 'Электрондық пошта мен құпиясөзді тексеріңіз.' });
    const result = await pool.query(
      'SELECT id, first_name, last_name, subject, email, password_hash FROM users WHERE email = $1',
      [email.trim().toLowerCase()]
    );
    const row = result.rows[0];
    const ok = row ? await bcrypt.compare(password, row.password_hash) : false;
    if (!ok) return res.status(401).json({ error: 'Мәліметтер сәйкес келмеді. Электрондық пошта мен құпиясөзді тексеріңіз.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Қауіпсіз сессияны бастау мүмкін болмады.' });
      req.session.userId = row.id;
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({ error: 'Сессияны сақтау мүмкін болмады.' });
        res.json({ user: publicUser(row) });
      });
    });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ error: 'Кіру кезінде сервер қатесі пайда болды.' });
  }
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  try {
    const result = await pool.query(
      'SELECT id, first_name, last_name, subject, email FROM users WHERE id = $1',
      [req.session.userId]
    );
    if (!result.rows[0]) {
      req.session.destroy(() => {});
      return res.json({ user: null });
    }
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('me error:', err.message);
    res.status(500).json({ error: 'Профильді жүктеу мүмкін болмады.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Жүйеден шығу кезінде қате пайда болды.' });
    res.clearCookie('ustazspace.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ ok: true });
  });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

pool.query('SELECT 1').then(() => {
  app.listen(port, () => console.log(`USTAZ SPACE сервері ${port}-портта іске қосылды.`));
}).catch(err => {
  console.error('Деректер базасына қосылу мүмкін болмады:', err.message);
  process.exit(1);
});
