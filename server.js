require('dotenv').config();
const express = require('express'), helmet = require('helmet'), cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit'), bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path');
const { Pool, types } = require('pg');
types.setTypeParser(1082, v => v); // DATE -> 'YYYY-MM-DD' (sin cambios de zona horaria)

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined });
const q = (t, p) => pool.query(t, p);
const app = express();
const PROD = process.env.NODE_ENV === 'production';
if (PROD) app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'] } } }));
app.use(express.json({ limit: '50kb' }));
app.use((req, _res, next) => { req.body ??= {}; next(); });
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- utilidades ---------- */
const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const clean = (s, n) => String(s ?? '').trim().slice(0, n);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s)) && Date.parse(s) - Date.now() < 2 * 864e5;
const DUMMY = bcrypt.hashSync('relleno-contra-timing', 12);
app.param('id', (req, res, next, v) => UUID.test(v) ? next() : bad(res, 'No encontrado', 404));

async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')", [sha(token), userId]);
  res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 30 * 864e5 });
}
async function auth(req, res, next) {
  const t = req.cookies.sid;
  const r = t && await q('SELECT u.id,u.username,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()', [sha(t)]);
  if (!r || !r.rows[0]) return bad(res, 'No autenticado', 401);
  req.user = r.rows[0]; next();
}
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Demasiados intentos. Espera unos minutos.' } });

/* ---------- autenticación ---------- */
app.post('/api/auth/register', authLimit, async (req, res) => {
  const username = clean(req.body.username, 24), email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password ?? '');
  if (!/^[\p{L}\p{N}_.-]{3,24}$/u.test(username)) return bad(res, 'Usuario: de 3 a 24 caracteres (letras, números, _ . -).');
  if (!EMAIL.test(email)) return bad(res, 'Correo no válido.');
  if (password.length < 8 || Buffer.byteLength(password) > 72) return bad(res, 'La contraseña debe tener entre 8 y 72 caracteres.');
  try {
    const { rows } = await q('INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id,username', [username, email, await bcrypt.hash(password, 12)]);
    await startSession(res, rows[0].id);
    res.status(201).json({ user: { username: rows[0].username } });
  } catch (e) {
    if (e.code === '23505') return bad(res, e.constraint === 'users_username_uq' ? 'Ese usuario ya existe.' : 'Ese correo ya está registrado.', 409);
    throw e;
  }
});
app.post('/api/auth/login', authLimit, async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase(), password = String(req.body.password ?? '');
  const { rows } = await q('SELECT id,username,password_hash FROM users WHERE lower(email)=$1', [email]);
  const ok = await bcrypt.compare(password, rows[0]?.password_hash || DUMMY);
  if (!rows[0] || !ok) return bad(res, 'Correo o contraseña incorrectos.', 401);
  await startSession(res, rows[0].id);
  res.json({ user: { username: rows[0].username } });
});
app.post('/api/auth/logout', async (req, res) => {
  if (req.cookies.sid) await q('DELETE FROM sessions WHERE token_hash=$1', [sha(req.cookies.sid)]);
  res.clearCookie('sid'); res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json({ user: { username: req.user.username, email: req.user.email } }));

/* ---------- rutinas ---------- */
app.get('/api/routines', auth, async (req, res) => {
  const { rows } = await q(`SELECT r.id, r.name, r.day_of_week AS day,
      json_agg(json_build_object('id',re.id,'name',e.name,'sets',re.sets,'reps',re.reps,'weight_kg',re.weight_kg) ORDER BY re.position) AS exercises
    FROM routines r JOIN routine_exercises re ON re.routine_id=r.id JOIN exercises e ON e.id=re.exercise_id
    WHERE r.user_id=$1 GROUP BY r.id ORDER BY r.created_at`, [req.user.id]);
  res.json({ routines: rows });
});
app.post('/api/routines', auth, async (req, res) => {
  const name = clean(req.body.name, 40), day = Number(req.body.day ?? 0), ex = req.body.exercises;
  if (!name) return bad(res, 'Pon un nombre a la rutina.');
  if (!Number.isInteger(day) || day < 0 || day > 7) return bad(res, 'Día no válido.');
  if (!Array.isArray(ex) || !ex.length || ex.length > 30) return bad(res, 'Agrega entre 1 y 30 ejercicios.');
  const items = [];
  for (const e of ex) {
    const n = clean(e?.name, 60), sets = Number(e?.sets), reps = Number(e?.reps), kg = e?.weight_kg == null ? null : Number(e.weight_kg);
    if (!n || !Number.isInteger(sets) || sets < 1 || sets > 99 || !Number.isInteger(reps) || reps < 1 || reps > 999 || (kg !== null && !(kg >= 0 && kg <= 9999)))
      return bad(res, 'Revisa los ejercicios: nombre, series (1-99), repeticiones (1-999) y peso opcional.');
    items.push({ n, sets, reps, kg });
  }
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows: [r] } = await c.query('INSERT INTO routines(user_id,name,day_of_week) VALUES($1,$2,$3) RETURNING id', [req.user.id, name, day]);
    for (const [i, it] of items.entries()) {
      await c.query('INSERT INTO exercises(name) VALUES($1) ON CONFLICT DO NOTHING', [it.n]);
      const { rows: [x] } = await c.query('SELECT id FROM exercises WHERE lower(name)=lower($1)', [it.n]);
      await c.query('INSERT INTO routine_exercises(routine_id,exercise_id,position,sets,reps,weight_kg) VALUES($1,$2,$3,$4,$5,$6)', [r.id, x.id, i + 1, it.sets, it.reps, it.kg]);
    }
    await c.query('COMMIT'); res.status(201).json({ id: r.id });
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
});
app.delete('/api/routines/:id', auth, async (req, res) => {
  const r = await q('DELETE FROM routines WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  r.rowCount ? res.json({ ok: true }) : bad(res, 'No encontrado', 404);
});

/* ---------- registro de ejercicios hechos ---------- */
app.get('/api/logs', auth, async (req, res) => {
  const date = isDate(req.query.date) ? req.query.date : new Date().toISOString().slice(0, 10);
  const base = 'FROM workout_logs wl JOIN routine_exercises re ON re.id=wl.routine_exercise_id JOIN routines r ON r.id=re.routine_id WHERE r.user_id=$1';
  const [done, dates, total] = await Promise.all([
    q(`SELECT wl.routine_exercise_id AS id ${base} AND wl.log_date=$2`, [req.user.id, date]),
    q(`SELECT DISTINCT wl.log_date::text AS d ${base} AND wl.log_date >= $2::date - 400 ORDER BY d`, [req.user.id, date]),
    q(`SELECT count(*)::int AS n ${base}`, [req.user.id])]);
  res.json({ done: done.rows.map(r => r.id), dates: dates.rows.map(r => r.d), total: total.rows[0].n });
});
app.post('/api/logs/toggle', auth, async (req, res) => {
  const { routine_exercise_id: id, date } = req.body;
  if (!UUID.test(id) || !isDate(date)) return bad(res, 'Datos no válidos.');
  const own = await q('SELECT 1 FROM routine_exercises re JOIN routines r ON r.id=re.routine_id WHERE re.id=$1 AND r.user_id=$2', [id, req.user.id]);
  if (!own.rowCount) return bad(res, 'No encontrado', 404);
  const del = await q('DELETE FROM workout_logs WHERE routine_exercise_id=$1 AND log_date=$2', [id, date]);
  if (!del.rowCount) await q('INSERT INTO workout_logs(routine_exercise_id,log_date) VALUES($1,$2) ON CONFLICT DO NOTHING', [id, date]);
  res.json({ done: !del.rowCount });
});

/* ---------- peso corporal ---------- */
app.get('/api/weights', auth, async (req, res) => {
  const { rows } = await q('SELECT log_date::text AS d, kg::float8 AS kg FROM weight_logs WHERE user_id=$1 ORDER BY log_date', [req.user.id]);
  res.json({ weights: rows });
});
app.post('/api/weights', auth, async (req, res) => {
  const kg = Math.round(Number(req.body.kg) * 10) / 10, date = req.body.date;
  if (!(kg >= 20 && kg <= 400) || !isDate(date)) return bad(res, 'Peso o fecha no válidos.');
  await q('INSERT INTO weight_logs(user_id,log_date,kg) VALUES($1,$2,$3) ON CONFLICT (user_id,log_date) DO UPDATE SET kg=EXCLUDED.kg', [req.user.id, date, kg]);
  res.json({ ok: true });
});

/* ---------- comunidad ---------- */
app.get('/api/posts', auth, async (req, res) => {
  const type = ['Tip', 'Pregunta'].includes(req.query.type) ? req.query.type : null;
  const term = clean(req.query.q, 60).replace(/[\\%_]/g, '\\$&') || null;
  const { rows: posts } = await q(`SELECT p.id, p.type, p.title, p.body, p.created_at, u.username AS author, p.user_id=$1 AS mine,
      (SELECT count(*)::int FROM post_likes l WHERE l.post_id=p.id) AS likes,
      EXISTS(SELECT 1 FROM post_likes l WHERE l.post_id=p.id AND l.user_id=$1) AS liked
    FROM posts p JOIN users u ON u.id=p.user_id
    WHERE ($2::text IS NULL OR p.type=$2) AND ($3::text IS NULL OR p.title ILIKE '%'||$3||'%' OR p.body ILIKE '%'||$3||'%')
    ORDER BY p.created_at DESC LIMIT 100`, [req.user.id, type, term]);
  const { rows: cs } = posts.length ? await q(`SELECT c.id, c.post_id, c.body, c.created_at, u.username AS author, c.user_id=$2 AS mine
      FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id = ANY($1::uuid[]) ORDER BY c.created_at`, [posts.map(p => p.id), req.user.id]) : { rows: [] };
  res.json({ posts: posts.map(p => ({ ...p, comments: cs.filter(c => c.post_id === p.id) })) });
});
app.post('/api/posts', auth, async (req, res) => {
  const type = req.body.type, title = clean(req.body.title, 80), body = clean(req.body.body, 1500);
  if (!['Tip', 'Pregunta'].includes(type) || !title || !body) return bad(res, 'Completa el tipo, el título y el texto.');
  const { rows } = await q('INSERT INTO posts(user_id,type,title,body) VALUES($1,$2,$3,$4) RETURNING id', [req.user.id, type, title, body]);
  res.status(201).json({ id: rows[0].id });
});
app.delete('/api/posts/:id', auth, async (req, res) => {
  const r = await q('DELETE FROM posts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  r.rowCount ? res.json({ ok: true }) : bad(res, 'No encontrado', 404);
});
app.post('/api/posts/:id/like', auth, async (req, res) => {
  const del = await q('DELETE FROM post_likes WHERE post_id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!del.rowCount) {
    try { await q('INSERT INTO post_likes(post_id,user_id) VALUES($1,$2)', [req.params.id, req.user.id]); }
    catch (e) { if (e.code === '23503') return bad(res, 'No encontrado', 404); throw e; }
  }
  res.json({ liked: !del.rowCount });
});
app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const body = clean(req.body.body, 500);
  if (!body) return bad(res, 'Escribe un comentario.');
  try { const { rows } = await q('INSERT INTO comments(post_id,user_id,body) VALUES($1,$2,$3) RETURNING id', [req.params.id, req.user.id, body]); res.status(201).json({ id: rows[0].id }); }
  catch (e) { if (e.code === '23503') return bad(res, 'No encontrado', 404); throw e; }
});
app.delete('/api/comments/:id', auth, async (req, res) => {
  const r = await q('DELETE FROM comments WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  r.rowCount ? res.json({ ok: true }) : bad(res, 'No encontrado', 404);
});

app.use('/api', (_req, res) => bad(res, 'Ruta no encontrada', 404));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Error del servidor' }); });
app.listen(process.env.PORT || 3000, () => console.log('El consejo fitness en http://localhost:' + (process.env.PORT || 3000)));
