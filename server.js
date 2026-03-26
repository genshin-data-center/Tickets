'use strict';

// ══════════════════════════════════════════════════════════════════
//  server.js — Ticket Dashboard
//  Hosted on Vercel — Database on Supabase (PostgreSQL)
//  Auth: Discord OAuth2 (مشرف role or Administrator only)
// ══════════════════════════════════════════════════════════════════

const express       = require('express');
const session       = require('express-session');
const pgSession     = require('connect-pg-simple')(session);
const { Pool }      = require('pg');
const fetch         = require('node-fetch');
const path          = require('path');

const app = express();

const PORT                  = process.env.PORT || 3000;
const DATABASE_URL          = process.env.DATABASE_URL;
const SESSION_SECRET        = process.env.SESSION_SECRET;
const DISCORD_CLIENT_ID     = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_GUILD_ID      = process.env.DISCORD_GUILD_ID;
const ALLOWED_ROLE_IDS      = (process.env.ALLOWED_ROLE_IDS || '').split(',').filter(Boolean);
const REDIRECT_URI          = process.env.REDIRECT_URI;
const INTERNAL_API_KEY      = process.env.INTERNAL_API_KEY;

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 5000,
});

async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS tickets (
            id               SERIAL PRIMARY KEY,
            ticket_id        INTEGER NOT NULL,
            guild_id         TEXT NOT NULL,
            category         TEXT,
            opened_by_id     TEXT NOT NULL,
            opened_by_name   TEXT,
            opened_by_avatar TEXT,
            claimed_by_id    TEXT,
            claimed_by_name  TEXT,
            closed_by_id     TEXT,
            closed_by_name   TEXT,
            close_reason     TEXT,
            opened_at        TIMESTAMPTZ,
            closed_at        TIMESTAMPTZ DEFAULT NOW(),
            category_role_id TEXT,
            messages         JSONB DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS session (
            sid    TEXT PRIMARY KEY,
            sess   JSONB NOT NULL,
            expire TIMESTAMPTZ NOT NULL
        );
    `);
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
    secret:            SESSION_SECRET || 'fallback',
    resave:            false,
    saveUninitialized: false,
    cookie: { maxAge: 86400000 * 7, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' },
}));

function requireAuth(req, res, next) {
    if (!req.session?.user) return res.redirect('/login');
    next();
}

async function checkDiscordAccess(accessToken) {
    try {
        const r = await fetch(
            `https://discord.com/api/v10/users/@me/guilds/${DISCORD_GUILD_ID}/member`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        if (!r.ok) return false;
        const member  = await r.json();
        const isAdmin = (BigInt(member.permissions || '0') & BigInt(0x8)) === BigInt(0x8);
        const hasRole = ALLOWED_ROLE_IDS.some(id => (member.roles || []).includes(id));
        return isAdmin || hasRole;
    } catch { return false; }
}

// ── Bot API endpoint ────────────────────────────────────────────
app.post('/api/ticket', async (req, res) => {
    if (req.headers['x-api-key'] !== INTERNAL_API_KEY)
        return res.status(403).json({ error: 'Forbidden' });
    const { ticketId, guildId, category, categoryRoleId, openedById, openedByName,
            openedByAvatar, claimedById, claimedByName, closedById, closedByName,
            closeReason, openedAt, messages } = req.body;
    try {
        await initDB();
        await pool.query(
            `INSERT INTO tickets (ticket_id,guild_id,category,opened_by_id,opened_by_name,
             opened_by_avatar,claimed_by_id,claimed_by_name,closed_by_id,closed_by_name,
             close_reason,opened_at,category_role_id,messages)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
            [ticketId, guildId, category||null, openedById, openedByName||null,
             openedByAvatar||null, claimedById||null, claimedByName||null,
             closedById, closedByName||null, closeReason||null, new Date(openedAt),
             categoryRoleId||null, JSON.stringify(messages||[])]
        );
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Auth ────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    const msgs = { noaccess: 'ليس لديك صلاحية للوصول. يجب أن تكون مشرفاً في السيرفر.', token: 'فشل التحقق من Discord.', error: 'حدث خطأ.' };
    const err  = msgs[req.query.err] || '';
    res.send(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>تسجيل الدخول</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;600&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0b0d0f;color:#e3e5e8;font-family:'IBM Plex Sans Arabic',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#111418;border:1px solid #1e2530;border-radius:16px;padding:48px 40px;text-align:center;width:360px}.logo{font-size:44px;margin-bottom:16px}h1{font-size:22px;font-weight:600;margin-bottom:6px}p{color:#72767d;font-size:14px;margin-bottom:28px}.btn{display:inline-flex;align-items:center;gap:10px;background:#5865F2;color:white;border:none;border-radius:10px;padding:13px 28px;font-family:inherit;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;transition:background 0.15s}.btn:hover{background:#4752c4}.err{background:rgba(237,66,69,.15);border:1px solid rgba(237,66,69,.3);color:#ed4245;border-radius:8px;padding:10px 16px;font-size:13px;margin-bottom:20px}</style>
</head><body><div class="card"><div class="logo">🎫</div><h1>لوحة التذاكر</h1><p>سجّل دخولك عبر Discord للمتابعة</p>
${err ? `<div class="err">${err}</div>` : ''}
<a class="btn" href="/auth/start">تسجيل الدخول عبر Discord</a></div></body></html>`);
});

app.get('/auth/start', (req, res) => {
    const p = new URLSearchParams({ client_id: DISCORD_CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code', scope: 'identify guilds.members.read' });
    res.redirect(`https://discord.com/api/oauth2/authorize?${p}`);
});

app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/login?err=token');
    try {
        const t = await (await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI }),
        })).json();
        if (!t.access_token) return res.redirect('/login?err=token');
        const user    = await (await fetch('https://discord.com/api/v10/users/@me', { headers: { Authorization: `Bearer ${t.access_token}` } })).json();
        const allowed = await checkDiscordAccess(t.access_token);
        if (!allowed) return res.redirect('/login?err=noaccess');
        req.session.user = { id: user.id, username: user.username, avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : `https://cdn.discordapp.com/embed/avatars/0.png` };
        req.session.save(() => res.redirect('/'));
    } catch { res.redirect('/login?err=error'); }
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// ── Dashboard ───────────────────────────────────────────────────
app.get('/', requireAuth, async (req, res) => {
    try {
        await initDB();
        const page=Math.max(1,parseInt(req.query.page)||1), limit=20, offset=(page-1)*limit;
        const search=req.query.q||'', category=req.query.cat||'';
        let where='WHERE guild_id=$1'; const params=[DISCORD_GUILD_ID]; let pi=2;
        if (search) { where+=` AND (opened_by_name ILIKE $${pi} OR ticket_id::text=$${pi+1})`; params.push(`%${search}%`,search); pi+=2; }
        if (category) { where+=` AND category=$${pi}`; params.push(category); pi++; }
        const total    = parseInt((await pool.query(`SELECT COUNT(*) FROM tickets ${where}`,params)).rows[0].count);
        const tickets  = (await pool.query(`SELECT id,ticket_id,category,opened_by_name,opened_by_avatar,claimed_by_name,closed_by_name,close_reason,opened_at,closed_at FROM tickets ${where} ORDER BY closed_at DESC LIMIT $${pi} OFFSET $${pi+1}`,[...params,limit,offset])).rows;
        const categories=(await pool.query(`SELECT DISTINCT category FROM tickets WHERE guild_id=$1 AND category IS NOT NULL ORDER BY category`,[DISCORD_GUILD_ID])).rows.map(r=>r.category);
        res.render('index',{user:req.session.user,tickets,total,page,pages:Math.ceil(total/limit),search,category,categories});
    } catch(e){res.status(500).send('Error: '+e.message);}
});

app.get('/ticket/:id', requireAuth, async (req, res) => {
    try {
        await initDB();
        const r = await pool.query('SELECT * FROM tickets WHERE id=$1 AND guild_id=$2',[req.params.id,DISCORD_GUILD_ID]);
        if (!r.rows.length) return res.status(404).render('404',{user:req.session.user});
        res.render('ticket',{ticket:r.rows[0],user:req.session.user});
    } catch(e){res.status(500).send('Error: '+e.message);}
});

if (require.main === module) {
    initDB().then(()=>app.listen(PORT,()=>console.log(`🚀 Port ${PORT}`))).catch(console.error);
}

module.exports = app;
