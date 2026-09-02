require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── BANCO ───────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ─── EMAIL ───────────────────────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

async function enviarEmail(para, assunto, html) {
  try {
    await mailer.sendMail({ from: `"ALMARE" <${process.env.SMTP_USER}>`, to: para, subject: assunto, html });
  } catch (e) { console.error('Erro email:', e.message); }
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'circulo-almare-secret-2026';
const ADMIN_SENHA = process.env.ADMIN_SENHA || 'admin123';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

function gerarToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authMembro(req, res, next) {
  const token = req.cookies.circulo_token;
  if (!token) return res.redirect('/login');
  try {
    req.membro = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.clearCookie('circulo_token'); return res.redirect('/login'); }
}

function authAdmin(req, res, next) {
  const token = req.cookies.circulo_admin;
  if (!token) return res.redirect('/admin/login');
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.clearCookie('circulo_admin'); return res.redirect('/admin/login'); }
}

// ─── CSS GLOBAL ───────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;500;600&family=Inter:wght@300;400;500&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0a0a; --surface: #111111; --border: #222; --border-light: #2a2a2a;
    --gold: #c9a96e; --gold-light: #e8d5b0; --text: #e8e8e8; --muted: #666;
    --danger: #c0392b; --success: #2ecc71;
  }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; font-size: 14px; min-height: 100vh; }
  h1,h2,h3 { font-family: 'Cormorant Garamond', serif; font-weight: 400; letter-spacing: 0.05em; }
  a { color: var(--gold); text-decoration: none; }
  a:hover { color: var(--gold-light); }
  .container { max-width: 960px; margin: 0 auto; padding: 0 24px; }
  .container-sm { max-width: 480px; margin: 0 auto; padding: 0 24px; }
  .logo { font-family: 'Cormorant Garamond', serif; font-size: 22px; letter-spacing: 0.3em; color: var(--gold); text-transform: uppercase; }
  .logo-sub { font-size: 10px; letter-spacing: 0.5em; color: var(--muted); text-transform: uppercase; margin-top: 2px; }
  header { padding: 24px 0; border-bottom: 1px solid var(--border); margin-bottom: 40px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 32px; }
  .field { margin-bottom: 20px; }
  .field label { display: block; font-size: 11px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
  .field input, .field textarea, .field select { width: 100%; background: #0d0d0d; border: 1px solid var(--border); color: var(--text); padding: 12px 14px; border-radius: 3px; font-family: 'Inter', sans-serif; font-size: 14px; outline: none; transition: border .2s; }
  .field input:focus, .field textarea:focus, .field select:focus { border-color: var(--gold); }
  .field textarea { resize: vertical; min-height: 80px; }
  .btn { display: inline-block; padding: 13px 28px; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase; font-family: 'Inter', sans-serif; cursor: pointer; border: none; border-radius: 3px; transition: all .2s; }
  .btn-primary { background: var(--gold); color: #000; font-weight: 500; }
  .btn-primary:hover { background: var(--gold-light); }
  .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
  .btn-outline:hover { border-color: var(--gold); color: var(--gold); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-full { width: 100%; text-align: center; }
  .badge { display: inline-block; padding: 3px 10px; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; border-radius: 20px; }
  .badge-gold { background: rgba(201,169,110,0.15); color: var(--gold); border: 1px solid rgba(201,169,110,0.3); }
  .badge-muted { background: rgba(255,255,255,0.05); color: var(--muted); border: 1px solid var(--border); }
  .badge-success { background: rgba(46,204,113,0.1); color: var(--success); border: 1px solid rgba(46,204,113,0.2); }
  .badge-pending { background: rgba(255,180,0,0.1); color: #f0a500; border: 1px solid rgba(255,180,0,0.2); }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
  .stat-box { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 20px; text-align: center; }
  .stat-box .num { font-family: 'Cormorant Garamond', serif; font-size: 36px; color: var(--gold); }
  .stat-box .label { font-size: 10px; letter-spacing: 0.2em; text-transform: uppercase; color: var(--muted); margin-top: 4px; }
  .divider { border: none; border-top: 1px solid var(--border); margin: 32px 0; }
  .msg-erro { background: rgba(192,57,43,0.1); border: 1px solid rgba(192,57,43,0.3); color: #e74c3c; padding: 12px 16px; border-radius: 3px; margin-bottom: 20px; font-size: 13px; }
  .msg-ok { background: rgba(46,204,113,0.1); border: 1px solid rgba(46,204,113,0.3); color: var(--success); padding: 12px 16px; border-radius: 3px; margin-bottom: 20px; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 10px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--muted); padding: 10px 14px; border-bottom: 1px solid var(--border); font-weight: 400; }
  td { padding: 14px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .nav-bar { display: flex; gap: 8px; margin-bottom: 32px; flex-wrap: wrap; }
  .nav-link { padding: 8px 16px; font-size: 11px; letter-spacing: 0.15em; text-transform: uppercase; color: var(--muted); border: 1px solid var(--border); border-radius: 3px; transition: all .2s; cursor: pointer; }
  .nav-link:hover, .nav-link.ativo { color: var(--gold); border-color: var(--gold); }
  .funcao-card { border: 1px solid var(--border); border-radius: 4px; padding: 20px; cursor: pointer; transition: all .2s; }
  .funcao-card:hover { border-color: var(--gold); }
  .funcao-card.selecionado { border-color: var(--gold); background: rgba(201,169,110,0.05); }
  .funcao-card input[type=checkbox] { display: none; }
  .funcao-card .funcao-nome { font-family: 'Cormorant Garamond', serif; font-size: 18px; color: var(--gold); margin-bottom: 6px; }
  .funcao-card .funcao-desc { font-size: 12px; color: var(--muted); line-height: 1.6; }
  @media(max-width:600px) { .grid-2,.grid-3 { grid-template-columns: 1fr; } }
`;

function html(titulo, corpo, navLogado = false) {
  const nav = navLogado ? `
    <div style="display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:12px;">
      <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Portal</a>
      <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Obras</a>
      <a href="/meu-impacto" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Impacto</a>
      <a href="/sugestoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Voz</a>
      <a href="/logout" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--danger);">Sair</a>
    </div>` : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${titulo} — Círculo ALMARE</title><style>${CSS}</style></head>
  <body><div class="container">
    <header>
      <div class="logo">ALMARE</div>
      <div class="logo-sub">Círculo</div>
      ${nav}
    </header>
    ${corpo}
  </div></body></html>`;
}

// ════════════════════════════════════════════════════════════════
// ROTAS PÚBLICAS
// ════════════════════════════════════════════════════════════════

// ─── HOME: redireciona pro portal se logado, ou pro convite ───────────────────
app.get('/', (req, res) => {
  const token = req.cookies.circulo_token;
  if (token) { try { jwt.verify(token, JWT_SECRET); return res.redirect('/portal'); } catch {} }
  res.redirect('/convite');
});

// ─── PÁGINA DE CONVITE ────────────────────────────────────────────────────────
app.get('/convite', (req, res) => res.redirect('/convite/geral'));

app.get('/convite/:codigo', async (req, res) => {
  const { codigo } = req.params;
  let conviteId = null;
  let nomeIndicador = '';

  if (codigo !== 'geral') {
    try {
      const r = await pool.query(
        `SELECT cc.id, cm.nome FROM circulo_convites cc
         JOIN circulo_membros cm ON cm.id = cc.membro_id
         WHERE cc.codigo = $1 AND cc.ativo = true`, [codigo]
      );
      if (r.rows.length) { conviteId = r.rows[0].id; nomeIndicador = r.rows[0].nome; }
    } catch {}
  }

  const indicadorHtml = nomeIndicador
    ? `<p style="font-size:12px;color:var(--gold);letter-spacing:.1em;margin-bottom:24px;">Convite de <strong>${nomeIndicador}</strong></p>` : '';

  res.send(html('Faça parte', `
    <div class="container-sm" style="padding-top:20px;">
      <h1 style="font-size:38px;margin-bottom:8px;">Uma obra não é uma compra.</h1>
      <h1 style="font-size:38px;color:var(--gold);margin-bottom:32px;">É uma escolha de permanência.</h1>
      <p style="color:var(--muted);line-height:1.8;margin-bottom:16px;">
        A ALMARE reúne obras autorais de edição limitada — criadas para espaços que entendem que a arte não decora. Transforma.
      </p>
      <p style="color:var(--muted);line-height:1.8;margin-bottom:40px;">
        O Círculo ALMARE é a comunidade de quem carrega essa proposta adiante. Não é um programa. É pertencimento.
      </p>
      <hr class="divider">
      <h2 style="font-size:24px;margin-bottom:24px;">Quero fazer parte</h2>
      ${indicadorHtml}
      <form method="POST" action="/candidatura">
        <input type="hidden" name="convite_id" value="${conviteId || ''}">
        <div class="field"><label>Nome completo</label><input name="nome" required placeholder="Seu nome"></div>
        <div class="field"><label>E-mail</label><input name="email" type="email" required placeholder="seu@email.com"></div>
        <div class="field"><label>Profissão</label><input name="profissao" placeholder="Arquiteto, designer, curador..."></div>
        <div class="field"><label>Como você conheceu a ALMARE? <span style="color:var(--muted)">(opcional)</span></label>
          <textarea name="como_conheceu" placeholder="Uma linha é suficiente"></textarea>
        </div>
        <button type="submit" class="btn btn-primary btn-full">Solicitar entrada no Círculo</button>
      </form>
    </div>
  `));
});

// ─── ENVIO DE CANDIDATURA ─────────────────────────────────────────────────────
app.post('/candidatura', async (req, res) => {
  const { nome, email, profissao, como_conheceu, convite_id } = req.body;
  try {
    // verifica se já existe candidatura pendente ou membro com esse email
    const existe = await pool.query(
      `SELECT id FROM circulo_candidatos WHERE email = $1
       UNION SELECT id FROM circulo_membros WHERE email = $1`, [email]
    );
    if (existe.rows.length) {
      return res.send(html('Solicitação', `
        <div class="container-sm"><div class="msg-erro">Este e-mail já tem uma solicitação ou cadastro no Círculo.</div>
        <a href="/login" class="btn btn-outline">Entrar no portal</a></div>`));
    }

    await pool.query(
      `INSERT INTO circulo_candidatos (nome, email, como_conheceu, convite_id)
       VALUES ($1, $2, $3, $4)`,
      [nome, email, como_conheceu || null, convite_id || null]
    );

    // registra uso do convite
    if (convite_id) {
      await pool.query(`UPDATE circulo_convites SET usos = usos + 1 WHERE id = $1`, [convite_id]);
    }

    res.send(html('Solicitação enviada', `
      <div class="container-sm" style="text-align:center;padding-top:40px;">
        <div style="font-size:40px;margin-bottom:24px;">✦</div>
        <h2 style="font-size:28px;margin-bottom:16px;">Sua solicitação foi recebida.</h2>
        <p style="color:var(--muted);line-height:1.8;">Em breve você receberá um e-mail com os próximos passos.<br>
        O Círculo é pequeno por intenção.</p>
      </div>
    `));
  } catch (e) {
    console.error(e);
    res.send(html('Erro', `<div class="container-sm"><div class="msg-erro">Erro ao enviar. Tente novamente.</div></div>`));
  }
});

// ─── CADASTRO (link enviado por email após aprovação) ─────────────────────────
app.get('/cadastro/:token', async (req, res) => {
  try {
    const payload = jwt.verify(req.params.token, JWT_SECRET);
    if (payload.tipo !== 'convite_aprovado') throw new Error();
    res.send(html('Criar conta', `
      <div class="container-sm">
        <h2 style="font-size:28px;margin-bottom:8px;">Bem-vindo ao Círculo.</h2>
        <p style="color:var(--muted);margin-bottom:32px;">Crie sua senha para acessar o portal.</p>
        <form method="POST" action="/cadastro">
          <input type="hidden" name="token" value="${req.params.token}">
          <div class="field"><label>E-mail</label><input value="${payload.email}" disabled style="opacity:.5"></div>
          <div class="field"><label>Crie uma senha</label><input type="password" name="senha" required minlength="8" placeholder="Mínimo 8 caracteres"></div>
          <div class="field"><label>Confirme a senha</label><input type="password" name="senha2" required placeholder="Repita a senha"></div>
          <button type="submit" class="btn btn-primary btn-full">Criar minha conta</button>
        </form>
      </div>
    `));
  } catch {
    res.send(html('Link inválido', `<div class="container-sm"><div class="msg-erro">Este link expirou ou é inválido. Solicite um novo acesso.</div></div>`));
  }
});

app.post('/cadastro', async (req, res) => {
  const { token, senha, senha2 } = req.body;
  if (senha !== senha2) {
    return res.send(html('Cadastro', `<div class="container-sm"><div class="msg-erro">As senhas não coincidem.</div><a href="javascript:history.back()" class="btn btn-outline">Voltar</a></div>`));
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const candidato = await pool.query(`SELECT * FROM circulo_candidatos WHERE id = $1`, [payload.candidato_id]);
    if (!candidato.rows.length) throw new Error('Candidato não encontrado');
    const c = candidato.rows[0];

    const hash = await bcrypt.hash(senha, 12);
    const total = await pool.query(`SELECT COUNT(*) FROM circulo_membros`);
    const num = String(parseInt(total.rows[0].count) + 1).padStart(4, '0');
    const codigo = `ALM-${num}`;

    const { rows } = await pool.query(
      `INSERT INTO circulo_membros (nome, email, senha_hash, profissao, status, aprovado_em, codigo_membro)
       VALUES ($1, $2, $3, $4, 'ativo', NOW(), $5) RETURNING id`,
      [c.nome, c.email, hash, c.profissao || '', codigo]
    );
    const membroId = rows[0].id;

    // cria saldo zerado
    await pool.query(`INSERT INTO circulo_saldo_credito (membro_id) VALUES ($1)`, [membroId]);
    // cria link de convite único
    const codigoConvite = crypto.randomBytes(6).toString('hex');
    await pool.query(`INSERT INTO circulo_convites (membro_id, codigo) VALUES ($1, $2)`, [membroId, codigoConvite]);
    // cria link de aquisição único
    const codigoAquis = crypto.randomBytes(6).toString('hex');
    await pool.query(`INSERT INTO circulo_links_aquisicao (membro_id, codigo) VALUES ($1, $2)`, [membroId, codigoAquis]);
    // registra evento no passaporte
    await pool.query(
      `INSERT INTO circulo_passaporte_eventos (membro_id, tipo, descricao) VALUES ($1, 'entrada', $2)`,
      [membroId, `${c.nome} entrou para o Círculo ALMARE`]
    );
    // atualiza candidato como aprovado
    await pool.query(`UPDATE circulo_candidatos SET status = 'aprovado' WHERE id = $1`, [payload.candidato_id]);

    const jwtToken = gerarToken({ id: membroId, nome: c.nome, email: c.email });
    res.cookie('circulo_token', jwtToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/onboarding');
  } catch (e) {
    console.error(e);
    res.send(html('Erro', `<div class="container-sm"><div class="msg-erro">Erro ao criar conta: ${e.message}</div></div>`));
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  res.send(html('Entrar', `
    <div class="container-sm">
      <h2 style="font-size:28px;margin-bottom:32px;">Círculo ALMARE</h2>
      ${req.query.erro ? `<div class="msg-erro">${req.query.erro}</div>` : ''}
      <form method="POST" action="/login">
        <div class="field"><label>E-mail</label><input name="email" type="email" required></div>
        <div class="field"><label>Senha</label><input name="senha" type="password" required></div>
        <button type="submit" class="btn btn-primary btn-full">Entrar</button>
      </form>
    </div>
  `));
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const { rows } = await pool.query(`SELECT * FROM circulo_membros WHERE email = $1`, [email]);
    if (!rows.length) return res.redirect('/login?erro=E-mail+ou+senha+inválidos');
    const m = rows[0];
    if (m.status !== 'ativo') return res.redirect('/login?erro=Conta+não+ativa.+Aguarde+aprovação.');
    const ok = await bcrypt.compare(senha, m.senha_hash);
    if (!ok) return res.redirect('/login?erro=E-mail+ou+senha+inválidos');
    const token = gerarToken({ id: m.id, nome: m.nome, email: m.email });
    res.cookie('circulo_token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/portal');
  } catch (e) {
    console.error(e);
    res.redirect('/login?erro=Erro+interno');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('circulo_token');
  res.redirect('/login');
});

// ════════════════════════════════════════════════════════════════
// ONBOARDING — escolha de funções
// ════════════════════════════════════════════════════════════════
app.get('/onboarding', authMembro, async (req, res) => {
  const funcoes = await pool.query(`SELECT * FROM circulo_funcoes ORDER BY id`);
  const cards = funcoes.rows.map(f => `
    <label class="funcao-card" id="card-${f.slug}" onclick="toggleCard('${f.slug}')">
      <input type="checkbox" name="funcoes" value="${f.id}" id="cb-${f.slug}">
      <div class="funcao-nome">${f.nome}</div>
      <div class="funcao-desc">${f.descricao}</div>
    </label>
  `).join('');

  res.send(html('Como quer participar', `
    <div class="container-sm">
      <h2 style="font-size:28px;margin-bottom:8px;">Como você quer participar?</h2>
      <p style="color:var(--muted);margin-bottom:32px;">Você pode escolher uma ou mais formas. Isso pode ser alterado depois.</p>
      <form method="POST" action="/onboarding">
        <div style="display:flex;flex-direction:column;gap:12px;margin-bottom:32px;">${cards}</div>
        <button type="submit" class="btn btn-primary btn-full">Entrar no Círculo</button>
      </form>
    </div>
    <script>
      function toggleCard(slug) {
        const cb = document.getElementById('cb-' + slug);
        const card = document.getElementById('card-' + slug);
        setTimeout(() => { card.classList.toggle('selecionado', cb.checked); }, 0);
      }
    </script>
  `));
});

app.post('/onboarding', authMembro, async (req, res) => {
  let funcoes = req.body.funcoes || [];
  if (!Array.isArray(funcoes)) funcoes = [funcoes];
  try {
    for (const fid of funcoes) {
      await pool.query(
        `INSERT INTO circulo_membro_funcoes (membro_id, funcao_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [req.membro.id, parseInt(fid)]
      );
    }
    res.redirect('/portal');
  } catch (e) {
    console.error(e);
    res.redirect('/portal');
  }
});

// ════════════════════════════════════════════════════════════════
// PORTAL DO MEMBRO
// ════════════════════════════════════════════════════════════════
app.get('/portal', authMembro, async (req, res) => {
  try {
    const resumo = await pool.query(`SELECT * FROM circulo_resumo_membro WHERE id = $1`, [req.membro.id]);
    const m = resumo.rows[0] || {};
    const funcoes = await pool.query(
      `SELECT f.nome FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id = mf.funcao_id
       WHERE mf.membro_id = $1 AND mf.ativo = true`, [req.membro.id]
    );
    const convite = await pool.query(`SELECT codigo FROM circulo_convites WHERE membro_id = $1 LIMIT 1`, [req.membro.id]);
    const linkConvite = convite.rows.length ? `${BASE_URL}/convite/${convite.rows[0].codigo}` : '';
    const eventos = await pool.query(
      `SELECT * FROM circulo_passaporte_eventos WHERE membro_id = $1 ORDER BY data_evento DESC LIMIT 10`,
      [req.membro.id]
    );

    const fnomes = funcoes.rows.map(f => `<span class="badge badge-gold">${f.nome}</span>`).join(' ');
    const dataEntrada = m.membro_desde ? new Date(m.membro_desde).toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }) : '';
    const eventosHtml = eventos.rows.map(e => `
      <div style="padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;color:var(--muted);">
        <span style="color:var(--text)">${e.descricao}</span>
        <span style="float:right;font-size:11px;">${new Date(e.data_evento).toLocaleDateString('pt-BR')}</span>
      </div>`).join('');

    res.send(html('Portal', `
      <div class="nav-bar">
        <a href="/portal" class="nav-link ativo">Passaporte</a>
        <a href="/catalogo" class="nav-link">Obras</a>
        <a href="/meu-impacto" class="nav-link">Impacto</a>
        <a href="/sugestoes" class="nav-link">Voz</a>
        <a href="/meu-convite" class="nav-link">Convidar</a>
      </div>

      <!-- IDENTIDADE -->
      <div class="card" style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
          <div>
            <h2 style="font-size:26px;margin-bottom:4px;">${m.nome || req.membro.nome}</h2>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">
              Membro desde ${dataEntrada} · ${m.codigo_membro || ''}
            </div>
            <div>${fnomes}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">Crédito disponível</div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:32px;color:var(--gold);">
              R$ ${parseFloat(m.credito_disponivel || 0).toFixed(2).replace('.',',')}
            </div>
          </div>
        </div>
      </div>

      <!-- ESTATÍSTICAS DO PASSAPORTE -->
      <div class="grid-3" style="margin-bottom:24px;">
        <div class="stat-box">
          <div class="num">${m.obras_que_encontraram_lar || 0}</div>
          <div class="label">Obras que encontraram lar</div>
        </div>
        <div class="stat-box">
          <div class="num">${m.total_indicacoes || 0}</div>
          <div class="label">Pessoas indicadas</div>
        </div>
        <div class="stat-box">
          <div class="num">${m.sugestoes_incorporadas || 0}</div>
          <div class="label">Sugestões incorporadas</div>
        </div>
      </div>

      <!-- HISTÓRICO DO PASSAPORTE -->
      <div class="card">
        <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Sua história no Círculo</h3>
        ${eventosHtml || '<p style="color:var(--muted);font-size:13px;">Nada registrado ainda.</p>'}
      </div>

      <!-- LINK DE CONVITE (discreto) -->
      ${linkConvite ? `
      <div style="margin-top:24px;padding:16px;border:1px solid var(--border);border-radius:4px;">
        <div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Seu link de convite</div>
        <div style="font-size:12px;color:var(--text);word-break:break-all;">${linkConvite}</div>
      </div>` : ''}
    `, true));
  } catch (e) {
    console.error(e);
    res.send(html('Erro', `<div class="msg-erro">Erro ao carregar portal: ${e.message}</div>`, true));
  }
});

// ─── CATÁLOGO DE OBRAS ────────────────────────────────────────────────────────
app.get('/catalogo', authMembro, async (req, res) => {
  try {
    const obras = await pool.query(
      `SELECT o.id, o.nome, o.conceito, o.status_curatorial,
              c.nome as colecao,
              COUNT(CASE WHEN t.status = 'disponivel' THEN 1 END) as disponiveis,
              o.tiragem_maxima
       FROM almare_obras o
       LEFT JOIN almare_fichas f ON f.obra_id = o.id
       LEFT JOIN colecoes c ON c.id = o.colecao_id
       LEFT JOIN almare_tiragem t ON t.obra_id = o.id
       WHERE o.status_curatorial = 'aprovada'
       GROUP BY o.id, o.nome, o.conceito, o.status_curatorial, c.nome, o.tiragem_maxima
       ORDER BY o.id DESC`
    );

    const cards = obras.rows.map(o => `
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;">
          <div>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${o.colecao || 'Sem coleção'}</div>
            <h3 style="font-size:20px;margin-bottom:8px;">${o.nome || 'Sem título'}</h3>
            <p style="font-size:13px;color:var(--muted);line-height:1.6;">${(o.conceito || '').substring(0, 140)}${(o.conceito || '').length > 140 ? '...' : ''}</p>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Tiragem</div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:22px;color:var(--gold);">${o.disponiveis}/${o.tiragem_maxima}</div>
          </div>
        </div>
      </div>
    `).join('');

    res.send(html('Catálogo', `
      <div class="nav-bar">
        <a href="/portal" class="nav-link">Passaporte</a>
        <a href="/catalogo" class="nav-link ativo">Obras</a>
        <a href="/meu-impacto" class="nav-link">Impacto</a>
        <a href="/sugestoes" class="nav-link">Voz</a>
        <a href="/meu-convite" class="nav-link">Convidar</a>
      </div>
      <h2 style="font-size:28px;margin-bottom:8px;">Catálogo ALMARE</h2>
      <p style="color:var(--muted);margin-bottom:32px;">${obras.rows.length} obras disponíveis para o Círculo.</p>
      ${cards || '<p style="color:var(--muted);">Nenhuma obra disponível no momento.</p>'}
    `, true));
  } catch (e) {
    console.error(e);
    res.send(html('Catálogo', `<div class="msg-erro">Erro ao carregar catálogo: ${e.message}</div>`, true));
  }
});

// ─── MEU IMPACTO ─────────────────────────────────────────────────────────────
app.get('/meu-impacto', authMembro, async (req, res) => {
  try {
    const trans = await pool.query(
      `SELECT t.*, o.nome as obra_nome FROM circulo_transacoes t
       LEFT JOIN almare_obras o ON o.id = t.obra_id
       WHERE t.membro_id = $1 ORDER BY t.criado_em DESC`, [req.membro.id]
    );
    const saldo = await pool.query(`SELECT * FROM circulo_saldo_credito WHERE membro_id = $1`, [req.membro.id]);
    const s = saldo.rows[0] || { saldo_disponivel: 0, saldo_total: 0 };

    const linhas = trans.rows.map(t => `
      <tr>
        <td>${t.obra_nome || `Obra #${t.obra_id}`}</td>
        <td>R$ ${parseFloat(t.valor_obra).toFixed(2).replace('.',',')}</td>
        <td><span class="badge ${t.modalidade === 'credito' ? 'badge-gold' : 'badge-muted'}">${t.modalidade === 'credito' ? 'Crédito' : 'Cashback'}</span></td>
        <td style="color:var(--gold);">R$ ${parseFloat(t.valor_beneficio).toFixed(2).replace('.',',')}</td>
        <td><span class="badge ${t.status === 'pago' ? 'badge-success' : 'badge-pending'}">${t.status}</span></td>
      </tr>`).join('');

    res.send(html('Impacto', `
      <div class="nav-bar">
        <a href="/portal" class="nav-link">Passaporte</a>
        <a href="/catalogo" class="nav-link">Obras</a>
        <a href="/meu-impacto" class="nav-link ativo">Impacto</a>
        <a href="/sugestoes" class="nav-link">Voz</a>
        <a href="/meu-convite" class="nav-link">Convidar</a>
      </div>
      <div class="grid-2" style="margin-bottom:32px;">
        <div class="stat-box">
          <div class="num">R$ ${parseFloat(s.saldo_disponivel).toFixed(2).replace('.',',')}</div>
          <div class="label">Crédito disponível para resgate</div>
        </div>
        <div class="stat-box">
          <div class="num">R$ ${parseFloat(s.saldo_total).toFixed(2).replace('.',',')}</div>
          <div class="label">Total acumulado histórico</div>
        </div>
      </div>
      <div class="card">
        <h3 style="font-size:18px;margin-bottom:20px;">Histórico de vendas</h3>
        ${trans.rows.length ? `
        <table>
          <thead><tr><th>Obra</th><th>Valor</th><th>Modalidade</th><th>Benefício</th><th>Status</th></tr></thead>
          <tbody>${linhas}</tbody>
        </table>` : '<p style="color:var(--muted);">Nenhuma venda registrada ainda.</p>'}
      </div>
    `, true));
  } catch (e) {
    console.error(e);
    res.send(html('Impacto', `<div class="msg-erro">Erro: ${e.message}</div>`, true));
  }
});

// ─── VOZ / SUGESTÕES ─────────────────────────────────────────────────────────
app.get('/sugestoes', authMembro, async (req, res) => {
  const lista = await pool.query(
    `SELECT * FROM circulo_sugestoes WHERE membro_id = $1 ORDER BY criado_em DESC`, [req.membro.id]
  );
  const itens = lista.rows.map(s => `
    <div style="padding:16px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span class="badge ${s.status === 'incorporada' ? 'badge-success' : s.status === 'em_analise' ? 'badge-pending' : 'badge-muted'}">${s.status}</span>
        <span style="font-size:11px;color:var(--muted);">${new Date(s.criado_em).toLocaleDateString('pt-BR')}</span>
      </div>
      <p style="font-size:13px;line-height:1.6;">${s.texto}</p>
      ${s.resposta ? `<p style="font-size:12px;color:var(--gold);margin-top:8px;font-style:italic;">↳ ${s.resposta}</p>` : ''}
    </div>`).join('');

  res.send(html('Voz', `
    <div class="nav-bar">
      <a href="/portal" class="nav-link">Passaporte</a>
      <a href="/catalogo" class="nav-link">Obras</a>
      <a href="/meu-impacto" class="nav-link">Impacto</a>
      <a href="/sugestoes" class="nav-link ativo">Voz</a>
      <a href="/meu-convite" class="nav-link">Convidar</a>
    </div>
    <h2 style="font-size:28px;margin-bottom:8px;">Sua voz no Círculo</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Sugira temas de coleção, formatos, ambientes. Anderson lê tudo.</p>
    <div class="card" style="margin-bottom:24px;">
      <form method="POST" action="/sugestoes">
        <div class="field"><label>Sua sugestão</label>
          <textarea name="texto" required placeholder="Uma ideia de coleção, formato, tema, ambiente..."></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Enviar</button>
      </form>
    </div>
    ${lista.rows.length ? `<div class="card"><h3 style="font-size:16px;margin-bottom:16px;">Suas sugestões anteriores</h3>${itens}</div>` : ''}
  `, true));
});

app.post('/sugestoes', authMembro, async (req, res) => {
  await pool.query(
    `INSERT INTO circulo_sugestoes (membro_id, texto) VALUES ($1, $2)`,
    [req.membro.id, req.body.texto]
  );
  res.redirect('/sugestoes');
});

// ─── CONVIDAR ─────────────────────────────────────────────────────────────────
app.get('/meu-convite', authMembro, async (req, res) => {
  const conv = await pool.query(`SELECT * FROM circulo_convites WHERE membro_id = $1 LIMIT 1`, [req.membro.id]);
  const c = conv.rows[0];
  const link = c ? `${BASE_URL}/convite/${c.codigo}` : '';

  res.send(html('Convidar', `
    <div class="nav-bar">
      <a href="/portal" class="nav-link">Passaporte</a>
      <a href="/catalogo" class="nav-link">Obras</a>
      <a href="/meu-impacto" class="nav-link">Impacto</a>
      <a href="/sugestoes" class="nav-link">Voz</a>
      <a href="/meu-convite" class="nav-link ativo">Convidar</a>
    </div>
    <h2 style="font-size:28px;margin-bottom:8px;">Seu link de convite</h2>
    <p style="color:var(--muted);margin-bottom:32px;">
      Compartilhe com quem você acredita que pertence ao Círculo.<br>
      A pessoa entra na lista de espera. Anderson aprova cada um individualmente.
    </p>
    <div class="card">
      <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Seu link pessoal de convite</div>
      <div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">
        ${link}
      </div>
      <button onclick="navigator.clipboard.writeText('${link}');this.textContent='Copiado ✓'" class="btn btn-outline">Copiar link</button>
      <div style="margin-top:24px;font-size:12px;color:var(--muted);">Usos: ${c ? c.usos : 0} pessoa(s) solicitou entrada pelo seu link</div>
    </div>
  `, true));
});

// ════════════════════════════════════════════════════════════════
// PAINEL ADMIN — Anderson
// ════════════════════════════════════════════════════════════════
app.get('/admin/login', (req, res) => {
  res.send(html('Admin', `
    <div class="container-sm">
      <h2 style="font-size:24px;margin-bottom:32px;">Painel Admin</h2>
      ${req.query.erro ? `<div class="msg-erro">${req.query.erro}</div>` : ''}
      <form method="POST" action="/admin/login">
        <div class="field"><label>Senha</label><input type="password" name="senha" required></div>
        <button type="submit" class="btn btn-primary btn-full">Entrar</button>
      </form>
    </div>
  `));
});

app.post('/admin/login', (req, res) => {
  if (req.body.senha !== ADMIN_SENHA) return res.redirect('/admin/login?erro=Senha+incorreta');
  const token = gerarToken({ admin: true });
  res.cookie('circulo_admin', token, { httpOnly: true, maxAge: 8 * 60 * 60 * 1000 });
  res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => { res.clearCookie('circulo_admin'); res.redirect('/admin/login'); });

app.get('/admin', authAdmin, async (req, res) => {
  const candidatos = await pool.query(`SELECT * FROM circulo_candidatos WHERE status = 'pendente' ORDER BY criado_em DESC`);
  const membros = await pool.query(`SELECT * FROM circulo_resumo_membro ORDER BY membro_desde DESC`);

  const linhaCand = candidatos.rows.map(c => `
    <tr>
      <td>${c.nome}</td>
      <td style="color:var(--muted)">${c.email}</td>
      <td style="color:var(--muted)">${c.como_conheceu || '—'}</td>
      <td style="color:var(--muted)">${new Date(c.criado_em).toLocaleDateString('pt-BR')}</td>
      <td>
        <form method="POST" action="/admin/candidatos/${c.id}/aprovar" style="display:inline">
          <button type="submit" class="btn btn-primary" style="padding:6px 14px;font-size:10px;">Aprovar</button>
        </form>
        <form method="POST" action="/admin/candidatos/${c.id}/recusar" style="display:inline;margin-left:6px">
          <button type="submit" class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Recusar</button>
        </form>
      </td>
    </tr>`).join('');

  const linhaMembros = membros.rows.map(m => `
    <tr>
      <td>${m.nome}</td>
      <td style="color:var(--muted)">${m.codigo_membro || '—'}</td>
      <td style="color:var(--muted)">${m.email}</td>
      <td>${m.total_funcoes} função(ões)</td>
      <td style="color:var(--gold);">R$ ${parseFloat(m.credito_disponivel).toFixed(2).replace('.',',')}</td>
      <td>${m.obras_que_encontraram_lar}</td>
      <td>${m.total_indicacoes}</td>
    </tr>`).join('');

  res.send(html('Admin', `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;">
      <h2 style="font-size:24px;">Painel do Círculo</h2>
      <a href="/admin/logout" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Sair</a>
    </div>
    <div class="grid-3" style="margin-bottom:32px;">
      <div class="stat-box"><div class="num">${candidatos.rows.length}</div><div class="label">Candidatos pendentes</div></div>
      <div class="stat-box"><div class="num">${membros.rows.length}</div><div class="label">Membros ativos</div></div>
      <div class="stat-box"><div class="num">${membros.rows.reduce((a,m)=>a+parseInt(m.obras_que_encontraram_lar||0),0)}</div><div class="label">Obras que encontraram lar</div></div>
    </div>

    ${candidatos.rows.length ? `
    <div class="card" style="margin-bottom:24px;">
      <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Candidatos pendentes</h3>
      <table><thead><tr><th>Nome</th><th>E-mail</th><th>Como conheceu</th><th>Data</th><th>Ação</th></tr></thead>
      <tbody>${linhaCand}</tbody></table>
    </div>` : ''}

    <div class="card">
      <h3 style="font-size:18px;margin-bottom:20px;">Membros do Círculo</h3>
      <table><thead><tr><th>Nome</th><th>Código</th><th>E-mail</th><th>Funções</th><th>Crédito</th><th>Obras</th><th>Indicações</th></tr></thead>
      <tbody>${linhaMembros || '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:24px;">Nenhum membro ainda</td></tr>'}</tbody>
      </table>
    </div>

    <div style="margin-top:16px;">
      <a href="/admin/sugestoes" class="btn btn-outline">Ver sugestões dos membros</a>
    </div>
  `));
});

// ─── APROVAR CANDIDATO ────────────────────────────────────────────────────────
app.post('/admin/candidatos/:id/aprovar', authAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`SELECT * FROM circulo_candidatos WHERE id = $1`, [id]);
    if (!rows.length) return res.redirect('/admin');
    const c = rows[0];

    const token = gerarToken({ tipo: 'convite_aprovado', candidato_id: c.id, email: c.email }, { expiresIn: '7d' });
    const link = `${BASE_URL}/cadastro/${token}`;

    await enviarEmail(c.email, 'Você foi convidado para o Círculo ALMARE', `
      <div style="background:#0a0a0a;color:#e8e8e8;padding:40px;font-family:Georgia,serif;">
        <h1 style="color:#c9a96e;font-size:28px;margin-bottom:24px;">Bem-vindo ao Círculo.</h1>
        <p style="line-height:1.8;margin-bottom:24px;">
          Sua solicitação foi aprovada. Você agora faz parte de algo que poucos acessam.
        </p>
        <a href="${link}" style="display:inline-block;background:#c9a96e;color:#000;padding:14px 32px;text-decoration:none;font-size:13px;letter-spacing:.15em;text-transform:uppercase;">
          Criar minha conta
        </a>
        <p style="margin-top:32px;font-size:12px;color:#666;">Este link expira em 7 dias.</p>
      </div>
    `);

    await pool.query(`UPDATE circulo_candidatos SET status = 'aprovado', respondido_em = NOW() WHERE id = $1`, [id]);
    res.redirect('/admin');
  } catch (e) {
    console.error(e);
    res.redirect('/admin');
  }
});

// ─── RECUSAR CANDIDATO ────────────────────────────────────────────────────────
app.post('/admin/candidatos/:id/recusar', authAdmin, async (req, res) => {
  await pool.query(`UPDATE circulo_candidatos SET status = 'recusado', respondido_em = NOW() WHERE id = $1`, [req.params.id]);
  res.redirect('/admin');
});

// ─── SUGESTÕES ADMIN ──────────────────────────────────────────────────────────
app.get('/admin/sugestoes', authAdmin, async (req, res) => {
  const lista = await pool.query(
    `SELECT s.*, m.nome as membro_nome FROM circulo_sugestoes s
     JOIN circulo_membros m ON m.id = s.membro_id
     ORDER BY s.status ASC, s.criado_em DESC`
  );
  const itens = lista.rows.map(s => `
    <div style="padding:20px;border:1px solid var(--border);border-radius:4px;margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
        <span style="font-size:12px;color:var(--gold);">${s.membro_nome}</span>
        <span class="badge ${s.status === 'incorporada' ? 'badge-success' : s.status === 'em_analise' ? 'badge-pending' : 'badge-muted'}">${s.status}</span>
      </div>
      <p style="font-size:13px;margin-bottom:12px;">${s.texto}</p>
      <form method="POST" action="/admin/sugestoes/${s.id}/responder" style="display:flex;gap:8px;flex-wrap:wrap;">
        <input name="resposta" placeholder="Resposta (opcional)" style="flex:1;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;">
        <select name="status" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;">
          <option value="aberta" ${s.status==='aberta'?'selected':''}>Aberta</option>
          <option value="em_analise" ${s.status==='em_analise'?'selected':''}>Em análise</option>
          <option value="incorporada" ${s.status==='incorporada'?'selected':''}>Incorporada</option>
          <option value="descartada" ${s.status==='descartada'?'selected':''}>Descartada</option>
        </select>
        <button type="submit" class="btn btn-primary" style="padding:8px 16px;">Salvar</button>
      </form>
    </div>`).join('');

  res.send(html('Sugestões', `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;">
      <h2 style="font-size:24px;">Sugestões dos membros</h2>
      <a href="/admin" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">← Voltar</a>
    </div>
    ${itens || '<p style="color:var(--muted);">Nenhuma sugestão ainda.</p>'}
  `));
});

app.post('/admin/sugestoes/:id/responder', authAdmin, async (req, res) => {
  const { resposta, status } = req.body;
  await pool.query(
    `UPDATE circulo_sugestoes SET status = $1, resposta = $2, respondido_em = NOW() WHERE id = $3`,
    [status, resposta || null, req.params.id]
  );
  if (status === 'incorporada') {
    const s = await pool.query(`SELECT * FROM circulo_sugestoes WHERE id = $1`, [req.params.id]);
    if (s.rows.length) {
      await pool.query(
        `INSERT INTO circulo_passaporte_eventos (membro_id, tipo, descricao) VALUES ($1, 'sugestao_incorporada', $2)`,
        [s.rows[0].membro_id, 'Sua sugestão foi incorporada à curadoria ALMARE']
      );
    }
  }
  res.redirect('/admin/sugestoes');
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Círculo ALMARE rodando na porta ${PORT}`));
