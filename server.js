// VERSAO-CLAUDE-XYZ789 — se voce ve este comentario no GitHub, o arquivo certo subiu
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'circulo-almare-secret-2026';
const ADMIN_SENHA = process.env.ADMIN_SENHA || 'admin123';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const BLING_CLIENT_ID = process.env.BLING_CLIENT_ID;
const BLING_CLIENT_SECRET = process.env.BLING_CLIENT_SECRET;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

function gerarToken(payload, opts) { return jwt.sign(payload, JWT_SECRET, opts || { expiresIn: '7d' }); }

function authMembro(req, res, next) {
  const token = req.cookies.circulo_token;
  if (!token) return res.redirect('/login');
  try { req.membro = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie('circulo_token'); return res.redirect('/login'); }
}

function authAdmin(req, res, next) {
  const token = req.cookies.circulo_admin;
  if (!token) return res.redirect('/admin/login');
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie('circulo_admin'); return res.redirect('/admin/login'); }
}

// ─── BLING ────────────────────────────────────────────────────────────────────
async function getBlingToken() {
  const r = await pool.query('SELECT * FROM almare_bling_config LIMIT 1');
  if (!r.rows.length) throw new Error('Token Bling não configurado');
  const config = r.rows[0];
  if (new Date(config.expira_em) <= new Date()) {
    const creds = Buffer.from(`${BLING_CLIENT_ID}:${BLING_CLIENT_SECRET}`).toString('base64');
    const resp = await fetch('https://www.bling.com.br/Api/v3/oauth/token', {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: config.refresh_token })
    });
    const data = await resp.json();
    if (!data.access_token) throw new Error('Erro ao renovar token Bling');
    await pool.query('UPDATE almare_bling_config SET access_token=$1, refresh_token=$2, expira_em=$3 WHERE id=1',
      [data.access_token, data.refresh_token, new Date(Date.now() + data.expires_in * 1000)]);
    return data.access_token;
  }
  return config.access_token;
}

async function buscarContatoBling(documento) {
  const token = await getBlingToken();
  const doc = documento.replace(/\D/g, '');
  const resp = await fetch(`https://api.bling.com.br/Api/v3/contatos?pesquisa=${doc}&limite=5`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const data = await resp.json();
  if (!data?.data?.length) return null;
  return data.data.find(c => {
    const cpf = (c.cpf || '').replace(/\D/g, '');
    const cnpj = (c.cnpj || '').replace(/\D/g, '');
    return cpf === doc || cnpj === doc;
  }) || null;
}

async function salvarContatoBling(dados, blingId) {
  const token = await getBlingToken();
  const isCNPJ = (dados.documento || '').replace(/\D/g, '').length > 11;
  const body = {
    nome: dados.nome, tipo: isCNPJ ? 'J' : 'F', email: dados.email,
    telefone: dados.telefone || '', celular: dados.celular || '',
    [isCNPJ ? 'cnpj' : 'cpf']: (dados.documento || '').replace(/\D/g, ''),
    ie: dados.ie || '',
    endereco: {
      endereco: dados.endereco || '', numero: dados.numero || '',
      complemento: dados.complemento || '', bairro: dados.bairro || '',
      cep: (dados.cep || '').replace(/\D/g, ''), municipio: dados.cidade || '', uf: dados.estado || ''
    }
  };
  if (blingId) {
    await fetch(`https://api.bling.com.br/Api/v3/contatos/${blingId}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return blingId;
  } else {
    const resp = await fetch('https://api.bling.com.br/Api/v3/contatos', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const result = await resp.json();
    return result?.data?.id || null;
  }
}

// ─── CSS ──────────────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;500;600&family=Inter:wght@300;400;500&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#0a0a0a;--surface:#111;--border:#222;--gold:#c9a96e;--gold-light:#e8d5b0;--text:#e8e8e8;--muted:#666;--danger:#c0392b;--success:#2ecc71;--warning:#f0a500}
  body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;min-height:100vh}
  h1,h2,h3{font-family:'Cormorant Garamond',serif;font-weight:400;letter-spacing:.05em}
  a{color:var(--gold);text-decoration:none} a:hover{color:var(--gold-light)}
  .container{max-width:960px;margin:0 auto;padding:0 24px}
  .container-sm{max-width:540px;margin:0 auto;padding:0 24px}
  .logo{font-family:'Cormorant Garamond',serif;font-size:22px;letter-spacing:.3em;color:var(--gold);text-transform:uppercase}
  .logo-sub{font-size:10px;letter-spacing:.5em;color:var(--muted);text-transform:uppercase;margin-top:2px}
  header{padding:24px 0;border-bottom:1px solid var(--border);margin-bottom:40px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:32px}
  .field{margin-bottom:18px}
  .field label{display:block;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
  .field input,.field select{width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:12px 14px;border-radius:3px;font-family:'Inter',sans-serif;font-size:14px;outline:none;transition:border .2s}
  .field input:focus,.field select:focus{border-color:var(--gold)}
  .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
  .btn{display:inline-block;padding:13px 28px;font-size:11px;letter-spacing:.2em;text-transform:uppercase;font-family:'Inter',sans-serif;cursor:pointer;border:none;border-radius:3px;transition:all .2s}
  .btn-primary{background:var(--gold);color:#000;font-weight:500} .btn-primary:hover{background:var(--gold-light)}
  .btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)} .btn-outline:hover{border-color:var(--gold);color:var(--gold)}
  .btn-danger{background:var(--danger);color:#fff}
  .btn-full{width:100%;text-align:center} .btn-lg{padding:18px 48px;font-size:12px}
  .badge{display:inline-block;padding:3px 10px;font-size:10px;letter-spacing:.15em;text-transform:uppercase;border-radius:20px}
  .badge-gold{background:rgba(201,169,110,.15);color:var(--gold);border:1px solid rgba(201,169,110,.3)}
  .badge-muted{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--border)}
  .badge-success{background:rgba(46,204,113,.1);color:var(--success);border:1px solid rgba(46,204,113,.2)}
  .badge-pending{background:rgba(240,165,0,.1);color:var(--warning);border:1px solid rgba(240,165,0,.2)}
  .divider{border:none;border-top:1px solid var(--border);margin:28px 0}
  .msg-erro{background:rgba(192,57,43,.1);border:1px solid rgba(192,57,43,.3);color:#e74c3c;padding:12px 16px;border-radius:3px;margin-bottom:20px;font-size:13px}
  .msg-ok{background:rgba(46,204,113,.1);border:1px solid rgba(46,204,113,.3);color:var(--success);padding:12px 16px;border-radius:3px;margin-bottom:20px;font-size:13px}
  .msg-info{background:rgba(201,169,110,.1);border:1px solid rgba(201,169,110,.3);color:var(--gold);padding:12px 16px;border-radius:3px;margin-bottom:20px;font-size:13px}
  .steps{display:flex;margin-bottom:40px;border-bottom:1px solid var(--border)}
  .step{flex:1;text-align:center;padding:12px;font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px}
  .step.ativo{color:var(--gold);border-color:var(--gold)}
  .step.feito{color:var(--muted);border-color:var(--success)}
  .funcao-item{display:flex;align-items:flex-start;gap:14px;padding:16px;border:1px solid var(--border);border-radius:4px;cursor:pointer;transition:all .2s;margin-bottom:8px;user-select:none}
  .funcao-item:hover{border-color:var(--gold)}
  .funcao-item.sel{border-color:var(--gold);background:rgba(201,169,110,.05)}
  .funcao-item.fixo{opacity:.55;cursor:default}
  .chk{width:18px;height:18px;border:1px solid var(--border);border-radius:3px;flex-shrink:0;margin-top:2px;display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--gold);transition:all .2s}
  .funcao-item.sel .chk,.funcao-item.fixo .chk{background:rgba(201,169,110,.2);border-color:var(--gold)}
  .fn{font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:2px}
  .fd{font-size:12px;color:var(--muted);line-height:1.5}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);padding:10px 14px;border-bottom:1px solid var(--border);font-weight:400}
  td{padding:13px 14px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  .nav-bar{display:flex;gap:8px;margin-bottom:32px;flex-wrap:wrap}
  .nav-link{padding:8px 16px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);border:1px solid var(--border);border-radius:3px;transition:all .2s}
  .nav-link:hover,.nav-link.ativo{color:var(--gold);border-color:var(--gold)}
  .stat-box{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:20px;text-align:center}
  .stat-box .num{font-family:'Cormorant Garamond',serif;font-size:36px;color:var(--gold)}
  .stat-box .lbl{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-top:4px}
  textarea{width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:12px;border-radius:3px;font-size:14px;min-height:80px;resize:vertical;font-family:'Inter',sans-serif;outline:none}
  textarea:focus{border-color:var(--gold)}
  #aviso-bling{display:none;margin-bottom:20px}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--gold);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
  @media(max-width:600px){.grid-2,.grid-3{grid-template-columns:1fr}.steps{flex-direction:column}}
`;

function html(titulo, corpo, nav=false) {
  const navHtml = nav ? `<div style="display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:12px;flex-wrap:wrap;">
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Portal</a>
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Obras</a>
    <a href="/meu-impacto" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Impacto</a>
    <a href="/sugestoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Voz</a>
    <a href="/minhas-funcoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Funções</a>
    <a href="/logout" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--danger)">Sair</a>
  </div>` : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${titulo} — Círculo ALMARE</title><style>${CSS}</style></head>
  <body><div class="container"><header><div class="logo">ALMARE</div><div class="logo-sub">Círculo</div>${navHtml}</header>${corpo}</div></body></html>`;
}

// Funções que o membro pode pedir no cadastro
const FUNCOES_CADASTRO = [
  {slug:'embaixador',nome:'Embaixador',desc:'Apresenta a ALMARE para outras pessoas.'},
  {slug:'especificador',nome:'Especificador',desc:'Arquiteto ou designer que incorpora obras em projetos.'},
  {slug:'artista',nome:'Artista',desc:'Submete obras originais para o catálogo ALMARE.'},
  {slug:'colaborador',nome:'Colaborador',desc:'Contribui para o ecossistema ALMARE.'},
];

// Todas as funções (incluindo curador — só admin atribui)
const TODAS_FUNCOES = [
  ...FUNCOES_CADASTRO,
  {slug:'curador',nome:'Curador',desc:'Participa de decisões curatoriais.'},
  {slug:'guardiao',nome:'Guardião',desc:'Possui obra ou matriz especial da ALMARE.'},
];

// ════════════════════════════════════════════════════════════════
// API — busca contato no Bling por CPF/CNPJ
// ════════════════════════════════════════════════════════════════
app.get('/api/buscar-contato', async (req, res) => {
  const { doc } = req.query;
  if (!doc || doc.replace(/\D/g,'').length < 11) return res.json({ encontrado: false });
  try {
    const contato = await buscarContatoBling(doc);
    if (!contato) return res.json({ encontrado: false });
    res.json({
      encontrado: true, bling_id: contato.id,
      nome: contato.nome || '', email: contato.email || '',
      telefone: contato.telefone || '', celular: contato.celular || '',
      ie: contato.ie || '', cep: contato.endereco?.cep || '',
      endereco: contato.endereco?.endereco || '', numero: contato.endereco?.numero || '',
      complemento: contato.endereco?.complemento || '', bairro: contato.endereco?.bairro || '',
      cidade: contato.endereco?.municipio || '', estado: contato.endereco?.uf || '',
    });
  } catch (e) { console.error('Bling busca:', e.message); res.json({ encontrado: false }); }
});

// ════════════════════════════════════════════════════════════════
// PASSO 1 — APRESENTAÇÃO
// ════════════════════════════════════════════════════════════════
app.get('/', (req,res) => {
  try { jwt.verify(req.cookies.circulo_token, JWT_SECRET); return res.redirect('/portal'); } catch {}
  res.redirect('/convite');
});
app.get('/versao', (req,res) => res.json({ versao: 'XYZ789', tabela_precos: true, alm001_excluido: true, deploy: new Date().toISOString() }));
app.get('/convite', (req,res) => res.redirect('/convite/geral'));

app.get('/convite/:codigo', async (req,res) => {
  const {codigo} = req.params;
  let conviteId=null, nomeIndicador='';
  if (codigo !== 'geral') {
    try {
      const r = await pool.query('SELECT cc.id,cm.nome FROM circulo_convites cc JOIN circulo_membros cm ON cm.id=cc.membro_id WHERE cc.codigo=$1 AND cc.ativo=true',[codigo]);
      if (r.rows.length) { conviteId=r.rows[0].id; nomeIndicador=r.rows[0].nome; }
    } catch {}
  }
  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Círculo ALMARE</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,500;1,300;1,400&family=Inter:wght@300;400;500&display=swap');
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0a0a0a;--gold:#c9a96e;--gold-light:#e8d5b0;--text:#e8e8e8;--muted:#555;--border:#1a1a1a}
    body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;display:flex;flex-direction:column;}
    
    /* HEADER */
    .header{padding:32px 48px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);}
    .logo{font-family:'Cormorant Garamond',serif;font-size:20px;letter-spacing:.4em;color:var(--gold);text-transform:uppercase;}
    .header-login{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);text-decoration:none;transition:color .2s;}
    .header-login:hover{color:var(--gold);}

    /* HERO */
    .hero{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:80px 24px;text-align:center;}
    .indicador{font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--gold);margin-bottom:48px;opacity:.8;}
    .hero-titulo{font-family:'Cormorant Garamond',serif;font-size:clamp(36px,5vw,56px);font-weight:300;line-height:1.15;margin-bottom:12px;max-width:640px;}
    .hero-titulo em{font-style:italic;color:var(--gold);}
    .hero-sub{font-size:15px;color:var(--muted);line-height:1.9;max-width:440px;margin:40px auto 0;}
    .hero-sub strong{color:#888;font-weight:400;}

    /* CTA */
    .cta-area{margin-top:64px;display:flex;flex-direction:column;align-items:center;gap:20px;}
    .btn-entrar{display:inline-block;padding:18px 56px;background:var(--gold);color:#000;font-family:'Inter',sans-serif;font-size:11px;letter-spacing:.25em;text-transform:uppercase;font-weight:500;text-decoration:none;border-radius:2px;transition:background .2s;}
    .btn-entrar:hover{background:var(--gold-light);}
    .login-link{display:inline-block;padding:16px 56px;border:1px solid var(--border);color:var(--text);font-family:'Inter',sans-serif;font-size:11px;letter-spacing:.25em;text-transform:uppercase;text-decoration:none;border-radius:2px;transition:all .2s;}
    .login-link:hover{border-color:var(--gold);color:var(--gold);}

    /* RODAPÉ */
    .footer{padding:24px 48px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;}
    .footer-txt{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);}

    @media(max-width:600px){.header{padding:24px}.footer{padding:20px 24px;flex-direction:column;gap:8px;text-align:center}}
  </style></head>
  <body>
    <header class="header">
      <div class="logo">ALMARE</div>
      <a href="/login" class="header-login">Entrar na minha conta</a>
    </header>

    <main class="hero">
      ${nomeIndicador ? `<p class="indicador">Você foi convidado por ${nomeIndicador}</p>` : ''}

      <h1 class="hero-titulo">
        Uma obra não é uma compra.<br>
        <em>É uma escolha de permanência.</em>
      </h1>

      <p class="hero-sub">
        A ALMARE reúne obras autorais de edição limitada.<br>
        <strong>O Círculo é a comunidade de quem carrega essa proposta adiante.</strong><br>
        Não é um programa. É pertencimento.
      </p>

      <div class="cta-area">
        <a href="/cadastro-passo2?convite=${conviteId||''}" class="btn-entrar">Quero entrar no Círculo</a>
        <a href="/login" class="login-link">Já sou membro</a>
      </div>
    </main>

    <footer class="footer">
      <span class="footer-txt">ALMARE · Círculo</span>
      <span class="footer-txt">Obras autorais de edição limitada</span>
    </footer>
  </body></html>`);
});

// ════════════════════════════════════════════════════════════════
// PASSO 2 — DADOS PESSOAIS
// ════════════════════════════════════════════════════════════════
app.get('/cadastro-passo2', (req,res) => {
  const convite = req.query.convite||'';
  res.send(html('Seus dados', `
    <div class="container-sm">
      <div class="steps">
        <div class="step feito">1 · Apresentação</div>
        <div class="step ativo">2 · Seus dados</div>
        <div class="step">3 · Criar senha</div>
      </div>
      <a href="/convite" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar</a>
      <h2 style="font-size:26px;margin-bottom:8px;">Seus dados</h2>
      <p style="color:var(--muted);margin-bottom:28px;">Preencha seus dados para completar o cadastro.</p>
      ${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}
      <div id="aviso-bling"></div>
      <form method="POST" action="/cadastro-passo2">
        <input type="hidden" name="convite_id" value="${convite}">
        <input type="hidden" name="bling_id" id="bling_id" value="">
        <div class="field">
          <label>CPF / CNPJ *</label>
          <div style="display:flex;gap:10px;align-items:center;">
            <input name="documento" id="documento" required placeholder="CPF ou CNPJ" style="flex:1" oninput="formatarDoc(this)" onblur="buscarNoBling(this.value)">
            <span id="status-busca" style="font-size:11px;color:var(--muted);white-space:nowrap;min-width:80px;"></span>
          </div>
        </div>
        <div id="campos-restantes" style="display:none;">
          <div class="field"><label>Nome completo / Razão social *</label><input name="nome" id="nome" required placeholder="Seu nome ou empresa"></div>
          <div class="grid-2">
            <div class="field"><label id="ie-label">RG / IE</label><input name="ie" id="ie" placeholder="Opcional"></div>
            <div class="field"><label>E-mail *</label><input name="email" id="email" type="email" required placeholder="seu@email.com"></div>
          </div>
          <div class="grid-2">
            <div class="field"><label>Telefone</label><input name="telefone" id="telefone" placeholder="(00) 0000-0000"></div>
            <div class="field"><label>Celular / WhatsApp</label><input name="celular" id="celular" placeholder="(00) 00000-0000"></div>
          </div>
          <hr class="divider">
          <h3 style="font-size:18px;margin-bottom:20px;">Endereço</h3>
          <div class="grid-2">
            <div class="field"><label>CEP *</label><input name="cep" id="cep" required placeholder="00000-000" oninput="buscarCep(this.value)"></div>
            <div class="field"><label>Estado</label><input name="estado" id="estado" placeholder="UF" maxlength="2"></div>
          </div>
          <div class="field"><label>Endereço *</label><input name="endereco" id="endereco" required placeholder="Rua, Avenida..."></div>
          <div class="grid-2">
            <div class="field"><label>Número *</label><input name="numero" id="numero" required placeholder="Nº"></div>
            <div class="field"><label>Complemento</label><input name="complemento" id="complemento" placeholder="Apto, sala..."></div>
          </div>
          <div class="grid-2">
            <div class="field"><label>Bairro</label><input name="bairro" id="bairro" placeholder="Bairro"></div>
            <div class="field"><label>Cidade *</label><input name="cidade" id="cidade" required placeholder="Cidade"></div>
          </div>

          <hr class="divider">
          <h3 style="font-size:18px;margin-bottom:8px;">Como quer participar?</h3>
          <p style="color:var(--muted);font-size:12px;margin-bottom:16px;">Você já entra como Membro. Marque se quiser solicitar funções adicionais.</p>
          <div class="funcao-item fixo" style="margin-bottom:8px;">
            <div class="chk" style="background:rgba(201,169,110,.2);border-color:var(--gold)">✓</div>
            <div><div class="fn">Membro</div><div class="fd">Acesso ao Círculo. Automático para todos.</div></div>
          </div>
          ${FUNCOES_CADASTRO.map(f=>`
          <div class="funcao-item" id="card-${f.slug}" onclick="toggle('${f.slug}')">
            <div class="chk" id="chk-${f.slug}"></div>
            <div><div class="fn">${f.nome}</div><div class="fd">${f.desc}</div></div>
            <input type="checkbox" name="funcoes" value="${f.slug}" id="cb-${f.slug}" style="display:none">
          </div>`).join('')}

          <hr class="divider">
          <h3 style="font-size:18px;margin-bottom:8px;">Criar senha</h3>
          <div class="grid-2">
            <div class="field"><label>Senha *</label><input type="password" name="senha" required minlength="8" placeholder="Mínimo 8 caracteres"></div>
            <div class="field"><label>Confirme a senha *</label><input type="password" name="senha2" required placeholder="Repita a senha"></div>
          </div>
          <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px;">Entrar no Círculo</button>
        </div>
      </form>
    </div>
    <script>
      function formatarDoc(el){
        const n=el.value.replace(/\\D/g,'');
        document.getElementById('ie-label').textContent=n.length>11?'Inscrição Estadual':'RG';
        document.getElementById('ie').placeholder=n.length>11?'IE (opcional)':'RG (opcional)';
      }
      async function buscarNoBling(val){
        const doc=val.replace(/\\D/g,'');
        if(doc.length<11)return;
        const status=document.getElementById('status-busca');
        const aviso=document.getElementById('aviso-bling');
        const campos=document.getElementById('campos-restantes');
        status.innerHTML='<span class="spinner"></span>Buscando...';
        try{
          const r=await fetch('/api/buscar-contato?doc='+encodeURIComponent(doc));
          const d=await r.json();
          if(d.encontrado){
            document.getElementById('bling_id').value=d.bling_id;
            preencherCampo('nome',d.nome);preencherCampo('email',d.email);
            preencherCampo('telefone',d.telefone);preencherCampo('celular',d.celular);
            preencherCampo('ie',d.ie);preencherCampo('cep',d.cep);
            preencherCampo('endereco',d.endereco);preencherCampo('numero',d.numero);
            preencherCampo('complemento',d.complemento);preencherCampo('bairro',d.bairro);
            preencherCampo('cidade',d.cidade);preencherCampo('estado',d.estado);
            aviso.innerHTML='<div class="msg-info">✓ Cadastro encontrado — dados preenchidos. Confira e corrija se necessário.</div>';
            aviso.style.display='block';status.textContent='✓ Encontrado';
          }else{
            document.getElementById('bling_id').value='';
            aviso.innerHTML='<div class="msg-ok">Cadastro novo — preencha seus dados abaixo.</div>';
            aviso.style.display='block';status.textContent='Não encontrado';
          }
          campos.style.display='block';
        }catch(e){status.textContent='';campos.style.display='block';}
      }
      function preencherCampo(id,val){const el=document.getElementById(id);if(el)el.value=val||'';}
      async function buscarCep(v){
        const cep=v.replace(/\\D/g,'');
        if(cep.length!==8)return;
        try{
          const r=await fetch('https://viacep.com.br/ws/'+cep+'/json/');
          const d=await r.json();
          if(d.erro)return;
          preencherCampo('endereco',d.logradouro);preencherCampo('bairro',d.bairro);
          preencherCampo('cidade',d.localidade);preencherCampo('estado',d.uf);
          document.getElementById('numero').focus();
        }catch{}
      }
      function toggle(slug){
        const cb=document.getElementById('cb-'+slug);
        const card=document.getElementById('card-'+slug);
        const chk=document.getElementById('chk-'+slug);
        cb.checked=!cb.checked;
        card.classList.toggle('sel',cb.checked);
        chk.textContent=cb.checked?'✓':'';
      }
    </script>
  `));
});

app.post('/cadastro-passo2', async (req,res) => {
  const {nome,documento,ie,email,telefone,celular,cep,endereco,numero,complemento,bairro,cidade,estado,convite_id,bling_id,senha,senha2} = req.body;

  if (senha !== senha2) return res.redirect(`/cadastro-passo2?convite=${convite_id||''}&erro=As+senhas+não+coincidem`);

  // Verifica email duplicado
  try {
    const existe = await pool.query('SELECT id FROM circulo_membros WHERE email=$1',[email]);
    if (existe.rows.length) return res.redirect(`/cadastro-passo2?convite=${convite_id||''}&erro=Este+e-mail+já+está+cadastrado`);
  } catch {}

  let funcoes = req.body.funcoes || [];
  if (!Array.isArray(funcoes)) funcoes = [funcoes];

  try {
    // Cria ou atualiza no Bling
    let blingIdFinal = bling_id || null;
    try {
      blingIdFinal = await salvarContatoBling({nome,email,documento,ie,telefone,celular,cep,endereco,numero,complemento,bairro,cidade,estado}, blingIdFinal);
    } catch(e) { console.error('Bling:', e.message); }

    // Cria membro
    const hash = await bcrypt.hash(senha, 12);
    const total = await pool.query('SELECT COUNT(*) FROM circulo_membros');
    const codigo = `ALM-${String(parseInt(total.rows[0].count)+1).padStart(4,'0')}`;
    const {rows} = await pool.query(
      `INSERT INTO circulo_membros (nome,email,senha_hash,status,aprovado_em,codigo_membro) VALUES ($1,$2,$3,'ativo',NOW(),$4) RETURNING id`,
      [nome, email, hash, codigo]
    );
    const mid = rows[0].id;

    // Infraestrutura do membro
    await pool.query('INSERT INTO circulo_saldo_credito (membro_id) VALUES ($1)',[mid]);
    await pool.query('INSERT INTO circulo_convites (membro_id,codigo) VALUES ($1,$2)',[mid,crypto.randomBytes(6).toString('hex')]);
    await pool.query('INSERT INTO circulo_links_aquisicao (membro_id,codigo) VALUES ($1,$2)',[mid,crypto.randomBytes(6).toString('hex')]);
    await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'entrada',$2)`,[mid,`${nome} entrou para o Círculo ALMARE`]);

    // Registra convite
    if (convite_id) await pool.query('UPDATE circulo_convites SET usos=usos+1 WHERE id=$1',[convite_id]);

    // Funções extras ficam PENDENTES de aprovação
    for (const slug of funcoes) {
      const fr = await pool.query('SELECT id FROM circulo_funcoes WHERE slug=$1',[slug]);
      if (fr.rows.length) {
        await pool.query(
          `INSERT INTO circulo_membro_funcoes (membro_id,funcao_id,ativo) VALUES ($1,$2,false) ON CONFLICT DO NOTHING`,
          [mid, fr.rows[0].id]
        );
      }
    }

    // Login automático
    const token = gerarToken({id:mid, nome, email});
    res.cookie('circulo_token', token, {httpOnly:true, maxAge:7*24*60*60*1000});
    res.redirect('/portal');
  } catch(e) {
    console.error(e);
    res.redirect(`/cadastro-passo2?convite=${convite_id||''}&erro=Erro+ao+cadastrar:+${encodeURIComponent(e.message)}`);
  }
});

// ════════════════════════════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════════════════════════════
app.get('/login',(req,res)=>res.send(html('Entrar',`
  <div class="container-sm">
    <h2 style="font-size:28px;margin-bottom:32px;">Círculo ALMARE</h2>
    ${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}
    <a href="/convite" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar</a>
    <form method="POST" action="/login">
      <div class="field"><label>E-mail</label><input name="email" type="email" required></div>
      <div class="field"><label>Senha</label><input name="senha" type="password" required></div>
      <button type="submit" class="btn btn-primary btn-full">Entrar</button>
    </form>
    <p style="margin-top:24px;text-align:center;font-size:12px;color:var(--muted);">Ainda não é membro? <a href="/convite">Quero entrar no Círculo</a></p>
  </div>
`)));

app.post('/login',async(req,res)=>{
  try{
    const {rows}=await pool.query('SELECT * FROM circulo_membros WHERE email=$1',[req.body.email]);
    if(!rows.length)return res.redirect('/login?erro=E-mail+ou+senha+inválidos');
    const m=rows[0];
    if(m.status!=='ativo')return res.redirect('/login?erro=Conta+não+ativa');
    if(!await bcrypt.compare(req.body.senha,m.senha_hash))return res.redirect('/login?erro=E-mail+ou+senha+inválidos');
    res.cookie('circulo_token',gerarToken({id:m.id,nome:m.nome,email:m.email}),{httpOnly:true,maxAge:7*24*60*60*1000});
    res.redirect('/portal');
  }catch{res.redirect('/login?erro=Erro+interno');}
});
app.get('/logout',(req,res)=>{res.clearCookie('circulo_token');res.redirect('/login');});

// ════════════════════════════════════════════════════════════════
// PORTAL
// ════════════════════════════════════════════════════════════════
app.get('/portal',authMembro,async(req,res)=>{
  try{
    const resumo=await pool.query('SELECT * FROM circulo_resumo_membro WHERE id=$1',[req.membro.id]);
    const m=resumo.rows[0]||{};
    const funcoes=await pool.query(`
      SELECT f.nome, f.slug, mf.ativo FROM circulo_membro_funcoes mf
      JOIN circulo_funcoes f ON f.id=mf.funcao_id
      WHERE mf.membro_id=$1`,[req.membro.id]);
    const convite=await pool.query('SELECT codigo FROM circulo_convites WHERE membro_id=$1 LIMIT 1',[req.membro.id]);
    const eventos=await pool.query('SELECT * FROM circulo_passaporte_eventos WHERE membro_id=$1 ORDER BY data_evento DESC LIMIT 10',[req.membro.id]);
    const link=convite.rows.length?`${BASE_URL}/convite/${convite.rows[0].codigo}`:'';
    const data=m.membro_desde?new Date(m.membro_desde).toLocaleDateString('pt-BR',{month:'long',year:'numeric'}):'';

    const fnomes = funcoes.rows.filter(f=>f.ativo).map(f=>
      `<span class="badge badge-gold">${f.nome}</span>`
    ).join(' ');
    // Membro sempre aparece

    const evHtml=eventos.rows.map(e=>`<div style="padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;"><span>${e.descricao}</span><span style="float:right;font-size:11px;color:var(--muted)">${new Date(e.data_evento).toLocaleDateString('pt-BR')}</span></div>`).join('');
    const temFuncaoExtra = funcoes.rows.some(f=>f.ativo && ['embaixador','especificador','artista','colaborador'].includes(f.slug));

    res.send(html('Portal',`
      <div class="nav-bar"><a href="/portal" class="nav-link ativo">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link">Simulador</a>${temFuncaoExtra ? '<a href="/meu-impacto" class="nav-link">Impacto</a>' : ''}<a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
      <div class="card" style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
          <div>
            <h2 style="font-size:26px;margin-bottom:4px;">${m.nome||req.membro.nome}</h2>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Membro desde ${data} · ${m.codigo_membro||''}</div>
            <div><span class="badge badge-gold">Membro</span>${fnomes ? " " + fnomes : ""}</div>
          </div>


          </div>
        </div>
      </div>
      <div class="grid-3" style="margin-bottom:24px;">
        <div class="stat-box"><div class="num">${m.obras_que_encontraram_lar||0}</div><div class="lbl">Obras que encontraram lar</div></div>
        <div class="stat-box"><div class="num">${m.total_indicacoes||0}</div><div class="lbl">Pessoas indicadas</div></div>
        <div class="stat-box"><div class="num">${m.sugestoes_incorporadas||0}</div><div class="lbl">Sugestões incorporadas</div></div>
      </div>
      <div class="card"><h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Sua história no Círculo</h3>${evHtml||'<p style="color:var(--muted);font-size:13px;">Nada registrado ainda.</p>'}</div>
      ${link?`<div style="margin-top:20px;padding:14px;border:1px solid var(--border);border-radius:4px;"><div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Seu link de convite</div><div style="font-size:12px;word-break:break-all;">${link}</div></div>`:''}
    `,true));
  }catch(e){res.send(html('Erro',`<div class="msg-erro">${e.message}</div>`,true));}
});

// ─── MINHAS FUNÇÕES — ativar/desativar ───────────────────────────────────────
app.get('/minhas-funcoes',authMembro,async(req,res)=>{
  const funcoes=await pool.query(`
    SELECT f.nome,f.slug,f.descricao,mf.ativo,mf.id as mf_id FROM circulo_membro_funcoes mf
    JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1`,[req.membro.id]);

  const itens=funcoes.rows.map(f=>`
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:10px;height:10px;border-radius:50%;background:${f.ativo?'#2ecc71':'#f0a500'};flex-shrink:0;"></div>
        <div>
          <div style="font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:3px;">${f.nome}</div>
          <div style="font-size:12px;color:var(--muted);">${f.descricao}</div>
        </div>
      </div>
      <div style="flex-shrink:0;margin-left:16px;">
        ${f.ativo ? `<form method="POST" action="/minhas-funcoes/${f.slug}/desativar"><button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Desativar</button></form>` : ''}
      </div>
    </div>`).join('');

  res.send(html('Minhas funções',`
    <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link">Simulador</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link ativo">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar ao portal</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Suas funções</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Funções ativas podem ser desativadas a qualquer momento. Funções aguardando estão pendentes de aprovação.</p>
    <div class="card">
      <div style="padding:16px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div><div style="font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:3px;">Membro</div><div style="font-size:12px;color:var(--muted);">Acesso ao Círculo. Permanente.</div></div>
        <span class="badge badge-gold">Ativo</span>
      </div>
      ${itens||'<p style="color:var(--muted);padding:16px 0;">Nenhuma função adicional solicitada.</p>'}
    </div>
  `,true));
});

app.post('/minhas-funcoes/:slug/desativar',authMembro,async(req,res)=>{
  await pool.query(`UPDATE circulo_membro_funcoes SET ativo=false WHERE membro_id=$1 AND funcao_id=(SELECT id FROM circulo_funcoes WHERE slug=$2)`,[req.membro.id,req.params.slug]);
  res.redirect('/minhas-funcoes');
});

// ════════════════════════════════════════════════════════════════
// SIMULADOR DE AMBIENTE — IA sugere obra para o espaço do cliente
// ════════════════════════════════════════════════════════════════

// Extrai medidas em cm de qualquer formato (array PG ou texto livre)
function extrairTamanhos(raw){
  if(!raw) return [];
  const txt = String(raw);
  const matches = txt.match(/(\d+)\s*[x×]\s*(\d+)/gi) || [];
  return matches.map(m=>{
    const p = m.match(/(\d+)\s*[x×]\s*(\d+)/i);
    return { largura: parseInt(p[1]), altura: parseInt(p[2]), label: `${p[1]}×${p[2]}cm` };
  });
}

// Tabela oficial de tamanhos por proporção — fonte de verdade fixa, porque o campo de texto
// preenchido no cadastro (tamanhos_recomendados) é inconsistente e não reflete o catálogo real
// de tamanhos que a ALMARE efetivamente produz para cada proporção de obra.
const TABELA_TAMANHOS_POR_FORMATO = {
  '1:1': [
    {largura:25, altura:25, preco:299},
    {largura:40, altura:40, preco:449},
    {largura:70, altura:70, preco:899},
    {largura:150, altura:150, preco:2890},
  ],
  '3:2': [
    {largura:60, altura:40, preco:519}, {largura:40, altura:60, preco:519},
    {largura:90, altura:60, preco:819}, {largura:60, altura:90, preco:819},
    {largura:120, altura:80, preco:1349}, {largura:80, altura:120, preco:1349},
    {largura:150, altura:100, preco:1790}, {largura:100, altura:150, preco:1790},
    {largura:180, altura:120, preco:2190}, {largura:120, altura:180, preco:2190},
    {largura:225, altura:150, preco:3690}, {largura:150, altura:225, preco:3690},
    {largura:265, altura:133, preco:5390}, {largura:133, altura:265, preco:5390},
  ],
};

function tamanhosOficiais(formatoRecomendado, raw){
  const bruto = String(formatoRecomendado||'').trim();
  const chave = bruto.replace(/\s+/g,'').replace(/\(adaptar\)/i,'').trim();

  // Match direto na tabela oficial (1:1 ou 3:2 exatos)
  if(TABELA_TAMANHOS_POR_FORMATO[chave]){
    return TABELA_TAMANHOS_POR_FORMATO[chave].map(t => ({...t, label: `${t.largura}×${t.altura}cm`, precoLabel: `R$ ${t.preco.toLocaleString('pt-BR')}`}));
  }

  // Formato "(adaptar)" ou proporção exótica: extrai a razão numérica e escolhe a família
  // produzível mais próxima (1:1 = razão 1.0, ou 3:2 = razão 1.5)
  const m = bruto.match(/([\d.]+)\s*:\s*([\d.]+)/);
  if(m){
    const razao = parseFloat(m[1]) / parseFloat(m[2]); // ex: 1.33:1 -> 1.33
    const distQuadrado = Math.abs(razao - 1.0);
    const distRetangulo = Math.abs(razao - 1.5);
    const familia = distQuadrado <= distRetangulo ? '1:1' : '3:2';
    return TABELA_TAMANHOS_POR_FORMATO[familia].map(t => ({...t, label: `${t.largura}×${t.altura}cm`, precoLabel: `R$ ${t.preco.toLocaleString('pt-BR')}`}));
  }

  // Sem formato reconhecível — assume 3:2 como padrão do catálogo (maioria retangular)
  return TABELA_TAMANHOS_POR_FORMATO['3:2'].map(t => ({...t, label: `${t.largura}×${t.altura}cm`, precoLabel: `R$ ${t.preco.toLocaleString('pt-BR')}`}));
}

// Analisa a foto do local (onde o quadro vai) + fotos de ambiente com Claude visão.
// Retorna leitura de estilo/paleta E a área da parede (bbox) calibrada por objetos de referência reais.
async function analisarAmbiente(fotoLocalBase64, fotosAmbienteBase64, dados){
  const content = [];

  const mLocal = fotoLocalBase64.match(/^data:(image\/\w+);base64,(.+)$/);
  if(mLocal) content.push({ type:'image', source:{ type:'base64', media_type:mLocal[1], data:mLocal[2] } });

  for(const f of (fotosAmbienteBase64||[])){
    const m = f.match(/^data:(image\/\w+);base64,(.+)$/);
    if(m) content.push({ type:'image', source:{ type:'base64', media_type:m[1], data:m[2] } });
  }

  content.push({ type:'text', text:`Você é um consultor curatorial de arte da ALMARE analisando fotos para sugerir onde e qual obra pendurar.

A PRIMEIRA imagem é a foto exata do local/parede onde o quadro vai ficar — é nela que você deve identificar a área da parede disponível. As imagens seguintes (se houver) são fotos adicionais do ambiente só para entender o estilo geral, não para posicionamento.

IMPORTANTE: o cliente foi instruído a fotografar a parede mostrando seus 4 limites reais — teto, chão, lateral esquerda e lateral direita, sem cortar nenhum. Ou seja, você pode assumir que as bordas da PRIMEIRA foto correspondem aproximadamente aos limites reais da parede informada (${dados.parede_largura}cm de largura × ${dados.parede_altura}cm de altura). Se a foto claramente NÃO seguir essa instrução (por exemplo, mostrando só um pedaço da parede, ou mostrando muito mais do ambiente do que só a parede), sinalize isso em "aviso_precisao".

Na primeira imagem, procure objetos de referência de tamanho real conhecido para calibrar a escala: porta padrão (altura aproximadamente 210cm), interruptor de luz (aproximadamente 110cm do chão), tomada (aproximadamente 30cm do chão), rodapé, altura de sofá (aproximadamente 85cm), pé-direito padrão (aproximadamente 270-300cm). Use o que estiver visível.

O cliente informou que a parede disponível mede ${dados.parede_largura}cm de largura por ${dados.parede_altura}cm de altura. Compare essa informação com o que você vê na imagem usando os objetos de referência. Se a proporção da parede que você identifica na foto for claramente incompatível com a medida informada, sinalize isso em "aviso_precisao".

Retorne SOMENTE um JSON válido, sem texto antes ou depois, com esta estrutura exata:
{
  "paleta_dominante": "descrição curta das cores predominantes do ambiente",
  "temperatura": "quente | fria | neutra",
  "estilo": "minimalista | classico | contemporaneo | industrial | organico",
  "carga_visual": "clean | equilibrado | carregado",
  "recomendacao_composicao": "obra_unica_protagonista | obra_unica_suave | composicao_multipla",
  "cor_parede": "cor da parede onde iria a obra",
  "moldura_recomendada": "preta | carvalho | aco_escovado",
  "justificativa_moldura": "1 frase curta sobre por que essa moldura combina com o ambiente",
  "justificativa_ambiente": "2 frases sobre o caráter visual do ambiente",
  "moveis_identificados": "liste rapidamente os móveis/objetos visíveis na parede ou na frente dela (ex: sofá baixo à esquerda, luminária de chão à direita)",
  "parede_bbox": { "top_pct": 0, "left_pct": 0, "width_pct": 0, "height_pct": 0 },
  "parede_bbox_largura_cm": 0,
  "referencia_usada": "qual objeto real você usou para calibrar a escala",
  "aviso_precisao": "aviso curto se a proporção parecer inconsistente com o que o cliente informou, ou null se estiver coerente"
}

Sobre "parede_bbox_largura_cm": este é o campo MAIS IMPORTANTE para a simulação ficar correta. É a largura REAL em centímetros da área de parede que você marcou em "parede_bbox", calculada usando os objetos de referência que você identificou na foto — NÃO copie o número que o cliente informou, calcule você mesmo pela imagem. Se a porta na foto mede visualmente cerca de 1/3 da largura da parede disponível, e porta padrão tem 80-90cm, então a parede tem por volta de 240-270cm — é esse tipo de cálculo que você deve fazer. Seja o mais preciso possível, porque um erro aqui faz o quadro aparecer do tamanho errado na simulação.

Sobre "moldura_recomendada": a ALMARE oferece três opções — preta, carvalho (madeira clara) e aço escovado. Escolha a que melhor combina com a cor da parede, o estilo do ambiente e a paleta da obra que será usada (você pode não saber a obra ainda, então baseie-se só no ambiente: paredes claras/neutras combinam bem com preta ou aço escovado para contraste, ambientes com madeira ou tom quente combinam com carvalho, ambientes industriais combinam com aço escovado ou preta). Este campo é obrigatório, sempre escolha uma das três opções.

Sobre "parede_bbox": são as coordenadas em PORCENTAGEM de 0 a 100 da área de parede vazia e disponível na PRIMEIRA imagem, usada apenas para saber a LARGURA disponível e a posição horizontal. top_pct e left_pct são a posição do canto superior esquerdo dessa área útil, width_pct e height_pct são o tamanho dela, todos relativos ao tamanho total da imagem.

ISSO É CRÍTICO E OBRIGATÓRIO: antes de definir "parede_bbox", primeiro identifique mentalmente TODOS os móveis e objetos visíveis na foto que ocupam a parede ou ficam na frente dela — sofás, poltronas, mesas, aparadores, estantes, plantas, portas, janelas, interruptores, tomadas, luminárias. A área de "parede_bbox" NUNCA pode se sobrepor a nenhum desses elementos, nem parcialmente. Se houver um móvel (como um sofá) na parte de baixo da parede, a área da bbox deve começar ACIMA do topo desse móvel, com uma margem de segurança equivalente a pelo menos 20-25cm reais de folga entre o topo do móvel e o início da bbox (isso é a distância mínima real entre um quadro pendurado e o encosto de um sofá, por exemplo). É um erro grave e inaceitável a bbox incluir qualquer parte de um móvel — verifique isso com atenção antes de responder.

ATENÇÃO ESPECIAL À LARGURA HORIZONTAL — REGRA IMPORTANTE: um móvel só "consome" a largura da parede se ele for do CHÃO ATÉ O TETO (como um armário alto, uma estante fechada que vai até em cima, um painel de parede inteiro). Nesse caso, essa faixa deixa de ser parede útil e a bbox deve terminar onde o móvel começa.

MAS: móveis que NÃO ocupam toda a altura — estantes de prateleiras vazadas, aparadores baixos, racks de TV, bancadas, cômodas, sofás — NÃO redefinem a largura da parede. A parede continua inteira acima e atrás deles, e o quadro deve ser centralizado na PAREDE INTEIRA, usando toda a largura disponível, não espremido só no pedaço "vazio". Um quadro pendurado ACIMA de um aparador baixo é normal e correto.

Então a regra é: para a largura da bbox (left_pct e width_pct), só exclua as áreas bloqueadas por móveis/portas que vão do chão ao teto. Aparadores, estantes vazadas e móveis baixos NÃO reduzem a largura — o quadro pode e deve ser centralizado na parede toda, na altura correta (acima desses móveis se necessário). Só a ALTURA (top_pct/height_pct) precisa respeitar o topo de um móvel baixo, não a largura.

Regra importante: se o ambiente estiver "carregado", recomende obra_unica_suave ou uma obra que não compita com o que já existe. Se estiver "clean", pode recomendar obra protagonista.` });

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method:'POST',
    headers:{ 'x-api-key':ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01', 'content-type':'application/json' },
    body: JSON.stringify({ model:'claude-sonnet-5', max_tokens:4096, thinking:{type:'disabled'}, messages:[{ role:'user', content }] })
  });
  if(!resp.ok){
    const errTxt = await resp.text();
    throw new Error('API Anthropic retornou erro '+resp.status+': '+errTxt.substring(0,300));
  }
  const data = await resp.json();
  if(data.error){
    throw new Error('Erro Anthropic: '+(data.error.message||JSON.stringify(data.error)));
  }
  const txt = (data.content||[]).filter(c=>c.type==='text').map(c=>c.text).join('');
  const jsonMatch = txt.match(/\{[\s\S]*\}/);
  if(!jsonMatch) throw new Error('IA não retornou análise válida. stop_reason: '+(data.stop_reason||'?')+' | resposta bruta: '+JSON.stringify(data).substring(0,500));
  const analise = JSON.parse(jsonMatch[0]);

  const b = analise.parede_bbox;
  if(!b || typeof b.top_pct!=='number' || typeof b.left_pct!=='number' || typeof b.width_pct!=='number' || typeof b.height_pct!=='number'){
    analise.parede_bbox = { top_pct:25, left_pct:20, width_pct:60, height_pct:50 };
    analise.aviso_precisao = analise.aviso_precisao || 'Não foi possível calibrar a posição exata pela imagem — a simulação usa uma posição aproximada.';
  }

  // Fallback: se a IA não calculou a largura real da parede na foto, usa a medida informada pelo cliente
  if(!analise.parede_bbox_largura_cm || analise.parede_bbox_largura_cm <= 0){
    analise.parede_bbox_largura_cm = parseInt(dados.parede_largura) || 300;
  }
  // Fallback: se a IA não recomendou moldura, decide por heurística simples
  if(!['preta','carvalho','aco_escovado'].includes(analise.moldura_recomendada)){
    const cp = (analise.cor_parede||'').toLowerCase();
    if(/madeira|amadeirad|quente|terroso|bege/.test(cp)) analise.moldura_recomendada = 'carvalho';
    else if(/industrial|cimento|concreto|cinza/.test(cp)) analise.moldura_recomendada = 'aco_escovado';
    else analise.moldura_recomendada = 'preta';
    if(!analise.justificativa_moldura) analise.justificativa_moldura = 'Recomendação padrão com base no tom geral do ambiente.';
  }

  return analise;
}

// Gera um watermark SVG real (padrão diagonal repetido) como data URI
function gerarMarcaDagua(codigo){
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="360" height="360">' +
    '<g transform="rotate(-32 180 180)" font-family="Georgia, serif" fill="rgba(255,255,255,0.5)">' +
    '<text x="-40" y="40" font-size="19" letter-spacing="4">ALMARE</text>' +
    '<text x="-40" y="80" font-size="10" letter-spacing="2">' + codigo + '</text>' +
    '<text x="-40" y="140" font-size="19" letter-spacing="4">ALMARE</text>' +
    '<text x="-40" y="180" font-size="10" letter-spacing="2">' + codigo + '</text>' +
    '<text x="-40" y="240" font-size="19" letter-spacing="4">ALMARE</text>' +
    '<text x="-40" y="280" font-size="10" letter-spacing="2">' + codigo + '</text>' +
    '<text x="-40" y="340" font-size="19" letter-spacing="4">ALMARE</text>' +
    '</g></svg>';
  return 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
}


// Rankeia obras do catálogo contra a análise do ambiente
function rankearObras(obras, analise, dados){
  const paredeL = parseInt(dados.parede_largura)||0;
  const paredeA = parseInt(dados.parede_altura)||0;

  return obras.map(o=>{
    let score = 0;
    const motivos = [];

    // 1. Tamanho compatível — padrão real de curadoria: quadro ocupa 50-60% da largura da parede (alvo ideal 55%)
    let tamanhos = tamanhosOficiais(o.formato_recomendado, o.tamanhos_recomendados);
    // Trava pela orientação real cadastrada — nunca deixa o algoritmo escolher a variante
    // horizontal de uma obra vertical (ou o contrário) só porque a largura bateu melhor
    const orientacaoObra = String(o.orientacao||'').toLowerCase();
    if(/vertical|retrato/.test(orientacaoObra)){
      const filtradoVert = tamanhos.filter(t => t.altura >= t.largura);
      if(filtradoVert.length) tamanhos = filtradoVert;
    } else if(/horizontal|paisagem/.test(orientacaoObra)){
      const filtradoHoriz = tamanhos.filter(t => t.largura >= t.altura);
      if(filtradoHoriz.length) tamanhos = filtradoHoriz;
    }
    const larguraIdeal = paredeL * 0.55;
    const alturaIdeal = paredeA * 0.55;
    // Teto de segurança apertado nos DOIS eixos — 65%, não 85%. Um quadro tecnicamente "cabe"
    // até quase encostar no teto, mas isso não significa que fica proporcional/curatorial.
    const dentroDoLimite = tamanhos.filter(t => t.largura <= paredeL*0.65 && t.altura <= paredeA*0.65);
    const candidatos = dentroDoLimite.length ? dentroDoLimite : tamanhos;
    // escolhe o tamanho mais próximo do alvo de 55% considerando LARGURA E ALTURA juntas —
    // nunca otimiza só um eixo deixando o outro desproporcional
    const melhorTamanho = candidatos.length
      ? candidatos.sort((a,b)=>{
          const distA = Math.abs(a.largura-larguraIdeal) + Math.abs(a.altura-alturaIdeal);
          const distB = Math.abs(b.largura-larguraIdeal) + Math.abs(b.altura-alturaIdeal);
          return distA - distB;
        })[0]
      : tamanhos[0];
    // Penaliza obras cujo tamanho disponível fica longe do ideal (55% da parede) — evita
    // recomendar peças pequenas demais numa parede grande só porque "tecnicamente cabe"
    const diffProporcional = (Math.abs(melhorTamanho.largura - larguraIdeal)/larguraIdeal + Math.abs(melhorTamanho.altura - alturaIdeal)/alturaIdeal) / 2;
    score += Math.max(0, 30 - diffProporcional*45);

    // 2. Paleta — harmônica ou conforme preferência
    if(dados.pref_paleta && o.paleta){
      if(o.paleta.toLowerCase().includes(dados.pref_paleta.toLowerCase())){ score += 20; motivos.push('paleta compatível com a preferência'); }
    }
    // temperatura
    if(analise.temperatura && o.paleta_detalhe){
      const pd = o.paleta_detalhe.toLowerCase();
      const quentes = /laranja|vermelho|ocre|ambar|dourado|terroso|bege|marrom/;
      const frios = /azul|verde|cinza|grafite|prata|off-white/;
      if(analise.temperatura==='quente' && quentes.test(pd)){ score+=12; }
      if(analise.temperatura==='fria' && frios.test(pd)){ score+=12; }
    }

    // 3. Personalidade vs carga visual
    const dest = (o.nivel_de_destaque||'').toLowerCase();
    if(analise.carga_visual==='carregado'){
      if(analise.recomendacao_composicao==='obra_unica_suave' && /suave|discret|complement|secund/.test(dest)){ score+=18; motivos.push('perfil suave para ambiente já carregado'); }
      if(/protagonist|hero|forte|impact/.test(dest)){ score-=10; }
    } else if(analise.carga_visual==='clean'){
      if(/protagonist|hero|forte|impact|destaque/.test(dest)){ score+=18; motivos.push('protagonista para ambiente clean'); }
    } else {
      score += 6;
    }

    // 4. Preferência de destaque do cliente
    if(dados.destaque==='ponto_focal' && /protagonist|hero|forte|impact|destaque/.test(dest)){ score+=10; }
    if(dados.destaque==='harmonia' && /suave|discret|complement|integr/.test(dest)){ score+=10; }

    // 5. Ambiente compatível
    if(o.ambientes_compativeis && dados.finalidade){
      const amb = String(o.ambientes_compativeis).toLowerCase();
      if(amb.includes(dados.finalidade.toLowerCase())){ score+=10; motivos.push('indicada para ambiente '+dados.finalidade); }
    }

    return { ...o, _score:score, _melhorTamanho:melhorTamanho, _motivos:motivos };
  })
  .filter(o=>o._melhorTamanho) // só obras que têm algum tamanho
  .sort((a,b)=>b._score-a._score);

  return diversificarPorOrientacao(candidatas);
}

// Evita entregar 3 sugestões da mesma orientação quando existem boas alternativas variadas.
// Só diversifica DENTRO das obras que realmente competem bem (score próximo do topo) —
// nunca puxa uma obra fraca só pra preencher variedade de orientação.
function diversificarPorOrientacao(candidatas){
  if(!candidatas.length) return [];
  const orientacaoDe = t => t.largura === t.altura ? 'quadrado' : (t.largura > t.altura ? 'horizontal' : 'vertical');
  const scoreTopo = candidatas[0]._score;
  // só entram no "pool competitivo" obras com pelo menos 65% do score da melhor colocada
  const pool = candidatas.filter(o => o._score >= scoreTopo*0.65);

  const escolhidas = [];
  const usadas = new Set();
  for(const o of pool){
    if(escolhidas.length >= 3) break;
    const orient = orientacaoDe(o._melhorTamanho);
    if(escolhidas.length < 2 && usadas.has(orient)) continue;
    escolhidas.push(o);
    usadas.add(orient);
  }
  // Completa com os melhores restantes (do ranking completo, não só do pool) se não fechou 3
  if(escolhidas.length < 3){
    for(const o of candidatas){
      if(escolhidas.length >= 3) break;
      if(!escolhidas.includes(o)) escolhidas.push(o);
    }
  }
  return escolhidas;
}

// GET — tela do simulador
app.get('/simulador', authMembro, async(req,res)=>{
  const fRows=await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
  const slugs=fRows.rows.map(r=>r.slug);
  const navImpacto=slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s))?'<a href="/meu-impacto" class="nav-link">Impacto</a>':'';

  res.send(html('Simulador',`
    <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link ativo">Simulador</a>${navImpacto}<a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar ao portal</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Simulador de ambiente</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Envie a foto do local exato e informe as medidas. A curadoria ALMARE sugere as obras que melhor se integram ao espaço.</p>

    <form id="form-sim" onsubmit="return enviar(event)">
      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:18px;margin-bottom:8px;color:var(--gold);">Foto do local exato</h3>
        <p style="font-size:12px;color:var(--muted);margin-bottom:16px;">A foto da parede onde o quadro vai ficar. <strong style="color:var(--gold);">Importante:</strong> enquadre a parede inteira mostrando os 4 limites — teto, chão, lateral esquerda e lateral direita — sem cortar nenhum deles. Isso é essencial para o cálculo de escala ficar correto.</p>
        <input type="file" id="foto-local" accept="image/*" required onchange="previewFotoLocal()" style="width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:12px;border-radius:3px;font-size:13px;">
        <div id="preview-local" style="margin-top:16px;"></div>
      </div>

      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:18px;margin-bottom:8px;color:var(--gold);">Outras fotos do ambiente <span style="color:var(--muted);font-weight:400;">(opcional)</span></h3>
        <p style="font-size:12px;color:var(--muted);margin-bottom:16px;">Fotos adicionais do cômodo ajudam a IA a entender o estilo geral — não são usadas na simulação, só na leitura.</p>
        <input type="file" id="fotos-ambiente" accept="image/*" multiple onchange="previewFotosAmbiente()" style="width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:12px;border-radius:3px;font-size:13px;">
        <div id="preview-ambiente" style="display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;"></div>
      </div>

      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Medida da parede</h3>
        <div class="grid-2">
          <div class="field"><label>Largura disponível (cm) *</label><input type="number" id="parede_largura" required placeholder="Ex: 300"></div>
          <div class="field"><label>Altura disponível (cm) *</label><input type="number" id="parede_altura" required placeholder="Ex: 250"></div>
        </div>
      </div>

      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Sobre o espaço</h3>
        <div class="grid-2">
          <div class="field"><label>Finalidade *</label>
            <select id="finalidade" required>
              <option value="Residencial">Residencial</option>
              <option value="Corporativo">Corporativo</option>
              <option value="Hotelaria">Hotelaria</option>
              <option value="Comercial">Comercial</option>
            </select>
          </div>
          <div class="field"><label>A obra deve ser... *</label>
            <select id="destaque" required>
              <option value="ponto_focal">O ponto focal do ambiente</option>
              <option value="harmonia">Integrada, em harmonia</option>
            </select>
          </div>
        </div>
        <div class="field"><label>Preferência de paleta <span style="color:var(--muted)">(opcional)</span></label>
          <select id="pref_paleta">
            <option value="">Sem preferência — deixar a curadoria decidir</option>
            <option value="quente">Cores quentes</option>
            <option value="fria">Cores frias</option>
            <option value="neutro">Neutros</option>
            <option value="monocromatico">Monocromático (P&B)</option>
          </select>
        </div>
      </div>

      <button type="submit" class="btn btn-primary btn-full" id="btn-analisar">Analisar ambiente e sugerir obras</button>
    </form>

    <div id="loading" style="display:none;text-align:center;padding:60px 0;">
      <div style="display:inline-block;width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--gold);border-radius:50%;animation:spin .8s linear infinite;"></div>
      <p style="margin-top:20px;color:var(--muted);font-size:14px;">A curadoria está analisando o ambiente...</p>
      <p style="margin-top:6px;color:var(--muted);font-size:12px;">Isso pode levar até 30 segundos.</p>
    </div>

    <div id="resultado" style="margin-top:40px;"></div>

    <!-- MODAL GALERIA DE TROCA DE OBRA -->
    <div id="galeria-modal" onclick="if(event.target===this)fecharGaleria()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:1000;overflow-y:auto;padding:30px 20px;">
      <div style="max-width:900px;margin:0 auto;background:#111;border:1px solid #222;border-radius:4px;">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:20px 24px;border-bottom:1px solid #222;position:sticky;top:0;background:#111;z-index:1;">
          <h3 style="font-size:20px;">Escolher outra obra</h3>
          <button onclick="fecharGaleria()" style="background:none;border:none;color:var(--muted);font-size:22px;cursor:pointer;">✕</button>
        </div>
        <div style="padding:20px 24px;">
          <input type="text" placeholder="Buscar por nome, código ou coleção..." oninput="renderGaleria(this.value)" style="width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:12px 14px;border-radius:3px;font-size:14px;font-family:'Inter',sans-serif;outline:none;margin-bottom:20px;">
          <div id="galeria-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;"></div>
        </div>
      </div>
    </div>

    <style>@keyframes spin{to{transform:rotate(360deg)}}</style>

    <script>
      let fotoLocalBase64 = null;
      let fotosAmbienteBase64 = [];

      function previewFotoLocal(){
        const input = document.getElementById('foto-local');
        const file = input.files[0];
        if(!file) return;
        const reader = new FileReader();
        reader.onload = e=>{
          fotoLocalBase64 = e.target.result;
          document.getElementById('preview-local').innerHTML = '<img src="'+e.target.result+'" style="width:100%;max-height:280px;object-fit:cover;border-radius:3px;border:1px solid var(--border);">';
        };
        reader.readAsDataURL(file);
      }

      function previewFotosAmbiente(){
        const input = document.getElementById('fotos-ambiente');
        const files = Array.from(input.files).slice(0,3);
        fotosAmbienteBase64 = [];
        const cont = document.getElementById('preview-ambiente');
        cont.innerHTML = '';
        files.forEach(file=>{
          const reader = new FileReader();
          reader.onload = e=>{
            fotosAmbienteBase64.push(e.target.result);
            const img = document.createElement('img');
            img.src = e.target.result;
            img.style.cssText = 'width:80px;height:80px;object-fit:cover;border-radius:3px;border:1px solid var(--border);';
            cont.appendChild(img);
          };
          reader.readAsDataURL(file);
        });
      }

      async function enviar(e){
        e.preventDefault();
        if(!fotoLocalBase64){ alert('Envie a foto do local onde o quadro vai ficar.'); return false; }

        document.getElementById('form-sim').style.display='none';
        document.getElementById('loading').style.display='block';
        document.getElementById('resultado').innerHTML='';

        const payload = {
          foto_local: fotoLocalBase64,
          fotos_ambiente: fotosAmbienteBase64,
          parede_largura: document.getElementById('parede_largura').value,
          parede_altura: document.getElementById('parede_altura').value,
          finalidade: document.getElementById('finalidade').value,
          destaque: document.getElementById('destaque').value,
          pref_paleta: document.getElementById('pref_paleta').value
        };

        try{
          const r = await fetch('/simulador/analisar', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
          const data = await r.json();
          document.getElementById('loading').style.display='none';
          if(data.erro){ document.getElementById('resultado').innerHTML='<div class="msg-erro">'+data.erro+'</div><button onclick="location.reload()" class="btn btn-outline" style="margin-top:16px;">Tentar de novo</button>'; return false; }
          renderResultado(data);
        }catch(err){
          document.getElementById('loading').style.display='none';
          document.getElementById('resultado').innerHTML='<div class="msg-erro">Erro ao analisar: '+err.message+'</div><button onclick="location.reload()" class="btn btn-outline" style="margin-top:16px;">Tentar de novo</button>';
        }
        return false;
      }

      // Estado global — guarda os dados da simulação atual para permitir edições (trocar tamanho/obra)
      let SIM = { data:null, cards:[] };

      function renderResultado(data){
        document.getElementById('resultado').innerHTML = '';
        SIM.data = data;
        const a = data.analise;
        const sugestoes = (data.sugestoes || []).slice(0, 3);

        // Estado editável de cada card (tamanho e obra podem mudar; moldura começa na recomendada)
        SIM.cards = sugestoes.map(o => ({
          obra: o,
          tamanho: o._melhorTamanho,
          moldura: a.moldura_recomendada || 'preta'
        }));

        const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};

        // ── Leitura do ambiente + curadoria em destaque ──
        let html = '<div class="card" style="margin-bottom:24px;">';
        html += '<h3 style="font-size:18px;margin-bottom:16px;color:var(--gold);">Leitura do ambiente</h3>';
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 24px;font-size:13px;margin-bottom:16px;">';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Paleta</span><br>'+a.paleta_dominante+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Temperatura</span><br>'+a.temperatura+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Estilo</span><br>'+a.estilo+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Carga visual</span><br>'+a.carga_visual+'</div>';
        html += '</div>';
        html += '<p style="font-size:13px;color:#ccc;font-style:italic;line-height:1.7;">'+a.justificativa_ambiente+'</p>';

        // Bloco de curadoria destacado (moldura recomendada + justificativa)
        if(a.moldura_recomendada){
          html += '<div style="margin-top:20px;padding:16px;background:rgba(201,169,110,.06);border:1px solid rgba(201,169,110,.25);border-radius:4px;">';
          html += '<div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin-bottom:6px;">Recomendação de curadoria</div>';
          html += '<div style="font-size:14px;margin-bottom:4px;">Moldura <strong style="color:var(--gold);">'+(nomesMoldura[a.moldura_recomendada]||a.moldura_recomendada)+'</strong></div>';
          if(a.justificativa_moldura) html += '<div style="font-size:12px;color:#bbb;line-height:1.6;">'+a.justificativa_moldura+'</div>';
          html += '</div>';
        }
        if(a.referencia_usada){ html += '<p style="margin-top:10px;font-size:11px;color:var(--muted);">Escala calibrada por: '+a.referencia_usada+'</p>'; }
        if(a.aviso_precisao){ html += '<div class="msg-info" style="margin-top:14px;">⚠ '+a.aviso_precisao+'</div>'; }
        html += '</div>';

        html += '<h3 style="font-size:22px;margin-bottom:8px;">Obras sugeridas</h3>';
        html += '<p style="font-size:12px;color:var(--muted);margin-bottom:20px;">Nossa curadoria escolheu estas três. Você pode ajustar o tamanho ou trocar a obra em cada uma.</p>';

        // Containers dos 3 cards (preenchidos por montarCard)
        SIM.cards.forEach((c,i)=>{ html += '<div id="card-slot-'+i+'"></div>'; });
        html += '<button onclick="location.reload()" class="btn btn-outline btn-full" style="margin-top:16px;">Simular outro ambiente</button>';

        document.getElementById('resultado').innerHTML = html;
        SIM.cards.forEach((c,i)=> montarCard(i));
      }

      // Desenha (ou redesenha) o card do slot i com o estado atual (obra + tamanho + moldura)
      function montarCard(i){
        const data = SIM.data;
        const a = data.analise;
        const c = SIM.cards[i];
        const o = c.obra;
        const t = c.tamanho;
        const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};
        const coresMoldura = { preta:'#1a1a1a', carvalho:'#8a6d3b', aco_escovado:'#9a9a9a' };

        const bbox = a.parede_bbox;
        const bx = (bbox && typeof bbox.left_pct==='number') ? bbox : {left_pct:15, top_pct:10, width_pct:70, height_pct:75};
        const larguraRealParede = parseInt(data.parede_largura) || 300;
        const fracaoParede = t ? Math.min(t.largura / larguraRealParede, 0.95) : 0.4;
        const larguraNaFoto = fracaoParede * bx.width_pct;
        const centroX = bx.left_pct + bx.width_pct/2;
        const alturaParedeCm = data.parede_altura;
        const centroY = Math.max(12, Math.min(88, ((alturaParedeCm - 160) / alturaParedeCm) * 100));
        const larguraFinal = Math.min(Math.max(larguraNaFoto, 8), bx.width_pct*0.98);
        const molduraCor = coresMoldura[c.moldura] || '#1a1a1a';
        const larguraCmObra = t ? t.largura : 100;
        const gapPct = Math.min(Math.max((0.6/larguraCmObra)*100, 0.4), 3.5);

        let html = '<div class="card" style="margin-bottom:24px;">';
        html += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;"><span class="badge badge-gold">'+(i+1)+'ª sugestão</span>'+(o._score?'<span style="font-size:11px;color:var(--muted);">'+Math.round(o._score)+' pontos de compatibilidade</span>':'')+'</div>';

        // Simulação
        html += '<div style="position:relative;background:#0d0d0d;border-radius:4px;overflow:hidden;margin-bottom:20px;line-height:0;">';
        html += '<img src="'+data.foto_local+'" style="width:100%;display:block;">';
        html += '<div class="quadro-wrap-'+i+'" style="position:absolute;top:'+centroY+'%;left:'+centroX+'%;transform:translate(-50%,-50%);width:'+larguraFinal+'%;aspect-ratio:'+(t?t.largura:1)+'/'+(t?t.altura:1)+';">';
        html += '<div class="moldura-'+i+'" style="border:2px solid '+molduraCor+';padding:'+gapPct.toFixed(2)+'%;background:#0a0a0a;box-sizing:border-box;width:100%;height:100%;">';
        html += '<div style="position:relative;width:100%;height:100%;">';
        html += '<img src="'+o.imagem_preview+'" style="width:100%;height:100%;object-fit:fill;background:#f4f2ee;display:block;">';
        html += '<div style="position:absolute;inset:0;background-image:url('+data.watermark+');background-repeat:repeat;mix-blend-mode:overlay;pointer-events:none;"></div>';
        html += '</div></div></div>';
        html += '</div>';

        // Info da obra
        html += '<div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">'+(o.colecao||'')+'</div>';
        html += '<h4 style="font-family:\\'Cormorant Garamond\\',serif;font-size:22px;margin-bottom:4px;">'+o.nome+'</h4>';
        html += '<div style="font-size:11px;color:var(--muted);margin-bottom:16px;">Código: '+(o.codigo||o.id)+'</div>';

        // Dropdown de tamanho
        const tamanhos = o._tamanhosDisponiveis || (t?[t]:[]);
        if(tamanhos.length){
          html += '<div style="margin-bottom:16px;">';
          html += '<div style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Tamanho</div>';
          html += '<select onchange="mudarTamanho('+i+',this.value)" style="width:100%;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:11px 14px;border-radius:3px;font-size:14px;font-family:\\'Inter\\',sans-serif;outline:none;cursor:pointer;">';
          tamanhos.forEach((tm,idx)=>{
            const sel = (t && tm.largura===t.largura && tm.altura===t.altura) ? 'selected' : '';
            html += '<option value="'+idx+'" '+sel+'>'+tm.label+(tm.precoLabel?' · '+tm.precoLabel:'')+'</option>';
          });
          html += '</select></div>';
        }

        // Moldura
        html += '<div style="margin-bottom:16px;">';
        html += '<div style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Moldura'+(c.moldura===a.moldura_recomendada?' <span style="color:var(--gold);">(recomendada)</span>':'')+'</div>';
        html += '<div style="display:flex;gap:8px;" id="molduras-'+i+'">';
        [['preta','#1a1a1a'],['carvalho','#8a6d3b'],['aco_escovado','linear-gradient(135deg,#aaa,#777)']].forEach(([slug,bg])=>{
          const borda = c.moldura===slug ? 'var(--gold)' : 'var(--border)';
          html += '<button type="button" onclick="mudarMoldura('+i+',\\''+slug+'\\')" data-cor="'+slug+'" style="width:36px;height:36px;background:'+bg+';border:2px solid '+borda+';border-radius:3px;cursor:pointer;" title="'+(nomesMoldura[slug])+'"></button>';
        });
        html += '</div></div>';

        // Trocar obra
        html += '<button type="button" onclick="abrirGaleria('+i+')" class="btn btn-outline" style="width:100%;margin-bottom:16px;">Trocar por outra obra</button>';

        // Por que combina
        if(o._motivos && o._motivos.length){
          html += '<div style="font-size:12px;color:#aaa;line-height:1.7;"><strong style="color:var(--gold);">Por que combina:</strong> '+o._motivos.join('; ')+'.</div>';
        }
        html += '</div>';

        document.getElementById('card-slot-'+i).innerHTML = html;
      }

      function mudarTamanho(i, idx){
        const tamanhos = SIM.cards[i].obra._tamanhosDisponiveis || [];
        if(tamanhos[idx]){ SIM.cards[i].tamanho = tamanhos[idx]; montarCard(i); }
      }

      function mudarMoldura(i, slug){
        SIM.cards[i].moldura = slug;
        montarCard(i);
      }

      // ── Galeria de troca de obra ──
      let GALERIA = { obras:null, slot:null };

      async function abrirGaleria(i){
        GALERIA.slot = i;
        const modal = document.getElementById('galeria-modal');
        modal.style.display = 'block';
        document.body.style.overflow = 'hidden';
        document.getElementById('galeria-grid').innerHTML = '<p style="color:var(--muted);text-align:center;padding:40px;">Carregando obras...</p>';
        if(!GALERIA.obras){
          try{
            const r = await fetch('/simulador/obras');
            const d = await r.json();
            GALERIA.obras = d.obras || [];
          }catch(e){ GALERIA.obras = []; }
        }
        renderGaleria('');
      }

      function fecharGaleria(){
        document.getElementById('galeria-modal').style.display = 'none';
        document.body.style.overflow = '';
      }

      function renderGaleria(busca){
        const b = (busca||'').toLowerCase();
        const filtradas = GALERIA.obras.filter(o =>
          !b || (o.nome||'').toLowerCase().includes(b) || (o.codigo||'').toLowerCase().includes(b) || (o.colecao||'').toLowerCase().includes(b)
        );
        let html = '';
        filtradas.forEach(o=>{
          html += '<div onclick="escolherObra('+o.id+')" style="cursor:pointer;border:1px solid var(--border);border-radius:4px;overflow:hidden;transition:border-color .2s;" onmouseover="this.style.borderColor=\\'var(--gold)\\'" onmouseout="this.style.borderColor=\\'var(--border)\\'">';
          html += '<div style="height:150px;background:#0d0d0d;display:flex;align-items:center;justify-content:center;overflow:hidden;">';
          html += o.imagem_preview ? '<img src="'+o.imagem_preview+'" style="max-width:100%;max-height:100%;object-fit:contain;">' : '<span style="color:var(--muted);font-size:10px;">SEM IMAGEM</span>';
          html += '</div>';
          html += '<div style="padding:10px;">';
          html += '<div style="font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">'+(o.colecao||'')+'</div>';
          html += '<div style="font-family:\\'Cormorant Garamond\\',serif;font-size:15px;">'+o.nome+'</div>';
          html += '<div style="font-size:10px;color:var(--muted);">'+o.codigo+'</div>';
          html += '</div></div>';
        });
        document.getElementById('galeria-grid').innerHTML = html || '<p style="color:var(--muted);text-align:center;padding:40px;grid-column:1/-1;">Nenhuma obra encontrada.</p>';
      }

      function escolherObra(id){
        const nova = GALERIA.obras.find(o=>o.id===id);
        if(!nova) return;
        const i = GALERIA.slot;
        // Monta o objeto obra no formato que montarCard espera
        SIM.cards[i].obra = {
          id: nova.id, codigo: nova.codigo, nome: nova.nome, colecao: nova.colecao,
          imagem_preview: nova.imagem_preview,
          _tamanhosDisponiveis: nova.tamanhos,
          _motivos: ['escolha do cliente']
        };
        SIM.cards[i].tamanho = nova.tamanhos && nova.tamanhos.length ? nova.tamanhos[0] : null;
        fecharGaleria();
        montarCard(i);
      }
    </script>
  `,true));
});

// POST — processa a análise
app.post('/simulador/analisar', authMembro, async(req,res)=>{
  try{
    const { foto_local, fotos_ambiente, parede_largura, parede_altura, finalidade, destaque, pref_paleta } = req.body;
    if(!foto_local) return res.json({ erro:'Nenhuma foto do local recebida.' });
    if(!ANTHROPIC_API_KEY) return res.json({ erro:'API de análise não configurada. Adicione ANTHROPIC_API_KEY nas variáveis do Railway.' });

    const dados = { parede_largura, parede_altura, finalidade, destaque, pref_paleta };

    const analise = await analisarAmbiente(foto_local, fotos_ambiente||[], dados);

    const obras = await pool.query(`
      SELECT id, codigo, nome, colecao, paleta, paleta_detalhe, personalidade_da_obra,
             nivel_de_destaque, ambientes_compativeis, tamanhos_recomendados,
             formato_recomendado, orientacao, imagem_preview
      FROM almare_obras WHERE status='aprovada' AND codigo <> 'ALM-001'`);

    const sugestoes = rankearObras(obras.rows, analise, dados).slice(0, 3);

    if(!sugestoes.length) return res.json({ erro:'Nenhuma obra do catálogo é compatível com essas medidas. Tente uma parede maior.' });

    // Anexa a cada sugestão TODOS os tamanhos disponíveis da obra (pro dropdown de troca de tamanho)
    for(const s of sugestoes){
      s._tamanhosDisponiveis = tamanhosOficiais(s.formato_recomendado, s.tamanhos_recomendados);
    }

    // Marca d'água genérica (uma só, o código muda visualmente por obra no front se quiser evoluir depois)
    const watermark = gerarMarcaDagua('ALMARE');

    res.json({
      analise, sugestoes, watermark,
      foto_local,
      parede_largura: parseInt(parede_largura),
      parede_altura: parseInt(parede_altura)
    });
  }catch(e){
    console.error('Simulador:', e.message);
    res.json({ erro:'Erro ao processar: '+e.message });
  }
});

// Rota que devolve todas as obras (pra galeria de troca de obra no simulador)
app.get('/simulador/obras', authMembro, async(req,res)=>{
  try{
    const obras = await pool.query(`
      SELECT id, codigo, nome, colecao, formato_recomendado, orientacao,
             tamanhos_recomendados, imagem_preview
      FROM almare_obras WHERE status='aprovada' AND codigo <> 'ALM-001'
      ORDER BY colecao, nome`);
    const lista = obras.rows.map(o => ({
      id: o.id, codigo: o.codigo, nome: o.nome, colecao: o.colecao,
      imagem_preview: o.imagem_preview,
      tamanhos: tamanhosOficiais(o.formato_recomendado, o.tamanhos_recomendados)
    }));
    res.json({ obras: lista });
  }catch(e){
    res.json({ erro: e.message });
  }
});



// ─── CATÁLOGO ─────────────────────────────────────────────────────────────────
app.get('/catalogo',authMembro,async(req,res)=>{
  try{
    const fRows=await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
    const slugs=fRows.rows.map(r=>r.slug);
    const isCurador=slugs.includes('curador');
    const isEspecificador=slugs.includes('especificador');
    const isEmbaixador=slugs.includes('embaixador');
    const navImpacto=slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s))?'<a href="/meu-impacto" class="nav-link">Impacto</a>':'';

    const obras=await pool.query(`
      SELECT o.id, o.nome, o.colecao, o.tiragem_total,
             o.conceito, o.essencia, o.sensacao_provocada, o.o_que_permanece,
             o.ambientes_compativeis, o.texto_curatorial, o.paleta, o.paleta_detalhe,
             o.perfil_de_cliente, o.nivel_de_destaque, o.personalidade_da_obra,
             o.perfil_arquitetonico, o.possibilidade_composicao, o.tamanhos_recomendados,
             o.formato_recomendado, o.nota_curador, o.potencial_nota, o.potencial_justificativa,
             o.observacoes_producao, o.descricao_comercial, o.direcao_artistica, o.imagem_preview
      FROM almare_obras o WHERE o.status='aprovada' ORDER BY o.colecao, o.nome`);

    // Listas únicas para filtros
    const colecoes=[...new Set(obras.rows.map(o=>o.colecao).filter(Boolean))].sort();
    const paletas=[...new Set(obras.rows.map(o=>o.paleta).filter(Boolean))].sort();

    function campo(label,valor){
      if(!valor)return '';
      return `<div style="margin-bottom:14px;"><div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${label}</div><div style="font-size:13px;line-height:1.7;color:#ccc;">${valor}</div></div>`;
    }

    const cardsHtml=obras.rows.map(o=>{
      let detalhe=campo('Conceito',o.conceito)+campo('Essência',o.essencia)+campo('Sensação',o.sensacao_provocada)+campo('O que permanece',o.o_que_permanece)+campo('Ambientes',o.ambientes_compativeis)+campo('Texto curatorial',o.texto_curatorial)+campo('Paleta',o.paleta)+campo('Cores',o.paleta_detalhe);
      if(isEmbaixador||isEspecificador||isCurador) detalhe+=campo('Perfil de cliente',o.perfil_de_cliente);
      if(isEspecificador||isCurador) detalhe+=campo('Nível de destaque',o.nivel_de_destaque)+campo('Personalidade',o.personalidade_da_obra)+campo('Perfil arquitetônico',o.perfil_arquitetonico)+campo('Composição múltipla',o.possibilidade_composicao)+campo('Tamanhos recomendados',o.tamanhos_recomendados)+campo('Formato recomendado',o.formato_recomendado);
      if(isCurador) detalhe+=campo('Nota do curador',o.nota_curador)+campo('Potencial',o.potencial_nota?o.potencial_nota+'/100':'')+campo('Justificativa',o.potencial_justificativa)+campo('Obs. produção',o.observacoes_producao)+campo('Descrição comercial',o.descricao_comercial);

      const palataAttr=o.paleta?o.paleta.toLowerCase().replace(/\s+/g,'-'):'';
      const colecaoAttr=o.colecao?o.colecao.toLowerCase().replace(/\s+/g,'-'):'';

      return `<div class="obra-card" data-colecao="${colecaoAttr}" data-paleta="${palataAttr}" data-nome="${(o.nome||'').toLowerCase()}">
        <div onclick="abrirObra(${o.id})" style="cursor:pointer;">
          <div style="position:relative;background:#0d0d0d;border-radius:4px 4px 0 0;overflow:hidden;height:300px;display:flex;align-items:center;justify-content:center;">
            ${o.imagem_preview?`<img src="${o.imagem_preview}" style="max-width:100%;max-height:100%;width:auto;height:auto;object-fit:contain;" loading="lazy">`:`<div style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:11px;letter-spacing:.15em;">SEM IMAGEM</div>`}
          </div>
          <div style="padding:16px;background:var(--surface);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;">
            <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${o.colecao||'—'}</div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:18px;margin-bottom:8px;">${o.nome||'Sem título'}</div>
            <div style="font-size:11px;color:var(--muted);">${o.paleta||''}</div>
          </div>
        </div>
        <!-- DETALHE (oculto, abre no modal) -->
        <div id="detalhe-${o.id}" style="display:none">${detalhe}${o.tiragem_total?`<div style="margin-top:16px;"><strong style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">Tiragem</strong><div style="font-family:'Cormorant Garamond',serif;font-size:18px;color:var(--gold);margin-top:4px;">${o.tiragem_total} exemplares</div></div>`:''}</div>
      </div>`;
    }).join('');

    const opcoesColecao=colecoes.map(c=>`<option value="${c.toLowerCase().replace(/\s+/g,'-')}">${c}</option>`).join('');
    const opcoesPaleta=paletas.map(p=>`<option value="${p.toLowerCase().replace(/\s+/g,'-')}">${p}</option>`).join('');

    res.send(html('Catálogo',`
      <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link ativo">Obras</a><a href="/simulador" class="nav-link">Simulador</a>${navImpacto}<a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>

      <!-- BARRA DE FILTROS -->
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px;align-items:center;">
        <input id="busca" type="text" placeholder="Buscar obra..." oninput="filtrar()" style="flex:1;min-width:200px;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:13px;font-family:'Inter',sans-serif;outline:none;">
        <select id="filtroColecao" onchange="filtrar()" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:12px;font-family:'Inter',sans-serif;outline:none;">
          <option value="">Todas as coleções</option>${opcoesColecao}
        </select>
        <select id="filtroPaleta" onchange="filtrar()" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:12px;font-family:'Inter',sans-serif;outline:none;">
          <option value="">Todas as paletas</option>${opcoesPaleta}
        </select>
        <span id="contagem" style="font-size:12px;color:var(--muted);white-space:nowrap;">${obras.rows.length} obras</span>
      </div>

      <!-- GRADE -->
      <div id="grade" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:20px;">
        ${cardsHtml}
      </div>
      <div id="sem-resultado" style="display:none;text-align:center;padding:60px 0;color:var(--muted);">Nenhuma obra encontrada.</div>

      <!-- MODAL DE DETALHE -->
      <div id="modal" onclick="fecharModal(event)" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:1000;overflow-y:auto;padding:40px 20px;">
        <div id="modal-conteudo" onclick="event.stopPropagation()" style="max-width:720px;margin:0 auto;background:#111;border:1px solid #222;border-radius:4px;overflow:hidden;">
          <div style="display:flex;justify-content:flex-end;padding:12px 16px;border-bottom:1px solid #222;">
            <button onclick="fecharModal()" style="background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;">✕</button>
          </div>
          <div id="modal-body" style="padding:32px;"></div>
        </div>
      </div>

      <script>
        function filtrar(){
          const busca=document.getElementById('busca').value.toLowerCase();
          const colecao=document.getElementById('filtroColecao').value;
          const paleta=document.getElementById('filtroPaleta').value;
          const cards=document.querySelectorAll('.obra-card');
          let visiveis=0;
          cards.forEach(c=>{
            const nomeOk=!busca||c.dataset.nome.includes(busca);
            const colecaoOk=!colecao||c.dataset.colecao===colecao;
            const paletaOk=!paleta||c.dataset.paleta===paleta;
            const ok=nomeOk&&colecaoOk&&paletaOk;
            c.style.display=ok?'':'none';
            if(ok)visiveis++;
          });
          document.getElementById('contagem').textContent=visiveis+' obra'+(visiveis!==1?'s':'');
          document.getElementById('sem-resultado').style.display=visiveis===0?'block':'none';
        }

        function abrirObra(id){
          const src=document.getElementById('detalhe-'+id);
          if(!src)return;
          const card=src.closest('.obra-card');
          const img=card.querySelector('img');
          const nome=card.querySelector('[style*="Cormorant"]').textContent;
          const colecao=card.querySelector('[style*="text-transform"]').textContent;
          let html='';
          if(img){
            html+=\`<div style="background:#0d0d0d;text-align:center;margin-bottom:16px;padding:24px;">
              <div id="moldura-preview" style="display:inline-block;border:2px solid #1a1a1a;padding:3px;background:#0a0a0a;">
                <img src="\${img.src}" style="max-width:100%;max-height:480px;width:auto;height:auto;object-fit:contain;display:block;">
              </div>
            </div>\`;
            html+=\`<div style="display:flex;gap:8px;align-items:center;justify-content:center;margin-bottom:24px;">
              <span style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-right:8px;">Moldura:</span>
              <button type="button" onclick="trocarMolduraModal('#1a1a1a',this)" data-cor="preta" style="width:32px;height:32px;background:#1a1a1a;border:2px solid var(--gold);border-radius:3px;cursor:pointer;" title="Preta"></button>
              <button type="button" onclick="trocarMolduraModal('#8a6d3b',this)" data-cor="carvalho" style="width:32px;height:32px;background:#8a6d3b;border:2px solid var(--border);border-radius:3px;cursor:pointer;" title="Carvalho"></button>
              <button type="button" onclick="trocarMolduraModal('#9a9a9a',this)" data-cor="aco_escovado" style="width:32px;height:32px;background:linear-gradient(135deg,#aaa,#777);border:2px solid var(--border);border-radius:3px;cursor:pointer;" title="Aço escovado"></button>
            </div>\`;
          }
          html+=\`<div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:6px;">\${colecao}</div>\`;
          html+=\`<h2 style="font-family:'Cormorant Garamond',serif;font-size:28px;font-weight:400;margin-bottom:24px;">\${nome}</h2>\`;
          html+=\`<div style="display:grid;grid-template-columns:1fr 1fr;gap:0 32px;">\${src.innerHTML}</div>\`;
          document.getElementById('modal-body').innerHTML=html;
          document.getElementById('modal').style.display='block';
          document.body.style.overflow='hidden';
        }

        function trocarMolduraModal(cor, btn){
          const el = document.getElementById('moldura-preview');
          if(el) el.style.borderColor = cor;
          const grupo = btn.parentElement;
          grupo.querySelectorAll('button').forEach(b=>{ b.style.borderColor = 'var(--border)'; });
          btn.style.borderColor = 'var(--gold)';
        }

        function fecharModal(e){
          if(e&&e.target!==document.getElementById('modal')&&e.type!=='click')return;
          document.getElementById('modal').style.display='none';
          document.body.style.overflow='';
        }
        document.addEventListener('keydown',e=>{if(e.key==='Escape')fecharModal();});
      </script>
    `,true));
  }catch(e){res.send(html('Catálogo',`<div class="msg-erro">${e.message}</div>`,true));}
});

// ─── IMPACTO ──────────────────────────────────────────────────────────────────
app.get('/meu-impacto',authMembro,async(req,res)=>{
  try{
    const trans=await pool.query('SELECT * FROM circulo_transacoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
    const saldo=await pool.query('SELECT * FROM circulo_saldo_credito WHERE membro_id=$1',[req.membro.id]);
    const s=saldo.rows[0]||{saldo_disponivel:0,saldo_total:0};
    const linhas=trans.rows.map(t=>`<tr><td>Obra #${t.obra_id}</td><td>R$ ${parseFloat(t.valor_obra).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.modalidade==='credito'?'badge-gold':'badge-muted'}">${t.modalidade==='credito'?'Crédito':'Cashback'}</span></td><td style="color:var(--gold)">R$ ${parseFloat(t.valor_beneficio).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.status==='pago'?'badge-success':'badge-pending'}">${t.status}</span></td></tr>`).join('');
    res.send(html('Impacto',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link">Simulador</a><a href="/meu-impacto" class="nav-link ativo">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div><div class="grid-2" style="margin-bottom:32px;"><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_disponivel).toFixed(2).replace('.',',')}</div><div class="lbl">Crédito disponível</div></div><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_total).toFixed(2).replace('.',',')}</div><div class="lbl">Total histórico</div></div></div><div class="card"><h3 style="font-size:18px;margin-bottom:20px;">Histórico</h3>${trans.rows.length?`<table><thead><tr><th>Obra</th><th>Valor</th><th>Modalidade</th><th>Benefício</th><th>Status</th></tr></thead><tbody>${linhas}</tbody></table>`:'<p style="color:var(--muted)">Nenhuma venda ainda.</p>'}</div>`,true));
  }catch(e){res.send(html('Impacto',`<div class="msg-erro">${e.message}</div>`,true));}
});

// ─── VOZ ──────────────────────────────────────────────────────────────────────
app.get('/sugestoes',authMembro,async(req,res)=>{
  const lista=await pool.query('SELECT * FROM circulo_sugestoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
  const itens=lista.rows.map(s=>`<div style="padding:16px 0;border-bottom:1px solid var(--border);"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${s.status}</span><span style="font-size:11px;color:var(--muted)">${new Date(s.criado_em).toLocaleDateString('pt-BR')}</span></div><p style="font-size:13px;line-height:1.6;">${s.texto}</p>${s.resposta?`<p style="font-size:12px;color:var(--gold);margin-top:8px;font-style:italic;">↳ ${s.resposta}</p>`:''}</div>`).join('');
  res.send(html('Voz',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link">Simulador</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link ativo">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Sua voz no Círculo</h2><p style="color:var(--muted);margin-bottom:32px;">Sugira temas, formatos, ambientes. Anderson lê tudo.</p><div class="card" style="margin-bottom:24px;"><form method="POST" action="/sugestoes"><div class="field"><label>Sua sugestão</label><textarea name="texto" required placeholder="Uma ideia..."></textarea></div><button type="submit" class="btn btn-primary">Enviar</button></form></div>${lista.rows.length?`<div class="card"><h3 style="font-size:16px;margin-bottom:16px;">Anteriores</h3>${itens}</div>`:''}`,true));
});
app.post('/sugestoes',authMembro,async(req,res)=>{
  await pool.query('INSERT INTO circulo_sugestoes (membro_id,texto) VALUES ($1,$2)',[req.membro.id,req.body.texto]);
  res.redirect('/sugestoes');
});

// ─── CONVIDAR ─────────────────────────────────────────────────────────────────
app.get('/meu-convite',authMembro,async(req,res)=>{
  const conv=await pool.query('SELECT * FROM circulo_convites WHERE membro_id=$1 LIMIT 1',[req.membro.id]);
  const c=conv.rows[0];
  const link=c?`${BASE_URL}/convite/${c.codigo}`:'';
  res.send(html('Convidar',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/simulador" class="nav-link">Simulador</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link ativo">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Seu link de convite</h2><p style="color:var(--muted);margin-bottom:32px;">Compartilhe com quem acredita que pertence ao Círculo.</p><div class="card"><div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Link pessoal</div><div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${link}</div><button onclick="navigator.clipboard.writeText('${link}');this.textContent='Copiado ✓'" class="btn btn-outline">Copiar link</button><div style="margin-top:20px;font-size:12px;color:var(--muted)">${c?c.usos:0} pessoa(s) entrou pela sua indicação</div></div>`,true));
});

// ════════════════════════════════════════════════════════════════
// ADMIN
// ════════════════════════════════════════════════════════════════
app.get('/admin/login',(req,res)=>res.send(html('Admin',`<div class="container-sm"><h2 style="font-size:24px;margin-bottom:32px;">Painel Admin</h2>${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}<form method="POST" action="/admin/login"><div class="field"><label>Senha</label><input type="password" name="senha" required></div><button type="submit" class="btn btn-primary btn-full">Entrar</button></form></div>`)));
app.post('/admin/login',(req,res)=>{
  if(req.body.senha!==ADMIN_SENHA)return res.redirect('/admin/login?erro=Senha+incorreta');
  res.cookie('circulo_admin',gerarToken({admin:true}),{httpOnly:true,maxAge:8*60*60*1000});
  res.redirect('/admin');
});
app.get('/admin/logout',(req,res)=>{res.clearCookie('circulo_admin');res.redirect('/admin/login');});

app.get('/admin',authAdmin,async(req,res)=>{
  // Funções pendentes de aprovação
  const pendentes=await pool.query(`
    SELECT mf.id as mf_id, m.nome, m.email, m.codigo_membro, f.nome as funcao, f.slug, m.id as membro_id
    FROM circulo_membro_funcoes mf
    JOIN circulo_membros m ON m.id=mf.membro_id
    JOIN circulo_funcoes f ON f.id=mf.funcao_id
    WHERE mf.ativo=false ORDER BY mf.id ASC`);
  const membros=await pool.query('SELECT * FROM circulo_resumo_membro ORDER BY membro_desde DESC');

  const linhaPendentes=pendentes.rows.map(p=>`
    <tr>
      <td><strong>${p.nome}</strong><br><span style="font-size:11px;color:var(--muted)">${p.email}</span></td>
      <td><span class="badge badge-gold">${p.funcao}</span></td>
      <td>
        <form method="POST" action="/admin/funcoes/${p.mf_id}/aprovar" style="display:inline">
          <button class="btn btn-primary" style="padding:6px 14px;font-size:10px;">Aprovar</button>
        </form>
        <form method="POST" action="/admin/funcoes/${p.mf_id}/recusar" style="display:inline;margin-left:6px">
          <button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Recusar</button>
        </form>
      </td>
    </tr>`).join('');

  const linhaMembros=membros.rows.map(m=>`
    <tr>
      <td>${m.nome}</td>
      <td style="color:var(--muted)">${m.codigo_membro||'—'}</td>
      <td style="color:var(--muted)">${m.email}</td>
      <td style="color:var(--gold)">R$ ${parseFloat(m.credito_disponivel).toFixed(2).replace('.',',')}</td>
      <td>${m.obras_que_encontraram_lar}</td>
      <td>${m.total_indicacoes}</td>
    </tr>`).join('');

  res.send(html('Admin',`
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;">
      <h2 style="font-size:24px;">Painel do Círculo</h2>
      <a href="/admin/logout" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Sair</a>
    </div>
    <div class="grid-3" style="margin-bottom:32px;">
      <div class="stat-box"><div class="num">${pendentes.rows.length}</div><div class="lbl">Funções pendentes</div></div>
      <div class="stat-box"><div class="num">${membros.rows.length}</div><div class="lbl">Membros ativos</div></div>
      <div class="stat-box"><div class="num">${membros.rows.reduce((a,m)=>a+parseInt(m.obras_que_encontraram_lar||0),0)}</div><div class="lbl">Obras que encontraram lar</div></div>
    </div>
    ${pendentes.rows.length?`
    <div class="card" style="margin-bottom:24px;">
      <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Funções aguardando aprovação</h3>
      <table><thead><tr><th>Membro</th><th>Função solicitada</th><th>Ação</th></tr></thead>
      <tbody>${linhaPendentes}</tbody></table>
    </div>`:''}
    <div class="card" style="margin-bottom:16px;">
      <h3 style="font-size:18px;margin-bottom:20px;">Membros do Círculo</h3>
      <table><thead><tr><th>Nome</th><th>Código</th><th>E-mail</th><th>Crédito</th><th>Obras</th><th>Indicações</th></tr></thead>
      <tbody>${linhaMembros||'<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:24px;">Nenhum membro ainda</td></tr>'}</tbody></table>
    </div>
    <a href="/admin/sugestoes" class="btn btn-outline">Ver sugestões dos membros</a>
  `));
});

// ─── APROVAR / RECUSAR FUNÇÃO ─────────────────────────────────────────────────
app.post('/admin/funcoes/:id/aprovar',authAdmin,async(req,res)=>{
  await pool.query('UPDATE circulo_membro_funcoes SET ativo=true WHERE id=$1',[req.params.id]);
  // registra no passaporte
  const mf=await pool.query('SELECT mf.*,f.nome as fn,m.nome as mn FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id JOIN circulo_membros m ON m.id=mf.membro_id WHERE mf.id=$1',[req.params.id]);
  if(mf.rows.length){
    await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'funcao_aprovada',$2)`,[mf.rows[0].membro_id,`Função ${mf.rows[0].fn} aprovada`]);
  }
  res.redirect('/admin');
});

app.post('/admin/funcoes/:id/recusar',authAdmin,async(req,res)=>{
  await pool.query('DELETE FROM circulo_membro_funcoes WHERE id=$1',[req.params.id]);
  res.redirect('/admin');
});

// ─── SUGESTÕES ADMIN ──────────────────────────────────────────────────────────
app.get('/admin/sugestoes',authAdmin,async(req,res)=>{
  const lista=await pool.query('SELECT s.*,m.nome as mn FROM circulo_sugestoes s JOIN circulo_membros m ON m.id=s.membro_id ORDER BY s.status ASC,s.criado_em DESC');
  const itens=lista.rows.map(s=>`<div style="padding:20px;border:1px solid var(--border);border-radius:4px;margin-bottom:12px;"><div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span style="font-size:12px;color:var(--gold)">${s.mn}</span><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${s.status}</span></div><p style="font-size:13px;margin-bottom:12px;">${s.texto}</p><form method="POST" action="/admin/sugestoes/${s.id}/responder" style="display:flex;gap:8px;flex-wrap:wrap;"><input name="resposta" placeholder="Resposta" value="${s.resposta||''}" style="flex:1;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><select name="status" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><option value="aberta" ${s.status==='aberta'?'selected':''}>Aberta</option><option value="em_analise" ${s.status==='em_analise'?'selected':''}>Em análise</option><option value="incorporada" ${s.status==='incorporada'?'selected':''}>Incorporada</option><option value="descartada" ${s.status==='descartada'?'selected':''}>Descartada</option></select><button type="submit" class="btn btn-primary" style="padding:8px 16px;">Salvar</button></form></div>`).join('');
  res.send(html('Sugestões',`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;"><h2 style="font-size:24px;">Sugestões dos membros</h2><a href="/admin" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">← Voltar</a></div>${itens||'<p style="color:var(--muted)">Nenhuma sugestão ainda.</p>'}`));
});
app.post('/admin/sugestoes/:id/responder',authAdmin,async(req,res)=>{
  const{resposta,status}=req.body;
  await pool.query('UPDATE circulo_sugestoes SET status=$1,resposta=$2,respondido_em=NOW() WHERE id=$3',[status,resposta||null,req.params.id]);
  if(status==='incorporada'){const s=await pool.query('SELECT * FROM circulo_sugestoes WHERE id=$1',[req.params.id]);if(s.rows.length)await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'sugestao_incorporada','Sua sugestão foi incorporada à curadoria ALMARE')`,[s.rows[0].membro_id]);}
  res.redirect('/admin/sugestoes');
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Círculo ALMARE rodando na porta ${PORT}`));
