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

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'circulo-almare-secret-2026';
const ADMIN_SENHA = process.env.ADMIN_SENHA || 'admin123';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const BLING_CLIENT_ID = process.env.BLING_CLIENT_ID;
const BLING_CLIENT_SECRET = process.env.BLING_CLIENT_SECRET;

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
    const expira = new Date(Date.now() + data.expires_in * 1000);
    await pool.query('UPDATE almare_bling_config SET access_token=$1, refresh_token=$2, expira_em=$3 WHERE id=1',
      [data.access_token, data.refresh_token, expira]);
    return data.access_token;
  }
  return config.access_token;
}

async function criarContatoBling(dados) {
  const token = await getBlingToken();
  const isCNPJ = (dados.documento||'').replace(/\D/g,'').length > 11;
  const body = {
    nome: dados.nome, tipo: isCNPJ ? 'J' : 'F', email: dados.email,
    telefone: dados.telefone || '', celular: dados.celular || '',
    [isCNPJ ? 'cnpj' : 'cpf']: (dados.documento||'').replace(/\D/g,''),
    ie: dados.ie || '',
    endereco: { endereco: dados.endereco||'', numero: dados.numero||'', complemento: dados.complemento||'',
      bairro: dados.bairro||'', cep: (dados.cep||'').replace(/\D/g,''), municipio: dados.cidade||'', uf: dados.estado||'' }
  };
  const resp = await fetch('https://www.bling.com.br/Api/v3/contatos', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const result = await resp.json();
  return result?.data?.id || null;
}

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400;500;600&family=Inter:wght@300;400;500&display=swap');
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{--bg:#0a0a0a;--surface:#111;--border:#222;--gold:#c9a96e;--gold-light:#e8d5b0;--text:#e8e8e8;--muted:#666;--danger:#c0392b;--success:#2ecc71}
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
  .btn-full{width:100%;text-align:center}
  .btn-lg{padding:18px 48px;font-size:12px}
  .badge{display:inline-block;padding:3px 10px;font-size:10px;letter-spacing:.15em;text-transform:uppercase;border-radius:20px}
  .badge-gold{background:rgba(201,169,110,.15);color:var(--gold);border:1px solid rgba(201,169,110,.3)}
  .badge-muted{background:rgba(255,255,255,.05);color:var(--muted);border:1px solid var(--border)}
  .badge-success{background:rgba(46,204,113,.1);color:var(--success);border:1px solid rgba(46,204,113,.2)}
  .badge-pending{background:rgba(255,180,0,.1);color:#f0a500;border:1px solid rgba(255,180,0,.2)}
  .divider{border:none;border-top:1px solid var(--border);margin:28px 0}
  .msg-erro{background:rgba(192,57,43,.1);border:1px solid rgba(192,57,43,.3);color:#e74c3c;padding:12px 16px;border-radius:3px;margin-bottom:20px;font-size:13px}
  .msg-ok{background:rgba(46,204,113,.1);border:1px solid rgba(46,204,113,.3);color:var(--success);padding:12px 16px;border-radius:3px;margin-bottom:20px;font-size:13px}
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
  @media(max-width:600px){.grid-2,.grid-3{grid-template-columns:1fr}.steps{flex-direction:column}}
`;

function html(titulo, corpo, nav=false) {
  const navHtml = nav ? `<div style="display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:12px;flex-wrap:wrap;">
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Portal</a>
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Obras</a>
    <a href="/meu-impacto" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Impacto</a>
    <a href="/sugestoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Voz</a>
    <a href="/logout" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--danger)">Sair</a>
  </div>` : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${titulo} — Círculo ALMARE</title><style>${CSS}</style></head>
  <body><div class="container"><header><div class="logo">ALMARE</div><div class="logo-sub">Círculo</div>${navHtml}</header>${corpo}</div></body></html>`;
}

const FUNCOES = [
  {slug:'embaixador',nome:'Embaixador',desc:'Apresenta a ALMARE para outras pessoas.'},
  {slug:'especificador',nome:'Especificador',desc:'Arquiteto ou designer que incorpora obras em projetos.'},
  {slug:'anfitriao',nome:'Anfitrião',desc:'Recebe e apresenta experiências ALMARE.'},
  {slug:'colaborador',nome:'Colaborador',desc:'Contribui para o ecossistema ALMARE.'},
  {slug:'curador',nome:'Curador',desc:'Participa de decisões curatoriais.'},
  {slug:'artista',nome:'Artista',desc:'Submete obras para o catálogo ALMARE.'},
  {slug:'guardiao',nome:'Guardião',desc:'Possui obra ou matriz especial da ALMARE.'},
];

// PASSO 1 — APRESENTAÇÃO
app.get('/', (req,res) => {
  try { jwt.verify(req.cookies.circulo_token, JWT_SECRET); return res.redirect('/portal'); } catch {}
  res.redirect('/convite');
});
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
  res.send(html('Bem-vindo', `
    <div class="container-sm" style="padding-top:20px;text-align:center;">
      ${nomeIndicador?`<p style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin-bottom:32px;">Convite de ${nomeIndicador}</p>`:''}
      <h1 style="font-size:40px;line-height:1.2;margin-bottom:16px;">Uma obra não é uma compra.</h1>
      <h1 style="font-size:40px;color:var(--gold);line-height:1.2;margin-bottom:40px;">É uma escolha de permanência.</h1>
      <p style="color:var(--muted);line-height:1.9;font-size:15px;max-width:420px;margin:0 auto 20px;">
        A ALMARE reúne obras autorais de edição limitada — criadas para espaços que entendem que a arte não decora. Transforma.
      </p>
      <p style="color:var(--muted);line-height:1.9;font-size:15px;max-width:420px;margin:0 auto 52px;">
        O Círculo ALMARE é a comunidade de quem carrega essa proposta adiante. Não é um programa. É pertencimento.
      </p>
      <a href="/cadastro-passo2?convite=${conviteId||''}" class="btn btn-primary btn-lg">Quero entrar no Círculo</a>
    </div>
  `));
});

// PASSO 2 — DADOS PESSOAIS
app.get('/cadastro-passo2', (req,res) => {
  const convite = req.query.convite||'';
  res.send(html('Seus dados', `
    <div class="container-sm">
      <div class="steps">
        <div class="step feito">1 · Apresentação</div>
        <div class="step ativo">2 · Seus dados</div>
        <div class="step">3 · Como participar</div>
      </div>
      <h2 style="font-size:26px;margin-bottom:8px;">Seus dados</h2>
      <p style="color:var(--muted);margin-bottom:28px;">Usamos as mesmas informações para emissão de nota fiscal.</p>
      ${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}
      <form method="POST" action="/cadastro-passo2">
        <input type="hidden" name="convite_id" value="${convite}">
        <div class="field"><label>Nome completo / Razão social *</label><input name="nome" required placeholder="Seu nome ou empresa"></div>
        <div class="grid-2">
          <div class="field"><label>CPF / CNPJ *</label><input name="documento" required placeholder="CPF ou CNPJ" id="doc" oninput="detectarDoc(this.value)"></div>
          <div class="field"><label id="ie-label">RG / IE</label><input name="ie" id="ie" placeholder="Opcional"></div>
        </div>
        <div class="field"><label>E-mail *</label><input name="email" type="email" required placeholder="seu@email.com"></div>
        <div class="grid-2">
          <div class="field"><label>Telefone</label><input name="telefone" placeholder="(00) 0000-0000"></div>
          <div class="field"><label>Celular / WhatsApp</label><input name="celular" placeholder="(00) 00000-0000"></div>
        </div>
        <hr class="divider">
        <h3 style="font-size:18px;margin-bottom:20px;">Endereço</h3>
        <div class="grid-2">
          <div class="field"><label>CEP *</label><input name="cep" required placeholder="00000-000" id="cep" oninput="buscarCep(this.value)"></div>
          <div class="field"><label>Estado</label><input name="estado" id="estado" placeholder="UF" maxlength="2"></div>
        </div>
        <div class="field"><label>Endereço *</label><input name="endereco" required id="endereco" placeholder="Rua, Avenida..."></div>
        <div class="grid-2">
          <div class="field"><label>Número *</label><input name="numero" required id="numero" placeholder="Nº"></div>
          <div class="field"><label>Complemento</label><input name="complemento" id="complemento" placeholder="Apto, sala..."></div>
        </div>
        <div class="grid-2">
          <div class="field"><label>Bairro</label><input name="bairro" id="bairro" placeholder="Bairro"></div>
          <div class="field"><label>Cidade *</label><input name="cidade" required id="cidade" placeholder="Cidade"></div>
        </div>
        <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px;">Continuar</button>
      </form>
    </div>
    <script>
      function detectarDoc(v){
        const n=v.replace(/\\D/g,'');
        document.getElementById('ie-label').textContent=n.length>11?'Inscrição Estadual':'RG';
        document.getElementById('ie').placeholder=n.length>11?'IE (opcional)':'RG (opcional)';
      }
      async function buscarCep(v){
        const cep=v.replace(/\\D/g,'');
        if(cep.length!==8)return;
        try{
          const r=await fetch('https://viacep.com.br/ws/'+cep+'/json/');
          const d=await r.json();
          if(d.erro)return;
          document.getElementById('endereco').value=d.logradouro||'';
          document.getElementById('bairro').value=d.bairro||'';
          document.getElementById('cidade').value=d.localidade||'';
          document.getElementById('estado').value=d.uf||'';
          document.getElementById('numero').focus();
        }catch{}
      }
    </script>
  `));
});

app.post('/cadastro-passo2', async (req,res) => {
  const {nome,documento,ie,email,telefone,celular,cep,endereco,numero,complemento,bairro,cidade,estado,convite_id}=req.body;
  try {
    const existe = await pool.query(
      `SELECT id FROM circulo_candidatos WHERE email=$1 AND status='pendente'
       UNION SELECT id FROM circulo_membros WHERE email=$1`,[email]);
    if (existe.rows.length) return res.redirect(`/cadastro-passo2?convite=${convite_id||''}&erro=Este+e-mail+já+tem+solicitação+no+Círculo`);
  } catch {}
  const t = gerarToken({tipo:'dados_passo2',nome,documento,ie,email,telefone,celular,cep,endereco,numero,complemento,bairro,cidade,estado,convite_id:convite_id||''},{expiresIn:'2h'});
  res.redirect(`/cadastro-passo3?t=${t}`);
});

// PASSO 3 — FUNÇÕES
app.get('/cadastro-passo3', (req,res) => {
  const t=req.query.t||'';
  try{jwt.verify(t,JWT_SECRET);}catch{return res.redirect('/convite');}
  const cards=FUNCOES.map(f=>`
    <div class="funcao-item" id="card-${f.slug}" onclick="toggle('${f.slug}')">
      <div class="chk" id="chk-${f.slug}"></div>
      <div><div class="fn">${f.nome}</div><div class="fd">${f.desc}</div></div>
      <input type="checkbox" name="funcoes" value="${f.slug}" id="cb-${f.slug}" style="display:none">
    </div>`).join('');
  res.send(html('Como participar',`
    <div class="container-sm">
      <div class="steps">
        <div class="step feito">1 · Apresentação</div>
        <div class="step feito">2 · Seus dados</div>
        <div class="step ativo">3 · Como participar</div>
      </div>
      <h2 style="font-size:26px;margin-bottom:8px;">Como você quer participar?</h2>
      <p style="color:var(--muted);margin-bottom:28px;">Todos entram como Membro. Marque também como quer contribuir.</p>
      <form method="POST" action="/cadastro-passo3">
        <input type="hidden" name="t" value="${t}">
        <div class="funcao-item fixo" style="margin-bottom:8px;">
          <div class="chk" style="background:rgba(201,169,110,.2);border-color:var(--gold)">✓</div>
          <div><div class="fn">Membro</div><div class="fd">Pertence ao Círculo. Base de todos os participantes.</div></div>
        </div>
        ${cards}
        <button type="submit" class="btn btn-primary btn-full" style="margin-top:24px;">Solicitar entrada no Círculo</button>
      </form>
    </div>
    <script>
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

app.post('/cadastro-passo3', async (req,res) => {
  const {t}=req.body;
  let payload;
  try{payload=jwt.verify(t,JWT_SECRET);}catch{return res.redirect('/convite');}
  let funcoes=req.body.funcoes||[];
  if(!Array.isArray(funcoes))funcoes=[funcoes];
  if(!funcoes.includes('membro'))funcoes.unshift('membro');
  try {
    await pool.query(
      'INSERT INTO circulo_candidatos (nome,email,convite_id,funcoes_desejadas,como_conheceu) VALUES ($1,$2,$3,$4,$5)',
      [payload.nome,payload.email,payload.convite_id||null,funcoes.join(', '),
       JSON.stringify({documento:payload.documento,ie:payload.ie,telefone:payload.telefone,celular:payload.celular,
         cep:payload.cep,endereco:payload.endereco,numero:payload.numero,complemento:payload.complemento,
         bairro:payload.bairro,cidade:payload.cidade,estado:payload.estado})]
    );
    if(payload.convite_id) await pool.query('UPDATE circulo_convites SET usos=usos+1 WHERE id=$1',[payload.convite_id]);
  } catch(e){console.error('Erro candidato:',e.message);}
  res.send(html('Solicitação enviada',`
    <div class="container-sm" style="text-align:center;padding-top:60px;">
      <div style="font-size:48px;margin-bottom:24px;color:var(--gold)">✦</div>
      <h2 style="font-size:32px;margin-bottom:16px;">Sua solicitação foi recebida.</h2>
      <p style="color:var(--muted);line-height:1.9;font-size:15px;">Em breve você receberá um retorno.<br>O Círculo é pequeno por intenção.</p>
    </div>
  `));
});

// ATIVAR CONTA
app.get('/ativar/:token', async (req,res) => {
  try {
    const p=jwt.verify(req.params.token,JWT_SECRET);
    if(p.tipo!=='convite_aprovado')throw new Error();
    res.send(html('Criar senha',`
      <div class="container-sm">
        <h2 style="font-size:28px;margin-bottom:8px;">Bem-vindo ao Círculo.</h2>
        <p style="color:var(--muted);margin-bottom:32px;">Crie sua senha para acessar o portal.</p>
        <form method="POST" action="/ativar">
          <input type="hidden" name="token" value="${req.params.token}">
          <div class="field"><label>E-mail</label><input value="${p.email}" disabled style="opacity:.5"></div>
          <div class="field"><label>Crie uma senha *</label><input type="password" name="senha" required minlength="8" placeholder="Mínimo 8 caracteres"></div>
          <div class="field"><label>Confirme a senha *</label><input type="password" name="senha2" required></div>
          <button type="submit" class="btn btn-primary btn-full">Entrar no Círculo</button>
        </form>
      </div>
    `));
  } catch{res.send(html('Link inválido',`<div class="container-sm"><div class="msg-erro">Este link expirou.</div></div>`));}
});

app.post('/ativar', async (req,res) => {
  const {token,senha,senha2}=req.body;
  if(senha!==senha2)return res.send(html('Erro',`<div class="container-sm"><div class="msg-erro">As senhas não coincidem.</div><a href="javascript:history.back()" class="btn btn-outline">Voltar</a></div>`));
  try {
    const p=jwt.verify(token,JWT_SECRET);
    const cand=await pool.query('SELECT * FROM circulo_candidatos WHERE id=$1',[p.candidato_id]);
    if(!cand.rows.length)throw new Error('Candidato não encontrado');
    const c=cand.rows[0];
    const hash=await bcrypt.hash(senha,12);
    const total=await pool.query('SELECT COUNT(*) FROM circulo_membros');
    const codigo=`ALM-${String(parseInt(total.rows[0].count)+1).padStart(4,'0')}`;
    const {rows}=await pool.query(
      `INSERT INTO circulo_membros (nome,email,senha_hash,status,aprovado_em,codigo_membro)
       VALUES ($1,$2,$3,'ativo',NOW(),$4) RETURNING id`,
      [c.nome,c.email,hash,codigo]
    );
    const mid=rows[0].id;
    await pool.query('INSERT INTO circulo_saldo_credito (membro_id) VALUES ($1)',[mid]);
    await pool.query('INSERT INTO circulo_convites (membro_id,codigo) VALUES ($1,$2)',[mid,crypto.randomBytes(6).toString('hex')]);
    await pool.query('INSERT INTO circulo_links_aquisicao (membro_id,codigo) VALUES ($1,$2)',[mid,crypto.randomBytes(6).toString('hex')]);
    await pool.query('INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,\'entrada\',$2)',[mid,`${c.nome} entrou para o Círculo ALMARE`]);
    if(c.funcoes_desejadas){
      for(const slug of c.funcoes_desejadas.split(',').map(s=>s.trim()).filter(Boolean)){
        const fr=await pool.query('SELECT id FROM circulo_funcoes WHERE slug=$1',[slug]);
        if(fr.rows.length)await pool.query('INSERT INTO circulo_membro_funcoes (membro_id,funcao_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',[mid,fr.rows[0].id]);
      }
    }
    await pool.query(`UPDATE circulo_candidatos SET status='aprovado' WHERE id=$1`,[p.candidato_id]);
    const jwtToken=gerarToken({id:mid,nome:c.nome,email:c.email});
    res.cookie('circulo_token',jwtToken,{httpOnly:true,maxAge:7*24*60*60*1000});
    res.redirect('/portal');
  }catch(e){console.error(e);res.send(html('Erro',`<div class="container-sm"><div class="msg-erro">${e.message}</div></div>`));}
});

// LOGIN
app.get('/login',(req,res)=>res.send(html('Entrar',`
  <div class="container-sm">
    <h2 style="font-size:28px;margin-bottom:32px;">Círculo ALMARE</h2>
    ${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}
    <form method="POST" action="/login">
      <div class="field"><label>E-mail</label><input name="email" type="email" required></div>
      <div class="field"><label>Senha</label><input name="senha" type="password" required></div>
      <button type="submit" class="btn btn-primary btn-full">Entrar</button>
    </form>
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

// PORTAL
app.get('/portal',authMembro,async(req,res)=>{
  try{
    const resumo=await pool.query('SELECT * FROM circulo_resumo_membro WHERE id=$1',[req.membro.id]);
    const m=resumo.rows[0]||{};
    const funcoes=await pool.query('SELECT f.nome FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true',[req.membro.id]);
    const convite=await pool.query('SELECT codigo FROM circulo_convites WHERE membro_id=$1 LIMIT 1',[req.membro.id]);
    const eventos=await pool.query('SELECT * FROM circulo_passaporte_eventos WHERE membro_id=$1 ORDER BY data_evento DESC LIMIT 10',[req.membro.id]);
    const link=convite.rows.length?`${BASE_URL}/convite/${convite.rows[0].codigo}`:'';
    const fnomes=funcoes.rows.map(f=>`<span class="badge badge-gold">${f.nome}</span>`).join(' ');
    const data=m.membro_desde?new Date(m.membro_desde).toLocaleDateString('pt-BR',{month:'long',year:'numeric'}):'';
    const evHtml=eventos.rows.map(e=>`<div style="padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;"><span>${e.descricao}</span><span style="float:right;font-size:11px;color:var(--muted)">${new Date(e.data_evento).toLocaleDateString('pt-BR')}</span></div>`).join('');
    res.send(html('Portal',`
      <div class="nav-bar"><a href="/portal" class="nav-link ativo">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
      <div class="card" style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
          <div>
            <h2 style="font-size:26px;margin-bottom:4px;">${m.nome||req.membro.nome}</h2>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Membro desde ${data} · ${m.codigo_membro||''}</div>
            <div>${fnomes||'<span class="badge badge-muted">Membro</span>'}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">Crédito disponível</div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:32px;color:var(--gold);">R$ ${parseFloat(m.credito_disponivel||0).toFixed(2).replace('.',',')}</div>
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

app.get('/catalogo',authMembro,async(req,res)=>{
  try{
    const obras=await pool.query(`SELECT o.id,o.nome,o.conceito,c.nome as colecao,o.tiragem_maxima,COUNT(CASE WHEN t.status='disponivel' THEN 1 END) as disponiveis FROM almare_obras o LEFT JOIN colecoes c ON c.id=o.colecao_id LEFT JOIN almare_tiragem t ON t.obra_id=o.id WHERE o.status_curatorial='aprovada' GROUP BY o.id,o.nome,o.conceito,c.nome,o.tiragem_maxima ORDER BY o.id DESC`);
    const cards=obras.rows.map(o=>`<div class="card" style="margin-bottom:16px;"><div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;"><div><div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${o.colecao||'—'}</div><h3 style="font-size:20px;margin-bottom:8px;">${o.nome||'Sem título'}</h3><p style="font-size:13px;color:var(--muted);line-height:1.6;">${(o.conceito||'').substring(0,140)}...</p></div><div style="text-align:right;flex-shrink:0;"><div style="font-size:11px;color:var(--muted)">Tiragem</div><div style="font-family:'Cormorant Garamond',serif;font-size:22px;color:var(--gold)">${o.disponiveis}/${o.tiragem_maxima}</div></div></div></div>`).join('');
    res.send(html('Catálogo',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link ativo">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/meu-convite" class="nav-link">Convidar</a></div><h2 style="font-size:28px;margin-bottom:32px;">Catálogo ALMARE</h2>${cards||'<p style="color:var(--muted)">Nenhuma obra disponível.</p>'}`,true));
  }catch(e){res.send(html('Catálogo',`<div class="msg-erro">${e.message}</div>`,true));}
});

app.get('/meu-impacto',authMembro,async(req,res)=>{
  try{
    const trans=await pool.query('SELECT * FROM circulo_transacoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
    const saldo=await pool.query('SELECT * FROM circulo_saldo_credito WHERE membro_id=$1',[req.membro.id]);
    const s=saldo.rows[0]||{saldo_disponivel:0,saldo_total:0};
    const linhas=trans.rows.map(t=>`<tr><td>Obra #${t.obra_id}</td><td>R$ ${parseFloat(t.valor_obra).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.modalidade==='credito'?'badge-gold':'badge-muted'}">${t.modalidade==='credito'?'Crédito':'Cashback'}</span></td><td style="color:var(--gold)">R$ ${parseFloat(t.valor_beneficio).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.status==='pago'?'badge-success':'badge-pending'}">${t.status}</span></td></tr>`).join('');
    res.send(html('Impacto',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link ativo">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/meu-convite" class="nav-link">Convidar</a></div><div class="grid-2" style="margin-bottom:32px;"><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_disponivel).toFixed(2).replace('.',',')}</div><div class="lbl">Crédito disponível</div></div><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_total).toFixed(2).replace('.',',')}</div><div class="lbl">Total histórico</div></div></div><div class="card"><h3 style="font-size:18px;margin-bottom:20px;">Histórico</h3>${trans.rows.length?`<table><thead><tr><th>Obra</th><th>Valor</th><th>Modalidade</th><th>Benefício</th><th>Status</th></tr></thead><tbody>${linhas}</tbody></table>`:'<p style="color:var(--muted)">Nenhuma venda ainda.</p>'}</div>`,true));
  }catch(e){res.send(html('Impacto',`<div class="msg-erro">${e.message}</div>`,true));}
});

app.get('/sugestoes',authMembro,async(req,res)=>{
  const lista=await pool.query('SELECT * FROM circulo_sugestoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
  const itens=lista.rows.map(s=>`<div style="padding:16px 0;border-bottom:1px solid var(--border);"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${s.status}</span><span style="font-size:11px;color:var(--muted)">${new Date(s.criado_em).toLocaleDateString('pt-BR')}</span></div><p style="font-size:13px;line-height:1.6;">${s.texto}</p>${s.resposta?`<p style="font-size:12px;color:var(--gold);margin-top:8px;font-style:italic;">↳ ${s.resposta}</p>`:''}</div>`).join('');
  res.send(html('Voz',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link ativo">Voz</a><a href="/meu-convite" class="nav-link">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Sua voz no Círculo</h2><p style="color:var(--muted);margin-bottom:32px;">Sugira temas, formatos, ambientes. Anderson lê tudo.</p><div class="card" style="margin-bottom:24px;"><form method="POST" action="/sugestoes"><div class="field"><label>Sua sugestão</label><textarea name="texto" required placeholder="Uma ideia..."></textarea></div><button type="submit" class="btn btn-primary">Enviar</button></form></div>${lista.rows.length?`<div class="card"><h3 style="font-size:16px;margin-bottom:16px;">Anteriores</h3>${itens}</div>`:''}`,true));
});
app.post('/sugestoes',authMembro,async(req,res)=>{
  await pool.query('INSERT INTO circulo_sugestoes (membro_id,texto) VALUES ($1,$2)',[req.membro.id,req.body.texto]);
  res.redirect('/sugestoes');
});

app.get('/meu-convite',authMembro,async(req,res)=>{
  const conv=await pool.query('SELECT * FROM circulo_convites WHERE membro_id=$1 LIMIT 1',[req.membro.id]);
  const c=conv.rows[0];
  const link=c?`${BASE_URL}/convite/${c.codigo}`:'';
  res.send(html('Convidar',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/meu-convite" class="nav-link ativo">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Seu link de convite</h2><p style="color:var(--muted);margin-bottom:32px;">Compartilhe com quem acredita que pertence ao Círculo.<br>Anderson aprova cada pessoa individualmente.</p><div class="card"><div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Link pessoal</div><div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${link}</div><button onclick="navigator.clipboard.writeText('${link}');this.textContent='Copiado ✓'" class="btn btn-outline">Copiar link</button><div style="margin-top:20px;font-size:12px;color:var(--muted)">${c?c.usos:0} pessoa(s) entrou pela sua indicação</div></div>`,true));
});

// ADMIN
app.get('/admin/login',(req,res)=>res.send(html('Admin',`<div class="container-sm"><h2 style="font-size:24px;margin-bottom:32px;">Painel Admin</h2>${req.query.erro?`<div class="msg-erro">${req.query.erro}</div>`:''}<form method="POST" action="/admin/login"><div class="field"><label>Senha</label><input type="password" name="senha" required></div><button type="submit" class="btn btn-primary btn-full">Entrar</button></form></div>`)));
app.post('/admin/login',(req,res)=>{
  if(req.body.senha!==ADMIN_SENHA)return res.redirect('/admin/login?erro=Senha+incorreta');
  res.cookie('circulo_admin',gerarToken({admin:true}),{httpOnly:true,maxAge:8*60*60*1000});
  res.redirect('/admin');
});
app.get('/admin/logout',(req,res)=>{res.clearCookie('circulo_admin');res.redirect('/admin/login');});

app.get('/admin',authAdmin,async(req,res)=>{
  const candidatos=await pool.query(`SELECT * FROM circulo_candidatos WHERE status='pendente' ORDER BY criado_em DESC`);
  const membros=await pool.query('SELECT * FROM circulo_resumo_membro ORDER BY membro_desde DESC');
  const linhaCand=candidatos.rows.map(c=>`<tr><td><strong>${c.nome}</strong><br><span style="font-size:11px;color:var(--muted)">${c.email}</span></td><td style="font-size:12px;">${(c.funcoes_desejadas||'membro').split(',').map(f=>`<span class="badge badge-gold" style="margin:2px;display:inline-block;">${f.trim()}</span>`).join('')}</td><td style="font-size:11px;color:var(--muted)">${new Date(c.criado_em).toLocaleDateString('pt-BR')}</td><td><form method="POST" action="/admin/candidatos/${c.id}/aprovar" style="display:inline"><button class="btn btn-primary" style="padding:6px 14px;font-size:10px;">Aprovar</button></form><form method="POST" action="/admin/candidatos/${c.id}/recusar" style="display:inline;margin-left:6px"><button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Recusar</button></form></td></tr>`).join('');
  const linhaMembros=membros.rows.map(m=>`<tr><td>${m.nome}</td><td style="color:var(--muted)">${m.codigo_membro||'—'}</td><td style="color:var(--muted)">${m.email}</td><td style="color:var(--gold)">R$ ${parseFloat(m.credito_disponivel).toFixed(2).replace('.',',')}</td><td>${m.obras_que_encontraram_lar}</td><td>${m.total_indicacoes}</td></tr>`).join('');
  res.send(html('Admin',`
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;"><h2 style="font-size:24px;">Painel do Círculo</h2><a href="/admin/logout" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Sair</a></div>
    <div class="grid-3" style="margin-bottom:32px;">
      <div class="stat-box"><div class="num">${candidatos.rows.length}</div><div class="lbl">Candidatos pendentes</div></div>
      <div class="stat-box"><div class="num">${membros.rows.length}</div><div class="lbl">Membros ativos</div></div>
      <div class="stat-box"><div class="num">${membros.rows.reduce((a,m)=>a+parseInt(m.obras_que_encontraram_lar||0),0)}</div><div class="lbl">Obras que encontraram lar</div></div>
    </div>
    ${candidatos.rows.length?`<div class="card" style="margin-bottom:24px;"><h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Candidatos pendentes</h3><table><thead><tr><th>Nome / E-mail</th><th>Funções desejadas</th><th>Data</th><th>Ação</th></tr></thead><tbody>${linhaCand}</tbody></table></div>`:''}
    <div class="card"><h3 style="font-size:18px;margin-bottom:20px;">Membros ativos</h3><table><thead><tr><th>Nome</th><th>Código</th><th>E-mail</th><th>Crédito</th><th>Obras</th><th>Indicações</th></tr></thead><tbody>${linhaMembros||'<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:24px;">Nenhum membro ainda</td></tr>'}</tbody></table></div>
    <div style="margin-top:16px;"><a href="/admin/sugestoes" class="btn btn-outline">Ver sugestões</a></div>
  `));
});

app.post('/admin/candidatos/:id/aprovar',authAdmin,async(req,res)=>{
  try{
    const {rows}=await pool.query('SELECT * FROM circulo_candidatos WHERE id=$1',[req.params.id]);
    if(!rows.length)return res.redirect('/admin');
    const c=rows[0];
    let dadosNF={};
    try{dadosNF=JSON.parse(c.como_conheceu||'{}');}catch{}
    let blingId=null;
    try{blingId=await criarContatoBling({nome:c.nome,email:c.email,...dadosNF});}catch(e){console.error('Bling:',e.message);}
    const token=gerarToken({tipo:'convite_aprovado',candidato_id:c.id,email:c.email});
    const link=`${BASE_URL}/ativar/${token}`;
    try{
      const mailer=nodemailer.createTransport({host:process.env.SMTP_HOST||'smtp.gmail.com',port:parseInt(process.env.SMTP_PORT||'587'),auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
      await mailer.sendMail({from:`"ALMARE" <${process.env.SMTP_USER}>`,to:c.email,subject:'Você foi convidado para o Círculo ALMARE',html:`<div style="background:#0a0a0a;color:#e8e8e8;padding:40px;font-family:Georgia,serif;"><h1 style="color:#c9a96e;font-size:28px;margin-bottom:24px;">Bem-vindo ao Círculo.</h1><p style="line-height:1.8;margin-bottom:24px;">Sua solicitação foi aprovada.</p><a href="${link}" style="display:inline-block;background:#c9a96e;color:#000;padding:14px 32px;text-decoration:none;font-size:13px;letter-spacing:.15em;text-transform:uppercase;">Criar minha conta</a><p style="margin-top:32px;font-size:12px;color:#666;">Este link expira em 7 dias.</p></div>`});
    }catch{}
    await pool.query(`UPDATE circulo_candidatos SET status='aprovado',respondido_em=NOW() WHERE id=$1`,[req.params.id]);
    res.send(html('Aprovado',`<div class="container-sm"><div class="msg-ok">Aprovado${blingId?' e cadastrado no Bling':' (Bling não configurado)'}.</div><div class="card"><p style="font-size:13px;margin-bottom:16px;">Link para enviar para <strong>${c.email}</strong>:</p><div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:12px;word-break:break-all;margin-bottom:16px;">${link}</div><button onclick="navigator.clipboard.writeText('${link}');this.textContent='Copiado ✓'" class="btn btn-outline" style="margin-right:8px">Copiar link</button><a href="/admin" class="btn btn-primary">Voltar ao painel</a></div></div>`));
  }catch(e){console.error(e);res.redirect('/admin');}
});

app.post('/admin/candidatos/:id/recusar',authAdmin,async(req,res)=>{
  await pool.query(`UPDATE circulo_candidatos SET status='recusado',respondido_em=NOW() WHERE id=$1`,[req.params.id]);
  res.redirect('/admin');
});

app.get('/admin/sugestoes',authAdmin,async(req,res)=>{
  const lista=await pool.query('SELECT s.*,m.nome as mn FROM circulo_sugestoes s JOIN circulo_membros m ON m.id=s.membro_id ORDER BY s.status ASC,s.criado_em DESC');
  const itens=lista.rows.map(s=>`<div style="padding:20px;border:1px solid var(--border);border-radius:4px;margin-bottom:12px;"><div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span style="font-size:12px;color:var(--gold)">${s.mn}</span><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${s.status}</span></div><p style="font-size:13px;margin-bottom:12px;">${s.texto}</p><form method="POST" action="/admin/sugestoes/${s.id}/responder" style="display:flex;gap:8px;flex-wrap:wrap;"><input name="resposta" placeholder="Resposta" value="${s.resposta||''}" style="flex:1;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><select name="status" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><option value="aberta" ${s.status==='aberta'?'selected':''}>Aberta</option><option value="em_analise" ${s.status==='em_analise'?'selected':''}>Em análise</option><option value="incorporada" ${s.status==='incorporada'?'selected':''}>Incorporada</option><option value="descartada" ${s.status==='descartada'?'selected':''}>Descartada</option></select><button type="submit" class="btn btn-primary" style="padding:8px 16px;">Salvar</button></form></div>`).join('');
  res.send(html('Sugestões',`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;"><h2 style="font-size:24px;">Sugestões dos membros</h2><a href="/admin" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">← Voltar</a></div>${itens||'<p style="color:var(--muted)">Nenhuma sugestão ainda.</p>'}`));
});

app.post('/admin/sugestoes/:id/responder',authAdmin,async(req,res)=>{
  const {resposta,status}=req.body;
  await pool.query('UPDATE circulo_sugestoes SET status=$1,resposta=$2,respondido_em=NOW() WHERE id=$3',[status,resposta||null,req.params.id]);
  if(status==='incorporada'){
    const s=await pool.query('SELECT * FROM circulo_sugestoes WHERE id=$1',[req.params.id]);
    if(s.rows.length)await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'sugestao_incorporada','Sua sugestão foi incorporada à curadoria ALMARE')`,[s.rows[0].membro_id]);
  }
  res.redirect('/admin/sugestoes');
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Círculo ALMARE rodando na porta ${PORT}`));
