// VERSAO-CLAUDE-XYZ789 — se voce ve este comentario no GitHub, o arquivo certo subiu
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const AdmZip = require('adm-zip');
const uploadFoto = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const app = express();
app.set('trust proxy', true); // essencial pro req.ip pegar o IP real do cliente (Railway fica atrás de proxy)
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const JWT_SECRET = process.env.JWT_SECRET || 'circulo-almare-secret-2026';
const ADMIN_SENHA = process.env.ADMIN_SENHA || 'admin123';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const BLING_CLIENT_ID = process.env.CIRCULO_BLING_CLIENT_ID;
const BLING_CLIENT_SECRET = process.env.CIRCULO_BLING_CLIENT_SECRET;
const BLING_REDIRECT_URI = process.env.CIRCULO_BLING_REDIRECT_URI || `${process.env.BASE_URL || ''}/auth/bling/callback`;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

function gerarToken(payload, opts) { return jwt.sign(payload, JWT_SECRET, opts || { expiresIn: '7d' }); }

// Rotas que precisam continuar acessíveis mesmo com cadastro incompleto — senão vira loop
const ROTAS_LIVRES_CADASTRO_INCOMPLETO = ['/completar-cadastro', '/logout'];

async function authMembro(req, res, next) {
  const token = req.cookies.circulo_token;
  if (!token) return res.redirect('/login');
  try { req.membro = jwt.verify(token, JWT_SECRET); }
  catch { res.clearCookie('circulo_token'); return res.redirect('/login'); }

  if (ROTAS_LIVRES_CADASTRO_INCOMPLETO.includes(req.path)) return next();
  try {
    const r = await pool.query('SELECT documento, cep, numero FROM circulo_membros WHERE id=$1',[req.membro.id]);
    if (r.rows.length && (!r.rows[0].documento || !r.rows[0].cep || !r.rows[0].numero)) {
      return res.redirect('/completar-cadastro');
    }
  } catch(e){ console.error('Checar cadastro completo:', e.message); }
  next();
}

function authAdmin(req, res, next) {
  const token = req.cookies.circulo_admin;
  if (!token) return res.redirect('/admin/login');
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.clearCookie('circulo_admin'); return res.redirect('/admin/login'); }
}

// ─── BLING (conexao propria e isolada do Circulo — nunca compartilhada com outro sistema) ──────
let _blingStateTemp = null;

app.get('/auth/bling/conectar', authAdmin, (req, res) => {
  _blingStateTemp = crypto.randomBytes(16).toString('hex');
  const url = `https://www.bling.com.br/Api/v3/oauth/authorize?response_type=code&client_id=${BLING_CLIENT_ID}&state=${_blingStateTemp}&redirect_uri=${encodeURIComponent(BLING_REDIRECT_URI)}`;
  res.redirect(url);
});

app.get('/auth/bling/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send('Código de autorização não recebido.');
    if (state !== _blingStateTemp) return res.status(400).send('Estado inválido — tenta conectar de novo pelo painel admin.');

    const creds = Buffer.from(`${BLING_CLIENT_ID}:${BLING_CLIENT_SECRET}`).toString('base64');
    const resp = await fetch('https://www.bling.com.br/Api/v3/oauth/token', {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: BLING_REDIRECT_URI })
    });
    const data = await resp.json();
    if (!data.access_token) return res.status(400).send('Erro ao obter token do Bling: ' + (data.error_description || data.error || 'desconhecido'));

    await pool.query(`
      INSERT INTO circulo_bling_config (id, access_token, refresh_token, expira_em, autorizado)
      VALUES (1, $1, $2, $3, TRUE)
      ON CONFLICT (id) DO UPDATE SET access_token=$1, refresh_token=$2, expira_em=$3, autorizado=TRUE
    `, [data.access_token, data.refresh_token, new Date(Date.now() + data.expires_in * 1000)]);

    res.redirect('/admin');
  } catch (e) {
    res.status(500).send('Erro ao conectar com o Bling: ' + e.message);
  }
});

async function getBlingToken() {
  const r = await pool.query('SELECT * FROM circulo_bling_config WHERE id=1');
  if (!r.rows.length || !r.rows[0].autorizado) throw new Error('Bling do Círculo não conectado. Vá em /admin e clique em Conectar Bling.');
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
    await pool.query('UPDATE circulo_bling_config SET access_token=$1, refresh_token=$2, expira_em=$3 WHERE id=1',
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
  const documentoLimpo = (dados.documento || '').replace(/\D/g, '');
  const isCNPJ = documentoLimpo.length > 11;

  const body = { nome: dados.nome, tipo: isCNPJ ? 'J' : 'F', situacao: 'A' };
  if (dados.email) body.email = dados.email;
  if (dados.telefone) body.telefone = dados.telefone;
  if (dados.celular) body.celular = dados.celular;
  if (documentoLimpo) body[isCNPJ ? 'cnpj' : 'cpf'] = documentoLimpo;
  if (dados.ie) body.ie = dados.ie;

  const enderecoLimpo = {};
  if (dados.endereco) enderecoLimpo.endereco = dados.endereco;
  if (dados.numero) enderecoLimpo.numero = dados.numero;
  if (dados.complemento) enderecoLimpo.complemento = dados.complemento;
  if (dados.bairro) enderecoLimpo.bairro = dados.bairro;
  if (dados.cep) enderecoLimpo.cep = dados.cep.replace(/\D/g, '');
  if (dados.cidade) enderecoLimpo.municipio = dados.cidade;
  if (dados.estado) enderecoLimpo.uf = dados.estado;
  if (Object.keys(enderecoLimpo).length) body.endereco = enderecoLimpo;

  if (blingId) {
    const resp = await fetch(`https://api.bling.com.br/Api/v3/contatos/${blingId}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const result = await resp.json();
    if (!resp.ok || result.error) {
      throw new Error(JSON.stringify(result));
    }
    return blingId;
  } else {
    const resp = await fetch('https://api.bling.com.br/Api/v3/contatos', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const result = await resp.json();
    if (!resp.ok || result.error) {
      throw new Error(JSON.stringify(result));
    }
    return result?.data?.id || null;
  }
}


// ─── BLING — sincroniza pedido de venda quando o pagamento é confirmado ──────
const MOLDURA_NOME_BLING = { preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço Escovado' };

// Garante que existe um produto no Bling pra essa combinação obra+tamanho+moldura.
// Busca pelo código antes de criar, pra nunca duplicar produto.
async function garantirProdutoBling(item){
  const token = await getBlingToken();
  const codigo = `${item.obra_codigo||'ALM'}-${String(item.tamanho_label||'').replace(/[^0-9x]/gi,'').toUpperCase()}-${(item.moldura||'preta').slice(0,3).toUpperCase()}`;

  const buscaResp = await fetch('https://api.bling.com.br/Api/v3/produtos?codigo='+encodeURIComponent(codigo), {
    headers: { 'Authorization': 'Bearer '+token }
  });
  const busca = await buscaResp.json();
  if(busca?.data?.length) return busca.data[0].id;

  const nome = `${item.obra_nome} — ${item.tamanho_label} — Moldura ${MOLDURA_NOME_BLING[item.moldura]||item.moldura}`;
  const criarResp = await fetch('https://api.bling.com.br/Api/v3/produtos', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer '+token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ nome, codigo, tipo:'P', situacao:'A', formato:'S', unidade:'UN', preco: parseFloat(item.preco_unitario) })
  });
  const criar = await criarResp.json();
  if(!criarResp.ok || criar.error) throw new Error('Erro ao criar produto no Bling: '+JSON.stringify(criar));
  return criar.data.id;
}

// Cria o pedido de venda no Bling pra um pedido do Círculo já pago. Idempotente —
// se já tiver sido sincronizado antes, não cria de novo.
async function sincronizarPedidoBling(pedidoId){
  const pedidoRes = await pool.query(`
    SELECT p.*, c.nome as cliente_nome, c.bling_id as cliente_bling_id, c.documento, c.email,
           c.telefone, c.celular, c.cep, c.endereco, c.numero, c.complemento, c.bairro, c.cidade, c.estado
    FROM circulo_pedidos p LEFT JOIN circulo_membros c ON c.id = p.cliente_membro_id
    WHERE p.id=$1`, [pedidoId]);
  const pedido = pedidoRes.rows[0];
  if(!pedido) throw new Error('Pedido não encontrado.');
  if(pedido.bling_pedido_id) return pedido.bling_pedido_id; // já sincronizado, não duplica

  let blingContatoId = pedido.cliente_bling_id;
  if(!blingContatoId){
    blingContatoId = await salvarContatoBling({
      nome: pedido.cliente_nome, documento: pedido.documento, email: pedido.email,
      telefone: pedido.telefone, celular: pedido.celular, cep: pedido.cep, endereco: pedido.endereco,
      numero: pedido.numero, complemento: pedido.complemento, bairro: pedido.bairro,
      cidade: pedido.cidade, estado: pedido.estado
    }, null);
    if(blingContatoId) await pool.query('UPDATE circulo_membros SET bling_id=$1 WHERE id=$2',[blingContatoId, pedido.cliente_membro_id]);
  }
  if(!blingContatoId) throw new Error('Não foi possível vincular o cliente ao Bling.');

  const itensRes = await pool.query(`
    SELECT pi.*, o.nome as obra_nome, o.codigo as obra_codigo
    FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id=pi.obra_id
    WHERE pi.pedido_id=$1`, [pedidoId]);
  if(!itensRes.rows.length) throw new Error('Pedido sem itens — nada pra sincronizar.');

  const itensBling = [];
  for(const it of itensRes.rows){
    const produtoId = await garantirProdutoBling({
      obra_codigo: it.obra_codigo, obra_nome: it.obra_nome, tamanho_label: it.tamanho_label,
      moldura: it.moldura, preco_unitario: it.preco_unitario
    });
    itensBling.push({ produto:{ id: produtoId }, quantidade: it.quantidade, valor: parseFloat(it.preco_unitario) });
  }

  const token = await getBlingToken();
  const hoje = new Date().toISOString().slice(0,10);
  const resp = await fetch('https://api.bling.com.br/Api/v3/pedidos/vendas', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer '+token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: hoje, contato: { id: blingContatoId }, itens: itensBling,
      observacoes: `Círculo ALMARE — Pedido ${pedido.numero}`
    })
  });
  const resultado = await resp.json();
  if(!resp.ok || resultado.error){
    await pool.query('UPDATE circulo_pedidos SET bling_erro=$1 WHERE id=$2',[JSON.stringify(resultado).slice(0,500), pedidoId]);
    throw new Error('Erro ao criar pedido de venda no Bling: '+JSON.stringify(resultado));
  }
  const blingPedidoId = resultado?.data?.id;
  await pool.query('UPDATE circulo_pedidos SET bling_pedido_id=$1, bling_erro=NULL WHERE id=$2',[blingPedidoId, pedidoId]);
  return blingPedidoId;
}

// Dispara a sincronização sem nunca travar a confirmação do pagamento — se o Bling
// falhar (ou não estiver conectado), só registra o erro, o pedido continua PAGO.
async function sincronizarPedidoBlingSeguro(pedidoId){
  try{
    await sincronizarPedidoBling(pedidoId);
  }catch(e){
    console.error('Sincronizar Bling pedido '+pedidoId+':', e.message);
    await pool.query('UPDATE circulo_pedidos SET bling_erro=$1 WHERE id=$2',[String(e.message).slice(0,500), pedidoId]).catch(()=>{});
  }
}


// ─── IMPACTO — cashback pro Embaixador/Especificador quando o pedido é confirmado ──
// Embaixador: 5% cashback. Especificador: 10% cashback. Um lançamento por obra vendida
// (não por pedido inteiro), com carência de 10 dias antes de virar saldo sacável.
async function concederBonusPedido(pedidoId){
  try{
    const pedidoRes = await pool.query('SELECT * FROM circulo_pedidos WHERE id=$1',[pedidoId]);
    const pedido = pedidoRes.rows[0];
    if(!pedido) return;

    // Já concedeu bônus pra esse pedido? Nunca concede duas vezes.
    const jaExiste = await pool.query('SELECT 1 FROM circulo_transacoes WHERE pedido_id=$1 LIMIT 1',[pedidoId]);
    if(jaExiste.rows.length) return;

    const funcoes = await pool.query(
      `SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,
      [pedido.membro_id]
    );
    const slugs = funcoes.rows.map(r=>r.slug);
    let taxa = null;
    if(slugs.includes('especificador')) taxa = 0.10;
    else if(slugs.includes('embaixador')) taxa = 0.05;
    if(!taxa) return; // quem processou não tem função que gera cashback

    const itensRes = await pool.query('SELECT * FROM circulo_pedido_itens WHERE pedido_id=$1',[pedidoId]);
    if(!itensRes.rows.length) return;

    const disponivelEm = new Date(Date.now() + 10*24*60*60*1000);

    for(const item of itensRes.rows){
      const valorBeneficio = Math.round(parseFloat(item.subtotal) * taxa * 100) / 100;
      await pool.query(
        `INSERT INTO circulo_transacoes (membro_id, obra_id, pedido_id, valor_obra, modalidade, percentual, valor_beneficio, status, disponivel_em)
         VALUES ($1,$2,$3,$4,'cashback',$5,$6,'pendente',$7)`,
        [pedido.membro_id, item.obra_id, pedidoId, item.subtotal, taxa, valorBeneficio, disponivelEm]
      );
      await pool.query(
        'UPDATE circulo_saldo_credito SET saldo_total = saldo_total + $1 WHERE membro_id=$2',
        [valorBeneficio, pedido.membro_id]
      );
    }
  }catch(e){
    console.error('Conceder bônus pedido '+pedidoId+':', e.message);
  }
}

// Solta pro saldo disponível qualquer bônus que já passou dos 10 dias de carência.
// Chamado sempre que o membro abre a tela de Impacto — sem depender de cron.
async function liberarBonusVencidos(membroId){
  try{
    const vencidos = await pool.query(
      `UPDATE circulo_transacoes SET status='pago' WHERE membro_id=$1 AND status='pendente' AND disponivel_em <= NOW() RETURNING valor_beneficio`,
      [membroId]
    );
    if(vencidos.rows.length){
      const soma = vencidos.rows.reduce((s,r)=>s+parseFloat(r.valor_beneficio),0);
      await pool.query('UPDATE circulo_saldo_credito SET saldo_disponivel = saldo_disponivel + $1 WHERE membro_id=$2',[soma, membroId]);
    }
  }catch(e){ console.error('Liberar bonus vencidos:', e.message); }
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
  const sairHtml = nav ? `<a href="/logout" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--danger);margin-top:12px;display:inline-block">Sair</a>` : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${titulo} — Círculo ALMARE</title><style>${CSS}</style></head>
  <body><div class="container"><header><div class="logo">ALMARE</div><div class="logo-sub">Círculo</div><div style="text-align:right">${sairHtml}</div></header>${corpo}</div></body></html>`;
}

async function ehEspecificador(membroId) {
  const r = await pool.query(`
    SELECT 1 FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id
    WHERE mf.membro_id=$1 AND mf.ativo=true AND f.slug='especificador' LIMIT 1`, [membroId]);
  return r.rows.length > 0;
}

async function temFuncaoComImpacto(membroId) {
  const r = await pool.query(`
    SELECT 1 FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id
    WHERE mf.membro_id=$1 AND mf.ativo=true AND f.slug IN ('embaixador','especificador','artista','colaborador') LIMIT 1`, [membroId]);
  return r.rows.length > 0;
}

function navBar(ativo, temImpacto=false, ehEspec=false) {
  const base = [
    { key: 'passaporte', href: '/portal', label: 'Passaporte' },
    { key: 'portfolio', href: '/portfolio', label: 'Portfólio' },
    { key: 'obras', href: '/catalogo', label: 'Obras' },
    { key: 'simulador', href: '/simulador', label: 'Simulador' },
    { key: 'identificar', href: '/identificar', label: 'Identificar' },
    { key: 'carrinho', href: '/carrinho', label: 'Carrinho' },
    { key: 'pedidos', href: '/meus-pedidos', label: 'Pedidos' },
    { key: 'meusdados', href: '/meus-dados', label: 'Meus dados' },
  ];
  const especLink = ehEspec ? [{ key: 'modelos3d', href: '/modelos-3d', label: 'Modelos 3D' }] : [];
  const impacto = temImpacto ? [{ key: 'impacto', href: '/meu-impacto', label: 'Impacto' }] : [];
  const indicacoes = [{ key: 'indicacoes', href: '/minhas-indicacoes', label: 'Indicações' }];
  const fim = [
    { key: 'voz', href: '/sugestoes', label: 'Voz' },
    { key: 'convidar', href: '/meu-convite', label: 'Convidar' },
  ];
  const item = l => `<a href="${l.href}" class="nav-link${ativo===l.key?' ativo':''}">${l.label}</a>`;
  const funcoesDestaque = `<a href="/minhas-funcoes" class="nav-link nav-link-destaque${ativo==='funcoes'?' ativo':''}">Funções</a>`;
  return `<div class="nav-bar">${base.map(item).join('')}${especLink.map(item).join('')}${impacto.map(item).join('')}${indicacoes.map(item).join('')}${fim.map(item).join('')}${funcoesDestaque}</div>`;
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
      `INSERT INTO circulo_membros (nome,email,senha_hash,status,aprovado_em,codigo_membro,documento,ie,telefone,celular,cep,endereco,numero,complemento,bairro,cidade,estado)
       VALUES ($1,$2,$3,'ativo',NOW(),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
      [nome, email, hash, codigo, documento||null, ie||null, telefone||null, celular||null, cep||null, endereco||null, numero||null, complemento||null, bairro||null, cidade||null, estado||null]
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
      SELECT f.nome, f.slug, f.descricao, mf.ativo FROM circulo_membro_funcoes mf
      JOIN circulo_funcoes f ON f.id=mf.funcao_id
      WHERE mf.membro_id=$1`,[req.membro.id]);
    const convite=await pool.query('SELECT codigo FROM circulo_convites WHERE membro_id=$1 LIMIT 1',[req.membro.id]);
    const eventos=await pool.query('SELECT * FROM circulo_passaporte_eventos WHERE membro_id=$1 ORDER BY data_evento DESC LIMIT 10',[req.membro.id]);
    const link=convite.rows.length?`${BASE_URL}/convite/${convite.rows[0].codigo}`:'';
    const data=m.membro_desde?new Date(m.membro_desde).toLocaleDateString('pt-BR',{month:'long',year:'numeric'}):'';

    const funcoesAtivas = funcoes.rows.filter(f=>f.ativo);
    const funcoesCards = funcoesAtivas.map(f=>`
      <div style="background:linear-gradient(135deg,rgba(212,175,55,.12),rgba(212,175,55,.03));border:1px solid var(--gold);border-radius:6px;padding:14px 18px;">
        <div style="font-family:'Cormorant Garamond',serif;font-size:18px;color:var(--gold);margin-bottom:3px;">${f.nome}</div>
        ${f.descricao ? `<div style="font-size:12px;color:var(--muted);">${f.descricao}</div>` : ''}
      </div>`).join('');
    // Membro sempre aparece

    const evHtml=eventos.rows.map(e=>`<div style="padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;"><span>${e.descricao}</span><span style="float:right;font-size:11px;color:var(--muted)">${new Date(e.data_evento).toLocaleDateString('pt-BR')}</span></div>`).join('');
    const temFuncaoExtra = funcoes.rows.some(f=>f.ativo && ['embaixador','especificador','artista','colaborador'].includes(f.slug));

    res.send(html('Portal',`
      ${navBar('passaporte', temFuncaoExtra, funcoes.rows.some(f=>f.ativo && f.slug==='especificador'))}
      <div class="card" style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
          <div>
            <h2 style="font-size:26px;margin-bottom:4px;">${m.nome||req.membro.nome}</h2>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Membro desde ${data} · ${m.codigo_membro||''}</div>
          </div>
        </div>
      </div>
      <div style="margin-bottom:24px;">
        <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Suas funções no Círculo</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;">
          ${funcoesCards || '<div style="padding:14px 18px;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-size:13px;">Nenhuma função ativa ainda.</div>'}
        </div>
        <a href="/minhas-funcoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--gold);display:inline-block;margin-top:12px;">+ Gerenciar funções</a>
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
// ─── MEUS DADOS — membro edita email, telefone e endereço (nunca nome/CPF) ────
// ─── PORTFÓLIO — obras que o membro possui de verdade (registradas em seu nome) ──
// Vínculo é pelo e-mail no cadastro do certificado (almare_exemplares.cliente_email),
// não pelo pagamento — cobre doações/fragmentos que não passam pelo checkout.
app.get('/portfolio', authMembro, async(req,res)=>{
  const fRows = await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
  const slugs = fRows.rows.map(r=>r.slug);
  const temImpacto = slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s));
  const ehEspec = slugs.includes('especificador');

  const r = await pool.query(`
    SELECT e.id as exemplar_id, e.numero, e.tamanho, e.tecnica_impressao, e.data_venda, e.arca_codigo,
           o.id as obra_id, o.codigo, o.nome, o.colecao, o.imagem_preview, o.tiragem_total, o.essencia,
           reg.codigo_arca, reg.token_verificacao, reg.ano
    FROM almare_exemplares e
    JOIN almare_obras o ON o.id = e.obra_id
    JOIN arca_registros reg ON reg.exemplar_id = e.id
    WHERE LOWER(e.cliente_email) = LOWER($1)
    ORDER BY e.data_venda DESC NULLS LAST, e.created_at DESC`, [req.membro.email]);

  const pecas = r.rows.map(p=>{
    const totalTiragem = p.tiragem_total || null;
    const peca = totalTiragem ? `Peça ${p.numero} de ${totalTiragem}` : (p.numero ? `Exemplar nº ${p.numero}` : '');
    const codigoArca = p.codigo_arca || p.arca_codigo || null;
    const qrUrl = p.token_verificacao
      ? `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent('https://almare-production.up.railway.app/arca/verificar/'+p.token_verificacao)}`
      : null;
    const dataAquisicao = p.data_venda ? new Date(p.data_venda).toLocaleDateString('pt-BR') : null;
    // Peça 001 é mantida em sigilo — nunca mostra a foto no portfólio, só ela.
    const sigilo = (p.codigo === 'ALM-001');

    return `
      <div class="card" style="margin-bottom:24px;overflow:hidden;padding:0;">
        <div style="background:#0d0d0d;text-align:center;${sigilo?'padding:60px 24px;':''}">
          ${sigilo
            ? `<div style="color:var(--muted);font-size:11px;letter-spacing:.15em;text-transform:uppercase;">Imagem mantida em sigilo</div>`
            : (p.imagem_preview?`<img src="${esc(p.imagem_preview)}" style="max-width:100%;max-height:420px;display:inline-block;">`:'')
          }
        </div>
        <div style="padding:24px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:8px;flex-wrap:wrap;">
            <div>
              <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${esc(p.colecao||'')}</div>
              <h3 style="font-family:'Cormorant Garamond',serif;font-size:26px;">${esc(p.nome)}</h3>
            </div>
            ${peca?`<span class="badge badge-gold">${esc(peca)}</span>`:''}
          </div>
          ${p.essencia?`<p style="font-style:italic;color:var(--gold-light);font-size:14px;margin:12px 0;">${esc(p.essencia)}</p>`:''}
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px 24px;font-size:13px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border);">
            ${p.tamanho?`<div><span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;">Tamanho</span><br>${esc(p.tamanho)}</div>`:''}
            ${p.tecnica_impressao?`<div><span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;">Técnica</span><br>${esc(p.tecnica_impressao)}</div>`:''}
            ${codigoArca?`<div><span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;">Código ARCA</span><br>${esc(codigoArca)}</div>`:''}
            ${dataAquisicao?`<div><span style="color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;">Desde</span><br>${esc(dataAquisicao)}</div>`:''}
          </div>
          ${qrUrl?`
            <div style="display:flex;align-items:center;gap:14px;margin-top:20px;padding-top:20px;border-top:1px solid var(--border);">
              <img src="${qrUrl}" style="width:72px;height:72px;border-radius:4px;background:#fff;padding:4px;">
              <div style="font-size:12px;color:var(--muted);">Escaneie para verificar a autenticidade desta obra no registro ARCA.</div>
            </div>`:''}
        </div>
      </div>`;
  }).join('');

  res.send(html('Meu Portfólio',`
    ${navBar('portfolio', temImpacto, ehEspec)}
    <h2 style="font-size:28px;margin-bottom:8px;">Meu Portfólio</h2>
    <p style="color:var(--muted);margin-bottom:32px;">As obras registradas em seu nome — sua coleção pessoal ALMARE.</p>
    ${pecas || '<div class="card" style="text-align:center;padding:48px 24px;"><p style="color:var(--muted);">Você ainda não tem nenhuma obra registrada em seu nome.</p></div>'}
  `,true));
});

// ─── COMPLETAR CADASTRO — obrigatório para quem se cadastrou antes de CPF/endereço
// existirem no formulário. Bloqueia o resto do sistema até preencher. ────────────
app.get('/completar-cadastro', authMembro, async(req,res)=>{
  const r = await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[req.membro.id]);
  const m = r.rows[0];
  res.send(html('Complete seu cadastro',`
    <div class="msg-info" style="margin-bottom:24px;">Seu cadastro está incompleto. Preencha os dados abaixo para continuar usando o Círculo ALMARE — são necessários para emissão de certificado e nota fiscal.</div>
    ${req.query.erro?`<div class="msg-erro">${esc(req.query.erro)}</div>`:''}
    <div class="card">
      <div class="field"><label>Nome</label><input value="${esc(m.nome)}" disabled style="opacity:.5"></div>
      <form method="POST" action="/completar-cadastro">
        <div class="field"><label>CPF / CNPJ *</label><input name="documento" required value="${esc(m.documento||'')}" placeholder="CPF ou CNPJ"></div>
        <div class="grid-2">
          <div class="field"><label>Telefone</label><input name="telefone" value="${esc(m.telefone||'')}"></div>
          <div class="field"><label>Celular / WhatsApp *</label><input name="celular" required value="${esc(m.celular||'')}"></div>
        </div>
        <hr class="divider">
        <h3 style="font-size:18px;margin-bottom:20px;">Endereço</h3>
        <div class="grid-2">
          <div class="field"><label>CEP *</label><input name="cep" id="cep" required value="${esc(m.cep||'')}" oninput="buscarCepCompletar(this.value)"></div>
          <div class="field"><label>Estado</label><input name="estado" id="estado" maxlength="2" value="${esc(m.estado||'')}"></div>
        </div>
        <div class="field"><label>Endereço</label><input name="endereco" id="endereco" value="${esc(m.endereco||'')}"></div>
        <div class="grid-2">
          <div class="field"><label>Número *</label><input name="numero" id="numero" required value="${esc(m.numero||'')}"></div>
          <div class="field"><label>Complemento</label><input name="complemento" id="complemento" value="${esc(m.complemento||'')}"></div>
        </div>
        <div class="grid-2">
          <div class="field"><label>Bairro</label><input name="bairro" id="bairro" value="${esc(m.bairro||'')}"></div>
          <div class="field"><label>Cidade</label><input name="cidade" id="cidade" value="${esc(m.cidade||'')}"></div>
        </div>
        <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px;">Salvar e continuar</button>
      </form>
    </div>
    <script>
      async function buscarCepCompletar(v){
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
        }catch{}
      }
    </script>
  `));
});

app.post('/completar-cadastro', authMembro, async(req,res)=>{
  const { documento, telefone, celular, cep, endereco, numero, complemento, bairro, cidade, estado } = req.body;
  try{
    if(!documento || !documento.trim()) return res.redirect('/completar-cadastro?erro=CPF/CNPJ+é+obrigatório');
    if(!cep || !numero) return res.redirect('/completar-cadastro?erro=CEP+e+número+são+obrigatórios');
    await pool.query(
      `UPDATE circulo_membros SET documento=$1,telefone=$2,celular=$3,cep=$4,endereco=$5,numero=$6,complemento=$7,bairro=$8,cidade=$9,estado=$10 WHERE id=$11`,
      [documento.trim(), telefone||null, celular||null, cep, endereco||null, numero, complemento||null, bairro||null, cidade||null, estado||null, req.membro.id]
    );
    // Sincroniza com o Bling em segundo plano — nunca bloqueia o cadastro se falhar
    try{
      const m = await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[req.membro.id]);
      const mm = m.rows[0];
      await salvarContatoBling({
        nome: mm.nome, email: mm.email, documento: mm.documento, ie: mm.ie,
        telefone: mm.telefone, celular: mm.celular, cep: mm.cep, endereco: mm.endereco,
        numero: mm.numero, complemento: mm.complemento, bairro: mm.bairro, cidade: mm.cidade, estado: mm.estado
      }, mm.bling_id || null);
    }catch(e){ console.error('Sync Bling completar-cadastro:', e.message); }
    res.redirect('/portal');
  }catch(e){
    res.redirect('/completar-cadastro?erro='+encodeURIComponent(e.message));
  }
});

app.get('/meus-dados', authMembro, async(req,res)=>{
  const r = await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[req.membro.id]);
  const m = r.rows[0];
  res.send(html('Meus dados',`
    ${navBar('meusdados', await temFuncaoComImpacto(req.membro.id), await ehEspecificador(req.membro.id))}
    <h2 style="font-size:28px;margin-bottom:8px;">Meus dados</h2>
    <p style="color:var(--muted);margin-bottom:28px;">Você pode atualizar seu contato e endereço a qualquer momento. Nome e CPF/CNPJ não podem ser alterados por aqui — se precisar corrigi-los, fale com a ALMARE.</p>
    ${req.query.ok?'<div class="msg-ok">Dados atualizados com sucesso.</div>':''}
    ${req.query.erro?`<div class="msg-erro">${esc(req.query.erro)}</div>`:''}
    <div class="card">
      <div class="field"><label>Nome</label><input value="${esc(m.nome)}" disabled style="opacity:.5"></div>
      <div class="field"><label>CPF / CNPJ</label><input value="${esc(m.documento||'—')}" disabled style="opacity:.5"></div>
      <hr class="divider">
      <form method="POST" action="/meus-dados">
        <div class="field"><label>E-mail *</label><input type="email" name="email" required value="${esc(m.email)}"></div>
        <div class="grid-2">
          <div class="field"><label>Telefone</label><input name="telefone" value="${esc(m.telefone||'')}" placeholder="(00) 0000-0000"></div>
          <div class="field"><label>Celular / WhatsApp</label><input name="celular" value="${esc(m.celular||'')}" placeholder="(00) 00000-0000"></div>
        </div>
        <hr class="divider">
        <h3 style="font-size:18px;margin-bottom:20px;">Endereço</h3>
        <div class="grid-2">
          <div class="field"><label>CEP</label><input name="cep" id="cep" value="${esc(m.cep||'')}" oninput="buscarCepDados(this.value)"></div>
          <div class="field"><label>Estado</label><input name="estado" id="estado" maxlength="2" value="${esc(m.estado||'')}"></div>
        </div>
        <div class="field"><label>Endereço</label><input name="endereco" id="endereco" value="${esc(m.endereco||'')}"></div>
        <div class="grid-2">
          <div class="field"><label>Número</label><input name="numero" id="numero" value="${esc(m.numero||'')}"></div>
          <div class="field"><label>Complemento</label><input name="complemento" id="complemento" value="${esc(m.complemento||'')}"></div>
        </div>
        <div class="grid-2">
          <div class="field"><label>Bairro</label><input name="bairro" id="bairro" value="${esc(m.bairro||'')}"></div>
          <div class="field"><label>Cidade</label><input name="cidade" id="cidade" value="${esc(m.cidade||'')}"></div>
        </div>
        <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px;">Salvar alterações</button>
      </form>
    </div>
    <script>
      async function buscarCepDados(v){
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
        }catch{}
      }
    </script>
  `,true));
});

app.post('/meus-dados', authMembro, async(req,res)=>{
  const { email, telefone, celular, cep, endereco, numero, complemento, bairro, cidade, estado } = req.body;
  try{
    if(!email || !email.trim()) return res.redirect('/meus-dados?erro=E-mail+é+obrigatório');
    const dup = await pool.query('SELECT id FROM circulo_membros WHERE email=$1 AND id<>$2',[email.trim(), req.membro.id]);
    if(dup.rows.length) return res.redirect('/meus-dados?erro=Este+e-mail+já+está+em+uso+por+outra+conta');

    await pool.query(
      `UPDATE circulo_membros SET email=$1,telefone=$2,celular=$3,cep=$4,endereco=$5,numero=$6,complemento=$7,bairro=$8,cidade=$9,estado=$10 WHERE id=$11`,
      [email.trim(), telefone||null, celular||null, cep||null, endereco||null, numero||null, complemento||null, bairro||null, cidade||null, estado||null, req.membro.id]
    );

    // Atualiza também no Bling (melhor esforço — nunca bloqueia o salvamento local)
    try{
      const m = await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[req.membro.id]);
      const mm = m.rows[0];
      await salvarContatoBling({
        nome: mm.nome, email: mm.email, documento: mm.documento, ie: mm.ie,
        telefone: mm.telefone, celular: mm.celular, cep: mm.cep, endereco: mm.endereco,
        numero: mm.numero, complemento: mm.complemento, bairro: mm.bairro, cidade: mm.cidade, estado: mm.estado
      }, mm.bling_id || null);
    }catch(e){ console.error('Sync Bling meus-dados:', e.message); }

    // Se o e-mail mudou, renova o token com o e-mail novo
    const token = gerarToken({id:req.membro.id, nome:req.membro.nome, email: email.trim()});
    res.cookie('circulo_token', token, {httpOnly:true, maxAge:7*24*60*60*1000});
    res.redirect('/meus-dados?ok=1');
  }catch(e){
    res.redirect('/meus-dados?erro='+encodeURIComponent(e.message));
  }
});

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
    ${navBar('funcoes', funcoes.rows.some(f=>f.ativo && ['embaixador','especificador','artista','colaborador'].includes(f.slug)), funcoes.rows.some(f=>f.ativo && f.slug==='especificador'))}
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
  ],
  '16:9': [
    {largura:265, altura:150, preco:5390}, {largura:150, altura:265, preco:5390},
  ],
};

function tamanhosOficiais(formatoRecomendado, raw){
  const bruto = String(formatoRecomendado||'').trim();
  const chave = bruto.replace(/\s+/g,'').replace(/\(adaptar\)/i,'').trim();

  const fmt = arr => arr.map(t => ({...t, label: `${t.largura}×${t.altura}cm`, precoLabel: `R$ ${t.preco.toLocaleString('pt-BR')}`}));

  // Match direto na tabela oficial (1:1, 3:2, 16:9 exatos)
  if(TABELA_TAMANHOS_POR_FORMATO[chave]){
    return fmt(TABELA_TAMANHOS_POR_FORMATO[chave]);
  }
  // 2:3 e 9:16 são as versões verticais de 3:2 e 16:9 (mesma tabela, o filtro de orientação cuida do resto)
  if(chave === '2:3') return fmt(TABELA_TAMANHOS_POR_FORMATO['3:2']);
  if(chave === '9:16') return fmt(TABELA_TAMANHOS_POR_FORMATO['16:9']);

  // Formato "(adaptar)" ou proporção exótica: extrai a razão e escolhe a família mais próxima
  const m = bruto.match(/([\d.]+)\s*:\s*([\d.]+)/);
  if(m){
    let razao = parseFloat(m[1]) / parseFloat(m[2]);
    if(razao < 1) razao = 1/razao; // normaliza vertical pra comparar proporção (1.5, 1.78, etc)
    // famílias produzíveis por razão: 1:1 (1.0), 3:2 (1.5), 16:9 (1.78)
    const familias = [['1:1',1.0],['3:2',1.5],['16:9',265/150]];
    familias.sort((a,b)=>Math.abs(razao-a[1])-Math.abs(razao-b[1]));
    return fmt(TABELA_TAMANHOS_POR_FORMATO[familias[0][0]]);
  }

  // Sem formato reconhecível — assume 3:2 como padrão do catálogo (maioria retangular)
  return fmt(TABELA_TAMANHOS_POR_FORMATO['3:2']);
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

ATENÇÃO ESPECIAL À LARGURA HORIZONTAL — REGRA CRÍTICA E OBRIGATÓRIA: Por padrão, "left_pct" deve ser próximo de 0 e "width_pct" próximo de 100 — ou seja, a bbox cobre QUASE A LARGURA INTEIRA da foto. Você só deve reduzir a largura da bbox nos casos abaixo:

(a) uma PORTA (que vai do chão até a altura de porta) — nesse caso comece a bbox depois da porta;
(b) um móvel que vai literalmente do CHÃO ATÉ O TETO (armário alto fechado, estante que encosta no teto, painel de parede inteiro).

NUNCA reduza a largura da bbox por causa de: estantes de prateleiras abertas/vazadas (mesmo que altas), aparadores, racks de TV, bancadas, cômodas, sofás, mesas, luminárias, ou qualquer móvel que tenha PAREDE VISÍVEL acima dele. Esses móveis têm parede livre em cima e o quadro pode ser pendurado acima deles usando a largura toda. Uma estante de prateleiras abertas (onde se vê a parede preta/colorida atrás das prateleiras) NÃO bloqueia a parede — ela é vazada, a parede continua ali.

EXEMPLO CONCRETO: numa foto com uma porta de madeira à esquerda, parede branca no meio, e uma estante de prateleiras abertas à direita com um aparador baixo embaixo — a bbox deve ir da borda direita da porta até a borda direita da FOTO (cobrindo por cima da estante vazada e do aparador), porque só a porta bloqueia. A largura seria algo como left_pct:12, width_pct:85. É ERRADO parar a bbox antes da estante (algo como width_pct:45) — isso espreme o quadro no meio e está errado.

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
// ─── HELPERS para indicação/e-commerce ────────────────────────────────────────
function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function gerarCodigo(){ return crypto.randomBytes(5).toString('hex'); }
// Só Embaixador ou Especificador (ativos) podem gerar link de indicação de obra
async function podeIndicarObra(membroId){
  const r = await pool.query(
    `SELECT 1 FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id
     WHERE mf.membro_id=$1 AND mf.ativo=true AND f.slug IN ('embaixador','especificador') LIMIT 1`,
    [membroId]
  );
  return r.rows.length > 0;
}

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
    // LIMITE FÍSICO DE ALTURA: centro do quadro fica a 160cm do chão, e precisa de 20cm de folga
    // até o teto. Logo a altura máxima do quadro = (altura_parede - 160 - 20) * 2.
    // Um quadro mais alto que isso não cabe fisicamente e deve ser eliminado.
    const alturaMaxObra = Math.max(0, (paredeA - 160 - 20) * 2);
    if(alturaMaxObra > 0){
      const cabemNaAltura = tamanhos.filter(t => t.altura <= alturaMaxObra);
      if(cabemNaAltura.length) tamanhos = cabemNaAltura;
      // se NENHUM tamanho cabe na altura, a obra inteira é incompatível — marca pra descarte
      else tamanhos = [];
    }
    // LIMITE FÍSICO DE LARGURA: o quadro nunca pode ser mais largo que a parede.
    // Elimina de verdade os tamanhos que não cabem (não mantém por fallback).
    const larguraMaxObra = paredeL; // largura da parede é o teto absoluto
    if(tamanhos.length && larguraMaxObra > 0){
      tamanhos = tamanhos.filter(t => t.largura <= larguraMaxObra);
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
      : (tamanhos[0] || null);
    // Obra sem nenhum tamanho que caiba fisicamente na parede — descarta com score muito negativo
    if(!melhorTamanho){
      return { ...o, _score:-999, _melhorTamanho:null, _motivos:[], _tamanhosCabem:[] };
    }
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

    return { ...o, _score:score, _melhorTamanho:melhorTamanho, _motivos:motivos, _tamanhosCabem:tamanhos };
  })
  .filter(o=>o._melhorTamanho && o._score > -900) // só obras com tamanho que cabe fisicamente
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
    ${navBar('simulador', !!navImpacto, slugs.includes('especificador'))}
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
      <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">← Voltar ao portal</a>
      <a href="/simulador/minhas" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Minhas simulações</a>
    </div>
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

      // Se veio ?abrir=ID na URL, carrega uma simulação salva direto
      (function(){
        const params = new URLSearchParams(window.location.search);
        const abrirId = params.get('abrir');
        if(abrirId){
          document.addEventListener('DOMContentLoaded', async ()=>{
            const formEl = document.getElementById('form-sim');
            if(formEl) formEl.style.display='none';
            const load = document.getElementById('loading');
            if(load) load.style.display='block';
            try{
              const r = await fetch('/simulador/salva/'+abrirId);
              const d = await r.json();
              if(load) load.style.display='none';
              if(d.erro){ document.getElementById('resultado').innerHTML='<div class="msg-erro">'+d.erro+'</div>'; return; }
              // Normaliza simulações salvas ANTES desta mudança (formato antigo: obra/tamanho
              // direto no card) para o formato novo (lista de peças por composição).
              const cardsNormalizados = d.cards.map(c => c.pecas ? c : { pecas: [c] });
              renderResultado({
                analise: d.analise || { parede_bbox:{left_pct:5,top_pct:5,width_pct:90,height_pct:90}, moldura_recomendada:'preta', paleta_dominante:'', temperatura:'', estilo:'', carga_visual:'', justificativa_ambiente:'' },
                sugestoes: cardsNormalizados.map(c=>({ ...c.pecas[0].obra, _melhorTamanho:c.pecas[0].tamanho, _tamanhosDisponiveis:c.pecas[0].obra._tamanhosDisponiveis })),
                watermark: d.watermark || '',
                foto_local: d.foto_local,
                parede_largura: d.parede_largura,
                parede_altura: d.parede_altura,
                _cardsRestore: cardsNormalizados
              });
            }catch(e){ if(load) load.style.display='none'; }
          });
        }
      })();

      function renderResultado(data){
        document.getElementById('resultado').innerHTML = '';
        SIM.data = data;
        const a = data.analise;
        const sugestoes = (data.sugestoes || []).slice(0, 3);

        // Cada sugestão agora guarda uma LISTA de peças (uma ou várias obras compondo a
        // mesma parede/foto). Por padrão começa com 1 peça (a sugestão da curadoria).
        SIM.cards = sugestoes.map((o,idx) => {
          const restore = (data._cardsRestore && data._cardsRestore[idx]) ? data._cardsRestore[idx] : null;
          if(restore && restore.pecas && restore.pecas.length){
            return { pecas: restore.pecas };
          }
          return {
            pecas: [{ obra:o, tamanho:o._melhorTamanho, moldura: a.moldura_recomendada || 'preta' }]
          };
        });

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
        html += '<p style="font-size:12px;color:var(--muted);margin-bottom:20px;">Nossa curadoria escolheu estas três. Em cada uma você pode ajustar tamanho, trocar a obra, ou incluir mais obras para montar uma composição na mesma parede.</p>';

        html += '<div id="cards-container">';
        SIM.cards.forEach((c,i)=>{ html += '<div id="card-slot-'+i+'"></div>'; });
        html += '</div>';

        html += '<div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap;">';
        html += '<button onclick="abrirSalvar()" class="btn btn-outline" style="flex:1;min-width:180px;">Salvar esta simulação</button>';
        html += '<button onclick="location.reload()" class="btn btn-outline" style="flex:1;min-width:180px;">Simular outro ambiente</button>';
        html += '</div>';

        document.getElementById('resultado').innerHTML = html;
        SIM.cards.forEach((c,i)=> montarCard(i));
      }

      // Mostra o preço só quando a pessoa pede — e só da sugestão que ela está olhando.
      // Cada sugestão é uma simulação independente; nunca soma entre sugestões diferentes.
      function verOrcamento(i){
        const c = SIM.cards[i];
        let total = 0;
        let linhas = '';
        c.pecas.forEach(p=>{
          if(p.tamanho && p.tamanho.preco){
            total += p.tamanho.preco;
            linhas += '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;">';
            linhas += '<span>'+p.obra.nome+' <span style="color:var(--muted);">· '+p.tamanho.label+'</span></span>';
            linhas += '<span style="color:var(--gold);">R$ '+p.tamanho.preco.toLocaleString('pt-BR')+'</span>';
            linhas += '</div>';
          }
        });
        const html =
          '<div class="card" style="border-color:var(--gold);margin-top:10px;">' +
          '<h3 style="font-size:16px;margin-bottom:14px;">Orçamento desta sugestão</h3>' +
          linhas +
          '<div style="display:flex;justify-content:space-between;align-items:center;padding-top:14px;margin-top:6px;">' +
          '<span style="font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total</span>' +
          '<span style="font-family:\\'Cormorant Garamond\\',serif;font-size:24px;color:var(--gold);">R$ '+total.toLocaleString('pt-BR')+'</span>' +
          '</div></div>';
        document.getElementById('orcamento-area-'+i).innerHTML = html;
      }

      // Desenha (ou redesenha) o card i — uma sugestão pode ter várias peças (composição)
      // dentro da MESMA foto/simulação.
      function montarCard(i){
        const data = SIM.data;
        const a = data.analise;
        const c = SIM.cards[i];
        const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};
        const coresMoldura = { preta:'#1a1a1a', carvalho:'#5c4a2e', aco_escovado:'#9a9a9a' };

        const bbox = a.parede_bbox;
        const bx = (bbox && typeof bbox.left_pct==='number') ? bbox : {left_pct:15, top_pct:10, width_pct:70, height_pct:75};
        const larguraRealParede = parseInt(data.parede_largura) || 300;
        const alturaParedeCm = parseInt(data.parede_altura) || 270;
        const centroXpadrao = bx.left_pct + bx.width_pct/2;
        const centroYpadrao = Math.max(12, Math.min(88, ((alturaParedeCm - 160) / alturaParedeCm) * 100));
        const numPecas = c.pecas.length;

        let html = '<div class="card" style="margin-bottom:24px;">';
        const scoreRef = c.pecas[0] && c.pecas[0].obra ? c.pecas[0].obra._score : null;
        html += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;"><span class="badge badge-gold">'+(i+1)+'ª sugestão</span>'+(scoreRef?'<span style="font-size:11px;color:var(--muted);">'+Math.round(scoreRef)+' pontos de compatibilidade</span>':'')+'</div>';

        // ── Uma única foto, com TODAS as peças desta composição sobrepostas ──
        html += '<div id="sim-container-'+i+'" style="position:relative;background:#0d0d0d;border-radius:4px;overflow:hidden;margin-bottom:12px;line-height:0;">';
        html += '<img src="'+data.foto_local+'" style="width:100%;display:block;" draggable="false" onload="recalcularMolduraCard('+i+')">';

        c.pecas.forEach((p,j)=>{
          const t = p.tamanho;
          const larguraFracao = t ? (t.largura / larguraRealParede) : 0.4;
          const larguraNaFoto = larguraFracao * bx.width_pct;
          const larguraFinal = Math.min(Math.max(larguraNaFoto, 1.5), bx.width_pct*0.98);
          const molduraCor = coresMoldura[p.moldura] || '#1a1a1a';
          let posX, posY;
          if(typeof p.posX === 'number'){ posX = p.posX; posY = p.posY; }
          else if(numPecas>1){ posX = bx.left_pct + bx.width_pct*(j+1)/(numPecas+1); posY = centroYpadrao; }
          else { posX = centroXpadrao; posY = centroYpadrao; }

          html += '<div id="quadro-wrap-'+i+'-'+j+'" style="position:absolute;top:'+posY+'%;left:'+posX+'%;transform:translate(-50%,-50%);width:'+larguraFinal+'%;aspect-ratio:'+(t?t.largura:1)+'/'+(t?t.altura:1)+';'+(c.ajustando?'cursor:move;box-shadow:0 0 0 2px var(--gold);z-index:10;':'z-index:2;')+'">';
          html += '<div id="moldura-real-'+i+'-'+j+'" style="border:1px solid '+molduraCor+';padding:1px;background:#000;box-sizing:border-box;width:100%;height:100%;">';
          html += '<div style="position:relative;width:100%;height:100%;">';
          html += '<img src="'+p.obra.imagem_preview+'" style="width:100%;height:100%;object-fit:fill;background:#f4f2ee;display:block;" draggable="false">';
          html += '<div style="position:absolute;inset:0;background-image:url('+data.watermark+');background-repeat:repeat;mix-blend-mode:overlay;pointer-events:none;"></div>';
          html += '</div></div></div>';
        });
        html += '</div>';

        // ── Um único controle de posição pra composição toda ──
        if(c.ajustando){
          html += '<div style="display:flex;gap:8px;margin-bottom:12px;">';
          html += '<button type="button" onclick="finalizarAjuste('+i+')" class="btn btn-primary" style="flex:1;font-size:12px;padding:9px;">✓ Concluir</button>';
          html += '<button type="button" onclick="resetarPosicao('+i+')" class="btn btn-outline" style="font-size:12px;padding:9px 14px;">Centralizar</button>';
          html += '</div>';
          if(numPecas>1){ html += '<div style="font-size:11px;color:var(--gold);text-align:center;margin-bottom:12px;">Arraste qualquer obra para reposicionar</div>'; }
        } else {
          html += '<button type="button" onclick="iniciarAjuste('+i+')" class="btn btn-outline" style="width:100%;margin-bottom:12px;font-size:12px;padding:9px;">✥ Ajustar posição'+(numPecas>1?' das obras':'')+'</button>';
        }

        // ── Lista compacta: miniatura + nome + tamanho + ícones (trocar/remover) ──
        html += '<div style="border:1px solid var(--border);border-radius:4px;overflow:hidden;margin-bottom:10px;">';
        c.pecas.forEach((p,j)=>{
          const o = p.obra;
          const t = p.tamanho;
          const tamanhos = o._tamanhosDisponiveis || (t?[t]:[]);
          html += '<div style="display:flex;align-items:center;gap:10px;padding:12px;'+(j<numPecas-1?'border-bottom:1px solid var(--border);':'')+'">';
          html += '<img src="'+o.imagem_preview+'" style="width:42px;height:42px;object-fit:cover;border-radius:3px;flex-shrink:0;background:#0d0d0d;">';
          html += '<div style="flex:1;min-width:0;">';
          html += '<div style="font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:\\'Cormorant Garamond\\',serif;">'+o.nome+'</div>';
          if(tamanhos.length){
            // Sem preço aqui de propósito — a experiência de simular não deve empurrar valor
            // o tempo todo. O preço só aparece quando a pessoa pede o orçamento, no final.
            html += '<select onchange="mudarTamanho('+i+','+j+',this.value)" style="font-size:11px;background:#0d0d0d;border:1px solid var(--border);color:var(--muted);padding:3px 5px;border-radius:2px;margin-top:3px;max-width:100%;">';
            tamanhos.forEach((tm,idx)=>{
              const sel = (t && tm.largura===t.largura && tm.altura===t.altura) ? 'selected' : '';
              html += '<option value="'+idx+'" '+sel+'>'+tm.label+'</option>';
            });
            html += '</select>';
          }
          html += '</div>';
          // molduras mini
          html += '<div style="display:flex;gap:4px;flex-shrink:0;">';
          [['preta','#1a1a1a'],['carvalho','#5c4a2e'],['aco_escovado','linear-gradient(135deg,#aaa,#777)']].forEach(([slug,bg])=>{
            const borda = p.moldura===slug ? 'var(--gold)' : 'var(--border)';
            html += '<button type="button" onclick="mudarMoldura('+i+','+j+',\\''+slug+'\\')" style="width:18px;height:18px;background:'+bg+';border:1.5px solid '+borda+';border-radius:2px;cursor:pointer;padding:0;" title="'+(nomesMoldura[slug])+'"></button>';
          });
          html += '</div>';
          // trocar — com texto, bem visível
          html += '<button type="button" onclick="abrirGaleria('+i+','+j+')" style="flex-shrink:0;display:flex;align-items:center;gap:5px;background:rgba(201,169,110,.08);border:1px solid var(--gold);color:var(--gold);border-radius:4px;padding:8px 12px;font-size:12px;cursor:pointer;font-weight:500;">⇄ Trocar</button>';
          // remover (só se tiver mais de 1)
          if(numPecas>1){
            html += '<button type="button" onclick="removerPeca('+i+','+j+')" title="Remover esta obra" style="flex-shrink:0;background:none;border:1px solid #e77;color:#e77;border-radius:4px;padding:8px 10px;font-size:13px;cursor:pointer;line-height:1;">✕</button>';
          }
          html += '</div>';
        });
        html += '</div>';

        // Incluir obra — botão claro, centralizado, com destaque real
        html += '<button type="button" onclick="abrirGaleriaAdicionar('+i+')" style="display:block;margin:0 auto;background:rgba(201,169,110,.08);border:1.5px dashed var(--gold);color:var(--gold);border-radius:4px;padding:10px 22px;font-size:13px;cursor:pointer;font-weight:500;">+ Incluir outra obra</button>';

        // Orçamento desta sugestão — só aparece quando pedido, nunca somado com outra sugestão
        html += '<button type="button" onclick="verOrcamento('+i+')" class="btn btn-outline" style="width:100%;margin-top:12px;">Ver orçamento desta sugestão</button>';
        html += '<div id="orcamento-area-'+i+'"></div>';

        html += '</div>'; // fecha .card

        document.getElementById('card-slot-'+i).innerHTML = html;

        if(c.ajustando){ setTimeout(()=>{ c.pecas.forEach((p,j)=>ativarArrastar(i,j)); }, 0); }
        // Fileto (6mm) e vão (7mm) em pixel real, por peça — CSS não aceita borda em porcentagem.
        c.pecas.forEach((p,j)=>{ setTimeout(()=>ajustarMolduraReal(i,j,p.tamanho), 0); });
      }

      function ajustarMolduraReal(i,j,t){
        const wrap = document.getElementById('quadro-wrap-'+i+'-'+j);
        const moldura = document.getElementById('moldura-real-'+i+'-'+j);
        if(!wrap || !moldura || !t) return;
        const larguraPxReal = wrap.offsetWidth;
        if(!larguraPxReal || !t.largura) return;
        const pxPorCm = larguraPxReal / t.largura;
        const filetoPx = Math.max(1, Math.round(pxPorCm * 0.6)); // 6mm
        const vaoPx = Math.max(1, Math.round(pxPorCm * 0.7));    // 7mm
        moldura.style.borderWidth = filetoPx + 'px';
        moldura.style.padding = vaoPx + 'px';
      }

      // Recalcula a moldura de TODAS as peças de um card — chamado quando a foto termina
      // de carregar de verdade (mais confiável que um timeout cego, especialmente no celular,
      // onde a imagem pode demorar mais a assentar no layout).
      function recalcularMolduraCard(i){
        const c = SIM.cards[i];
        if(!c) return;
        c.pecas.forEach((p,j)=>ajustarMolduraReal(i,j,p.tamanho));
      }

      // Recalcula tudo que está na tela — chamado ao girar o celular ou redimensionar a
      // janela, pra moldura nunca ficar desproporcional por causa de mudança de layout.
      function recalcularTodasMolduras(){
        if(!SIM.cards) return;
        SIM.cards.forEach((c,i)=>recalcularMolduraCard(i));
      }
      window.addEventListener('resize', recalcularTodasMolduras);
      window.addEventListener('orientationchange', ()=>setTimeout(recalcularTodasMolduras, 200));

      function mudarTamanho(i,j,idx){
        const tamanhos = SIM.cards[i].pecas[j].obra._tamanhosDisponiveis || [];
        if(tamanhos[idx]){ SIM.cards[i].pecas[j].tamanho = tamanhos[idx]; montarCard(i); }
      }

      function mudarMoldura(i,j,slug){
        SIM.cards[i].pecas[j].moldura = slug;
        montarCard(i);
      }

      // ── Salvar simulação ──
      function abrirSalvar(){
        const nome = prompt('Dê um nome para esta simulação (ex: Sala do cliente João):');
        if(nome === null) return;
        if(!nome.trim()){ alert('Digite um nome.'); return; }
        salvarSimulacao(nome.trim());
      }
      async function salvarSimulacao(nome){
        const cardsSalvar = SIM.cards.map(c => ({
          pecas: c.pecas.map(p => ({
            obra: {
              id: p.obra.id, codigo: p.obra.codigo, nome: p.obra.nome, colecao: p.obra.colecao,
              imagem_preview: p.obra.imagem_preview, _tamanhosDisponiveis: p.obra._tamanhosDisponiveis || [],
              _motivos: p.obra._motivos || []
            },
            tamanho: p.tamanho, moldura: p.moldura, posX: p.posX, posY: p.posY
          }))
        }));
        try{
          const r = await fetch('/simulador/salvar', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({
              nome, foto_local: SIM.data.foto_local,
              parede_largura: SIM.data.parede_largura, parede_altura: SIM.data.parede_altura,
              analise: SIM.data.analise, watermark: SIM.data.watermark,
              cards: cardsSalvar
            })
          });
          const d = await r.json();
          if(d.erro){ alert(d.erro); return; }
          alert('Simulação salva! Você pode consultá-la em "Minhas simulações".');
        }catch(e){ alert('Erro ao salvar: '+e.message); }
      }

      // ── Ajuste manual de posição (arrastar), pra composição TODA de uma vez ──
      function iniciarAjuste(i){
        SIM.cards[i].ajustando = true;
        montarCard(i);
        SIM.cards[i].pecas.forEach((p,j)=>ativarArrastar(i,j));
      }
      function finalizarAjuste(i){
        SIM.cards[i].ajustando = false;
        montarCard(i);
      }
      function resetarPosicao(i){
        SIM.cards[i].pecas.forEach(p=>{ delete p.posX; delete p.posY; });
        montarCard(i);
        if(SIM.cards[i].ajustando){ SIM.cards[i].pecas.forEach((p,j)=>ativarArrastar(i,j)); }
      }
      // Controle de arrastar CENTRALIZADO e único — evita qualquer sobra de "escutadores"
      // de uma peça interferindo na próxima. Só existe UM arrasto ativo por vez, sempre.
      let ARRASTAR_ATIVO = null; // { i, j, container, wrap }

      function ativarArrastar(i,j){
        const wrap = document.getElementById('quadro-wrap-'+i+'-'+j);
        const container = document.getElementById('sim-container-'+i);
        if(!wrap || !container) return;
        wrap.onmousedown = function(e){ iniciarArrasto(e,i,j,container,wrap); };
        wrap.ontouchstart = function(e){ iniciarArrasto(e,i,j,container,wrap); };
      }

      function iniciarArrasto(e,i,j,container,wrap){
        e.preventDefault();
        // Limpa qualquer arrasto anterior que por algum motivo não tenha sido finalizado
        soltarArrasto();
        ARRASTAR_ATIVO = { i:i, j:j, container:container, wrap:wrap };
        document.addEventListener('mousemove', moverArrasto);
        document.addEventListener('mouseup', soltarArrasto);
        document.addEventListener('touchmove', moverArrasto, {passive:false});
        document.addEventListener('touchend', soltarArrasto);
      }

      function moverArrasto(e){
        if(!ARRASTAR_ATIVO) return;
        e.preventDefault();
        const { i, j, container, wrap } = ARRASTAR_ATIVO;
        const rect = container.getBoundingClientRect();
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        const clientY = e.touches ? e.touches[0].clientY : e.clientY;
        let px = ((clientX - rect.left) / rect.width) * 100;
        let py = ((clientY - rect.top) / rect.height) * 100;
        px = Math.max(0, Math.min(100, px));
        py = Math.max(0, Math.min(100, py));
        SIM.cards[i].pecas[j].posX = px;
        SIM.cards[i].pecas[j].posY = py;
        wrap.style.left = px + '%';
        wrap.style.top = py + '%';
      }

      function soltarArrasto(){
        ARRASTAR_ATIVO = null;
        document.removeEventListener('mousemove', moverArrasto);
        document.removeEventListener('mouseup', soltarArrasto);
        document.removeEventListener('touchmove', moverArrasto);
        document.removeEventListener('touchend', soltarArrasto);
      }

      // ── Galeria de obras — "trocar" (substitui uma peça) ou "adicionar" (nova peça na composição) ──
      let GALERIA = { obras:null, alvo:null, modo:'trocar' };

      async function abrirGaleria(i,j){
        GALERIA.alvo = {i:i,j:j};
        GALERIA.modo = 'trocar';
        abrirModalGaleria();
      }

      async function abrirGaleriaAdicionar(i){
        GALERIA.alvo = {i:i};
        GALERIA.modo = 'adicionar';
        abrirModalGaleria();
      }

      async function abrirModalGaleria(){
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
        const objObra = {
          id: nova.id, codigo: nova.codigo, nome: nova.nome, colecao: nova.colecao,
          imagem_preview: nova.imagem_preview,
          _tamanhosDisponiveis: nova.tamanhos,
          _motivos: ['escolha do cliente']
        };
        const tamanhoInicial = nova.tamanhos && nova.tamanhos.length ? nova.tamanhos[0] : null;

        if(GALERIA.modo === 'adicionar'){
          const i = GALERIA.alvo.i;
          SIM.cards[i].pecas.push({ obra: objObra, tamanho: tamanhoInicial, moldura: (SIM.data.analise.moldura_recomendada || 'preta') });
          fecharGaleria();
          montarCard(i);
        } else {
          const i = GALERIA.alvo.i, j = GALERIA.alvo.j;
          SIM.cards[i].pecas[j].obra = objObra;
          SIM.cards[i].pecas[j].tamanho = tamanhoInicial;
          fecharGaleria();
          montarCard(i);
        }
      }

      // Remove uma peça específica da composição (nunca remove a última peça de uma sugestão)
      function removerPeca(i,j){
        if(!confirm('Remover esta obra da composição?')) return;
        SIM.cards[i].pecas.splice(j,1);
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

    // Anexa a cada sugestão os tamanhos disponíveis para o dropdown. Usa _tamanhosCabem, que já foi
    // filtrado no ranking por orientação real E limite físico (altura e largura da parede).
    for(const s of sugestoes){
      s._tamanhosDisponiveis = (s._tamanhosCabem && s._tamanhosCabem.length)
        ? s._tamanhosCabem
        : (s._melhorTamanho ? [s._melhorTamanho] : []);
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
    const lista = obras.rows.map(o => {
      let tams = tamanhosOficiais(o.formato_recomendado, o.tamanhos_recomendados);
      const orient = String(o.orientacao||'').toLowerCase();
      if(/vertical|retrato/.test(orient)){
        const v = tams.filter(t => t.altura >= t.largura);
        if(v.length) tams = v;
      } else if(/horizontal|paisagem/.test(orient)){
        const h = tams.filter(t => t.largura >= t.altura);
        if(h.length) tams = h;
      }
      return {
        id: o.id, codigo: o.codigo, nome: o.nome, colecao: o.colecao,
        imagem_preview: o.imagem_preview, tamanhos: tams
      };
    });
    res.json({ obras: lista });
  }catch(e){
    res.json({ erro: e.message });
  }
});

// ── SALVAR / LISTAR / APAGAR SIMULAÇÕES ──
const DIAS_EXPIRACAO_SIM = 20;

// Limpa simulações expiradas (roda oportunisticamente quando alguém acessa)
async function limparSimulacoesExpiradas(){
  try{
    await pool.query(`DELETE FROM circulo_simulacoes WHERE criado_em < NOW() - INTERVAL '${DIAS_EXPIRACAO_SIM} days'`);
  }catch(e){ console.error('Limpeza simulacoes:', e.message); }
}

// Salvar uma simulação
app.post('/simulador/salvar', authMembro, async(req,res)=>{
  try{
    await limparSimulacoesExpiradas();
    const { nome, foto_local, parede_largura, parede_altura, cards } = req.body;
    if(!nome || !nome.trim()) return res.json({ erro:'Dê um nome para a simulação.' });
    if(!foto_local || !cards) return res.json({ erro:'Dados da simulação incompletos.' });

    // Checa limite de 10
    const cont = await pool.query('SELECT COUNT(*) FROM circulo_simulacoes WHERE membro_id=$1', [req.membro.id]);
    if(parseInt(cont.rows[0].count) >= 10){
      return res.json({ erro:'Você atingiu o limite de 10 simulações salvas. Apague uma antes de salvar outra.' });
    }

    await pool.query(
      `INSERT INTO circulo_simulacoes (membro_id, nome, foto_local, parede_largura, parede_altura, cards_json)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [req.membro.id, nome.trim(), foto_local, parseInt(parede_largura)||null, parseInt(parede_altura)||null, JSON.stringify(cards)]
    );
    res.json({ ok:true });
  }catch(e){
    console.error('Salvar simulacao:', e.message);
    res.json({ erro:'Erro ao salvar: '+e.message });
  }
});

// Listar simulações salvas do membro
app.get('/simulador/salvas', authMembro, async(req,res)=>{
  try{
    await limparSimulacoesExpiradas();
    const r = await pool.query(
      `SELECT id, nome, criado_em, criado_em + INTERVAL '${DIAS_EXPIRACAO_SIM} days' AS expira_em
       FROM circulo_simulacoes WHERE membro_id=$1 ORDER BY criado_em DESC`, [req.membro.id]
    );
    res.json({ simulacoes: r.rows });
  }catch(e){ res.json({ erro:e.message }); }
});

// Abrir uma simulação salva (dados completos)
app.get('/simulador/salva/:id', authMembro, async(req,res)=>{
  try{
    const r = await pool.query('SELECT * FROM circulo_simulacoes WHERE id=$1 AND membro_id=$2', [req.params.id, req.membro.id]);
    if(!r.rows.length) return res.json({ erro:'Simulação não encontrada.' });
    const s = r.rows[0];
    res.json({
      nome: s.nome, foto_local: s.foto_local,
      parede_largura: s.parede_largura, parede_altura: s.parede_altura,
      cards: JSON.parse(s.cards_json)
    });
  }catch(e){ res.json({ erro:e.message }); }
});

// Apagar uma simulação
app.post('/simulador/salva/:id/apagar', authMembro, async(req,res)=>{
  try{
    await pool.query('DELETE FROM circulo_simulacoes WHERE id=$1 AND membro_id=$2', [req.params.id, req.membro.id]);
    res.json({ ok:true });
  }catch(e){ res.json({ erro:e.message }); }
});

// Tela: Minhas simulações
app.get('/simulador/minhas', authMembro, async(req,res)=>{
  const fRows=await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
  const slugs=fRows.rows.map(r=>r.slug);
  const navImpacto=slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s))?'<a href="/meu-impacto" class="nav-link">Impacto</a>':'';
  res.send(html('Minhas simulações',`
    ${navBar('simulador', !!navImpacto, slugs.includes('especificador'))}
    <a href="/simulador" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar ao simulador</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Minhas simulações</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Suas simulações salvas. Elas ficam disponíveis por 20 dias. Limite de 10 salvas.</p>
    <div id="lista-sim"><p style="color:var(--muted);">Carregando...</p></div>
    <script>
      async function carregarSalvas(){
        try{
          const r = await fetch('/simulador/salvas');
          const d = await r.json();
          if(d.erro){ document.getElementById('lista-sim').innerHTML='<div class="msg-erro">'+d.erro+'</div>'; return; }
          if(!d.simulacoes.length){ document.getElementById('lista-sim').innerHTML='<p style="color:var(--muted);">Nenhuma simulação salva ainda.</p>'; return; }
          let html='';
          d.simulacoes.forEach(s=>{
            const data = new Date(s.criado_em).toLocaleDateString('pt-BR');
            const exp = new Date(s.expira_em).toLocaleDateString('pt-BR');
            html+='<div class="card" style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;">';
            html+='<div><div style="font-family:\\'Cormorant Garamond\\',serif;font-size:20px;margin-bottom:4px;">'+s.nome+'</div>';
            html+='<div style="font-size:11px;color:var(--muted);">Criada em '+data+' · expira em '+exp+'</div></div>';
            html+='<div style="display:flex;gap:8px;">';
            html+='<a href="/simulador?abrir='+s.id+'" class="btn btn-primary" style="padding:8px 16px;font-size:10px;">Abrir</a>';
            html+='<button onclick="apagarSim('+s.id+')" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Apagar</button>';
            html+='</div></div>';
          });
          document.getElementById('lista-sim').innerHTML=html;
        }catch(e){ document.getElementById('lista-sim').innerHTML='<div class="msg-erro">Erro: '+e.message+'</div>'; }
      }
      async function apagarSim(id){
        if(!confirm('Apagar esta simulação?')) return;
        await fetch('/simulador/salva/'+id+'/apagar', {method:'POST'});
        carregarSalvas();
      }
      carregarSalvas();
    </script>
  `,true));
});



// ════════════════════════════════════════════════════════════════
// SISTEMA DE INDICAÇÃO — membro gera link de obra e compartilha
// ════════════════════════════════════════════════════════════════

// Gera/recupera o link de indicação de uma obra para o membro
app.get('/obra/:obraId/link', authMembro, async(req,res)=>{
  if(!(await podeIndicarObra(req.membro.id))){
    return res.send(html('Indicar obra',`<div class="msg-erro">Esta função é para Embaixadores e Especificadores. Solicite uma dessas funções em "Funções".</div><a href="/catalogo" class="btn btn-outline" style="margin-top:16px;">← Voltar às obras</a>`,true));
  }
  const obraId = parseInt(req.params.obraId);
  const obra = await pool.query('SELECT id,nome,colecao,imagem_preview FROM almare_obras WHERE id=$1',[obraId]);
  if(!obra.rows.length) return res.send(html('Indicar obra',`<div class="msg-erro">Obra não encontrada.</div>`,true));

  let link = await pool.query('SELECT codigo FROM circulo_obra_links WHERE membro_id=$1 AND obra_id=$2',[req.membro.id,obraId]);
  if(!link.rows.length){
    const codigo = gerarCodigo();
    await pool.query('INSERT INTO circulo_obra_links (membro_id,obra_id,codigo) VALUES ($1,$2,$3)',[req.membro.id,obraId,codigo]);
    link = {rows:[{codigo}]};
  }
  const url = `${BASE_URL}/indicar/${link.rows[0].codigo}`;
  const o = obra.rows[0];
  res.send(html('Indicar obra',`
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar às obras</a>
    <h2 style="font-size:26px;margin-bottom:4px;">Indicar "${esc(o.nome)}"</h2>
    <p style="color:var(--muted);margin-bottom:28px;">Envie este link para quem você acha que pertence a essa obra. Todo interesse aparece em "Minhas indicações", com o seu nome.</p>
    <div class="card">
      ${o.imagem_preview?`<img src="${esc(o.imagem_preview)}" style="max-width:100%;max-height:400px;display:block;margin:0 auto 20px;border-radius:4px;">`:''}
      <div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Seu link de indicação</div>
      <div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${esc(url)}</div>
      <button onclick="navigator.clipboard.writeText('${esc(url)}');this.textContent='Copiado ✓'" class="btn btn-primary">Copiar link</button>
      <a href="/minhas-indicacoes" class="btn btn-outline" style="margin-left:8px;">Ver minhas indicações</a>
    </div>
  `,true));
});

// Lista as indicações do membro
app.get('/minhas-indicacoes', authMembro, async(req,res)=>{
  if(!(await podeIndicarObra(req.membro.id))) return res.redirect('/catalogo');
  const links = await pool.query(`
    SELECT ol.id, ol.codigo, ol.obra_id, o.nome as obra_nome, o.imagem_preview,
           (SELECT COUNT(*) FROM circulo_indicacoes ci WHERE ci.obra_link_id=ol.id) as total_leads,
           (SELECT COUNT(*) FROM circulo_indicacoes ci WHERE ci.obra_link_id=ol.id AND ci.status='novo') as leads_novos
    FROM circulo_obra_links ol JOIN almare_obras o ON o.id=ol.obra_id
    WHERE ol.membro_id=$1 ORDER BY ol.criado_em DESC`, [req.membro.id]);

  const itens = links.rows.map(l=>`
    <div style="display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:1px solid var(--border);">
      <div style="width:56px;height:56px;border-radius:4px;overflow:hidden;background:#0d0d0d;flex-shrink:0;">
        ${l.imagem_preview?`<img src="${esc(l.imagem_preview)}" style="width:100%;height:100%;object-fit:cover;">`:''}
      </div>
      <div style="flex:1;">
        <div style="font-family:'Cormorant Garamond',serif;font-size:17px;">${esc(l.obra_nome)}</div>
        <div style="font-size:12px;color:var(--muted);">${l.total_leads} interesse${l.total_leads!=1?'s':''} recebido${l.total_leads!=1?'s':''}${l.leads_novos>0?` · <span style="color:var(--gold)">${l.leads_novos} novo${l.leads_novos!=1?'s':''}</span>`:''}</div>
      </div>
      <a href="/obra/${l.obra_id}/link" class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Ver link</a>
    </div>`).join('');

  const detalhes = await pool.query(`
    SELECT ci.nome_lead, ci.contato_lead, ci.mensagem, ci.status, ci.criado_em, o.nome as obra_nome
    FROM circulo_indicacoes ci
    JOIN circulo_obra_links ol ON ol.id=ci.obra_link_id
    JOIN almare_obras o ON o.id=ol.obra_id
    WHERE ol.membro_id=$1 ORDER BY ci.criado_em DESC LIMIT 50`, [req.membro.id]);

  const leadsHtml = detalhes.rows.map(d=>`
    <div style="padding:14px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:14px;">${esc(d.nome_lead||'Sem nome')} <span style="color:var(--muted);font-size:12px;">· ${esc(d.obra_nome)}</span></span>
        <span class="badge ${d.status==='novo'?'badge-gold':'badge-muted'}">${esc(d.status)}</span>
      </div>
      <div style="font-size:12px;color:var(--muted);">${esc(d.contato_lead||'')}</div>
      ${d.mensagem?`<div style="font-size:12px;color:#bbb;margin-top:4px;font-style:italic;">"${esc(d.mensagem)}"</div>`:''}
    </div>`).join('');

  res.send(html('Minhas indicações',`
    ${navBar('indicacoes', await temFuncaoComImpacto(req.membro.id), await ehEspecificador(req.membro.id))}
    <h2 style="font-size:28px;margin-bottom:8px;">Minhas indicações</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Cada obra do catálogo tem seu próprio link. Toque em "Indicar esta obra" no catálogo para gerar um.</p>
    <div class="card" style="margin-bottom:24px;"><h3 style="font-size:16px;margin-bottom:12px;color:var(--gold);">Seus links por obra</h3>${itens||'<p style="color:var(--muted);padding:12px 0;">Você ainda não indicou nenhuma obra. Vá ao catálogo e toque em "Indicar esta obra".</p>'}</div>
    ${leadsHtml?`<div class="card"><h3 style="font-size:16px;margin-bottom:12px;color:var(--gold);">Interesses recebidos</h3>${leadsHtml}</div>`:''}
  `,true));
});

// Página PÚBLICA de indicação — quem recebe o link não precisa ter conta
app.get('/indicar/:codigo', async(req,res)=>{
  const r = await pool.query(`
    SELECT ol.id as link_id, o.id as obra_id, o.nome, o.colecao, o.essencia,
           o.texto_curatorial, o.o_que_permanece, o.imagem_preview, m.nome as membro_nome
    FROM circulo_obra_links ol
    JOIN almare_obras o ON o.id=ol.obra_id
    JOIN circulo_membros m ON m.id=ol.membro_id
    WHERE ol.codigo=$1`, [req.params.codigo]);
  if(!r.rows.length) return res.status(404).send(html('Indicação',`<div class="container-sm"><div class="msg-erro">Este link não existe mais.</div></div>`));
  const o = r.rows[0];
  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${esc(o.nome)} — ALMARE</title><style>${CSS}</style></head>
    <body><div class="container" style="max-width:640px;padding-top:48px;">
      <div class="logo" style="margin-bottom:6px;">ALMARE</div>
      <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin-bottom:40px;">Uma indicação de ${esc(o.membro_nome)}</div>
      ${o.imagem_preview?`<img src="${esc(o.imagem_preview)}" style="width:100%;display:block;margin-bottom:32px;border-radius:4px;">`:''}
      <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">${esc(o.colecao||'')}</div>
      <h1 style="font-size:32px;margin-bottom:20px;">${esc(o.nome)}</h1>
      ${o.essencia?`<p style="font-style:italic;color:var(--gold-light);margin-bottom:20px;">${esc(o.essencia)}</p>`:''}
      ${o.texto_curatorial?`<p style="line-height:1.9;color:#ccc;margin-bottom:16px;">${esc(o.texto_curatorial)}</p>`:''}
      ${o.o_que_permanece?`<p style="font-style:italic;color:var(--muted);margin-bottom:40px;">${esc(o.o_que_permanece)}</p>`:''}
      <div class="card">
        <h3 style="font-size:18px;margin-bottom:16px;">Tenho interesse nesta obra</h3>
        <form method="POST" action="/indicar/${esc(req.params.codigo)}">
          <div class="field"><label>Seu nome</label><input name="nome" required placeholder="Seu nome"></div>
          <div class="field"><label>Contato (WhatsApp ou e-mail)</label><input name="contato" required placeholder="Como falar com você"></div>
          <div class="field"><label>Mensagem <span style="color:var(--muted)">(opcional)</span></label><textarea name="mensagem" placeholder="Alguma observação"></textarea></div>
          <button type="submit" class="btn btn-primary btn-full">Enviar interesse</button>
        </form>
      </div>
      <div style="text-align:center;margin-top:24px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">ALMARE · Obras autorais de edição limitada</div>
    </div></body></html>`);
});

// Registra o interesse (lead) da página pública
app.post('/indicar/:codigo', async(req,res)=>{
  const r = await pool.query('SELECT id FROM circulo_obra_links WHERE codigo=$1',[req.params.codigo]);
  if(!r.rows.length) return res.status(404).send(html('Indicação',`<div class="container-sm"><div class="msg-erro">Link inválido.</div></div>`));
  const { nome, contato, mensagem } = req.body;
  await pool.query(
    'INSERT INTO circulo_indicacoes (obra_link_id,nome_lead,contato_lead,mensagem) VALUES ($1,$2,$3,$4)',
    [r.rows[0].id, nome||null, contato||null, mensagem||null]
  );
  res.send(html('Interesse enviado',`
    <div class="container-sm" style="text-align:center;padding-top:60px;">
      <div style="font-size:48px;margin-bottom:24px;color:var(--gold);">✦</div>
      <h2 style="font-size:30px;margin-bottom:16px;">Seu interesse foi enviado.</h2>
      <p style="color:var(--muted);line-height:1.9;">Em breve alguém da ALMARE entrará em contato com você.</p>
    </div>
  `));
});


// ════════════════════════════════════════════════════════════════
// CARRINHO DE COMPRAS (checkout/pagamento vem na função 3)
// ════════════════════════════════════════════════════════════════
const MOLDURA_NOME = { preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado' };

// Retorna os tamanhos de uma obra (com id sequencial pro select), respeitando orientação
async function tamanhosDaObra(obraId){
  const o = await pool.query('SELECT formato_recomendado, tamanhos_recomendados, orientacao FROM almare_obras WHERE id=$1',[obraId]);
  if(!o.rows.length) return [];
  let tams = tamanhosOficiais(o.rows[0].formato_recomendado, o.rows[0].tamanhos_recomendados);
  const orient = String(o.rows[0].orientacao||'').toLowerCase();
  if(/vertical|retrato/.test(orient)){ const v=tams.filter(t=>t.altura>=t.largura); if(v.length) tams=v; }
  else if(/horizontal|paisagem/.test(orient)){ const h=tams.filter(t=>t.largura>=t.altura); if(h.length) tams=h; }
  // dá um id sequencial estável a cada tamanho
  return tams.map((t,i)=>({ id:i, label:t.label, largura:t.largura, altura:t.altura, preco:t.preco }));
}

async function pegarOuCriarCarrinho(membroId){
  let p = await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status='CARRINHO' ORDER BY criado_em DESC LIMIT 1`,[membroId]);
  if(p.rows.length) return p.rows[0];
  const numero = 'C'+Date.now().toString(36).toUpperCase();
  const r = await pool.query(
    `INSERT INTO circulo_pedidos (numero,membro_id,status,total) VALUES ($1,$2,'CARRINHO',0) RETURNING *`,
    [numero, membroId]
  );
  return r.rows[0];
}

async function recalcularTotalCarrinho(pedidoId){
  const r = await pool.query('SELECT COALESCE(SUM(subtotal),0) as t FROM circulo_pedido_itens WHERE pedido_id=$1',[pedidoId]);
  await pool.query('UPDATE circulo_pedidos SET total=$1 WHERE id=$2',[r.rows[0].t, pedidoId]);
}

// Adicionar obra ao carrinho
app.post('/comprar/:obraId/adicionar', authMembro, async(req,res)=>{
  const obraId = parseInt(req.params.obraId);
  const { tamanho_id, moldura, codigo_indicacao } = req.body;
  const quantidade = Math.max(1, Math.min(20, parseInt(req.body.quantidade)||1));
  try{
    const tamanhos = await tamanhosDaObra(obraId);
    const tamanho = tamanhos.find(t=>t.id===parseInt(tamanho_id));
    if(!tamanho || !MOLDURA_NOME[moldura]) return res.redirect('/catalogo');

    let obraLinkId = null;
    if(codigo_indicacao){
      const link = await pool.query('SELECT id FROM circulo_obra_links WHERE codigo=$1',[codigo_indicacao]);
      if(link.rows.length) obraLinkId = link.rows[0].id;
    }
    const pedido = await pegarOuCriarCarrinho(req.membro.id);
    const subtotal = Math.round(tamanho.preco*quantidade*100)/100;
    await pool.query(
      `INSERT INTO circulo_pedido_itens (pedido_id,obra_id,obra_link_id,tamanho_id,tamanho_label,largura,altura,moldura,quantidade,preco_unitario,subtotal)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [pedido.id,obraId,obraLinkId,tamanho.id,tamanho.label,tamanho.largura,tamanho.altura,moldura,quantidade,tamanho.preco,subtotal]
    );
    await recalcularTotalCarrinho(pedido.id);
    res.redirect('/carrinho');
  }catch(e){
    res.send(html('Erro',`<div class="container-sm"><div class="msg-erro">${esc(e.message)}</div></div>`,true));
  }
});

// Ver o carrinho
// ─── MEUS PEDIDOS — histórico de pedidos (feitos por mim ou pra mim), pagos ou não ──
app.get('/meus-pedidos', authMembro, async(req,res)=>{
  const fRows = await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
  const slugs = fRows.rows.map(r=>r.slug);
  const temImpacto = slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s));
  const ehEspec = slugs.includes('especificador');

  const r = await pool.query(`
    SELECT p.id, p.numero, p.status, p.total, p.criado_em, p.membro_id, p.cliente_membro_id,
           m.nome as membro_nome, c.nome as cliente_nome, c.documento as cliente_documento
    FROM circulo_pedidos p
    LEFT JOIN circulo_membros m ON m.id = p.membro_id
    LEFT JOIN circulo_membros c ON c.id = p.cliente_membro_id
    WHERE (p.membro_id = $1 OR p.cliente_membro_id = $1) AND p.status <> 'CARRINHO'
    ORDER BY p.criado_em DESC`, [req.membro.id]);

  const idsPedidos = r.rows.map(p=>p.id);
  let itensPorPedido = {};
  if(idsPedidos.length){
    const itensRes = await pool.query(`
      SELECT pi.pedido_id, o.nome as obra_nome, o.imagem_preview, pi.tamanho_label, pi.moldura, pi.quantidade
      FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id = pi.obra_id
      WHERE pi.pedido_id = ANY($1) ORDER BY pi.criado_em`, [idsPedidos]);
    itensRes.rows.forEach(it=>{
      if(!itensPorPedido[it.pedido_id]) itensPorPedido[it.pedido_id] = [];
      itensPorPedido[it.pedido_id].push(it);
    });
  }

  const statusInfo = {
    AGUARDANDO_PAGAMENTO: { label:'Aguardando pagamento', cor:'var(--gold)' },
    PAGO: { label:'Pago', cor:'#4caf6a' },
    CANCELADO: { label:'Cancelado', cor:'#e77' },
  };
  const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};

  const linhas = r.rows.map(p=>{
    const info = statusInfo[p.status] || { label:p.status, cor:'var(--muted)' };
    const data = new Date(p.criado_em).toLocaleDateString('pt-BR');
    const itens = itensPorPedido[p.id] || [];
    const obrasTexto = itens.map(it=>it.obra_nome).join(', ');
    const itensDetalhe = itens.map(it=>
      `<div style="display:flex;align-items:center;gap:8px;padding:4px 0;">
        <div style="width:26px;height:26px;border-radius:3px;overflow:hidden;background:#0d0d0d;flex-shrink:0;">
          ${it.imagem_preview?`<img src="${esc(it.imagem_preview)}" style="width:100%;height:100%;object-fit:cover;">`:''}
        </div>
        <div style="font-size:12px;color:var(--muted);">${esc(it.obra_nome)} · ${esc(it.tamanho_label||'')} · ${esc(nomesMoldura[it.moldura]||it.moldura||'')}${it.quantidade>1?' · Qtd '+it.quantidade:''}</div>
      </div>`
    ).join('');

    return `
      <div class="card" style="margin-bottom:12px;" data-busca="${esc((p.numero+' '+(p.cliente_nome||'')+' '+(p.membro_nome||'')+' '+obrasTexto).toLowerCase())}" data-status="${esc(p.status)}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
          <div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:18px;margin-bottom:2px;">Pedido ${esc(p.numero)}</div>
            <div style="font-size:12px;color:var(--muted);">${data}</div>
          </div>
          <div style="display:flex;align-items:center;gap:16px;">
            <span style="font-size:12px;color:${info.cor};font-weight:600;">${info.label}</span>
            <span style="font-family:'Cormorant Garamond',serif;font-size:20px;color:var(--gold);">R$ ${parseFloat(p.total).toLocaleString('pt-BR',{minimumFractionDigits:2})}</span>
          </div>
        </div>
        <div style="border-top:1px solid var(--border);padding-top:10px;">
          ${itensDetalhe || '<div style="font-size:12px;color:var(--muted);">Sem itens.</div>'}
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;color:var(--muted);margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
          <div><span style="text-transform:uppercase;letter-spacing:.05em;">Cliente:</span> ${esc(p.cliente_nome||'—')}${p.cliente_documento?' · '+esc(p.cliente_documento):''}</div>
          <div><span style="text-transform:uppercase;letter-spacing:.05em;">Processado por:</span> ${esc(p.membro_nome||'—')}</div>
        </div>
        ${p.status === 'AGUARDANDO_PAGAMENTO' ? `
          <div style="display:flex;gap:8px;margin-top:14px;">
            <a href="/pedido-interno/${p.id}/pagar" class="btn btn-primary" style="flex:1;">Pagar agora</a>
            <button type="button" onclick="editarPedido(${p.id})" class="btn btn-outline">Editar</button>
            <button type="button" onclick="cancelarPedido(${p.id})" class="btn btn-outline" style="color:#e77;border-color:#e77;">Cancelar</button>
          </div>` : ''}
      </div>`;
  }).join('');

  res.send(html('Meus Pedidos',`
    ${navBar('pedidos', temImpacto, ehEspec)}
    <h2 style="font-size:28px;margin-bottom:8px;">Meus Pedidos</h2>
    <p style="color:var(--muted);margin-bottom:24px;">Pedidos que você fez ou que foram faturados em seu nome.</p>
    <div class="field" style="margin-bottom:14px;">
      <input type="text" id="busca-pedidos" placeholder="Buscar por número, cliente ou obra..." oninput="filtrarPedidos()">
    </div>
    <div style="display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap;">
      <button type="button" onclick="filtrarStatus('TODOS', this)" class="btn btn-outline filtro-status" style="padding:8px 16px;font-size:11px;">Todos</button>
      <button type="button" onclick="filtrarStatus('PADRAO', this)" class="btn btn-outline filtro-status ativo" style="padding:8px 16px;font-size:11px;border-color:var(--gold);color:var(--gold);">Ativos</button>
      <button type="button" onclick="filtrarStatus('AGUARDANDO_PAGAMENTO', this)" class="btn btn-outline filtro-status" style="padding:8px 16px;font-size:11px;">Aguardando pagamento</button>
      <button type="button" onclick="filtrarStatus('PAGO', this)" class="btn btn-outline filtro-status" style="padding:8px 16px;font-size:11px;">Pagos</button>
      <button type="button" onclick="filtrarStatus('CANCELADO', this)" class="btn btn-outline filtro-status" style="padding:8px 16px;font-size:11px;">Cancelados</button>
    </div>
    <div id="lista-pedidos">
      ${linhas || '<div class="card" style="text-align:center;padding:48px 24px;"><p style="color:var(--muted);">Nenhum pedido ainda.</p></div>'}
    </div>
    <script>
      // "Ativos" (padrão) esconde cancelados — só aparecem se escolher "Todos" ou "Cancelados" direto.
      let STATUS_ATIVO = 'PADRAO';
      function filtrarStatus(status, btn){
        STATUS_ATIVO = status;
        document.querySelectorAll('.filtro-status').forEach(b=>{ b.style.borderColor='var(--border)'; b.style.color='var(--text)'; });
        btn.style.borderColor = 'var(--gold)'; btn.style.color = 'var(--gold)';
        filtrarPedidos();
      }
      function filtrarPedidos(){
        const termo = document.getElementById('busca-pedidos').value.toLowerCase();
        document.querySelectorAll('#lista-pedidos [data-busca]').forEach(el=>{
          const bateBusca = el.dataset.busca.includes(termo);
          let bateStatus;
          if(STATUS_ATIVO === 'TODOS') bateStatus = true;
          else if(STATUS_ATIVO === 'PADRAO') bateStatus = el.dataset.status !== 'CANCELADO';
          else bateStatus = el.dataset.status === STATUS_ATIVO;
          el.style.display = (bateBusca && bateStatus) ? '' : 'none';
        });
      }
      async function cancelarPedido(id){
        if(!confirm('Cancelar este pedido? Isso não pode ser desfeito.')) return;
        try{
          const r = await fetch('/pedido-interno/'+id+'/cancelar', { method:'POST' });
          const d = await r.json();
          if(d.erro){ alert(d.erro); return; }
          location.reload();
        }catch(e){ alert('Erro ao cancelar pedido.'); }
      }
      async function editarPedido(id){
        if(!confirm('Reabrir este pedido para edição? A cobrança pendente será descartada e uma nova será gerada quando você finalizar de novo.')) return;
        try{
          const r = await fetch('/pedido-interno/'+id+'/reabrir', { method:'POST' });
          const d = await r.json();
          if(d.erro){ alert(d.erro); return; }
          window.location.href = '/carrinho';
        }catch(e){ alert('Erro ao reabrir pedido.'); }
      }
    </script>
  `,true));
});

app.get('/carrinho', authMembro, async(req,res)=>{
  const pedidoRes = await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status='CARRINHO' ORDER BY criado_em DESC LIMIT 1`,[req.membro.id]);
  const navBarHtml = navBar('carrinho', await temFuncaoComImpacto(req.membro.id), await ehEspecificador(req.membro.id));
  if(!pedidoRes.rows.length){
    return res.send(html('Carrinho',`${navBarHtml}<h2 style="font-size:28px;margin-bottom:16px;">Seu carrinho</h2><div class="card" style="text-align:center;padding:48px 24px;"><p style="color:var(--muted);margin-bottom:20px;">Seu carrinho está vazio.</p><a href="/catalogo" class="btn btn-primary">Ver obras no catálogo</a></div>`,true));
  }
  const p = pedidoRes.rows[0];
  const itens = await pool.query(`
    SELECT pi.*, o.nome as obra_nome, o.imagem_preview
    FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id=pi.obra_id
    WHERE pi.pedido_id=$1 ORDER BY pi.criado_em`, [p.id]);

  const linhas = itens.rows.map(it=>`
    <div style="display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:1px solid var(--border);">
      <div style="width:64px;height:64px;border-radius:4px;overflow:hidden;background:#0d0d0d;flex-shrink:0;">
        ${it.imagem_preview?`<img src="${esc(it.imagem_preview)}" style="width:100%;height:100%;object-fit:cover;">`:''}
      </div>
      <div style="flex:1;">
        <div style="font-family:'Cormorant Garamond',serif;font-size:17px;">${esc(it.obra_nome)}</div>
        <div style="font-size:12px;color:var(--muted);">${esc(it.tamanho_label)} · Moldura ${esc(MOLDURA_NOME[it.moldura]||it.moldura)} · Qtd ${it.quantidade}</div>
        <div style="font-size:13px;color:var(--gold);margin-top:2px;">R$ ${parseFloat(it.subtotal).toFixed(2).replace('.',',')}</div>
      </div>
      <form method="POST" action="/carrinho/${it.id}/remover"><button class="btn btn-outline" style="padding:6px 12px;font-size:10px;">Remover</button></form>
    </div>`).join('');

  // Cliente já vinculado a este pedido? Mostra os dados que confirmam a identidade dele.
  let clienteBox = `
    <div id="cliente-confirmado" style="display:none;padding:16px;background:rgba(46,204,113,.06);border:1px solid rgba(46,204,113,.25);border-radius:4px;margin-bottom:16px;">
      <div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--success);margin-bottom:8px;">✓ Cliente deste pedido — a obra será faturada e registrada no nome dele</div>
      <div id="cliente-confirmado-dados" style="font-size:15px;margin-bottom:12px;"></div>
      <button type="button" onclick="trocarCliente()" class="btn btn-outline" style="padding:6px 12px;font-size:10px;">Trocar cliente</button>
    </div>`;

  let clienteInicialScript = '';
  if(p.cliente_membro_id){
    const cliente = await pool.query('SELECT id,nome,documento,cidade,estado FROM circulo_membros WHERE id=$1',[p.cliente_membro_id]);
    if(cliente.rows.length){
      const c = cliente.rows[0];
      clienteInicialScript = `mostrarClienteConfirmado(${JSON.stringify({id:c.id,nome:c.nome,documento:c.documento,cidade:c.cidade,estado:c.estado})});`;
    }
  }

  res.send(html('Carrinho',`
    ${navBarHtml}
    <h2 style="font-size:28px;margin-bottom:24px;">Seu carrinho</h2>
    <div class="card" style="margin-bottom:20px;">
      ${linhas}
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:20px;margin-top:8px;border-top:1px solid var(--border);">
        <span style="font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total</span>
        <span style="font-family:'Cormorant Garamond',serif;font-size:28px;color:var(--gold);">R$ ${parseFloat(p.total).toFixed(2).replace('.',',')}</span>
      </div>
    </div>
    <a href="/catalogo" class="btn btn-outline btn-full" style="margin-bottom:20px;">+ Adicionar outra obra</a>

    <div class="card" style="margin-bottom:20px;">
      <h3 style="font-size:18px;margin-bottom:6px;">Cliente do pedido</h3>
      <p style="color:var(--muted);font-size:13px;margin-bottom:16px;">Quem vai ficar com a obra. Mesmo que seja você mesmo comprando, informe seus dados aqui. O cliente precisa ser membro do Círculo.</p>
      ${clienteBox}
      <div id="busca-cliente-area">
        <div class="field">
          <label>Nome ou CPF/CNPJ do cliente</label>
          <div style="display:flex;gap:8px;">
            <input type="text" id="termo-cliente" placeholder="Digite o nome ou CPF/CNPJ" style="flex:1;">
            <button type="button" onclick="buscarCliente()" class="btn btn-outline" style="white-space:nowrap;">Buscar</button>
          </div>
        </div>
        <div id="resultado-busca-cliente" style="margin-top:12px;"></div>
      </div>
    </div>

    <div class="card">
      <h3 style="font-size:18px;margin-bottom:16px;">Finalizar compra</h3>
      ${p.cliente_membro_id
        ? `<a href="/carrinho/finalizar" class="btn btn-primary btn-full">Ir para o pagamento</a>`
        : `<p style="color:var(--muted);font-size:13px;margin-bottom:16px;">Vincule um cliente ao pedido acima antes de continuar.</p><button class="btn btn-primary btn-full" disabled style="opacity:.5;cursor:not-allowed;">Ir para o pagamento</button>`
      }
    </div>

    <script>
      function mostrarClienteConfirmado(c){
        const linhaDoc = c.documento ? ' · '+c.documento : '';
        const linhaCidade = (c.cidade ? ' · '+c.cidade+(c.estado?'/'+c.estado:'') : '');
        document.getElementById('cliente-confirmado-dados').innerHTML = '<strong>'+c.nome+'</strong>'+linhaDoc+linhaCidade;
        document.getElementById('cliente-confirmado').style.display = 'block';
        document.getElementById('busca-cliente-area').style.display = 'none';
      }
      function trocarCliente(){
        document.getElementById('cliente-confirmado').style.display = 'none';
        document.getElementById('busca-cliente-area').style.display = 'block';
        document.getElementById('resultado-busca-cliente').innerHTML = '';
        document.getElementById('termo-cliente').value = '';
      }
      async function buscarCliente(){
        const termo = document.getElementById('termo-cliente').value.trim();
        const areaResultado = document.getElementById('resultado-busca-cliente');
        if(!termo){ areaResultado.innerHTML='<div class="msg-erro">Digite o nome ou CPF/CNPJ.</div>'; return; }
        areaResultado.innerHTML = '<p style="color:var(--muted);font-size:13px;">Buscando...</p>';
        try{
          const r = await fetch('/carrinho/buscar-cliente?termo='+encodeURIComponent(termo));
          const d = await r.json();
          if(!d.resultados || !d.resultados.length){
            areaResultado.innerHTML = '<div class="msg-info">Nenhum membro encontrado com esse nome/CPF. O cliente precisa se cadastrar no Círculo primeiro. <a href="/convite">Enviar convite</a></div>';
            return;
          }
          let htmlLista = '';
          d.resultados.forEach(c=>{
            const linhaDoc = c.documento ? c.documento : 'sem CPF/CNPJ cadastrado';
            const linhaCidade = c.cidade ? (c.cidade+(c.estado?'/'+c.estado:'')) : '';
            htmlLista += '<div style="display:flex;justify-content:space-between;align-items:center;padding:14px;border:1px solid var(--border);border-radius:4px;margin-bottom:8px;">';
            htmlLista += '<div><div style="font-size:15px;margin-bottom:2px;">'+c.nome+'</div><div style="font-size:12px;color:var(--muted);">'+linhaDoc+(linhaCidade?' · '+linhaCidade:'')+'</div></div>';
            htmlLista += '<button onclick=\\'selecionarCliente('+JSON.stringify(c)+')\\' class="btn btn-primary" style="padding:8px 16px;font-size:11px;">Selecionar</button>';
            htmlLista += '</div>';
          });
          areaResultado.innerHTML = htmlLista;
        }catch(e){ areaResultado.innerHTML = '<div class="msg-erro">Erro ao buscar.</div>'; }
      }
      async function selecionarCliente(c){
        try{
          await fetch('/carrinho/definir-cliente', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ cliente_membro_id: c.id }) });
          location.reload();
        }catch(e){ alert('Erro ao vincular cliente.'); }
      }
      ${clienteInicialScript}
    </script>
  `,true));
});

// Busca membros por nome OU CPF/CNPJ (para identificar e vincular como cliente do pedido)
app.get('/carrinho/buscar-cliente', authMembro, async(req,res)=>{
  const termo = String(req.query.termo||'').trim();
  if(!termo) return res.json({ resultados:[] });
  const soDigitos = termo.replace(/\D/g,'');
  let r;
  if(soDigitos.length >= 5){
    // parece CPF/CNPJ — busca por documento (ignorando pontuação) OU nome, o que vier
    r = await pool.query(
      `SELECT id,nome,documento,cidade,estado FROM circulo_membros
       WHERE regexp_replace(COALESCE(documento,''),'\\D','','g') LIKE $1 OR nome ILIKE $2
       LIMIT 8`,
      ['%'+soDigitos+'%', '%'+termo+'%']
    );
  } else {
    r = await pool.query(
      `SELECT id,nome,documento,cidade,estado FROM circulo_membros WHERE nome ILIKE $1 LIMIT 8`,
      ['%'+termo+'%']
    );
  }
  res.json({ resultados: r.rows.map(c=>({ id:c.id, nome:esc(c.nome), documento:c.documento||'', cidade:c.cidade||'', estado:c.estado||'' })) });
});

// Vincula o cliente (membro) ao pedido/carrinho atual
app.post('/carrinho/definir-cliente', authMembro, async(req,res)=>{
  try{
    const { cliente_membro_id } = req.body;
    // Busca o pedido mais recente do membro que ainda pode receber cliente (carrinho aberto
    // ou aguardando pagamento) — nunca um pedido antigo/esquecido de uma tentativa anterior.
    const pedido = await pool.query(
      `SELECT id, cliente_membro_id FROM circulo_pedidos WHERE membro_id=$1 AND status IN ('CARRINHO','AGUARDANDO_PAGAMENTO') ORDER BY criado_em DESC LIMIT 1`,
      [req.membro.id]
    );
    if(!pedido.rows.length) return res.json({ erro:'Carrinho não encontrado.' });
    const pedidoId = pedido.rows[0].id;
    const clienteMudou = pedido.rows[0].cliente_membro_id !== parseInt(cliente_membro_id);

    if(clienteMudou){
      // O cliente mudou — qualquer cobrança já gerada era pro cliente ANTERIOR e não vale
      // mais. Limpa tudo e volta pro status de carrinho, forçando gerar uma cobrança nova
      // na próxima vez que a pessoa for pro pagamento.
      await pool.query(
        `UPDATE circulo_pedidos SET cliente_membro_id=$1, asaas_cliente_id=NULL, asaas_cobranca_id=NULL, invoice_url=NULL, link_publico=NULL, status='CARRINHO' WHERE id=$2`,
        [cliente_membro_id, pedidoId]
      );
    } else {
      await pool.query('UPDATE circulo_pedidos SET cliente_membro_id=$1 WHERE id=$2',[cliente_membro_id, pedidoId]);
    }
    res.json({ ok:true });
  }catch(e){ res.json({ erro:e.message }); }
});


// Remover item do carrinho
app.post('/carrinho/:itemId/remover', authMembro, async(req,res)=>{
  const item = await pool.query(`SELECT pi.*, p.membro_id FROM circulo_pedido_itens pi JOIN circulo_pedidos p ON p.id=pi.pedido_id WHERE pi.id=$1`,[req.params.itemId]);
  if(item.rows.length && item.rows[0].membro_id===req.membro.id){
    const pedidoId = item.rows[0].pedido_id;
    await pool.query('DELETE FROM circulo_pedido_itens WHERE id=$1',[req.params.itemId]);
    const restantes = await pool.query('SELECT COUNT(*) as n FROM circulo_pedido_itens WHERE pedido_id=$1',[pedidoId]);
    if(parseInt(restantes.rows[0].n)===0) await pool.query('DELETE FROM circulo_pedidos WHERE id=$1',[pedidoId]);
    else await recalcularTotalCarrinho(pedidoId);
  }
  res.redirect('/carrinho');
});


// ════════════════════════════════════════════════════════════════
// FUNÇÃO 3 — CHECKOUT E PAGAMENTO (Asaas)
// ════════════════════════════════════════════════════════════════
const ASAAS_API_URL = process.env.ASAAS_API_URL || 'https://sandbox.asaas.com/api/v3';
const ASAAS_API_KEY = process.env.ASAAS_API_KEY;

async function asaasRequest(metodo, caminho, corpo){
  const resp = await fetch(ASAAS_API_URL + caminho, {
    method: metodo,
    headers: { 'access_token': ASAAS_API_KEY, 'Content-Type': 'application/json' },
    body: corpo ? JSON.stringify(corpo) : undefined
  });
  const data = await resp.json();
  if(!resp.ok){
    throw new Error((data.errors && data.errors[0] && data.errors[0].description) || 'Erro na comunicação com o Asaas');
  }
  return data;
}

// Garante que o CLIENTE FINAL (não o embaixador) tenha um cadastro no Asaas — a fatura é sempre em nome dele
async function garantirClienteAsaas(clienteMembroId){
  const r = await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[clienteMembroId]);
  if(!r.rows.length) throw new Error('Cliente não encontrado.');
  const c = r.rows[0];
  if(!c.documento) throw new Error('O cliente precisa ter CPF/CNPJ cadastrado em "Meus dados" antes de gerar o pagamento.');
  if(!c.cep || !c.numero) throw new Error('O cliente precisa completar CEP e número do endereço em "Meus dados" antes de gerar o pagamento — assim ele não precisa preencher tudo de novo na hora de pagar.');
  if(!c.celular && !c.telefone) throw new Error('O cliente precisa cadastrar um telefone/celular em "Meus dados" antes de gerar o pagamento.');

  // Manda o endereço completo — o Asaas resolve rua/bairro/cidade sozinho a partir do CEP + número,
  // então a fatura já chega pronta e o cliente não precisa preencher nada de novo.
  const dadosAsaas = {
    name: c.nome, cpfCnpj: c.documento.replace(/\D/g,''), email: c.email,
    phone: c.telefone || c.celular, mobilePhone: c.celular || c.telefone,
    postalCode: c.cep.replace(/\D/g,''), addressNumber: c.numero,
    complement: c.complemento || undefined,
    externalReference: 'circulo-membro-'+c.id
  };

  if(c.asaas_cliente_id){
    // Sempre re-sincroniza — se o cliente completou/corrigiu os dados depois da primeira vez,
    // a ficha no Asaas não pode ficar desatualizada e voltar a pedir tudo de novo na fatura.
    try{
      await asaasRequest('PUT', '/customers/'+c.asaas_cliente_id, dadosAsaas);
    }catch(e){ console.error('Sync cliente Asaas:', e.message); }
    return c.asaas_cliente_id;
  }

  const novo = await asaasRequest('POST', '/customers', dadosAsaas);
  await pool.query('UPDATE circulo_membros SET asaas_cliente_id=$1 WHERE id=$2',[novo.id, c.id]);
  return novo.id;
}

// Cria (ou reaproveita) a cobrança do pedido no Asaas
// Gera um link público único para o pedido (usado quando o cliente vai pagar sozinho)
async function garantirLinkPublico(pedidoId){
  const r = await pool.query('SELECT link_publico FROM circulo_pedidos WHERE id=$1',[pedidoId]);
  if(r.rows[0] && r.rows[0].link_publico) return r.rows[0].link_publico;
  const token = crypto.randomBytes(8).toString('hex');
  await pool.query('UPDATE circulo_pedidos SET link_publico=$1 WHERE id=$2',[token, pedidoId]);
  return token;
}

// Cria (ou reaproveita) uma cobrança PIX vinculada ao cliente, devolve QR pra exibir na hora.
async function obterOuCriarPix(pedidoId){
  const pRes = await pool.query('SELECT * FROM circulo_pedidos WHERE id=$1',[pedidoId]);
  const p = pRes.rows[0];
  if(!p) throw new Error('Pedido não encontrado.');
  if(!p.cliente_membro_id) throw new Error('Vincule um cliente ao pedido antes de gerar o pagamento.');
  if(p.status === 'PAGO') throw new Error('Este pedido já foi pago.');

  const asaasClienteId = await garantirClienteAsaas(p.cliente_membro_id);
  let paymentId = p.asaas_cobranca_id;

  if(!paymentId){
    const vencimento = new Date(Date.now() + 1*24*60*60*1000).toISOString().slice(0,10);
    const cobranca = await asaasRequest('POST', '/payments', {
      customer: asaasClienteId, billingType: 'PIX', value: parseFloat(p.total),
      dueDate: vencimento, description: 'Pedido ALMARE '+p.numero,
      externalReference: 'circulo-pedido-'+p.id
    });
    paymentId = cobranca.id;
    await pool.query(`UPDATE circulo_pedidos SET asaas_cliente_id=$1, asaas_cobranca_id=$2, status='AGUARDANDO_PAGAMENTO' WHERE id=$3`,[asaasClienteId, paymentId, p.id]);
  }

  const qr = await asaasRequest('GET', '/payments/'+paymentId+'/pixQrCode');
  return { encodedImage: qr.encodedImage, payload: qr.payload, expirationDate: qr.expirationDate };
}

// Cobra no cartão diretamente (sem redirecionar pro Asaas) — cliente continua vinculado,
// e a pessoa escolhe o parcelamento (1 a 6x) na NOSSA tela, não na deles.
async function pagarComCartao(pedidoId, dados, remoteIp){
  const pRes = await pool.query('SELECT * FROM circulo_pedidos WHERE id=$1',[pedidoId]);
  const p = pRes.rows[0];
  if(!p) throw new Error('Pedido não encontrado.');
  if(!p.cliente_membro_id) throw new Error('Vincule um cliente ao pedido antes de gerar o pagamento.');
  if(p.status === 'PAGO') throw new Error('Este pedido já foi pago.');

  const asaasClienteId = await garantirClienteAsaas(p.cliente_membro_id);
  const valorTotal = Math.round(parseFloat(p.total)*100)/100;
  const parcelas = Math.max(1, Math.min(6, parseInt(dados.parcelas)||1));
  const hoje = new Date().toISOString().slice(0,10);

  const corpo = {
    customer: asaasClienteId, billingType: 'CREDIT_CARD', dueDate: hoje,
    description: 'Pedido ALMARE '+p.numero, externalReference: 'circulo-pedido-'+p.id,
    remoteIp: remoteIp,
    creditCard: {
      holderName: dados.holderName,
      number: String(dados.number||'').replace(/\s+/g,''),
      expiryMonth: String(dados.expiryMonth||'').padStart(2,'0'),
      expiryYear: dados.expiryYear,
      ccv: dados.ccv
    },
    creditCardHolderInfo: {
      name: dados.holderName, email: dados.email,
      cpfCnpj: String(dados.cpfCnpj||'').replace(/\D/g,''),
      postalCode: String(dados.postalCode||'').replace(/\D/g,''),
      addressNumber: dados.addressNumber,
      phone: String(dados.phone||'').replace(/\D/g,'')
    }
  };
  if(parcelas > 1){ corpo.installmentCount = parcelas; corpo.totalValue = valorTotal; }
  else { corpo.value = valorTotal; }

  const resultado = await asaasRequest('POST', '/payments', corpo);
  const novoStatus = (resultado.status==='CONFIRMED' || resultado.status==='RECEIVED') ? 'PAGO' : 'AGUARDANDO_PAGAMENTO';
  await pool.query(`UPDATE circulo_pedidos SET asaas_cliente_id=$1, asaas_cobranca_id=$2, status=$3 WHERE id=$4`,
    [asaasClienteId, resultado.id, novoStatus, p.id]);
  if(novoStatus === 'PAGO'){ sincronizarPedidoBlingSeguro(p.id); concederBonusPedido(p.id); } // não bloqueia a resposta do pagamento
  return { status: resultado.status, pago: novoStatus==='PAGO' };
}

// Monta o formulário/UI de pagamento (PIX + Cartão) — reaproveitado na tela do membro
// e na página pública do cliente. urlBasePix/urlBaseCartao são os endpoints a chamar.
function montarUiPagamento(urlBasePix, urlBaseCartao, urlStatus, urlConfirmacao, dadosPreenchidos){
  const d = dadosPreenchidos || {};
  return `
    <div style="display:flex;gap:8px;margin-bottom:20px;">
      <button type="button" onclick="mostrarAba('pix')" id="aba-pix" class="btn btn-outline" style="flex:1;">PIX</button>
      <button type="button" onclick="mostrarAba('cartao')" id="aba-cartao" class="btn btn-outline" style="flex:1;">Cartão de crédito</button>
    </div>

    <div id="painel-pix" style="display:none;">
      <button type="button" onclick="gerarPix()" id="btn-gerar-pix" class="btn btn-primary btn-full">Gerar QR Code PIX</button>
      <div id="resultado-pix" style="margin-top:16px;"></div>
    </div>

    <div id="painel-cartao" style="display:none;">
      <div class="field"><label>Parcelas</label>
        <select id="pg-parcelas"></select>
      </div>
      <div class="field"><label>Nome impresso no cartão</label><input id="pg-holderName" placeholder="Como está no cartão"></div>
      <div class="field"><label>Número do cartão</label><input id="pg-number" placeholder="0000 0000 0000 0000" maxlength="19"></div>
      <div class="grid-2">
        <div class="field"><label>Validade (MM/AAAA)</label>
          <div style="display:flex;gap:8px;">
            <input id="pg-expiryMonth" placeholder="MM" maxlength="2" style="width:70px;">
            <input id="pg-expiryYear" placeholder="AAAA" maxlength="4" style="width:90px;">
          </div>
        </div>
        <div class="field"><label>CVV</label><input id="pg-ccv" placeholder="000" maxlength="4" style="width:90px;"></div>
      </div>
      <hr class="divider">
      <p style="font-size:12px;color:var(--muted);margin-bottom:12px;">Dados do titular do cartão (pode ser diferente do cliente, se estiver pagando com cartão de outra pessoa).</p>
      <div class="field"><label>Nome completo do titular</label><input id="pg-nome" value="${esc(d.nome||'')}"></div>
      <div class="grid-2">
        <div class="field"><label>CPF/CNPJ do titular</label><input id="pg-cpf" value="${esc(d.documento||'')}"></div>
        <div class="field"><label>Telefone do titular</label><input id="pg-telefone" value="${esc(d.telefone||'')}"></div>
      </div>
      <div class="field"><label>E-mail do titular</label><input id="pg-email" value="${esc(d.email||'')}"></div>
      <div class="grid-2">
        <div class="field"><label>CEP do titular</label><input id="pg-cep" value="${esc(d.cep||'')}"></div>
        <div class="field"><label>Número do endereço</label><input id="pg-numero" value="${esc(d.numero||'')}"></div>
      </div>
      <button type="button" onclick="pagarCartao()" id="btn-pagar-cartao" class="btn btn-primary btn-full" style="margin-top:8px;">Pagar</button>
      <div id="resultado-cartao" style="margin-top:16px;"></div>
    </div>

    <script>
      const PG_TOTAL = ${dadosPreenchidos.total || 0};
      const PG_URL_PIX = '${urlBasePix}';
      const PG_URL_CARTAO = '${urlBaseCartao}';
      const PG_URL_STATUS = '${urlStatus}';
      const PG_URL_CONFIRMACAO = '${urlConfirmacao}';

      function mostrarAba(aba){
        document.getElementById('painel-pix').style.display = aba==='pix' ? 'block' : 'none';
        document.getElementById('painel-cartao').style.display = aba==='cartao' ? 'block' : 'none';
        document.getElementById('aba-pix').style.borderColor = aba==='pix' ? 'var(--gold)' : 'var(--border)';
        document.getElementById('aba-cartao').style.borderColor = aba==='cartao' ? 'var(--gold)' : 'var(--border)';
        if(aba==='cartao' && document.getElementById('pg-parcelas').options.length===0) montarParcelas();
      }
      function montarParcelas(){
        const sel = document.getElementById('pg-parcelas');
        for(let n=1;n<=6;n++){
          const valor = (PG_TOTAL/n).toLocaleString('pt-BR',{minimumFractionDigits:2});
          const opt = document.createElement('option');
          opt.value = n;
          opt.textContent = n===1 ? '1x de R$ '+valor+' (à vista)' : n+'x de R$ '+valor;
          sel.appendChild(opt);
        }
      }
      async function gerarPix(){
        const btn = document.getElementById('btn-gerar-pix'); btn.disabled=true; btn.textContent='Gerando...';
        const areaR = document.getElementById('resultado-pix');
        try{
          const r = await fetch(PG_URL_PIX, { method:'POST' });
          const d = await r.json();
          btn.disabled=false; btn.textContent='Gerar QR Code PIX';
          if(d.erro){ areaR.innerHTML='<div class="msg-erro">'+d.erro+'</div>'; return; }
          areaR.innerHTML =
            '<div style="text-align:center;">'+
            '<img src="data:image/png;base64,'+d.encodedImage+'" style="width:220px;height:220px;background:#fff;padding:10px;border-radius:6px;">'+
            '<p style="font-size:12px;color:var(--muted);margin-top:12px;">Ou copie o código:</p>'+
            '<div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:12px;font-size:11px;word-break:break-all;margin:8px 0;">'+d.payload+'</div>'+
            '<button onclick="navigator.clipboard.writeText(this.dataset.payload);this.textContent=\\'Copiado ✓\\'" data-payload="'+d.payload+'" class="btn btn-outline" style="margin-bottom:14px;">Copiar código PIX</button>'+
            '<button onclick="verificarPix(this)" class="btn btn-primary btn-full">Já paguei — verificar</button>'+
            '<div id="status-pix" style="margin-top:10px;"></div>'+
            '</div>';
        }catch(e){ btn.disabled=false; btn.textContent='Gerar QR Code PIX'; areaR.innerHTML='<div class="msg-erro">Erro ao gerar PIX.</div>'; }
      }
      async function verificarPix(btn){
        btn.disabled=true; btn.textContent='Verificando...';
        const areaStatus = document.getElementById('status-pix');
        try{
          const r = await fetch(PG_URL_STATUS);
          const d = await r.json();
          btn.disabled=false; btn.textContent='Já paguei — verificar';
          if(d.pago){ window.location.href = PG_URL_CONFIRMACAO; return; }
          areaStatus.innerHTML = '<div class="msg-info">Ainda não identificamos o pagamento. Se já pagou, aguarde alguns segundos e tente de novo.</div>';
        }catch(e){ btn.disabled=false; btn.textContent='Já paguei — verificar'; areaStatus.innerHTML='<div class="msg-erro">Erro ao verificar.</div>'; }
      }
      async function pagarCartao(){
        const btn = document.getElementById('btn-pagar-cartao'); btn.disabled=true; btn.textContent='Processando...';
        const areaR = document.getElementById('resultado-cartao');
        areaR.innerHTML = '';
        const corpo = {
          parcelas: document.getElementById('pg-parcelas').value,
          holderName: document.getElementById('pg-holderName').value,
          number: document.getElementById('pg-number').value,
          expiryMonth: document.getElementById('pg-expiryMonth').value,
          expiryYear: document.getElementById('pg-expiryYear').value,
          ccv: document.getElementById('pg-ccv').value,
          email: document.getElementById('pg-email').value,
          cpfCnpj: document.getElementById('pg-cpf').value,
          postalCode: document.getElementById('pg-cep').value,
          addressNumber: document.getElementById('pg-numero').value,
          phone: document.getElementById('pg-telefone').value
        };
        try{
          const r = await fetch(PG_URL_CARTAO, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(corpo) });
          const d = await r.json();
          if(d.erro){ btn.disabled=false; btn.textContent='Pagar'; areaR.innerHTML='<div class="msg-erro">'+d.erro+'</div>'; return; }
          if(d.pago){ window.location.href = PG_URL_CONFIRMACAO; return; }
          btn.disabled=false; btn.textContent='Pagar';
          areaR.innerHTML='<div class="msg-info">Pagamento em análise (status: '+d.status+').</div>';
        }catch(e){ btn.disabled=false; btn.textContent='Pagar'; areaR.innerHTML='<div class="msg-erro">Erro ao processar pagamento.</div>'; }
      }
    </script>
  `;
}

// Tela de confirmação — celebra a compra, mostra número do pedido e resumo, com
// botão de baixar (imprimir/salvar) e um botão de fechar que volta pro Círculo.
function montarTelaConfirmacaoHtml(pedido, linhas, linkFechar, textoFechar){
  return `
    <div style="text-align:center;padding:20px 0 32px;">
      <div style="font-size:48px;margin-bottom:16px;">🎉</div>
      <h1 style="font-family:'Cormorant Garamond',serif;font-size:32px;margin-bottom:8px;">Parabéns!</h1>
      <p style="color:var(--gold);font-size:16px;margin-bottom:4px;">Você fez uma ótima compra.</p>
      <p style="color:var(--muted);font-size:13px;">Seu pedido está confirmado.</p>
    </div>
    <div class="card" style="margin-bottom:20px;">
      <div style="text-align:center;margin-bottom:20px;">
        <div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">Número do pedido</div>
        <div style="font-family:'Cormorant Garamond',serif;font-size:26px;color:var(--gold);">${esc(pedido.numero)}</div>
      </div>
      ${linhas}
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:20px;margin-top:8px;border-top:1px solid var(--border);">
        <span style="font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total pago</span>
        <span style="font-family:'Cormorant Garamond',serif;font-size:28px;color:var(--gold);">R$ ${parseFloat(pedido.total).toFixed(2).replace('.',',')}</span>
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button onclick="window.print()" class="btn btn-outline" style="flex:1;min-width:160px;">Baixar confirmação</button>
      ${linkFechar ? `<a href="${linkFechar}" class="btn btn-primary" style="flex:1;min-width:160px;text-align:center;">${esc(textoFechar)}</a>` : `<div style="flex:1;min-width:160px;text-align:center;color:var(--muted);font-size:12px;padding:13px 0;">Você já pode fechar esta janela.</div>`}
    </div>
  `;
}

// Monta o HTML do resumo do pedido (reaproveitado na tela do membro e na página pública)
async function montarResumoPedidoHtml(pedidoId){
  const pRes = await pool.query('SELECT * FROM circulo_pedidos WHERE id=$1',[pedidoId]);
  const pedido = pRes.rows[0];
  const itens = await pool.query(`
    SELECT pi.*, o.nome as obra_nome, o.imagem_preview
    FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id=pi.obra_id
    WHERE pi.pedido_id=$1 ORDER BY pi.criado_em`, [pedidoId]);
  const cliente = pedido.cliente_membro_id ? (await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[pedido.cliente_membro_id])).rows[0] : null;

  const linhas = itens.rows.map(it=>`
    <div style="display:flex;align-items:center;gap:16px;padding:14px 0;border-bottom:1px solid var(--border);">
      <div style="width:56px;height:56px;border-radius:4px;overflow:hidden;background:#0d0d0d;flex-shrink:0;">
        ${it.imagem_preview?`<img src="${esc(it.imagem_preview)}" style="width:100%;height:100%;object-fit:cover;">`:''}
      </div>
      <div style="flex:1;">
        <div style="font-family:'Cormorant Garamond',serif;font-size:16px;">${esc(it.obra_nome)}</div>
        <div style="font-size:12px;color:var(--muted);">${esc(it.tamanho_label)} · Moldura ${esc(MOLDURA_NOME[it.moldura]||it.moldura)} · Qtd ${it.quantidade}</div>
      </div>
      <div style="font-size:14px;color:var(--gold);">R$ ${parseFloat(it.subtotal).toFixed(2).replace('.',',')}</div>
    </div>`).join('');

  return { pedido, cliente, itens: itens.rows, linhas };
}

// ─── ROTA: membro finaliza o pedido (resumo + pagamento embutido: PIX ou cartão) ──
// ─── Retomar pagamento de um pedido específico (a partir de "Meus Pedidos") ──
app.post('/pedido-interno/:id/cancelar', authMembro, async(req,res)=>{
  try{
    const pedidoId = parseInt(req.params.id);
    const r = await pool.query(
      `UPDATE circulo_pedidos SET status='CANCELADO' WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2) AND status='AGUARDANDO_PAGAMENTO' RETURNING id`,
      [pedidoId, req.membro.id]
    );
    if(!r.rows.length) return res.json({ erro:'Não foi possível cancelar este pedido.' });
    res.json({ ok:true });
  }catch(e){ res.json({ erro: e.message }); }
});

// Reabre um pedido AGUARDANDO_PAGAMENTO pra edição — nunca mexe em pedido já PAGO.
// Limpa a cobrança pendente (senão ficaria órfã, vinculada a um pedido que vai mudar)
// e devolve pro estado de carrinho, onde a edição normal já existe.
app.post('/pedido-interno/:id/reabrir', authMembro, async(req,res)=>{
  try{
    const pedidoId = parseInt(req.params.id);
    const r = await pool.query(
      `UPDATE circulo_pedidos SET status='CARRINHO', asaas_cliente_id=NULL, asaas_cobranca_id=NULL, invoice_url=NULL, link_publico=NULL
       WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2) AND status='AGUARDANDO_PAGAMENTO' RETURNING id`,
      [pedidoId, req.membro.id]
    );
    if(!r.rows.length) return res.json({ erro:'Não foi possível reabrir este pedido.' });
    res.json({ ok:true });
  }catch(e){ res.json({ erro: e.message }); }
});

app.get('/pedido-interno/:id/pagar', authMembro, async(req,res)=>{
  const pedidoId = parseInt(req.params.id);
  const check = await pool.query(
    `SELECT id, status FROM circulo_pedidos WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2)`,
    [pedidoId, req.membro.id]
  );
  if(!check.rows.length) return res.redirect('/meus-pedidos');
  if(check.rows[0].status === 'PAGO') return res.redirect('/meus-pedidos');

  const { pedido, cliente, linhas } = await montarResumoPedidoHtml(pedidoId);
  const uiPagamento = montarUiPagamento(
    '/pedido-interno/'+pedidoId+'/pagamento/pix',
    '/pedido-interno/'+pedidoId+'/pagamento/cartao',
    '/pedido-interno/'+pedidoId+'/status',
    '/pedido-interno/'+pedidoId+'/confirmado',
    { total: parseFloat(pedido.total), nome: cliente.nome, documento: cliente.documento,
      telefone: cliente.telefone||cliente.celular, email: cliente.email, cep: cliente.cep, numero: cliente.numero }
  );

  res.send(html('Pagar pedido',`
    <a href="/meus-pedidos" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar aos pedidos</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Pedido ${esc(pedido.numero)}</h2>
    <div class="card" style="margin-bottom:20px;">
      <div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Faturado em nome de</div>
      <div style="font-size:16px;margin-bottom:20px;">${esc(cliente.nome)} ${cliente.documento?'· '+esc(cliente.documento):''}</div>
      ${linhas}
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:20px;margin-top:8px;border-top:1px solid var(--border);">
        <span style="font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total</span>
        <span style="font-family:'Cormorant Garamond',serif;font-size:28px;color:var(--gold);">R$ ${parseFloat(pedido.total).toFixed(2).replace('.',',')}</span>
      </div>
    </div>
    <div class="card">
      <h3 style="font-size:18px;margin-bottom:16px;">Pagar agora</h3>
      ${uiPagamento}
    </div>
  `,true));
});

app.post('/pedido-interno/:id/pagamento/pix', authMembro, async(req,res)=>{
  try{
    const pedidoId = parseInt(req.params.id);
    const check = await pool.query(`SELECT id FROM circulo_pedidos WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2)`,[pedidoId, req.membro.id]);
    if(!check.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const dadosPix = await obterOuCriarPix(pedidoId);
    res.json(dadosPix);
  }catch(e){ res.json({ erro: e.message }); }
});

app.post('/pedido-interno/:id/pagamento/cartao', authMembro, async(req,res)=>{
  try{
    const pedidoId = parseInt(req.params.id);
    const check = await pool.query(`SELECT id FROM circulo_pedidos WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2)`,[pedidoId, req.membro.id]);
    if(!check.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const resultado = await pagarComCartao(pedidoId, req.body, req.ip);
    res.json(resultado);
  }catch(e){ res.json({ erro: e.message }); }
});

app.get('/pedido-interno/:id/status', authMembro, async(req,res)=>{
  const pedidoId = parseInt(req.params.id);
  const r = await pool.query(`SELECT status FROM circulo_pedidos WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2)`,[pedidoId, req.membro.id]);
  if(!r.rows.length) return res.json({ erro:'Pedido não encontrado.' });
  res.json({ pago: r.rows[0].status === 'PAGO' });
});

app.get('/pedido-interno/:id/confirmado', authMembro, async(req,res)=>{
  const pedidoId = parseInt(req.params.id);
  const check = await pool.query(`SELECT id FROM circulo_pedidos WHERE id=$1 AND (membro_id=$2 OR cliente_membro_id=$2)`,[pedidoId, req.membro.id]);
  if(!check.rows.length) return res.redirect('/meus-pedidos');
  const { pedido, linhas } = await montarResumoPedidoHtml(pedidoId);
  res.send(html('Pedido confirmado', montarTelaConfirmacaoHtml(pedido, linhas, '/portal', 'Fechar'), true));
});

app.get('/carrinho/finalizar', authMembro, async(req,res)=>{
  const pedidoRes = await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status IN ('CARRINHO','AGUARDANDO_PAGAMENTO') ORDER BY criado_em DESC LIMIT 1`,[req.membro.id]);
  if(!pedidoRes.rows.length) return res.redirect('/carrinho');
  const pedido = pedidoRes.rows[0];
  if(!pedido.cliente_membro_id) return res.redirect('/carrinho');

  const { cliente, linhas } = await montarResumoPedidoHtml(pedido.id);
  const uiPagamento = montarUiPagamento(
    '/carrinho/pagamento/pix', '/carrinho/pagamento/cartao',
    '/pedido-interno/'+pedido.id+'/status', '/pedido-interno/'+pedido.id+'/confirmado',
    { total: parseFloat(pedido.total),
      nome: cliente.nome, documento: cliente.documento, telefone: cliente.telefone||cliente.celular,
      email: cliente.email, cep: cliente.cep, numero: cliente.numero }
  );

  res.send(html('Finalizar pedido',`
    <a href="/carrinho" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar ao carrinho</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Finalizar pedido</h2>
    <p style="color:var(--muted);margin-bottom:24px;">Confira tudo antes de seguir para o pagamento.</p>
    <div class="card" style="margin-bottom:20px;">
      <div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Faturado em nome de</div>
      <div style="font-size:16px;margin-bottom:20px;">${esc(cliente.nome)} ${cliente.documento?'· '+esc(cliente.documento):''}</div>
      ${linhas}
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:20px;margin-top:8px;border-top:1px solid var(--border);">
        <span style="font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total</span>
        <span style="font-family:'Cormorant Garamond',serif;font-size:28px;color:var(--gold);">R$ ${parseFloat(pedido.total).toFixed(2).replace('.',',')}</span>
      </div>
    </div>
    <div class="card" style="margin-bottom:20px;">
      <h3 style="font-size:18px;margin-bottom:16px;">Pagar agora</h3>
      ${uiPagamento}
    </div>
    <div class="card">
      <h3 style="font-size:16px;margin-bottom:12px;">Ou envie para o cliente pagar sozinho</h3>
      <button onclick="gerarLinkCliente()" class="btn btn-outline btn-full" id="btn-link-cliente">Gerar link para o cliente</button>
      <div id="resultado-link" style="margin-top:16px;"></div>
    </div>
    <script>
      async function gerarLinkCliente(){
        const btn=document.getElementById('btn-link-cliente'); btn.disabled=true; btn.textContent='Gerando link...';
        try{
          const r = await fetch('/carrinho/gerar-link', { method:'POST' });
          const d = await r.json();
          btn.disabled=false; btn.textContent='Gerar link para o cliente';
          if(d.erro){ document.getElementById('resultado-link').innerHTML='<div class="msg-erro">'+d.erro+'</div>'; return; }
          document.getElementById('resultado-link').innerHTML =
            '<div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:12px;">'+d.linkPublico+'</div>'+
            '<button onclick="navigator.clipboard.writeText(\\''+d.linkPublico+'\\');this.textContent=\\'Copiado ✓\\'" class="btn btn-outline">Copiar link</button>';
        }catch(e){ document.getElementById('resultado-link').innerHTML='<div class="msg-erro">Erro ao gerar link.</div>'; btn.disabled=false; }
      }
    </script>
  `,true));
});

app.post('/carrinho/gerar-link', authMembro, async(req,res)=>{
  try{
    const pedidoRes = await pool.query(`SELECT id FROM circulo_pedidos WHERE membro_id=$1 AND status IN ('CARRINHO','AGUARDANDO_PAGAMENTO') ORDER BY criado_em DESC LIMIT 1`,[req.membro.id]);
    if(!pedidoRes.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const token = await garantirLinkPublico(pedidoRes.rows[0].id);
    res.json({ linkPublico: BASE_URL+'/pedido/'+token });
  }catch(e){ res.json({ erro: e.message }); }
});

app.post('/carrinho/pagamento/pix', authMembro, async(req,res)=>{
  try{
    const pedidoRes = await pool.query(`SELECT id FROM circulo_pedidos WHERE membro_id=$1 AND status IN ('CARRINHO','AGUARDANDO_PAGAMENTO') ORDER BY criado_em DESC LIMIT 1`,[req.membro.id]);
    if(!pedidoRes.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const dadosPix = await obterOuCriarPix(pedidoRes.rows[0].id);
    res.json(dadosPix);
  }catch(e){ res.json({ erro: e.message }); }
});

app.post('/carrinho/pagamento/cartao', authMembro, async(req,res)=>{
  try{
    const pedidoRes = await pool.query(`SELECT id FROM circulo_pedidos WHERE membro_id=$1 AND status IN ('CARRINHO','AGUARDANDO_PAGAMENTO') ORDER BY criado_em DESC LIMIT 1`,[req.membro.id]);
    if(!pedidoRes.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const resultado = await pagarComCartao(pedidoRes.rows[0].id, req.body, req.ip);
    res.json(resultado);
  }catch(e){ res.json({ erro: e.message }); }
});

// ─── PÁGINA PÚBLICA — cliente vê o pedido e paga sozinho, sem precisar de login ──
app.get('/pedido/:token', async(req,res)=>{
  const r = await pool.query('SELECT id FROM circulo_pedidos WHERE link_publico=$1',[req.params.token]);
  if(!r.rows.length) return res.status(404).send(html('Pedido',`<div class="container-sm"><div class="msg-erro">Este link não existe mais.</div></div>`));
  const { pedido, cliente, linhas } = await montarResumoPedidoHtml(r.rows[0].id);
  const tokenEsc = esc(req.params.token);
  const uiPagamento = montarUiPagamento(
    '/pedido/'+tokenEsc+'/pagamento/pix', '/pedido/'+tokenEsc+'/pagamento/cartao',
    '/pedido/'+tokenEsc+'/status', '/pedido/'+tokenEsc+'/confirmado',
    { total: parseFloat(pedido.total),
      nome: cliente.nome, documento: cliente.documento, telefone: cliente.telefone||cliente.celular,
      email: cliente.email, cep: cliente.cep, numero: cliente.numero }
  );

  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Seu pedido — ALMARE</title><style>${CSS}</style></head>
    <body><div class="container" style="max-width:640px;padding-top:48px;">
      <div class="logo" style="margin-bottom:32px;">ALMARE</div>
      <h1 style="font-size:28px;margin-bottom:8px;">Seu pedido</h1>
      <p style="color:var(--muted);margin-bottom:24px;">Confira os itens abaixo antes de pagar.</p>
      <div class="card" style="margin-bottom:20px;">
        <div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Faturado em nome de</div>
        <div style="font-size:16px;margin-bottom:20px;">${esc(cliente.nome)} ${cliente.documento?'· '+esc(cliente.documento):''}</div>
        ${linhas}
        <div style="display:flex;justify-content:space-between;align-items:center;padding-top:20px;margin-top:8px;border-top:1px solid var(--border);">
          <span style="font-size:14px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);">Total</span>
          <span style="font-family:'Cormorant Garamond',serif;font-size:28px;color:var(--gold);">R$ ${parseFloat(pedido.total).toFixed(2).replace('.',',')}</span>
        </div>
      </div>
      <div class="card">
        <h3 style="font-size:18px;margin-bottom:16px;">Pagamento</h3>
        <p style="color:var(--muted);font-size:12px;margin-bottom:16px;">PIX ou cartão de crédito em até 6x, processado com segurança pelo Asaas.</p>
        ${uiPagamento}
      </div>
    </div></body></html>`);
});

app.post('/pedido/:token/pagamento/pix', async(req,res)=>{
  try{
    const r = await pool.query('SELECT id FROM circulo_pedidos WHERE link_publico=$1',[req.params.token]);
    if(!r.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const dadosPix = await obterOuCriarPix(r.rows[0].id);
    res.json(dadosPix);
  }catch(e){ res.json({ erro: e.message }); }
});

app.post('/pedido/:token/pagamento/cartao', async(req,res)=>{
  try{
    const r = await pool.query('SELECT id FROM circulo_pedidos WHERE link_publico=$1',[req.params.token]);
    if(!r.rows.length) return res.json({ erro:'Pedido não encontrado.' });
    const resultado = await pagarComCartao(r.rows[0].id, req.body, req.ip);
    res.json(resultado);
  }catch(e){ res.json({ erro: e.message }); }
});

app.get('/pedido/:token/status', async(req,res)=>{
  const r = await pool.query('SELECT status FROM circulo_pedidos WHERE link_publico=$1',[req.params.token]);
  if(!r.rows.length) return res.json({ erro:'Pedido não encontrado.' });
  res.json({ pago: r.rows[0].status === 'PAGO' });
});

app.get('/pedido/:token/confirmado', async(req,res)=>{
  const r = await pool.query('SELECT id FROM circulo_pedidos WHERE link_publico=$1',[req.params.token]);
  if(!r.rows.length) return res.status(404).send(html('Pedido',`<div class="container-sm"><div class="msg-erro">Este link não existe mais.</div></div>`));
  const { pedido, linhas } = await montarResumoPedidoHtml(r.rows[0].id);
  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Pedido confirmado — ALMARE</title><style>${CSS}</style></head>
    <body><div class="container" style="max-width:640px;padding-top:48px;">
      <div class="logo" style="margin-bottom:32px;">ALMARE</div>
      ${montarTelaConfirmacaoHtml(pedido, linhas, null, 'Fechar')}
    </div></body></html>`);
});

// ─── WEBHOOK ASAAS — confirma pagamento automaticamente ──────────────────────
// O Asaas chama esta rota sozinho quando o status de uma cobrança muda. Nunca requer
// login (é o próprio Asaas batendo aqui, não um membro). Sempre responde rápido.
app.post('/webhook/asaas', async(req,res)=>{
  try{
    // Valida que a chamada realmente veio do Asaas — protege contra alguém forjar o aviso.
    // Se a variável não estiver configurada ainda, deixa passar (evita travar antes de configurar).
    if(process.env.ASAAS_WEBHOOK_TOKEN){
      const tokenRecebido = req.headers['asaas-access-token'];
      if(tokenRecebido !== process.env.ASAAS_WEBHOOK_TOKEN){
        console.error('Webhook Asaas: token inválido, requisição rejeitada.');
        return res.status(401).json({ received:false });
      }
    }

    const { id: eventId, event, payment } = req.body || {};
    if(!eventId || !event) return res.json({ received:true });

    // Idempotência: o Asaas pode reenviar o mesmo evento mais de uma vez. Se já
    // processamos este event_id antes, não processa de novo — só confirma recebido.
    const dedup = await pool.query(
      'INSERT INTO circulo_asaas_eventos (event_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING event_id',
      [eventId]
    );
    if(!dedup.rows.length) return res.json({ received:true });

    if((event === 'PAYMENT_CONFIRMED' || event === 'PAYMENT_RECEIVED') && payment && payment.externalReference){
      const m = String(payment.externalReference).match(/^circulo-pedido-(\d+)$/);
      if(m){
        const pedidoId = parseInt(m[1]);
        const upd = await pool.query(
          `UPDATE circulo_pedidos SET status='PAGO' WHERE id=$1 AND status<>'PAGO' RETURNING id`,
          [pedidoId]
        );
        if(upd.rows.length){
          console.log(`Webhook Asaas: pedido ${pedidoId} marcado como PAGO (evento ${event})`);
          sincronizarPedidoBlingSeguro(pedidoId); // não bloqueia a resposta ao Asaas
          concederBonusPedido(pedidoId);
        }
      }
    }
    res.json({ received:true });
  }catch(e){
    console.error('Webhook Asaas erro:', e.message);
    // Responde erro pro Asaas tentar de novo mais tarde — só em falha real (ex: banco fora do ar)
    res.status(500).json({ received:false });
  }
});


// Página de compra de uma obra (escolher tamanho, moldura, quantidade)
// Tamanhos oficiais da obra (com preço), pra exibir no catálogo assim que a pessoa abre a obra
app.get('/obra/:obraId/tamanhos-json', authMembro, async(req,res)=>{
  try{
    const tamanhos = await tamanhosDaObra(parseInt(req.params.obraId));
    res.json({ tamanhos: tamanhos.map(t=>({ id:t.id, label:t.label, preco:t.preco, precoLabel: 'R$ '+t.preco.toLocaleString('pt-BR') })) });
  }catch(e){ res.status(500).json({ erro: e.message }); }
});

app.get('/obra/:obraId/comprar', authMembro, async(req,res)=>{
  const obraId = parseInt(req.params.obraId);
  const obra = await pool.query('SELECT id,nome,colecao,imagem_preview FROM almare_obras WHERE id=$1 AND status=\'aprovada\'',[obraId]);
  if(!obra.rows.length) return res.send(html('Comprar',`<div class="msg-erro">Obra não encontrada.</div>`,true));
  const o = obra.rows[0];
  const tamanhos = await tamanhosDaObra(obraId);
  if(!tamanhos.length) return res.send(html('Comprar',`<div class="msg-erro">Esta obra não tem tamanhos disponíveis.</div>`,true));

  const opcoesTam = tamanhos.map(t=>`<option value="${t.id}">${esc(t.label)} · R$ ${t.preco.toLocaleString('pt-BR')}</option>`).join('');
  const codigoInd = req.query.ref || '';

  res.send(html('Comprar',`
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar às obras</a>
    <h2 style="font-size:26px;margin-bottom:4px;">${esc(o.nome)}</h2>
    <div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:24px;">${esc(o.colecao||'')}</div>
    ${o.imagem_preview?`<img src="${esc(o.imagem_preview)}" style="max-width:100%;max-height:360px;display:block;margin:0 auto 24px;border-radius:4px;">`:''}
    <div class="card">
      <form method="POST" action="/comprar/${obraId}/adicionar">
        <input type="hidden" name="codigo_indicacao" value="${esc(codigoInd)}">
        <div class="field"><label>Tamanho</label><select name="tamanho_id" required>${opcoesTam}</select></div>
        <div class="field"><label>Moldura</label>
          <select name="moldura" required>
            <option value="preta">Preta</option>
            <option value="carvalho">Carvalho</option>
            <option value="aco_escovado">Aço escovado</option>
          </select>
        </div>
        <div class="field"><label>Quantidade</label><input type="number" name="quantidade" value="1" min="1" max="20"></div>
        <button type="submit" class="btn btn-primary btn-full">Adicionar ao carrinho</button>
      </form>
    </div>
  `,true));
});

// ─── CATÁLOGO ─────────────────────────────────────────────────────────────────
// ─── ESPECIFICADOR — modelos 3D gerados SOB DEMANDA (.skp/.obj/.dxf) ──
// Nao ha arquivo pre-fabricado: cada download e gerado na hora do pedido,
// a partir da imagem real da obra + tamanho + moldura escolhidos.
const { gerarModelo3D, NOMES_MOLDURA } = require('./gerador3d');

app.get('/modelos-3d', authMembro, async(req,res)=>{
  if(!(await ehEspecificador(req.membro.id))){
    return res.send(html('Modelos 3D', `<div class="card"><p style="color:var(--muted)">Esta ferramenta é exclusiva de membros com a função <strong style="color:var(--gold)">Especificador</strong> ativa. <a href="/minhas-funcoes" style="color:var(--gold)">Ativar função →</a></p></div>`, true));
  }
  const temImpacto = await temFuncaoComImpacto(req.membro.id);
  const obras = await pool.query(`
    SELECT id, codigo, nome, colecao, formato_recomendado, tamanhos_recomendados, orientacao, imagem_preview
    FROM almare_obras WHERE status='aprovada' AND codigo <> 'ALM-001' AND imagem_preview IS NOT NULL
    ORDER BY nome`);

  let corpo = navBar('modelos3d', temImpacto, true);
  corpo += `<h2 style="font-size:28px;margin-bottom:8px;">Modelos 3D</h2>`;
  corpo += `<p style="color:var(--muted);margin-bottom:24px;">Escolha a obra, o tamanho, a moldura e o formato. O arquivo é gerado na hora — monte sua lista e baixe tudo de uma vez.</p>`;

  corpo += `<div id="carrinho-3d-resumo" class="card" style="margin-bottom:24px;display:none;position:sticky;top:12px;z-index:10;border-color:var(--gold);">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div><strong id="carrinho-3d-contagem">0</strong> arquivo(s) na lista</div>
      <div style="display:flex;gap:8px;">
        <button onclick="limparCarrinho3d()" class="btn btn-outline" style="padding:8px 14px;font-size:11px;">Limpar</button>
        <button onclick="baixarCarrinho3d()" class="btn btn-primary" style="padding:8px 14px;font-size:11px;">Gerar e baixar (.zip)</button>
      </div>
    </div>
    <div id="carrinho-3d-itens" style="margin-top:10px;font-size:12px;color:var(--muted);"></div>
  </div>`;

  obras.rows.forEach(o=>{
    corpo += `<div class="card" style="margin-bottom:16px;" data-obra="${o.id}" data-codigo="${o.codigo}" data-nome="${o.nome.replace(/"/g,'&quot;')}">
      <div style="display:flex;gap:14px;align-items:center;margin-bottom:14px;">
        <img src="${o.imagem_preview}" style="width:56px;height:56px;object-fit:cover;border-radius:4px;">
        <div><div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">${o.colecao||''}</div>
        <div style="font-family:'Cormorant Garamond',serif;font-size:19px;">${o.nome}</div></div>
      </div>
      <div id="opcoes-${o.id}" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">
        <div style="flex:1;min-width:140px;"><label style="font-size:10px;color:var(--muted);">Tamanho</label>
          <select id="tam-${o.id}" style="width:100%;padding:8px;background:#0d0d0d;border:1px solid var(--border);color:#fff;border-radius:3px;">Carregando...</select></div>
        <div style="min-width:130px;"><label style="font-size:10px;color:var(--muted);">Moldura</label>
          <select id="mold-${o.id}" style="width:100%;padding:8px;background:#0d0d0d;border:1px solid var(--border);color:#fff;border-radius:3px;">
            <option value="preta">Preta</option><option value="carvalho">Carvalho</option><option value="aco_escovado">Aço escovado</option>
          </select></div>
        <div style="min-width:100px;"><label style="font-size:10px;color:var(--muted);">Formato</label>
          <select id="fmt-${o.id}" style="width:100%;padding:8px;background:#0d0d0d;border:1px solid var(--border);color:#fff;border-radius:3px;">
            <option value="skp">.skp</option><option value="obj">.obj</option><option value="dxf">.dxf</option>
          </select></div>
        <button type="button" onclick="adicionarItem3d(${o.id})" class="btn btn-outline" style="padding:8px 14px;font-size:11px;">+ Adicionar</button>
      </div>
    </div>`;
  });

  corpo += `<script>
    let CARRINHO3D = [];

    document.querySelectorAll('[data-obra]').forEach(async (cardEl) => {
      const obraId = cardEl.dataset.obra;
      const r = await fetch('/modelos-3d/tamanhos/' + obraId);
      const d = await r.json();
      const sel = document.getElementById('tam-' + obraId);
      sel.innerHTML = (d.tamanhos||[]).map((t,idx)=>'<option value=\\''+t.largura+'x'+t.altura+'\\'>'+t.label+'</option>').join('');
    });

    function adicionarItem3d(obraId){
      const cardEl = document.querySelector('[data-obra="'+obraId+'"]');
      const [largura, altura] = document.getElementById('tam-'+obraId).value.split('x').map(Number);
      const moldura = document.getElementById('mold-'+obraId).value;
      const formato = document.getElementById('fmt-'+obraId).value;
      CARRINHO3D.push({ obraId: Number(obraId), obraCodigo: cardEl.dataset.codigo, obraNome: cardEl.dataset.nome, largura, altura, moldura, formato });
      atualizarResumoCarrinho3d();
    }

    function atualizarResumoCarrinho3d(){
      const resumo = document.getElementById('carrinho-3d-resumo');
      const contagem = document.getElementById('carrinho-3d-contagem');
      const itens = document.getElementById('carrinho-3d-itens');
      if(CARRINHO3D.length === 0){ resumo.style.display = 'none'; return; }
      resumo.style.display = 'block';
      contagem.textContent = CARRINHO3D.length;
      const nomesMoldura = { preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado' };
      itens.innerHTML = CARRINHO3D.map((i,idx) => i.obraNome+' · '+i.largura+'×'+i.altura+'cm · '+(nomesMoldura[i.moldura]||i.moldura)+' · .'+i.formato+' <a href="#" onclick="removerItem3d('+idx+');return false;" style="color:var(--danger);margin-left:6px;">✕</a>').join('<br>');
    }

    function removerItem3d(idx){ CARRINHO3D.splice(idx,1); atualizarResumoCarrinho3d(); }
    function limparCarrinho3d(){ CARRINHO3D = []; atualizarResumoCarrinho3d(); }

    async function baixarCarrinho3d(){
      if(!CARRINHO3D.length) return;
      const btn = event.target;
      const textoOriginal = btn.textContent;
      btn.disabled = true; btn.textContent = 'Gerando arquivos...';
      try{
        const r = await fetch('/modelos-3d/baixar', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ itens: CARRINHO3D }) });
        if(!r.ok){ const t = await r.text(); alert('Erro: '+t); btn.disabled=false; btn.textContent=textoOriginal; return; }
        const blob = await r.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'ALMARE_modelos-3d.zip';
        document.body.appendChild(a); a.click(); a.remove();
        window.URL.revokeObjectURL(url);
      }catch(e){ alert('Erro ao gerar: '+e.message); }
      btn.disabled = false; btn.textContent = textoOriginal;
    }
  </script>`;

  res.send(html('Modelos 3D', corpo, true));
});

// Tamanhos validos pra essa obra (mesma regra ja usada no simulador — respeita formato/orientacao)
app.get('/modelos-3d/tamanhos/:obraId', authMembro, async(req,res)=>{
  try{
    const o = await pool.query('SELECT formato_recomendado, tamanhos_recomendados, orientacao FROM almare_obras WHERE id=$1', [req.params.obraId]);
    if(!o.rows.length) return res.json({ tamanhos: [] });
    let tams = tamanhosOficiais(o.rows[0].formato_recomendado, o.rows[0].tamanhos_recomendados);
    const orient = String(o.rows[0].orientacao||'').toLowerCase();
    if(/vertical|retrato/.test(orient)){ const v = tams.filter(t=>t.altura>=t.largura); if(v.length) tams=v; }
    else if(/horizontal|paisagem/.test(orient)){ const h = tams.filter(t=>t.largura>=t.altura); if(h.length) tams=h; }
    res.json({ tamanhos: tams });
  }catch(e){ res.status(500).json({ erro: e.message }); }
});

app.post('/modelos-3d/baixar', authMembro, async(req,res)=>{
  try{
    if(!(await ehEspecificador(req.membro.id))) return res.status(403).send('Acesso restrito a especificadores.');
    const { itens } = req.body;
    if(!itens || !itens.length) return res.status(400).send('Nenhum item selecionado.');
    if(itens.length > 30) return res.status(400).send('Máximo de 30 arquivos por download.');

    const zip = new AdmZip();
    for(const item of itens){
      const obra = await pool.query('SELECT imagem_preview FROM almare_obras WHERE id=$1', [item.obraId]);
      if(!obra.rows.length || !obra.rows[0].imagem_preview) continue;
      const base64Img = obra.rows[0].imagem_preview.replace(/^data:image\/\w+;base64,/, '');
      const imagemBytes = Buffer.from(base64Img, 'base64');

      const resultado = await gerarModelo3D({
        obraCodigo: item.obraCodigo, obraNome: item.obraNome,
        larguraCm: item.largura, alturaCm: item.altura, moldura: item.moldura, formato: item.formato,
        imagemBytes
      });
      zip.addFile(resultado.nomeArquivo, resultado.buffer);
      if(resultado.mtlBuffer) zip.addFile(resultado.nomeArquivoMtl, resultado.mtlBuffer);

      await pool.query(
        `INSERT INTO circulo_downloads_3d (membro_id, obra_id, obra_nome, largura, altura, moldura, formato) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [req.membro.id, item.obraId, item.obraNome, item.largura, item.altura, item.moldura, item.formato]);
    }

    const buf = zip.toBuffer();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="ALMARE_modelos-3d.zip"');
    res.send(buf);
  }catch(e){
    console.error('ERRO GERACAO 3D:', e.message);
    res.status(500).send('Erro ao gerar modelo: ' + e.message);
  }
});

app.get('/identificar', authMembro, async(req,res)=>{
  const temImpacto = await temFuncaoComImpacto(req.membro.id);
  res.send(html('Identificar obra',`
    ${navBar('identificar', temImpacto, await ehEspecificador(req.membro.id))}
    <h2 style="font-size:28px;margin-bottom:8px;">Identificar obra</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Tire uma foto de uma peça física e o sistema reconhece qual obra do acervo ALMARE ela é.</p>
    <div class="card">
      <div class="field">
        <label>Foto da peça</label>
        <input type="file" id="id-foto" accept="image/*" capture="environment" style="width:100%;padding:10px;background:#0d0d0d;border:1px solid var(--border);border-radius:3px;color:#fff">
      </div>
      <div id="id-preview" style="margin:16px 0;"></div>
      <button class="btn btn-primary" id="id-btn" onclick="identificarFoto()">Identificar</button>
      <div id="id-resultado" style="margin-top:20px;"></div>
    </div>
    <script>
      document.getElementById('id-foto').addEventListener('change', function(e){
        const f = e.target.files[0];
        if (!f) return;
        document.getElementById('id-preview').innerHTML = '<img src="'+URL.createObjectURL(f)+'" style="max-width:240px;border-radius:4px;">';
      });
      async function identificarFoto(){
        const inp = document.getElementById('id-foto');
        const btn = document.getElementById('id-btn');
        const res = document.getElementById('id-resultado');
        if (!inp.files[0]) { alert('Escolhe uma foto primeiro.'); return; }
        btn.disabled = true; btn.textContent = 'Identificando...';
        res.innerHTML = '';
        try {
          const fd = new FormData();
          fd.append('foto', inp.files[0]);
          const r = await fetch('/identificar', { method: 'POST', body: fd });
          const texto = await r.text();
          let d; try { d = JSON.parse(texto); } catch(e) { throw new Error('O servidor demorou ou teve uma instabilidade. Tenta de novo.'); }
          if (!r.ok) throw new Error(d.erro || 'Erro ao identificar');
          if (!d.encontrado) {
            res.innerHTML = '<div class="msg-erro">Não consegui identificar com segurança. '+(d.justificativa||'')+'</div>';
          } else {
            res.innerHTML = '<div style="display:flex;gap:16px;align-items:center;padding:16px;border:1px solid var(--gold);border-radius:4px;">'
              + (d.obra.imagem_preview ? '<img src="'+d.obra.imagem_preview+'" style="width:80px;height:80px;object-fit:cover;border-radius:4px;flex-shrink:0;">' : '')
              + '<div><div style="font-family:\\'Cormorant Garamond\\',serif;font-size:20px;">'+d.obra.nome+'</div>'
              + '<div style="font-size:12px;color:var(--muted);margin-bottom:8px;">'+d.obra.codigo+' · '+(d.obra.colecao||'')+' · Confiança: '+d.confianca+'</div>'
              + '<a href="/obra/'+d.obra.id+'/comprar" class="btn btn-outline" style="padding:6px 14px;font-size:11px;">Ver obra</a></div></div>';
          }
        } catch(e) {
          res.innerHTML = '<div class="msg-erro">'+e.message+'</div>';
        }
        btn.disabled = false; btn.textContent = 'Identificar';
      }
    </script>
  `,true));
});

app.post('/identificar', authMembro, uploadFoto.single('foto'), async(req,res)=>{
  try {
    if (!req.file) return res.status(400).json({ erro: 'Nenhuma foto enviada' });

    const fotoResized = await sharp(req.file.buffer).resize({ width: 500, height: 500, fit: 'inside' }).jpeg({ quality: 75 }).toBuffer();
    const fotoB64 = fotoResized.toString('base64');

    const obras = await pool.query(`SELECT id, codigo, nome, colecao, imagem_preview FROM almare_obras WHERE imagem_preview IS NOT NULL ORDER BY id`);
    if (!obras.rows.length) return res.status(404).json({ erro: 'Nenhuma obra cadastrada no acervo ainda' });

    const referencias = [];
    for (const o of obras.rows) {
      try {
        const base64Original = o.imagem_preview.replace(/^data:image\/\w+;base64,/, '');
        const buf = Buffer.from(base64Original, 'base64');
        const mini = await sharp(buf).resize({ width: 300, height: 300, fit: 'inside' }).jpeg({ quality: 70 }).toBuffer();
        referencias.push({ codigo: o.codigo, nome: o.nome, colecao: o.colecao, b64: mini.toString('base64') });
      } catch (e) {}
    }

    const content = [
      { type: 'text', text: `Voce e um especialista em reconhecimento visual de obras de arte. A primeira imagem abaixo e uma FOTO de uma peca fisica que precisa ser identificada. As imagens seguintes sao referencias do banco de dados, cada uma com um codigo.\n\nCompare a foto com cada referencia considerando: padrao de cores, textura, composicao, formas — mesmo com variacao de iluminacao, angulo ou reflexo.\n\nResponda APENAS com JSON, sem markdown:\n{"codigo_identificado":"ALM-XXX ou null se nenhuma bater","confianca":"Alta/Media/Baixa/Nenhuma","justificativa":"1 frase curta"}` },
      { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: fotoB64 } }
    ];
    referencias.forEach(r => {
      content.push({ type: 'text', text: `Referencia ${r.codigo} — ${r.nome || 'sem nome'} (${r.colecao || 'sem colecao'}):` });
      content.push({ type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: r.b64 } });
    });

    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 500, messages: [{ role: 'user', content }] })
    });
    const apiData = await apiRes.json();
    if (apiData.error) throw new Error(apiData.error.message);
    const txt = apiData.content?.map(i => i.text || '').join('') || '';
    const resultado = JSON.parse(txt.replace(/```json|```/g, '').trim());

    if (!resultado.codigo_identificado || resultado.confianca === 'Nenhuma') {
      return res.json({ encontrado: false, justificativa: resultado.justificativa });
    }
    const obraEncontrada = await pool.query('SELECT * FROM almare_obras WHERE codigo=$1', [resultado.codigo_identificado]);
    if (!obraEncontrada.rows.length) return res.json({ encontrado: false, justificativa: 'Código identificado não encontrado no banco' });

    res.json({ encontrado: true, confianca: resultado.confianca, justificativa: resultado.justificativa, obra: obraEncontrada.rows[0] });
  } catch (e) {
    console.error('ERRO IDENTIFICAR:', e.message);
    res.status(500).json({ erro: e.message });
  }
});


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
      ${navBar('obras', !!navImpacto, slugs.includes('especificador'))}

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
              <button type="button" onclick="trocarMolduraModal('#5c4a2e',this)" data-cor="carvalho" style="width:32px;height:32px;background:#5c4a2e;border:2px solid var(--border);border-radius:3px;cursor:pointer;" title="Carvalho"></button>
              <button type="button" onclick="trocarMolduraModal('#9a9a9a',this)" data-cor="aco_escovado" style="width:32px;height:32px;background:linear-gradient(135deg,#aaa,#777);border:2px solid var(--border);border-radius:3px;cursor:pointer;" title="Aço escovado"></button>
            </div>\`;
          }
          html+=\`<div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:6px;">\${colecao}</div>\`;
          html+=\`<h2 style="font-family:'Cormorant Garamond',serif;font-size:28px;font-weight:400;margin-bottom:24px;">\${nome}</h2>\`;
          html+=\`<div style="display:grid;grid-template-columns:1fr 1fr;gap:0 32px;">\${src.innerHTML}</div>\`;
          html+=\`<a href="/obra/\${id}/link" class="btn btn-outline btn-full" style="margin-top:24px;">Indicar esta obra</a>\`;
          html+=\`<a href="/obra/\${id}/comprar" class="btn btn-primary btn-full" style="margin-top:10px;">Adicionar ao carrinho</a>\`;
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
    await liberarBonusVencidos(req.membro.id); // solta pro saldo qualquer bônus que já passou da carência de 10 dias
    const trans=await pool.query('SELECT * FROM circulo_transacoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
    const saldo=await pool.query('SELECT * FROM circulo_saldo_credito WHERE membro_id=$1',[req.membro.id]);
    const s=saldo.rows[0]||{saldo_disponivel:0,saldo_total:0};
    const linhas=trans.rows.map(t=>{
      const dataDisp = t.disponivel_em ? new Date(t.disponivel_em).toLocaleDateString('pt-BR') : '—';
      const celulaData = t.status==='pago' ? '<span style="color:var(--muted)">liberado</span>' : dataDisp;
      return `<tr><td>Obra #${t.obra_id}</td><td>R$ ${parseFloat(t.valor_obra).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.modalidade==='credito'?'badge-gold':'badge-muted'}">${t.modalidade==='credito'?'Crédito':'Cashback'}</span></td><td style="color:var(--gold)">R$ ${parseFloat(t.valor_beneficio).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.status==='pago'?'badge-success':'badge-pending'}">${t.status}</span></td><td style="font-size:12px;color:var(--muted)">${celulaData}</td></tr>`;
    }).join('');
    res.send(html('Impacto',`${await navBar('impacto', true, await ehEspecificador(req.membro.id))}<div class="grid-2" style="margin-bottom:32px;"><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_disponivel).toFixed(2).replace('.',',')}</div><div class="lbl">Crédito disponível</div></div><div class="stat-box"><div class="num">R$ ${parseFloat(s.saldo_total).toFixed(2).replace('.',',')}</div><div class="lbl">Total histórico</div></div></div><div class="card"><h3 style="font-size:18px;margin-bottom:20px;">Histórico</h3>${trans.rows.length?`<table><thead><tr><th>Obra</th><th>Valor</th><th>Modalidade</th><th>Benefício</th><th>Status</th><th>Disponível em</th></tr></thead><tbody>${linhas}</tbody></table>`:'<p style="color:var(--muted)">Nenhuma venda ainda.</p>'}</div>`,true));
  }catch(e){res.send(html('Impacto',`<div class="msg-erro">${e.message}</div>`,true));}
});

// ─── VOZ ──────────────────────────────────────────────────────────────────────
app.get('/sugestoes',authMembro,async(req,res)=>{
  const lista=await pool.query('SELECT * FROM circulo_sugestoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
  const itens=lista.rows.map(s=>`<div style="padding:16px 0;border-bottom:1px solid var(--border);"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${s.status}</span><span style="font-size:11px;color:var(--muted)">${new Date(s.criado_em).toLocaleDateString('pt-BR')}</span></div><p style="font-size:13px;line-height:1.6;">${s.texto}</p>${s.resposta?`<p style="font-size:12px;color:var(--gold);margin-top:8px;font-style:italic;">↳ ${s.resposta}</p>`:''}</div>`).join('');
  res.send(html('Voz',`${await navBar('voz', await temFuncaoComImpacto(req.membro.id), await ehEspecificador(req.membro.id))}<h2 style="font-size:28px;margin-bottom:8px;">Sua voz no Círculo</h2><p style="color:var(--muted);margin-bottom:32px;">Sugira temas, formatos, ambientes. Anderson lê tudo.</p><div class="card" style="margin-bottom:24px;"><form method="POST" action="/sugestoes"><div class="field"><label>Sua sugestão</label><textarea name="texto" required placeholder="Uma ideia..."></textarea></div><button type="submit" class="btn btn-primary">Enviar</button></form></div>${lista.rows.length?`<div class="card"><h3 style="font-size:16px;margin-bottom:16px;">Anteriores</h3>${itens}</div>`:''}`,true));
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
  res.send(html('Convidar',`${await navBar('convidar', await temFuncaoComImpacto(req.membro.id), await ehEspecificador(req.membro.id))}<h2 style="font-size:28px;margin-bottom:8px;">Seu link de convite</h2><p style="color:var(--muted);margin-bottom:32px;">Compartilhe com quem acredita que pertence ao Círculo.</p><div class="card"><div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Link pessoal</div><div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${link}</div><button onclick="navigator.clipboard.writeText('${link}');this.textContent='Copiado ✓'" class="btn btn-outline">Copiar link</button><div style="margin-top:20px;font-size:12px;color:var(--muted)">${c?c.usos:0} pessoa(s) entrou pela sua indicação</div></div>`,true));
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


// ─── SINCRONIZAR MEMBROS ANTIGOS COM O BLING (retroativo, so nome+email — sem documento/endereco que nunca foram guardados) ──
app.post('/admin/bling/sincronizar', authAdmin, async (req, res) => {
  const pendentes = await pool.query("SELECT id, nome, email FROM circulo_membros WHERE bling_id IS NULL");
  let ok = 0, falhas = [];
  for (const m of pendentes.rows) {
    try {
      const blingId = await salvarContatoBling({ nome: m.nome, email: m.email }, null);
      if (blingId) {
        await pool.query('UPDATE circulo_membros SET bling_id=$1 WHERE id=$2', [blingId, m.id]);
        ok++;
      } else {
        falhas.push(m.nome);
      }
    } catch (e) {
      falhas.push(`${m.nome} (${e.message})`);
    }
    await new Promise(r => setTimeout(r, 1500)); // bem abaixo do limite de 3 req/s do Bling
  }
  res.redirect(`/admin?bling_sync=${ok}&bling_falhas=${encodeURIComponent(falhas.join(', '))}`);
});

// ─── ADMIN — MODELOS 3D: dashboard de downloads (a geracao e sob demanda, nao ha upload) ──
app.get('/admin/modelos-3d', authAdmin, async(req,res)=>{
  const stats = await pool.query(`SELECT COUNT(*) total, COUNT(DISTINCT membro_id) especificadores FROM circulo_downloads_3d`);
  const topObras = await pool.query(`SELECT obra_nome, COUNT(*) qtd FROM circulo_downloads_3d GROUP BY obra_nome ORDER BY qtd DESC LIMIT 10`);
  const recentes = await pool.query(`
    SELECT d.*, m.nome as membro_nome FROM circulo_downloads_3d d
    LEFT JOIN circulo_membros m ON m.id=d.membro_id
    ORDER BY d.baixado_em DESC LIMIT 20`);
  const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};

  let corpo = `<a href="/admin" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">← Voltar ao admin</a>`;
  corpo += `<h2 style="font-size:28px;margin:12px 0 8px;">Modelos 3D</h2>`;
  corpo += `<p style="color:var(--muted);font-size:13px;margin-bottom:24px;">Os arquivos sao gerados na hora do pedido do especificador — nao ha upload manual.</p>`;

  corpo += `<div class="grid-3" style="margin-bottom:24px;">
    <div class="stat-box"><div class="num">${stats.rows[0].total}</div><div class="lbl">Downloads totais</div></div>
    <div class="stat-box"><div class="num">${stats.rows[0].especificadores}</div><div class="lbl">Especificadores ativos</div></div>
  </div>`;

  if(topObras.rows.length){
    corpo += `<div class="card" style="margin-bottom:24px;"><div style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:10px;">Mais baixadas</div>`;
    topObras.rows.forEach(t => { corpo += `<div style="display:flex;justify-content:space-between;padding:6px 0;font-size:13px;"><span>${t.obra_nome}</span><span style="color:var(--gold);">${t.qtd}</span></div>`; });
    corpo += `</div>`;
  }

  if(recentes.rows.length){
    corpo += `<div class="card"><div style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:10px;">Downloads recentes</div>`;
    recentes.rows.forEach(d => {
      corpo += `<div style="display:flex;justify-content:space-between;padding:6px 0;border-top:1px solid var(--border);font-size:12px;">
        <span>${d.obra_nome} · ${d.largura}×${d.altura}cm · ${nomesMoldura[d.moldura]||d.moldura} · .${d.formato}</span>
        <span style="color:var(--muted);">${d.membro_nome||'—'}</span>
      </div>`;
    });
    corpo += `</div>`;
  } else {
    corpo += `<div class="card"><p style="color:var(--muted)">Nenhum download ainda.</p></div>`;
  }

  res.send(html('Modelos 3D', corpo));
});



app.get('/admin',authAdmin,async(req,res)=>{
  const blingCfg = await pool.query('SELECT autorizado, expira_em FROM circulo_bling_config WHERE id=1').catch(()=>({rows:[]}));
  const blingConectado = blingCfg.rows[0]?.autorizado;
  const pendentesBling = await pool.query("SELECT COUNT(*) FROM circulo_membros WHERE bling_id IS NULL").catch(()=>({rows:[{count:0}]}));
  const qtdPendentesBling = parseInt(pendentesBling.rows[0].count);
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
      <td><a href="/admin/membros/${m.id}/editar-email" class="btn btn-outline" style="padding:5px 12px;font-size:10px;">Editar e-mail</a></td>
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
    <div class="card" style="margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;">
      <div><strong>Modelos 3D para especificadores</strong><br><span style="font-size:12px;color:var(--muted)">Gerados sob demanda (.skp/.obj/.dxf) — dashboard de downloads</span></div>
      <a href="/admin/modelos-3d" class="btn btn-outline" style="padding:8px 16px;font-size:11px;">Gerenciar</a>
    </div>
    <div class="card" style="margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;">
      <div>
        <strong>Conexão Bling do Círculo</strong><br>
        <span style="font-size:12px;color:var(--muted)">${blingConectado?'✓ Conectado (isolado, exclusivo do Círculo)':'⚠ Não conectado — cadastros não sincronizam com o Bling'}</span>
        ${blingConectado && qtdPendentesBling > 0 ? `<br><span style="font-size:12px;color:var(--gold)">${qtdPendentesBling} membro(s) ainda sem contato no Bling</span>` : ''}
      </div>
      <div style="display:flex;gap:8px">
        ${blingConectado && qtdPendentesBling > 0 ? `
          <form method="POST" action="/admin/bling/sincronizar" style="display:inline">
            <button class="btn btn-primary" style="padding:8px 16px;font-size:11px;">Sincronizar ${qtdPendentesBling} pendente(s)</button>
          </form>` : ''}
        <a href="/auth/bling/conectar" class="btn btn-outline" style="padding:8px 16px;font-size:11px;">${blingConectado?'Reconectar':'Conectar Bling'}</a>
      </div>
    </div>
    ${req.query.bling_sync !== undefined ? `
    <div class="card" style="margin-bottom:24px;background:rgba(0,255,150,0.05);">
      <strong>Sincronização concluída:</strong> ${req.query.bling_sync} membro(s) enviado(s) ao Bling com sucesso.
      ${req.query.bling_falhas ? `<br><span style="font-size:12px;color:var(--muted)">Falharam: ${decodeURIComponent(req.query.bling_falhas)}</span>` : ''}
    </div>` : ''}
    ${pendentes.rows.length?`
    <div class="card" style="margin-bottom:24px;">
      <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Funções aguardando aprovação</h3>
      <table><thead><tr><th>Membro</th><th>Função solicitada</th><th>Ação</th></tr></thead>
      <tbody>${linhaPendentes}</tbody></table>
    </div>`:''}
    <div class="card" style="margin-bottom:16px;">
      <h3 style="font-size:18px;margin-bottom:20px;">Membros do Círculo</h3>
      <table><thead><tr><th>Nome</th><th>Código</th><th>E-mail</th><th>Crédito</th><th>Obras</th><th>Indicações</th><th>Ação</th></tr></thead>
      <tbody>${linhaMembros||'<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:24px;">Nenhum membro ainda</td></tr>'}</tbody></table>
    </div>
    <a href="/admin/sugestoes" class="btn btn-outline">Ver sugestões dos membros</a>
  `));
});

// ─── APROVAR / RECUSAR FUNÇÃO ─────────────────────────────────────────────────
// Admin edita o e-mail de um membro (para quando o cliente pede correção diretamente)
app.get('/admin/membros/:id/editar-email', authAdmin, async(req,res)=>{
  const r = await pool.query('SELECT id,nome,email FROM circulo_membros WHERE id=$1',[req.params.id]);
  if(!r.rows.length) return res.redirect('/admin');
  const m = r.rows[0];
  res.send(html('Editar e-mail',`
    <div class="container-sm">
      <a href="/admin" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar</a>
      <h2 style="font-size:24px;margin-bottom:24px;">Editar e-mail de ${esc(m.nome)}</h2>
      ${req.query.erro?`<div class="msg-erro">${esc(req.query.erro)}</div>`:''}
      <div class="card">
        <form method="POST" action="/admin/membros/${m.id}/editar-email">
          <div class="field"><label>Novo e-mail</label><input type="email" name="email" required value="${esc(m.email)}"></div>
          <button type="submit" class="btn btn-primary btn-full">Salvar</button>
        </form>
      </div>
    </div>
  `));
});

app.post('/admin/membros/:id/editar-email', authAdmin, async(req,res)=>{
  const { email } = req.body;
  try{
    if(!email || !email.trim()) return res.redirect(`/admin/membros/${req.params.id}/editar-email?erro=E-mail+obrigatório`);
    const dup = await pool.query('SELECT id FROM circulo_membros WHERE email=$1 AND id<>$2',[email.trim(), req.params.id]);
    if(dup.rows.length) return res.redirect(`/admin/membros/${req.params.id}/editar-email?erro=Este+e-mail+já+está+em+uso`);
    await pool.query('UPDATE circulo_membros SET email=$1 WHERE id=$2',[email.trim(), req.params.id]);
    res.redirect('/admin');
  }catch(e){
    res.redirect(`/admin/membros/${req.params.id}/editar-email?erro=${encodeURIComponent(e.message)}`);
  }
});

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


// ─── GARANTE ESTRUTURA DO BANCO (cria o que faltar ao iniciar, nunca apaga nada) ──────────
async function garantirTabelas(){
  try{
    // Conexao Bling PROPRIA do Circulo — isolada de qualquer outro sistema (nunca compartilha tabela/token com o ALMARE)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_bling_config (
        id INTEGER PRIMARY KEY DEFAULT 1,
        access_token TEXT,
        refresh_token TEXT,
        expira_em TIMESTAMPTZ,
        autorizado BOOLEAN DEFAULT FALSE,
        CONSTRAINT circulo_bling_config_singleton CHECK (id = 1)
      );`);
    // Registro de downloads de modelos 3D (gerados sob demanda) — pro dashboard do admin
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_downloads_3d (
        id SERIAL PRIMARY KEY,
        membro_id INTEGER REFERENCES circulo_membros(id) ON DELETE SET NULL,
        obra_id INTEGER,
        obra_nome VARCHAR(255),
        largura INTEGER, altura INTEGER,
        moldura VARCHAR(20), formato VARCHAR(10),
        baixado_em TIMESTAMPTZ DEFAULT NOW()
      );`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_obra_links (
        id SERIAL PRIMARY KEY,
        membro_id INTEGER NOT NULL REFERENCES circulo_membros(id),
        obra_id INTEGER NOT NULL,
        codigo VARCHAR(20) UNIQUE NOT NULL,
        criado_em TIMESTAMP DEFAULT NOW(),
        UNIQUE(membro_id, obra_id)
      );`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_indicacoes (
        id SERIAL PRIMARY KEY,
        obra_link_id INTEGER NOT NULL REFERENCES circulo_obra_links(id),
        nome_lead VARCHAR(200),
        contato_lead VARCHAR(200),
        mensagem TEXT,
        status VARCHAR(20) DEFAULT 'novo',
        criado_em TIMESTAMP DEFAULT NOW()
      );`);
    // Carência de 10 dias antes do crédito/cashback ficar disponível (dá tempo da venda confirmar)
    await pool.query(`ALTER TABLE circulo_transacoes ADD COLUMN IF NOT EXISTS disponivel_em TIMESTAMP;`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_transacoes ADD COLUMN IF NOT EXISTS pedido_id INTEGER;`).catch(()=>{});
    // Dados do membro reaproveitados no faturamento
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS bling_id VARCHAR(50);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS documento VARCHAR(20);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS asaas_cliente_id VARCHAR(50);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS telefone VARCHAR(20);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS celular VARCHAR(20);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS ie VARCHAR(30);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS cep VARCHAR(10);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS endereco VARCHAR(200);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS numero VARCHAR(20);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS complemento VARCHAR(100);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS bairro VARCHAR(100);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS cidade VARCHAR(100);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS estado VARCHAR(2);`).catch(()=>{});
    // Evita processar o mesmo evento do Asaas duas vezes (eles reenviam em caso de falha)
    await pool.query(`CREATE TABLE IF NOT EXISTS circulo_asaas_eventos (
      event_id VARCHAR(80) PRIMARY KEY,
      recebido_em TIMESTAMP DEFAULT NOW()
    );`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_pedidos ADD COLUMN IF NOT EXISTS cliente_membro_id INTEGER REFERENCES circulo_membros(id);`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_pedidos ADD COLUMN IF NOT EXISTS link_publico VARCHAR(20) UNIQUE;`).catch(()=>{});
    await pool.query(`ALTER TABLE circulo_pedidos ADD COLUMN IF NOT EXISTS invoice_url TEXT;`).catch(()=>{});
    // Carrinho e checkout de obras
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_pedidos (
        id SERIAL PRIMARY KEY,
        numero VARCHAR(30) UNIQUE NOT NULL,
        membro_id INTEGER NOT NULL REFERENCES circulo_membros(id),
        status VARCHAR(30) NOT NULL DEFAULT 'CARRINHO',
        total NUMERIC(10,2) DEFAULT 0,
        metodo_pagamento VARCHAR(20),
        asaas_cliente_id VARCHAR(50),
        asaas_cobranca_id VARCHAR(50),
        bling_pedido_id VARCHAR(50),
        bling_erro TEXT,
        criado_em TIMESTAMP DEFAULT NOW()
      );`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS circulo_pedido_itens (
        id SERIAL PRIMARY KEY,
        pedido_id INTEGER NOT NULL REFERENCES circulo_pedidos(id),
        obra_id INTEGER NOT NULL,
        obra_link_id INTEGER REFERENCES circulo_obra_links(id),
        tamanho_id INTEGER,
        tamanho_label VARCHAR(100),
        largura NUMERIC(6,2),
        altura NUMERIC(6,2),
        moldura VARCHAR(20) NOT NULL DEFAULT 'preta',
        quantidade INTEGER NOT NULL DEFAULT 1,
        preco_unitario NUMERIC(10,2) NOT NULL,
        subtotal NUMERIC(10,2) NOT NULL,
        bling_produto_id VARCHAR(50),
        criado_em TIMESTAMP DEFAULT NOW()
      );`);
    console.log('garantirTabelas: estrutura verificada/criada com sucesso');
  }catch(e){
    console.error('garantirTabelas erro:', e.message);
  }
}

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>{
  console.log(`Círculo ALMARE rodando na porta ${PORT}`);
  garantirTabelas();
});
