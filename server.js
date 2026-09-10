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

// Escapa texto vindo de usuários/IA antes de injetar em HTML (evita quebra de layout e XSS)
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Gera um código curto e único para links rastreáveis (convite, indicação de obra etc.)
function gerarCodigo() { return crypto.randomBytes(5).toString('hex'); }

// Cria as tabelas do Círculo que ainda não existiam no banco original — roda uma vez no boot,
// não apaga nem altera nada que já existe (IF NOT EXISTS), então é seguro rodar sempre.
async function garantirTabelas() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS circulo_obra_links (
      id SERIAL PRIMARY KEY,
      membro_id INTEGER NOT NULL REFERENCES circulo_membros(id),
      obra_id INTEGER NOT NULL,
      codigo VARCHAR(20) UNIQUE NOT NULL,
      criado_em TIMESTAMP DEFAULT NOW(),
      UNIQUE(membro_id, obra_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS circulo_indicacoes (
      id SERIAL PRIMARY KEY,
      obra_link_id INTEGER NOT NULL REFERENCES circulo_obra_links(id),
      nome_lead VARCHAR(200),
      contato_lead VARCHAR(200),
      mensagem TEXT,
      status VARCHAR(20) DEFAULT 'novo',
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);
  // Carência de 10 dias antes do crédito/cashback ficar disponível — dá tempo pra venda ser
  // confirmada de vez (sem devolução/cancelamento) antes de liberar pro membro.
  await pool.query(`ALTER TABLE circulo_transacoes ADD COLUMN IF NOT EXISTS disponivel_em TIMESTAMP;`).catch(()=>{});
  // ID do contato no Bling — gravado no cadastro, reaproveitado na hora de faturar a venda.
  await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS bling_id VARCHAR(50);`).catch(()=>{});
  await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS documento VARCHAR(20);`).catch(()=>{});
  await pool.query(`ALTER TABLE circulo_membros ADD COLUMN IF NOT EXISTS asaas_cliente_id VARCHAR(50);`).catch(()=>{});

  // Carrinho e checkout de obras (compra pelo link de indicação ou pelo catálogo)
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
    );
  `);
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
    );
  `);
}

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

// ─── ASAAS (pagamento — mesma conta/chave usada pelo Vista Signa) ─────────────
const ASAAS_BASE_URL = process.env.ASAAS_ENV === 'production'
  ? 'https://api.asaas.com/v3'
  : 'https://api-sandbox.asaas.com/v3';

async function asaasFetch(path, options = {}) {
  const resp = await fetch(ASAAS_BASE_URL + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'access_token': process.env.ASAAS_API_KEY, ...(options.headers || {}) },
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data?.errors?.[0]?.description || 'Erro na comunicação com o Asaas');
  return data;
}

async function garantirClienteAsaas(membro) {
  if (membro.asaas_cliente_id) return membro.asaas_cliente_id;
  const cliente = await asaasFetch('/customers', {
    method: 'POST',
    body: JSON.stringify({ name: membro.nome, email: membro.email, cpfCnpj: (membro.documento||'').replace(/\D/g,''), externalReference: membro.id }),
  });
  await pool.query('UPDATE circulo_membros SET asaas_cliente_id=$1 WHERE id=$2',[cliente.id, membro.id]);
  return cliente.id;
}

async function criarCobranca(asaasClienteId, valor, pedidoId, metodoPagamento) {
  const hoje = new Date().toISOString().slice(0, 10);
  const billingType = metodoPagamento === 'CARTAO' ? 'CREDIT_CARD' : 'PIX';
  const pagamento = await asaasFetch('/payments', {
    method: 'POST',
    body: JSON.stringify({ customer: asaasClienteId, billingType, value: valor, dueDate: hoje, externalReference: String(pedidoId) }),
  });
  const resultado = { id: pagamento.id, invoiceUrl: pagamento.invoiceUrl };
  if (billingType === 'PIX') {
    const qr = await asaasFetch('/payments/' + pagamento.id + '/pixQrCode');
    resultado.qrCodeImagem = qr.encodedImage;
    resultado.copiaCola = qr.payload;
  }
  return resultado;
}

// ─── BLING (produto por obra+tamanho+moldura, venda ao confirmar pagamento) ───
async function blingFetch(path, options = {}) {
  const token = await getBlingToken();
  const resp = await fetch('https://api.bling.com.br/Api/v3' + path, {
    ...options,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data?.error?.description || 'Erro na comunicação com o Bling');
  return data;
}

const MOLDURA_NOME = { preta: 'Moldura Preta', carvalho: 'Moldura Carvalho', aco: 'Moldura Aço Escovado' };

async function garantirProdutoBlingObra(item, obraCodigo, obraNome){
  if (item.bling_produto_id) return item.bling_produto_id;
  const codigo = `${obraCodigo || 'ALM'}-${String(item.tamanho_label||'').replace(/[^0-9x]/gi,'').toUpperCase()}-${(item.moldura||'preta').slice(0,2).toUpperCase()}`;
  const nome = `${obraNome} — ${item.tamanho_label} — ${MOLDURA_NOME[item.moldura]||item.moldura}`;
  const corpo = { nome, codigo, tipo: 'P', situacao: 'A', formato: 'S', unidade: 'UN', preco: parseFloat(item.preco_unitario), ncm: '4911.99.00' };
  const resultado = await blingFetch('/produtos', { method: 'POST', body: JSON.stringify(corpo) });
  const produtoId = resultado?.data?.id;
  if (produtoId) await pool.query('UPDATE circulo_pedido_itens SET bling_produto_id=$1 WHERE id=$2',[produtoId,item.id]);
  return produtoId;
}

async function sincronizarPedidoBlingObra(pedidoId){
  try{
    const pedidoRes = await pool.query(`SELECT p.*, m.nome, m.email, m.bling_id FROM circulo_pedidos p JOIN circulo_membros m ON m.id=p.membro_id WHERE p.id=$1`,[pedidoId]);
    if(!pedidoRes.rows.length) return;
    const pedido = pedidoRes.rows[0];
    const itensRes = await pool.query(`SELECT pi.*, o.nome as obra_nome, o.codigo as obra_codigo FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id=pi.obra_id WHERE pi.pedido_id=$1`,[pedidoId]);
    if(!itensRes.rows.length) return;
    if(!pedido.bling_id) return; // sem contato Bling vinculado, não dá pra faturar — fica registrado o erro

    const itensBling=[];
    for(const item of itensRes.rows){
      const produtoId = await garantirProdutoBlingObra(item, item.obra_codigo, item.obra_nome);
      const linha = { descricao: `${item.obra_nome} — ${item.tamanho_label} — ${MOLDURA_NOME[item.moldura]||item.moldura}`, quantidade: item.quantidade, valor: parseFloat(item.preco_unitario), unidade: 'UN' };
      if(produtoId) linha.produto = { id: produtoId };
      itensBling.push(linha);
    }
    const hoje = new Date().toISOString().slice(0,10);
    const corpoPedido = { numero: pedido.numero, data: hoje, dataSaida: hoje, contato: { id: pedido.bling_id }, itens: itensBling, observacoes: `Pedido ${pedido.numero} — Círculo ALMARE — pagamento via Asaas` };
    const resultado = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(corpoPedido) });
    const blingPedidoId = resultado?.data?.id;
    if(blingPedidoId) await pool.query('UPDATE circulo_pedidos SET bling_pedido_id=$1, bling_erro=NULL WHERE id=$2',[blingPedidoId,pedidoId]);
  }catch(err){
    console.error('Erro ao sincronizar pedido Círculo com Bling:', err.message);
    await pool.query('UPDATE circulo_pedidos SET bling_erro=$1 WHERE id=$2',[String(err.message).slice(0,500),pedidoId]).catch(()=>{});
  }
}

// ─── SIMULADOR DE AMBIENTE — funções auxiliares (IA analisa foto e sugere obra) ──
function extrairTamanhos(raw){
  if(!raw) return [];
  const txt = String(raw);
  const matches = txt.match(/(\d+)\s*[x×]\s*(\d+)/gi) || [];
  return matches.map(m=>{
    const p = m.match(/(\d+)\s*[x×]\s*(\d+)/i);
    return { largura: parseInt(p[1]), altura: parseInt(p[2]), label: `${p[1]}×${p[2]}cm` };
  });
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
  "centro_vertical_ideal_pct": 0,
  "referencia_usada": "qual objeto real você usou para calibrar a escala",
  "aviso_precisao": "aviso curto se a proporção parecer inconsistente com o que o cliente informou, ou null se estiver coerente"
}

Sobre "parede_bbox_largura_cm": este é o campo MAIS IMPORTANTE para a simulação ficar correta. É a largura REAL em centímetros da área de parede que você marcou em "parede_bbox", calculada usando os objetos de referência que você identificou na foto — NÃO copie o número que o cliente informou, calcule você mesmo pela imagem. Se a porta na foto mede visualmente cerca de 1/3 da largura da parede disponível, e porta padrão tem 80-90cm, então a parede tem por volta de 240-270cm — é esse tipo de cálculo que você deve fazer. Seja o mais preciso possível, porque um erro aqui faz o quadro aparecer do tamanho errado na simulação.

Sobre "moldura_recomendada": a ALMARE oferece três opções — preta, carvalho (madeira clara) e aço escovado. Escolha a que melhor combina com a cor da parede, o estilo do ambiente e a paleta da obra que será usada (você pode não saber a obra ainda, então baseie-se só no ambiente: paredes claras/neutras combinam bem com preta ou aço escovado para contraste, ambientes com madeira ou tom quente combinam com carvalho, ambientes industriais combinam com aço escovado ou preta). Este campo é obrigatório, sempre escolha uma das três opções.

Sobre "centro_vertical_ideal_pct": este campo é OBRIGATÓRIO e segue uma regra fixa e inegociável de museus e galerias: o CENTRO de qualquer quadro pendurado deve ficar a 150cm de altura do chão (regra internacional de curadoria). Para calcular esse valor, identifique onde fica o CHÃO na foto (a linha onde a parede encontra o piso) usando os mesmos objetos de referência (porta, interruptor, tomada, rodapé). Depois calcule: partindo do chão, suba 150cm reais, e determine em que PORCENTAGEM da altura total da foto (contando do topo da imagem) essa marca de 150cm cai. Esse número é o "centro_vertical_ideal_pct". NUNCA calcule esse valor com base em "espaço livre na parede" — ele depende exclusivamente da altura real do chão até 150cm, independente de haver parede vazia acima ou abaixo. Se essa altura ideal cair em cima de um móvel identificado, ajuste o valor para logo acima do móvel (com a margem de 20-25cm já mencionada), mas nunca ignore a regra dos 150cm sem necessidade.

Sobre "parede_bbox": são as coordenadas em PORCENTAGEM de 0 a 100 da área de parede vazia e disponível na PRIMEIRA imagem, usada apenas para saber a LARGURA disponível e a posição horizontal — não use para calcular a altura vertical do quadro, isso é definido só por "centro_vertical_ideal_pct". top_pct e left_pct são a posição do canto superior esquerdo dessa área útil, width_pct e height_pct são o tamanho dela, todos relativos ao tamanho total da imagem.

ISSO É CRÍTICO E OBRIGATÓRIO: antes de definir "parede_bbox", primeiro identifique mentalmente TODOS os móveis e objetos visíveis na foto que ocupam a parede ou ficam na frente dela — sofás, poltronas, mesas, aparadores, estantes, plantas, portas, janelas, interruptores, tomadas, luminárias. A área de "parede_bbox" NUNCA pode se sobrepor a nenhum desses elementos, nem parcialmente. Se houver um móvel (como um sofá) na parte de baixo da parede, a área da bbox deve começar ACIMA do topo desse móvel, com uma margem de segurança equivalente a pelo menos 20-25cm reais de folga entre o topo do móvel e o início da bbox (isso é a distância mínima real entre um quadro pendurado e o encosto de um sofá, por exemplo). É um erro grave e inaceitável a bbox incluir qualquer parte de um móvel — verifique isso com atenção antes de responder.

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

  // Fallback: se a IA não calculou a altura ideal (regra dos 150cm do chão), usa 48% como aproximação segura
  if(typeof analise.centro_vertical_ideal_pct !== 'number' || analise.centro_vertical_ideal_pct <= 0 || analise.centro_vertical_ideal_pct >= 100){
    analise.centro_vertical_ideal_pct = 48;
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

    // 1. Tamanho compatível — obra deve caber com folga (60-75% da parede)
    const tamanhos = extrairTamanhos(o.tamanhos_recomendados);
    const cabe = tamanhos.filter(t => t.largura <= paredeL*0.85 && t.altura <= paredeA*0.85);
    if(cabe.length){ score += 30; }
    const melhorTamanho = cabe.sort((a,b)=>(b.largura*b.altura)-(a.largura*a.altura))[0] || tamanhos[0];

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
  .sort((a,b)=>b._score-a._score)
  .slice(0,3);
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
  .ficha-conceito{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--gold);border-radius:0 4px 4px 0;padding:18px 20px;margin-bottom:14px}
  .ficha-essencia{background:linear-gradient(135deg,#1a1408,var(--surface));border:1px solid #3d2f10;border-radius:4px;padding:20px;margin-bottom:14px}
  .ficha-essencia-label{font-size:10px;color:var(--gold);text-transform:uppercase;letter-spacing:.2em;margin-bottom:8px;font-weight:600}
  .ficha-essencia-texto{font-size:16px;color:var(--gold-light);font-style:italic;line-height:1.6}
  .ficha-quote{font-size:14px;font-style:italic;color:#e8e0d0;line-height:1.75}
  .ficha-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:18px 20px;margin-bottom:14px}
  .ficha-card-titulo{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.15em;margin-bottom:12px;font-weight:500}
  .ficha-plana{font-size:13px;line-height:1.75;color:#bbb}
  .ficha-chips{display:flex;flex-wrap:wrap;gap:6px}
  .ficha-chip{background:rgba(201,169,110,.1);border:1px solid rgba(201,169,110,.3);color:var(--gold);padding:3px 12px;border-radius:20px;font-size:11px}
  .ficha-linha{display:flex;gap:14px;padding:8px 0;border-bottom:1px solid var(--border)}
  .ficha-linha:last-child{border-bottom:none}
  .ficha-linha-label{font-size:10px;color:var(--muted);min-width:150px;flex-shrink:0;padding-top:2px;text-transform:uppercase;letter-spacing:.05em}
  .ficha-linha-valor{font-size:13px;color:#ccc;flex:1;line-height:1.6}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--gold);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
  @media(max-width:600px){.grid-2,.grid-3{grid-template-columns:1fr}.steps{flex-direction:column}}
  .obra-lado-a-lado{display:flex;gap:28px;align-items:flex-start;}
  .obra-lado-img{flex:1 1 300px;max-width:360px;min-width:0;}
  .obra-lado-texto{flex:1 1 320px;min-width:0;}
  @media(max-width:680px){
    .obra-lado-a-lado{display:block;}
    .obra-lado-img{max-width:100%;margin-bottom:24px;}
  }
  .moldura-wrap{max-width:480px;margin:0 auto;}
  .moldura{padding:5px;border-radius:1px;box-shadow:0 14px 40px rgba(0,0,0,.5),inset 0 0 0 1px rgba(255,255,255,.05);}
  .moldura-preta{background:linear-gradient(160deg,#2e2e2e,#050505 60%,#161616);}
  .moldura-carvalho{background:linear-gradient(135deg,#9c6b3f,#5a3a20);}
  .moldura-aco{background:linear-gradient(135deg,#d6d6d6,#9a9a9a);}
  .moldura-vao{background:#000;padding:5px;}
  .moldura-vao img{display:block;width:100%;height:auto;}
  .moldura-swatches{display:flex;gap:10px;align-items:center;margin:16px 0 0;justify-content:center;}
  .moldura-swatch{width:26px;height:26px;border-radius:50%;cursor:pointer;border:2px solid transparent;box-shadow:0 0 0 1px var(--border);}
  .moldura-swatch.ativo{border-color:var(--gold);}
  .moldura-swatch-preta{background:linear-gradient(160deg,#2e2e2e,#050505);}
  .moldura-swatch-carvalho{background:linear-gradient(135deg,#9c6b3f,#5a3a20);}
  .moldura-swatch-aco{background:linear-gradient(135deg,#d6d6d6,#9a9a9a);}
`;

function html(titulo, corpo, nav=false, membro=null) {
  // Painel de identidade — sempre visível no topo quando há sessão, princípio permanente de UI/UX:
  // qualquer pessoa reconhece de cara qual conta está logada, sem precisar procurar.
  const identidade = (nav && membro) ? `<div style="font-size:10px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-top:6px;">
    Logado como <span style="color:var(--gold)">${esc(membro.nome||'')}</span>
  </div>` : '';
  const navHtml = nav ? `<div style="display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:12px;flex-wrap:wrap;">
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Portal</a>
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Obras</a>
    <a href="/simulador" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Simulador</a>
    <a href="/meu-impacto" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Impacto</a>
    <a href="/minhas-indicacoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Indicações</a>
    <a href="/carrinho" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Carrinho</a>
    <a href="/sugestoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Voz</a>
    <a href="/minhas-funcoes" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted)">Funções</a>
    <a href="/logout" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--danger)">Sair</a>
  </div>` : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(titulo)} — Círculo ALMARE</title><style>${CSS}</style></head>
  <body><div class="container"><header><div class="logo">ALMARE</div><div class="logo-sub">Círculo</div>${identidade}${navHtml}</header>${corpo}</div></body></html>`;
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
      `INSERT INTO circulo_membros (nome,email,senha_hash,status,aprovado_em,codigo_membro,bling_id,documento) VALUES ($1,$2,$3,'ativo',NOW(),$4,$5,$6) RETURNING id`,
      [nome, email, hash, codigo, blingIdFinal, documento]
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

    // Membro entra direto — a aprovação é só para as funções extras (Embaixador, Especificador etc.), não para virar Membro.
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
      `<span class="badge badge-gold">${esc(f.nome)}</span>`
    ).join(' ');
    // Membro sempre aparece

    const evHtml=eventos.rows.map(e=>`<div style="padding:12px 0;border-bottom:1px solid var(--border);font-size:13px;"><span>${esc(e.descricao)}</span><span style="float:right;font-size:11px;color:var(--muted)">${new Date(e.data_evento).toLocaleDateString('pt-BR')}</span></div>`).join('');
    const temFuncaoExtra = funcoes.rows.some(f=>f.ativo && ['embaixador','especificador','artista','colaborador'].includes(f.slug));
    const temIndicar = funcoes.rows.some(f=>f.ativo && ['embaixador','especificador','curador'].includes(f.slug));
    const membroNome = m.nome||req.membro.nome;

    res.send(html('Portal',`
      <div class="nav-bar"><a href="/portal" class="nav-link ativo">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a>${temFuncaoExtra ? '<a href="/meu-impacto" class="nav-link">Impacto</a>' : ''}${temIndicar ? '<a href="/minhas-indicacoes" class="nav-link">Indicações</a>' : ''}<a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
      <div class="card" style="margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
          <div>
            <h2 style="font-size:26px;margin-bottom:4px;">${esc(membroNome)}</h2>
            <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Membro desde ${data}</div>
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
      ${link?`<div style="margin-top:20px;padding:14px;border:1px solid var(--border);border-radius:4px;"><div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Seu link de convite</div><div style="font-size:12px;word-break:break-all;">${esc(link)}</div></div>`:''}
    `,true,{nome:membroNome,codigo:m.codigo_membro}));
  }catch(e){res.send(html('Erro',`<div class="msg-erro">${esc(e.message)}</div>`,true,req.membro));}
});

// ─── MINHAS FUNÇÕES — ativar/desativar ───────────────────────────────────────
app.get('/minhas-funcoes',authMembro,async(req,res)=>{
  const funcoes=await pool.query(`
    SELECT f.nome,f.slug,f.descricao,mf.ativo,mf.id as mf_id FROM circulo_membro_funcoes mf
    JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1`,[req.membro.id]);
  const membroRow=await pool.query('SELECT nome,codigo_membro FROM circulo_membros WHERE id=$1',[req.membro.id]);
  const membroInfo={nome:membroRow.rows[0]?.nome||req.membro.nome, codigo:membroRow.rows[0]?.codigo_membro};

  const itens=funcoes.rows.map(f=>`
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:10px;height:10px;border-radius:50%;background:${f.ativo?'#2ecc71':'#f0a500'};flex-shrink:0;"></div>
        <div>
          <div style="font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:3px;">${esc(f.nome)}</div>
          <div style="font-size:12px;color:var(--muted);">${esc(f.descricao)}${f.ativo?'':' — aguardando aprovação'}</div>
        </div>
      </div>
      <div style="flex-shrink:0;margin-left:16px;">
        ${f.ativo ? `<form method="POST" action="/minhas-funcoes/${encodeURIComponent(f.slug)}/desativar"><button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Desativar</button></form>` : `<span class="badge badge-pending">Aguardando</span>`}
      </div>
    </div>`).join('');

  // Funções autosserviço que o membro ainda não tem (nem ativa, nem pendente) — ele pode solicitar a qualquer momento,
  // não só no cadastro; sem isso, quem desativa uma função ou não marcou no início ficava sem caminho de volta.
  const slugsExistentes = funcoes.rows.map(f=>f.slug);
  const disponiveis = FUNCOES_CADASTRO.filter(f=>!funcoes.rows.some(r=>r.slug===f.slug && r.ativo) );
  const solicitarHtml = disponiveis.map(f=>{
    const jaTem = funcoes.rows.find(r=>r.slug===f.slug);
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid var(--border);">
      <div><div style="font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:3px;">${esc(f.nome)}</div><div style="font-size:12px;color:var(--muted);">${esc(f.desc)}</div></div>
      ${jaTem?'<span class="badge badge-pending">Aguardando</span>':`<form method="POST" action="/minhas-funcoes/${f.slug}/solicitar"><button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Solicitar</button></form>`}
    </div>`;
  }).join('');

  res.send(html('Minhas funções',`
    <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link ativo">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
    <a href="/portal" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar ao portal</a>
    <h2 style="font-size:28px;margin-bottom:8px;">Suas funções</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Funções ativas podem ser desativadas a qualquer momento — e solicitadas de novo depois, sem perder seu histórico.</p>
    <div class="card" style="margin-bottom:24px;">
      <div style="padding:16px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div><div style="font-family:'Cormorant Garamond',serif;font-size:17px;margin-bottom:3px;">Membro</div><div style="font-size:12px;color:var(--muted);">Acesso ao Círculo. Permanente.</div></div>
        <span class="badge badge-gold">Ativo</span>
      </div>
      ${itens||'<p style="color:var(--muted);padding:16px 0;">Nenhuma função adicional solicitada.</p>'}
    </div>
    ${solicitarHtml?`<div class="card"><h3 style="font-size:16px;margin-bottom:8px;">Solicitar outra função</h3><p style="color:var(--muted);font-size:12px;margin-bottom:16px;">Fica pendente de aprovação, como no cadastro.</p>${solicitarHtml}</div>`:''}
  `,true,membroInfo));
});

app.post('/minhas-funcoes/:slug/desativar',authMembro,async(req,res)=>{
  await pool.query(`UPDATE circulo_membro_funcoes SET ativo=false WHERE membro_id=$1 AND funcao_id=(SELECT id FROM circulo_funcoes WHERE slug=$2)`,[req.membro.id,req.params.slug]);
  res.redirect('/minhas-funcoes');
});

// Reabre uma função autosserviço (reativa se já existia desativada, ou cria pedido novo) — fecha o
// "caminho sem volta" de quem desativou uma função e não tinha como voltar sem falar com o admin.
app.post('/minhas-funcoes/:slug/solicitar',authMembro,async(req,res)=>{
  const slug=req.params.slug;
  if(!FUNCOES_CADASTRO.some(f=>f.slug===slug)) return res.redirect('/minhas-funcoes');
  const fr=await pool.query('SELECT id FROM circulo_funcoes WHERE slug=$1',[slug]);
  if(fr.rows.length){
    const existente=await pool.query('SELECT id FROM circulo_membro_funcoes WHERE membro_id=$1 AND funcao_id=$2',[req.membro.id,fr.rows[0].id]);
    if(existente.rows.length){
      await pool.query('UPDATE circulo_membro_funcoes SET ativo=false WHERE id=$1',[existente.rows[0].id]);
    }else{
      await pool.query('INSERT INTO circulo_membro_funcoes (membro_id,funcao_id,ativo) VALUES ($1,$2,false)',[req.membro.id,fr.rows[0].id]);
    }
  }
  res.redirect('/minhas-funcoes');
});

// ─── SIMULADOR DE AMBIENTE — telas e processamento ────────────────────────────
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
        <p style="font-size:12px;color:var(--muted);margin-bottom:16px;">A foto da parede onde o quadro vai ficar. É nela que a simulação será montada — tente enquadrar a parede inteira, de frente, com boa luz.</p>
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

      function renderResultado(data){
        const a = data.analise;
        const bbox = a.parede_bbox;

        let html = '<div class="card" style="margin-bottom:24px;"><h3 style="font-size:18px;margin-bottom:16px;color:var(--gold);">Leitura do ambiente</h3>';
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 24px;font-size:13px;">';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Paleta</span><br>'+a.paleta_dominante+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Temperatura</span><br>'+a.temperatura+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Estilo</span><br>'+a.estilo+'</div>';
        html += '<div><span style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Carga visual</span><br>'+a.carga_visual+'</div>';
        html += '</div><p style="margin-top:16px;font-size:13px;color:#ccc;font-style:italic;">'+a.justificativa_ambiente+'</p>';
        if(a.referencia_usada){ html += '<p style="margin-top:10px;font-size:11px;color:var(--muted);">Escala calibrada por: '+a.referencia_usada+'</p>'; }
        if(a.moldura_recomendada){
          const nomesMoldura = {preta:'Preta', carvalho:'Carvalho', aco_escovado:'Aço escovado'};
          html += '<p style="margin-top:10px;font-size:12px;color:var(--gold);">Moldura recomendada pela curadoria: '+(nomesMoldura[a.moldura_recomendada]||a.moldura_recomendada)+(a.justificativa_moldura?' — '+a.justificativa_moldura:'')+'</p>';
        }
        if(a.aviso_precisao){ html += '<div class="msg-info" style="margin-top:14px;">⚠ '+a.aviso_precisao+'</div>'; }
        html += '</div>';

        html += '<h3 style="font-size:22px;margin-bottom:20px;">Obras sugeridas</h3>';

        data.sugestoes.forEach((o,i)=>{
          const t = o._melhorTamanho;
          // Escala real: usa a largura da PAREDE NA FOTO calculada pela IA (não o número digitado),
          // porque a foto pode não enquadrar a parede inteira do jeito que foi medida
          // Usa DIRETO o número que o cliente digitou — a estimativa da IA por objetos de referência
          // provou ser instável e gerava quadros do tamanho errado (às vezes gigantes)
          const larguraRealParede = parseInt(data.parede_largura) || 300;
          const fracaoParede = t ? Math.min(t.largura / larguraRealParede, 1) : 0.3;
          const larguraNaFoto = fracaoParede * bbox.width_pct; // % da FOTO INTEIRA
          const centroX = bbox.left_pct + bbox.width_pct/2;
          const centroY = a.centro_vertical_ideal_pct;
          const larguraFinal = Math.min(Math.max(larguraNaFoto, 10), 75);
          const coresMoldura = { preta:'#1a1a1a', carvalho:'#8a6d3b', aco_escovado:'#9a9a9a' };
          const molduraInicial = coresMoldura[a.moldura_recomendada] || '#1a1a1a';

          html += '<div class="card" style="margin-bottom:24px;">';
          html += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;"><span class="badge badge-gold">'+(i+1)+'ª sugestão</span><span style="font-size:11px;color:var(--muted);">'+(o._score)+' pontos de compatibilidade</span></div>';

          html += '<div style="position:relative;background:#0d0d0d;border-radius:4px;overflow:hidden;margin-bottom:20px;line-height:0;">';
          html += '<img src="'+data.foto_local+'" style="width:100%;display:block;">';
          html += '<div style="position:absolute;top:'+centroY+'%;left:'+centroX+'%;transform:translate(-50%,-50%);width:'+larguraFinal+'%;">';
          html += '<div class="moldura moldura-'+i+'" style="border:2px solid '+molduraInicial+';padding:3px;background:#0a0a0a;box-sizing:border-box;">';
          html += '<div style="position:relative;">';
          html += '<img src="'+o.imagem_preview+'" style="width:100%;display:block;">';
          html += '<div style="position:absolute;inset:0;background-image:url(\\''+data.watermark+'\\');background-repeat:repeat;mix-blend-mode:overlay;pointer-events:none;"></div>';
          html += '</div></div></div>';
          html += '</div>';

          html += '<div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">'+(o.colecao||'')+'</div>';
          html += '<h4 style="font-family:\\'Cormorant Garamond\\',serif;font-size:22px;margin-bottom:4px;">'+o.nome+'</h4>';
          html += '<div style="font-size:11px;color:var(--muted);margin-bottom:12px;">Código: '+(o.codigo||o.id)+'</div>';
          if(t) html += '<p style="font-size:13px;color:var(--gold);margin-bottom:12px;">Tamanho sugerido: '+t.label+'</p>';

          html += '<div style="margin-bottom:16px;">';
          html += '<div style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">Moldura — comparar outras opções</div>';
          html += '<div style="display:flex;gap:8px;" id="molduras-'+i+'">';
          html += '<button type="button" onclick="trocarMoldura('+i+',\\'#1a1a1a\\',\\'preta\\')" data-cor="preta" style="width:36px;height:36px;background:#1a1a1a;border:2px solid '+(a.moldura_recomendada==='preta'?'var(--gold)':'var(--border)')+';border-radius:3px;cursor:pointer;" title="Preta"></button>';
          html += '<button type="button" onclick="trocarMoldura('+i+',\\'#8a6d3b\\',\\'carvalho\\')" data-cor="carvalho" style="width:36px;height:36px;background:#8a6d3b;border:2px solid '+(a.moldura_recomendada==='carvalho'?'var(--gold)':'var(--border)')+';border-radius:3px;cursor:pointer;" title="Carvalho"></button>';
          html += '<button type="button" onclick="trocarMoldura('+i+',\\'#9a9a9a\\',\\'aco_escovado\\')" data-cor="aco_escovado" style="width:36px;height:36px;background:linear-gradient(135deg,#aaa,#777);border:2px solid '+(a.moldura_recomendada==='aco_escovado'?'var(--gold)':'var(--border)')+';border-radius:3px;cursor:pointer;" title="Aço escovado"></button>';
          html += '</div></div>';

          if(o._motivos && o._motivos.length){
            html += '<div style="font-size:12px;color:#aaa;line-height:1.7;"><strong style="color:var(--gold);">Por que combina:</strong> '+o._motivos.join('; ')+'.</div>';
          }
          html += '</div>';
        });

        html += '<button onclick="location.reload()" class="btn btn-outline btn-full" style="margin-top:16px;">Simular outro ambiente</button>';
        document.getElementById('resultado').innerHTML = html;
      }

      function trocarMoldura(idx, cor, slug){
        const el = document.querySelector('.moldura-'+idx);
        if(el) el.style.borderColor = cor;
        const grupo = document.getElementById('molduras-'+idx);
        if(grupo){
          grupo.querySelectorAll('button').forEach(b=>{
            b.style.borderColor = b.dataset.cor===slug ? 'var(--gold)' : 'var(--border)';
          });
        }
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
             formato_recomendado, imagem_preview
      FROM almare_obras WHERE status='aprovada'`);

    const sugestoes = rankearObras(obras.rows, analise, dados);

    if(!sugestoes.length) return res.json({ erro:'Nenhuma obra do catálogo é compatível com essas medidas. Tente uma parede maior.' });

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

// ─── CATÁLOGO ─────────────────────────────────────────────────────────────────
app.get('/catalogo',authMembro,async(req,res)=>{
  try{
    const fRows=await pool.query(`SELECT f.slug FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true`,[req.membro.id]);
    const slugs=fRows.rows.map(r=>r.slug);
    const isCurador=slugs.includes('curador');
    const isEspecificador=slugs.includes('especificador');
    const isEmbaixador=slugs.includes('embaixador');
    const navImpacto=slugs.some(s=>['embaixador','especificador','artista','colaborador'].includes(s))?'<a href="/meu-impacto" class="nav-link">Impacto</a>':'';
    const podeIndicar=isEmbaixador||isEspecificador||isCurador;
    const navIndicacoes=podeIndicar?'<a href="/minhas-indicacoes" class="nav-link">Indicações</a>':'';

    const obras=await pool.query(`
      SELECT o.id, o.codigo, o.nome, o.colecao, o.tags, o.orientacao,
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

    function campoConceito(valor){
      if(!valor)return '';
      return `<div class="ficha-conceito"><div class="ficha-quote">"${esc(valor)}"</div></div>`;
    }
    function campoEssencia(valor){
      if(!valor)return '';
      return `<div class="ficha-essencia"><div class="ficha-essencia-label">Essência</div><div class="ficha-essencia-texto">${esc(valor)}</div></div>`;
    }
    function campoPermanece(valor){
      if(!valor)return '';
      return `<div class="ficha-conceito"><div class="ficha-quote">"${esc(valor)}"</div></div>`;
    }
    function campoCard(titulo,valor){
      if(!valor)return '';
      return `<div class="ficha-card"><div class="ficha-card-titulo">${esc(titulo)}</div><div class="ficha-plana">${esc(valor)}</div></div>`;
    }
    function campoChips(titulo,valor){
      if(!valor)return '';
      const itens=Array.isArray(valor)?valor:String(valor).split(',').map(v=>v.trim()).filter(Boolean);
      if(!itens.length)return '';
      return `<div class="ficha-card"><div class="ficha-card-titulo">${esc(titulo)}</div><div class="ficha-chips">${itens.map(v=>`<span class="ficha-chip">${esc(v)}</span>`).join('')}</div></div>`;
    }
    function linha(label,valor){
      if(!valor)return '';
      return `<div class="ficha-linha"><span class="ficha-linha-label">${esc(label)}</span><span class="ficha-linha-valor">${esc(valor)}</span></div>`;
    }

    const cardsHtml=obras.rows.map(o=>{
      let detalhe=campoChips('Tags',o.tags)+campoConceito(o.conceito)+campoEssencia(o.essencia)+campoPermanece(o.o_que_permanece)+campoChips('Ambientes compatíveis',o.ambientes_compativeis)+campoCard('Texto Curatorial',o.texto_curatorial);
      let linhas=linha('Paleta',o.paleta)+linha('Cores observadas',o.paleta_detalhe)+linha('Sensação provocada',o.sensacao_provocada);
      if(isEmbaixador||isEspecificador||isCurador) linhas+=linha('Perfil de cliente',o.perfil_de_cliente);
      if(isEspecificador||isCurador) linhas+=linha('Nível de destaque',o.nivel_de_destaque)+linha('Personalidade',o.personalidade_da_obra)+linha('Perfil arquitetônico',o.perfil_arquitetonico)+linha('Composição múltipla',o.possibilidade_composicao)+linha('Tamanhos recomendados',o.tamanhos_recomendados)+linha('Formato recomendado',o.formato_recomendado);
      if(isCurador){
        detalhe+=campoCard('Descrição Comercial',o.descricao_comercial);
        linhas+=linha('Nota do curador',o.nota_curador)+linha('Potencial de venda',o.potencial_nota?o.potencial_nota+'/100':'')+linha('Justificativa',o.potencial_justificativa)+linha('Obs. de produção',o.observacoes_producao);
      }
      if(linhas) detalhe+=`<div class="ficha-card"><div class="ficha-card-titulo">Ficha</div>${linhas}</div>`;

      const palataAttr=o.paleta?o.paleta.toLowerCase().replace(/\s+/g,'-'):'';
      const colecaoAttr=o.colecao?o.colecao.toLowerCase().replace(/\s+/g,'-'):'';

      return `<div class="obra-card" data-colecao="${esc(colecaoAttr)}" data-paleta="${esc(palataAttr)}" data-nome="${esc((o.nome||'').toLowerCase())}" data-orientacao="${esc((o.orientacao||'').toLowerCase())}">
        <div onclick="abrirObra(${o.id})" style="cursor:pointer;">
          <div style="position:relative;background:#0d0d0d;border-radius:4px 4px 0 0;overflow:hidden;aspect-ratio:1/1;">
            ${o.imagem_preview?`<img src="${esc(o.imagem_preview)}" style="width:100%;height:100%;object-fit:cover;" loading="lazy">`:`<div style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:11px;letter-spacing:.15em;">SEM IMAGEM</div>`}
          </div>
          <div style="padding:16px;background:var(--surface);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;">
            <div style="font-size:10px;font-family:monospace;color:var(--muted);margin-bottom:6px;">${esc(o.codigo)||''}</div>
            <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;">${esc(o.colecao)||'—'}</div>
            <div style="font-family:'Cormorant Garamond',serif;font-size:18px;margin-bottom:8px;">${esc(o.nome)||'Sem título'}</div>
            <div style="font-size:11px;color:var(--muted);">${esc(o.paleta)||''}</div>
          </div>
        </div>
        <!-- DETALHE (oculto, abre no modal) -->
        <div id="detalhe-${o.id}" style="display:none">${detalhe}</div>
      </div>`;
    }).join('');

    const opcoesColecao=colecoes.map(c=>`<option value="${esc(c.toLowerCase().replace(/\s+/g,'-'))}">${esc(c)}</option>`).join('');
    const opcoesPaleta=paletas.map(p=>`<option value="${esc(p.toLowerCase().replace(/\s+/g,'-'))}">${esc(p)}</option>`).join('');

    res.send(html('Catálogo',`
      <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link ativo">Obras</a>${navImpacto}${navIndicacoes}<a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>

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
        <div id="modal-conteudo" onclick="event.stopPropagation()" style="max-width:880px;margin:0 auto;background:#111;border:1px solid #222;border-radius:4px;overflow:hidden;">
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

        function moldurarImg(src){
          return \`<div class="moldura-wrap">
            <div class="moldura moldura-preta">
              <div class="moldura-vao"><img src="\${src}"></div>
            </div>
            <div class="moldura-swatches">
              <span class="moldura-swatch moldura-swatch-preta ativo" onclick="trocarMoldura(this,'preta')" title="Preta"></span>
              <span class="moldura-swatch moldura-swatch-carvalho" onclick="trocarMoldura(this,'carvalho')" title="Carvalho"></span>
              <span class="moldura-swatch moldura-swatch-aco" onclick="trocarMoldura(this,'aco')" title="Aço escovado"></span>
            </div>
          </div>\`;
        }
        function trocarMoldura(el,cor){
          const wrap=el.closest('.moldura-wrap');
          const moldura=wrap.querySelector('.moldura');
          moldura.classList.remove('moldura-preta','moldura-carvalho','moldura-aco');
          moldura.classList.add('moldura-'+cor);
          wrap.querySelectorAll('.moldura-swatch').forEach(s=>s.classList.remove('ativo'));
          el.classList.add('ativo');
        }

        function abrirObra(id){
          const src=document.getElementById('detalhe-'+id);
          if(!src)return;
          const card=src.closest('.obra-card');
          const img=card.querySelector('img');
          const nome=card.querySelector('[style*="Cormorant"]').textContent;
          const colecao=card.querySelector('[style*="text-transform"]').textContent;
          const orientacao=(card.dataset.orientacao||'').toLowerCase();
          const ladoALado=orientacao!=='horizontal'; // vertical, quadrado ou sem info: imagem à esquerda

          const imgHtml=img?moldurarImg(img.src):'';
          const textoHtml=\`<div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:6px;">\${colecao}</div>
            <h2 style="font-family:'Cormorant Garamond',serif;font-size:28px;font-weight:400;margin-bottom:24px;">\${nome}</h2>
            <div>\${src.innerHTML}</div>\`;

          let html='';
          if(ladoALado){
            html=\`<div class="obra-lado-a-lado">
              <div class="obra-lado-img">\${imgHtml}</div>
              <div class="obra-lado-texto">\${textoHtml}</div>
            </div>\`;
          }else{
            html=imgHtml+textoHtml;
          }
          document.getElementById('modal-body').innerHTML=html;
          document.getElementById('modal').style.display='block';
          document.body.style.overflow='hidden';
        }

        function fecharModal(e){
          if(e&&e.target!==document.getElementById('modal')&&e.type!=='click')return;
          document.getElementById('modal').style.display='none';
          document.body.style.overflow='';
        }
        document.addEventListener('keydown',e=>{if(e.key==='Escape')fecharModal();});
      </script>
    `,true,{nome:req.membro.nome}));
  }catch(e){res.send(html('Catálogo',`<div class="msg-erro">${esc(e.message)}</div>`,true,req.membro));}
});

// ─── INDICAR OBRA — link pessoal por obra ─────────────────────────────────────
// Só quem tem função de apresentar a ALMARE para fora (embaixador, especificador, curador) cria link.
async function podeIndicarObra(membroId){
  const r=await pool.query(`SELECT 1 FROM circulo_membro_funcoes mf JOIN circulo_funcoes f ON f.id=mf.funcao_id WHERE mf.membro_id=$1 AND mf.ativo=true AND f.slug IN ('embaixador','especificador','curador')`,[membroId]);
  return r.rows.length>0;
}

app.get('/obra/:obraId/link',authMembro,async(req,res)=>{
  if(!(await podeIndicarObra(req.membro.id))) return res.send(html('Indicar obra',`<div class="msg-erro">Esta função ainda não pode gerar links de indicação. Solicite Embaixador ou Especificador em Funções.</div><a href="/catalogo" class="btn btn-outline" style="margin-top:16px;">← Voltar às obras</a>`,true,req.membro));
  const obraId=parseInt(req.params.obraId);
  const obra=await pool.query('SELECT id,nome,colecao,imagem_preview FROM almare_obras WHERE id=$1',[obraId]);
  if(!obra.rows.length) return res.send(html('Indicar obra',`<div class="msg-erro">Obra não encontrada.</div>`,true,req.membro));

  let link=await pool.query('SELECT codigo FROM circulo_obra_links WHERE membro_id=$1 AND obra_id=$2',[req.membro.id,obraId]);
  if(!link.rows.length){
    const codigo=gerarCodigo();
    await pool.query('INSERT INTO circulo_obra_links (membro_id,obra_id,codigo) VALUES ($1,$2,$3)',[req.membro.id,obraId,codigo]);
    link={rows:[{codigo}]};
  }
  const url=`${BASE_URL}/indicar/${link.rows[0].codigo}`;
  const o=obra.rows[0];

  res.send(html('Indicar obra',`
    <a href="/catalogo" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);display:inline-block;margin-bottom:24px;">← Voltar às obras</a>
    <h2 style="font-size:26px;margin-bottom:4px;">Indicar "${esc(o.nome)}"</h2>
    <p style="color:var(--muted);margin-bottom:28px;">Envie este link para quem você acha que pertence a essa obra. Todo interesse recebido aparece em Minhas Indicações, com o seu nome.</p>
    <div class="card">
      ${o.imagem_preview?`<img src="${esc(o.imagem_preview)}" style="max-width:100%;max-height:400px;display:block;margin:0 auto 20px;border-radius:4px;">`:''}
      <div style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Seu link de indicação</div>
      <div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${esc(url)}</div>
      <button onclick="navigator.clipboard.writeText('${esc(url)}');this.textContent='Copiado ✓'" class="btn btn-primary">Copiar link</button>
      <a href="/minhas-indicacoes" class="btn btn-outline" style="margin-left:8px;">Ver minhas indicações</a>
    </div>
  `,true,req.membro));
});

app.get('/minhas-indicacoes',authMembro,async(req,res)=>{
  if(!(await podeIndicarObra(req.membro.id))) return res.redirect('/catalogo');
  const links=await pool.query(`
    SELECT ol.id, ol.codigo, ol.obra_id, o.nome as obra_nome, o.imagem_preview,
      (SELECT COUNT(*) FROM circulo_indicacoes ci WHERE ci.obra_link_id=ol.id) as total_leads,
      (SELECT COUNT(*) FROM circulo_indicacoes ci WHERE ci.obra_link_id=ol.id AND ci.status='novo') as leads_novos
    FROM circulo_obra_links ol JOIN almare_obras o ON o.id=ol.obra_id
    WHERE ol.membro_id=$1 ORDER BY ol.criado_em DESC`,[req.membro.id]);

  const itens=links.rows.map(l=>`
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

  res.send(html('Minhas indicações',`
    <div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/minhas-indicacoes" class="nav-link ativo">Indicações</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
    <h2 style="font-size:28px;margin-bottom:8px;">Minhas indicações</h2>
    <p style="color:var(--muted);margin-bottom:32px;">Cada obra do catálogo tem seu próprio link. Toque em "Indicar esta obra" no catálogo para gerar um novo.</p>
    <div class="card">${itens||'<p style="color:var(--muted);padding:16px 0;">Você ainda não indicou nenhuma obra. Vá até o catálogo e toque em "Indicar esta obra".</p>'}</div>
  `,true,req.membro));
});

// Página PÚBLICA de indicação — quem recebe o link não precisa de conta no Círculo
app.get('/indicar/:codigo',async(req,res)=>{
  const r=await pool.query(`
    SELECT ol.id as link_id, o.id as obra_id, o.nome, o.colecao, o.essencia, o.texto_curatorial, o.o_que_permanece, o.imagem_preview, o.orientacao, m.nome as membro_nome
    FROM circulo_obra_links ol
    JOIN almare_obras o ON o.id=ol.obra_id
    JOIN circulo_membros m ON m.id=ol.membro_id
    WHERE ol.codigo=$1`,[req.params.codigo]);
  if(!r.rows.length) return res.status(404).send(html('Indicação',`<div class="msg-erro">Este link não existe mais.</div>`));
  const o=r.rows[0];
  const ladoALado=(o.orientacao||'').toLowerCase()!=='horizontal';
  const tamanhos=await tamanhosDaObra(o.orientacao);

  let logado=null;
  try{ logado=jwt.verify(req.cookies.circulo_token, JWT_SECRET); }catch{}

  const imgHtml=o.imagem_preview?`<div class="moldura-wrap">
      <div class="moldura moldura-preta">
        <div class="moldura-vao"><img src="${esc(o.imagem_preview)}"></div>
      </div>
      <div class="moldura-swatches">
        <span class="moldura-swatch moldura-swatch-preta ativo" onclick="trocarMoldura(this,'preta')" title="Preta"></span>
        <span class="moldura-swatch moldura-swatch-carvalho" onclick="trocarMoldura(this,'carvalho')" title="Carvalho"></span>
        <span class="moldura-swatch moldura-swatch-aco" onclick="trocarMoldura(this,'aco')" title="Aço escovado"></span>
      </div>
    </div>`:'';
  const textoHtml=`
    <div style="font-size:10px;letter-spacing:.25em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;">${esc(o.colecao)||''}</div>
    <h1 style="font-size:32px;margin-bottom:20px;">${esc(o.nome)}</h1>
    ${o.essencia?`<p style="font-style:italic;color:var(--gold-light);margin-bottom:20px;">${esc(o.essencia)}</p>`:''}
    ${o.texto_curatorial?`<p style="line-height:1.9;color:#ccc;margin-bottom:16px;">${esc(o.texto_curatorial)}</p>`:''}
    ${o.o_que_permanece?`<p style="font-style:italic;color:var(--muted);margin-bottom:${ladoALado?'0':'40px'};">${esc(o.o_que_permanece)}</p>`:''}
  `;
  const corpoObra=ladoALado
    ? `<div class="obra-lado-a-lado" style="margin-bottom:40px;">
        <div class="obra-lado-img">${imgHtml}</div>
        <div class="obra-lado-texto">${textoHtml}</div>
      </div>`
    : `${imgHtml}<div style="margin-bottom:40px;">${textoHtml}</div>`;

  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(o.nome)} — ALMARE</title><style>${CSS}</style></head>
  <body><div class="container" style="max-width:${ladoALado?'820px':'640px'};padding-top:48px;">
    <div class="logo" style="margin-bottom:6px;">ALMARE</div>
    <div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin-bottom:40px;">Uma indicação de ${esc(o.membro_nome)}</div>
    ${corpoObra}
    <div class="card" style="margin-bottom:20px;">
      <h3 style="font-size:18px;margin-bottom:16px;">Comprar esta obra</h3>
      ${logado?`
      <form method="POST" action="/comprar/${o.obra_id}/adicionar">
        <input type="hidden" name="codigo_indicacao" value="${esc(req.params.codigo)}">
        <input type="hidden" name="moldura" id="moldura_escolhida" value="preta">
        <div class="field"><label>Tamanho</label>
          <select name="tamanho_id" required>
            ${tamanhos.map(t=>`<option value="${t.id}">${esc(t.label)} — R$ ${t.preco.toFixed(2).replace('.',',')}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label>Moldura</label><div style="font-size:12px;color:var(--muted);">Escolhida acima na imagem — atualiza sozinho.</div></div>
        <button type="submit" class="btn btn-primary btn-full">Adicionar ao carrinho</button>
      </form>
      `:`
      <p style="color:var(--muted);margin-bottom:16px;">Pra comprar, entre com sua conta do Círculo (ou crie uma — leva um minuto).</p>
      <a href="/login" class="btn btn-primary btn-full" style="margin-bottom:10px;display:block;text-align:center;">Já sou membro — Entrar</a>
      <a href="/convite" class="btn btn-outline btn-full" style="display:block;text-align:center;">Quero entrar no Círculo</a>
      `}
    </div>
    <div class="card">
      <h3 style="font-size:18px;margin-bottom:16px;">Tenho interesse nesta obra</h3>
      <form method="POST" action="/indicar/${esc(req.params.codigo)}">
        <div class="field"><label>Nome *</label><input name="nome" required></div>
        <div class="field"><label>E-mail ou WhatsApp *</label><input name="contato" required></div>
        <div class="field"><label>Mensagem</label><textarea name="mensagem" placeholder="Opcional"></textarea></div>
        <button type="submit" class="btn btn-primary btn-full">Enviar interesse</button>
      </form>
    </div>
    <script>
      function trocarMoldura(el,cor){
        const wrap=el.closest('.moldura-wrap');
        const moldura=wrap.querySelector('.moldura');
        moldura.classList.remove('moldura-preta','moldura-carvalho','moldura-aco');
        moldura.classList.add('moldura-'+cor);
        const campoOculto=document.getElementById('moldura_escolhida');
        if(campoOculto) campoOculto.value=cor;
        wrap.querySelectorAll('.moldura-swatch').forEach(s=>s.classList.remove('ativo'));
        el.classList.add('ativo');
      }
    </script>
  </div></body></html>`);
});

app.post('/indicar/:codigo',async(req,res)=>{
  const r=await pool.query('SELECT ol.id as link_id, ol.membro_id, o.nome as obra_nome FROM circulo_obra_links ol JOIN almare_obras o ON o.id=ol.obra_id WHERE ol.codigo=$1',[req.params.codigo]);
  if(!r.rows.length) return res.status(404).send(html('Indicação',`<div class="msg-erro">Este link não existe mais.</div>`));
  const {link_id,membro_id,obra_nome}=r.rows[0];
  const {nome,contato,mensagem}=req.body;
  await pool.query('INSERT INTO circulo_indicacoes (obra_link_id,nome_lead,contato_lead,mensagem) VALUES ($1,$2,$3,$4)',[link_id,nome,contato,mensagem||null]);
  await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'novo_interesse',$2)`,[membro_id,`Alguém demonstrou interesse em "${obra_nome}" através da sua indicação`]);

  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Obrigado — ALMARE</title><style>${CSS}</style></head>
  <body><div class="container-sm" style="text-align:center;padding-top:80px;">
    <div class="logo" style="margin-bottom:32px;">ALMARE</div>
    <h2 style="font-size:26px;margin-bottom:16px;">Recebemos seu interesse</h2>
    <p style="color:var(--muted);line-height:1.8;">Em breve alguém da ALMARE entra em contato com você.</p>
  </div></body></html>`);
});

// ─── COMPRAR OBRA — tamanhos, carrinho e checkout ─────────────────────────────
// Busca os tamanhos válidos pra uma obra, a partir da orientação dela (quadrada usa
// os tamanhos 1:1; vertical/horizontal usa os 3:2, girando largura x altura conforme o caso).
async function tamanhosDaObra(orientacao){
  const quadrada = (orientacao||'').toLowerCase()==='quadrado'||(orientacao||'').toLowerCase()==='quadrada';
  const formato = quadrada?'1:1':'3:2';
  const r = await pool.query('SELECT id,tamanho,preco FROM almare_tamanhos WHERE formato=$1 AND ativo=true ORDER BY ordem',[formato]);
  return r.rows.map(t=>{
    const nums=(t.tamanho.match(/\d+/g)||[]).map(Number);
    let largura=nums[0]||0, altura=nums[1]||nums[0]||0;
    if(!quadrada && (orientacao||'').toLowerCase()==='vertical' && largura>altura){ [largura,altura]=[altura,largura]; }
    const preco=parseFloat(String(t.preco).replace(/[^\d,.-]/g,'').replace(',','.'))||0;
    return {id:t.id, label:`${largura}×${altura} cm`, largura, altura, preco};
  });
}

async function pegarOuCriarCarrinhoObra(membroId){
  const existente = await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status='CARRINHO'`,[membroId]);
  if(existente.rows.length) return existente.rows[0];
  const numero = `CIR-${new Date().getFullYear()}-${Date.now().toString().slice(-6)}`;
  const novo = await pool.query(`INSERT INTO circulo_pedidos (numero,membro_id,total,status) VALUES ($1,$2,0,'CARRINHO') RETURNING *`,[numero,membroId]);
  return novo.rows[0];
}
async function recalcularTotalCarrinhoObra(pedidoId){
  const soma = await pool.query('SELECT COALESCE(SUM(subtotal),0) as total FROM circulo_pedido_itens WHERE pedido_id=$1',[pedidoId]);
  const total = parseFloat(soma.rows[0].total);
  await pool.query('UPDATE circulo_pedidos SET total=$1 WHERE id=$2',[total,pedidoId]);
  return total;
}

// Adiciona ao carrinho a partir da página pública de indicação (ou do catálogo, sem link)
app.post('/comprar/:obraId/adicionar',authMembro,async(req,res)=>{
  const obraId=parseInt(req.params.obraId);
  const {tamanho_id,moldura,codigo_indicacao}=req.body;
  const quantidade=Math.max(1,Math.min(20,parseInt(req.body.quantidade)||1));
  try{
    const obra=await pool.query('SELECT id,orientacao FROM almare_obras WHERE id=$1',[obraId]);
    if(!obra.rows.length) return res.redirect('back');
    const tamanhos=await tamanhosDaObra(obra.rows[0].orientacao);
    const tamanho=tamanhos.find(t=>t.id===parseInt(tamanho_id));
    if(!tamanho||!MOLDURA_NOME[moldura]) return res.redirect('back');

    let obraLinkId=null;
    if(codigo_indicacao){
      const link=await pool.query('SELECT id FROM circulo_obra_links WHERE codigo=$1',[codigo_indicacao]);
      if(link.rows.length) obraLinkId=link.rows[0].id;
    }

    const pedido=await pegarOuCriarCarrinhoObra(req.membro.id);
    const subtotal=Math.round(tamanho.preco*quantidade*100)/100;
    await pool.query(
      `INSERT INTO circulo_pedido_itens (pedido_id,obra_id,obra_link_id,tamanho_id,tamanho_label,largura,altura,moldura,quantidade,preco_unitario,subtotal) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [pedido.id,obraId,obraLinkId,tamanho.id,tamanho.label,tamanho.largura,tamanho.altura,moldura,quantidade,tamanho.preco,subtotal]
    );
    await recalcularTotalCarrinhoObra(pedido.id);
    res.redirect('/carrinho');
  }catch(e){ res.send(html('Erro',`<div class="msg-erro">${esc(e.message)}</div>`,true,req.membro)); }
});

app.get('/carrinho',authMembro,async(req,res)=>{
  const pedido=await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status='CARRINHO'`,[req.membro.id]);
  if(!pedido.rows.length) return res.send(html('Carrinho',`<h2 style="font-size:28px;margin-bottom:16px;">Seu carrinho</h2><p style="color:var(--muted)">Vazio. Volte ao <a href="/catalogo">catálogo</a> pra escolher uma obra.</p>`,true,{nome:req.membro.nome}));
  const p=pedido.rows[0];
  const itens=await pool.query(`SELECT pi.*, o.nome as obra_nome, o.imagem_preview FROM circulo_pedido_itens pi JOIN almare_obras o ON o.id=pi.obra_id WHERE pi.pedido_id=$1 ORDER BY pi.id`,[p.id]);
  const linhas=itens.rows.map(i=>`
    <tr>
      <td>${i.imagem_preview?`<img src="${esc(i.imagem_preview)}" style="width:56px;height:56px;object-fit:cover;border-radius:4px;">`:''}</td>
      <td>${esc(i.obra_nome)}<br><span style="font-size:11px;color:var(--muted)">${esc(i.tamanho_label)} · ${esc(MOLDURA_NOME[i.moldura]||i.moldura)}</span></td>
      <td>${i.quantidade}</td>
      <td>R$ ${parseFloat(i.subtotal).toFixed(2).replace('.',',')}</td>
      <td><form method="POST" action="/carrinho/${i.id}/remover"><button class="btn btn-outline" style="padding:5px 10px;font-size:10px;">Remover</button></form></td>
    </tr>`).join('');
  res.send(html('Carrinho',`
    <h2 style="font-size:28px;margin-bottom:24px;">Seu carrinho</h2>
    <div class="card" style="margin-bottom:24px;">
      <table><thead><tr><th></th><th>Obra</th><th>Qtd.</th><th>Valor</th><th></th></tr></thead><tbody>${linhas}</tbody></table>
      <div style="text-align:right;margin-top:20px;font-family:'Cormorant Garamond',serif;font-size:24px;color:var(--gold);">Total: R$ ${parseFloat(p.total).toFixed(2).replace('.',',')}</div>
    </div>
    <div class="card">
      <h3 style="font-size:16px;margin-bottom:16px;">Forma de pagamento</h3>
      <form method="POST" action="/carrinho/finalizar">
        <div class="field"><label>Como prefere pagar?</label>
          <select name="metodo_pagamento">
            <option value="PIX">PIX</option>
            <option value="CARTAO">Cartão de crédito</option>
          </select>
        </div>
        <button type="submit" class="btn btn-primary btn-full">Finalizar e pagar</button>
      </form>
    </div>
  `,true,{nome:req.membro.nome}));
});

app.post('/carrinho/:itemId/remover',authMembro,async(req,res)=>{
  const item=await pool.query(`SELECT pi.*, p.membro_id FROM circulo_pedido_itens pi JOIN circulo_pedidos p ON p.id=pi.pedido_id WHERE pi.id=$1`,[req.params.itemId]);
  if(item.rows.length && item.rows[0].membro_id===req.membro.id){
    const pedidoId=item.rows[0].pedido_id;
    await pool.query('DELETE FROM circulo_pedido_itens WHERE id=$1',[req.params.itemId]);
    const restantes=await pool.query('SELECT COUNT(*) as n FROM circulo_pedido_itens WHERE pedido_id=$1',[pedidoId]);
    if(parseInt(restantes.rows[0].n)===0) await pool.query('DELETE FROM circulo_pedidos WHERE id=$1',[pedidoId]);
    else await recalcularTotalCarrinhoObra(pedidoId);
  }
  res.redirect('/carrinho');
});

app.post('/carrinho/finalizar',authMembro,async(req,res)=>{
  try{
    const {metodo_pagamento}=req.body;
    if(!['PIX','CARTAO'].includes(metodo_pagamento)) return res.redirect('/carrinho');
    const pedidoRes=await pool.query(`SELECT * FROM circulo_pedidos WHERE membro_id=$1 AND status='CARRINHO'`,[req.membro.id]);
    if(!pedidoRes.rows.length) return res.redirect('/carrinho');
    const pedido=pedidoRes.rows[0];
    if(parseFloat(pedido.total)<=0) return res.redirect('/carrinho');

    const membroRes=await pool.query('SELECT * FROM circulo_membros WHERE id=$1',[req.membro.id]);
    const membro=membroRes.rows[0];

    await pool.query(`UPDATE circulo_pedidos SET status='AGUARDANDO_PAGAMENTO', metodo_pagamento=$1 WHERE id=$2`,[metodo_pagamento,pedido.id]);

    const asaasClienteId=await garantirClienteAsaas(membro);
    const cobranca=await criarCobranca(asaasClienteId,parseFloat(pedido.total),pedido.id,metodo_pagamento);
    await pool.query('UPDATE circulo_pedidos SET asaas_cobranca_id=$1, asaas_cliente_id=$2 WHERE id=$3',[cobranca.id,asaasClienteId,pedido.id]);

    res.send(html('Pagamento',`
      <h2 style="font-size:26px;margin-bottom:16px;">Pedido ${esc(pedido.numero)}</h2>
      <div class="card">
        ${cobranca.qrCodeImagem?`
          <div style="text-align:center;margin-bottom:16px;"><img src="data:image/png;base64,${cobranca.qrCodeImagem}" style="width:220px;height:220px;background:#fff;border-radius:8px;padding:8px;"></div>
          <div class="field"><label>Código para copiar e colar</label><input readonly value="${esc(cobranca.copiaCola||'')}" onclick="this.select()"></div>
        `:`<p style="color:var(--muted)">Termine o pagamento por cartão pelo link abaixo.</p><a href="${esc(cobranca.invoiceUrl||'#')}" target="_blank" class="btn btn-primary btn-full" style="margin-top:12px;">Ir para pagamento</a>`}
      </div>
    `,true,{nome:req.membro.nome}));
  }catch(e){
    res.send(html('Erro',`<div class="msg-erro">Não foi possível gerar o pagamento: ${esc(e.message)}</div><a href="/carrinho" class="btn btn-outline" style="margin-top:16px;">← Voltar ao carrinho</a>`,true,req.membro));
  }
});

// Webhook do Asaas — confirma pagamento, credita quem indicou (10 dias de carência) e fatura no Bling
app.post('/webhook/asaas', async (req, res) => {
  try {
    const tokenRecebido = req.headers['asaas-access-token'];
    if (process.env.ASAAS_WEBHOOK_TOKEN && tokenRecebido !== process.env.ASAAS_WEBHOOK_TOKEN) {
      return res.status(401).json({ erro: 'Token inválido' });
    }
    const { event, payment } = req.body;
    if (!payment || !payment.id) return res.status(200).json({ ok: true });

    const pedidoRes = await pool.query('SELECT * FROM circulo_pedidos WHERE asaas_cobranca_id=$1',[payment.id]);
    if (!pedidoRes.rows.length) return res.status(200).json({ ok: true });
    const pedido = pedidoRes.rows[0];

    if ((event==='PAYMENT_RECEIVED'||event==='PAYMENT_CONFIRMED') && pedido.status==='AGUARDANDO_PAGAMENTO'){
      await pool.query(`UPDATE circulo_pedidos SET status='PAGO' WHERE id=$1`,[pedido.id]);

      const itens=await pool.query('SELECT * FROM circulo_pedido_itens WHERE pedido_id=$1',[pedido.id]);
      for(const item of itens.rows){
        if(!item.obra_link_id) continue; // sem indicação vinculada, ninguém a creditar
        const link=await pool.query('SELECT membro_id FROM circulo_obra_links WHERE id=$1',[item.obra_link_id]);
        if(!link.rows.length) continue;
        const membroIndicador=link.rows[0].membro_id;
        const beneficio=parseFloat(item.subtotal)*0.10; // nasce como cashback — o membro pode converter em crédito depois
        await pool.query(
          `INSERT INTO circulo_transacoes (membro_id,obra_id,valor_obra,modalidade,valor_beneficio,status,criado_em,disponivel_em) VALUES ($1,$2,$3,'cashback',$4,'pendente',NOW(),NOW() + INTERVAL '10 days')`,
          [membroIndicador,item.obra_id,item.subtotal,beneficio]
        );
        await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'venda_indicacao',$2)`,
          [membroIndicador, `Uma indicação sua virou venda — cashback contabilizado, libera em 10 dias`]);
      }
      await sincronizarPedidoBlingObra(pedido.id);
    } else if (event==='PAYMENT_REFUNDED' || event==='PAYMENT_OVERDUE'){
      await pool.query(`UPDATE circulo_pedidos SET status='CANCELADO' WHERE id=$1`,[pedido.id]);
    }
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(200).json({ ok: true });
  }
});

// ─── IMPACTO ──────────────────────────────────────────────────────────────────
app.get('/meu-impacto',authMembro,async(req,res)=>{
  try{
    const trans=await pool.query(`
      SELECT t.*, o.nome as obra_nome
      FROM circulo_transacoes t
      LEFT JOIN almare_obras o ON o.id=t.obra_id
      WHERE t.membro_id=$1 ORDER BY t.criado_em DESC`,[req.membro.id]);

    const agora=Date.now();
    const disponivel=(t)=>t.disponivel_em && new Date(t.disponivel_em).getTime()<=agora;
    const dinheiroDisponivel=trans.rows.filter(t=>t.modalidade==='cashback'&&disponivel(t)).reduce((a,t)=>a+parseFloat(t.valor_beneficio),0);
    const creditoDisponivel=trans.rows.filter(t=>t.modalidade==='credito'&&disponivel(t)).reduce((a,t)=>a+parseFloat(t.valor_beneficio),0);
    const emCarencia=trans.rows.filter(t=>!disponivel(t));
    const emCarenciaTotal=emCarencia.reduce((a,t)=>a+parseFloat(t.valor_beneficio),0);
    const proximaLiberacao=emCarencia.length?emCarencia.map(t=>new Date(t.disponivel_em)).sort((a,b)=>a-b)[0]:null;

    const linhas=trans.rows.map(t=>{
      const disp=disponivel(t);
      const statusHtml=disp
        ?`<span class="badge badge-success">Disponível</span>`
        :`<span class="badge badge-pending">Libera ${t.disponivel_em?new Date(t.disponivel_em).toLocaleDateString('pt-BR'):'em breve'}</span>`;
      const converterBtn=(disp&&t.modalidade==='cashback')
        ?`<form method="POST" action="/meu-impacto/${t.id}/converter-credito" onsubmit="return confirm('Converter esse valor em crédito? Depois de convertido não dá pra voltar pra dinheiro.')"><button class="btn btn-outline" style="padding:5px 10px;font-size:10px;">Converter em crédito</button></form>`
        :'';
      return `<tr><td>${esc(t.obra_nome)||'Obra #'+t.obra_id}</td><td>R$ ${parseFloat(t.valor_obra).toFixed(2).replace('.',',')}</td><td><span class="badge ${t.modalidade==='credito'?'badge-gold':'badge-muted'}">${t.modalidade==='credito'?'Crédito':'Cashback'}</span></td><td style="color:var(--gold)">R$ ${parseFloat(t.valor_beneficio).toFixed(2).replace('.',',')}</td><td>${statusHtml}</td><td>${converterBtn}</td></tr>`;
    }).join('');

    res.send(html('Impacto',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link ativo">Impacto</a><a href="/minhas-indicacoes" class="nav-link">Indicações</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div>
    <div class="grid-3" style="margin-bottom:16px;">
      <div class="stat-box"><div class="num">R$ ${dinheiroDisponivel.toFixed(2).replace('.',',')}</div><div class="lbl">Cashback disponível</div></div>
      <div class="stat-box"><div class="num">R$ ${creditoDisponivel.toFixed(2).replace('.',',')}</div><div class="lbl">Crédito disponível</div></div>
      <div class="stat-box"><div class="num">R$ ${emCarenciaTotal.toFixed(2).replace('.',',')}</div><div class="lbl">Aguardando liberação</div></div>
    </div>
    ${proximaLiberacao?`<p style="color:var(--muted);font-size:12px;margin-bottom:24px;">Toda venda fica 10 dias em carência antes de liberar, pra cobrir o prazo de troca ou cancelamento. Próxima liberação: ${proximaLiberacao.toLocaleDateString('pt-BR')}.</p>`:'<div style="margin-bottom:24px;"></div>'}
    <div class="card"><h3 style="font-size:18px;margin-bottom:20px;">Histórico</h3>${trans.rows.length?`<table><thead><tr><th>Obra</th><th>Valor</th><th>Modalidade</th><th>Benefício</th><th>Status</th><th></th></tr></thead><tbody>${linhas}</tbody></table>`:'<p style="color:var(--muted)">Nenhuma venda ainda.</p>'}</div>`,true,{nome:req.membro.nome}));
  }catch(e){res.send(html('Impacto',`<div class="msg-erro">${esc(e.message)}</div>`,true,req.membro));}
});

// Converte cashback (dinheiro) já disponível em crédito — mesmo valor, sem volta.
app.post('/meu-impacto/:id/converter-credito',authMembro,async(req,res)=>{
  const t=await pool.query(`SELECT * FROM circulo_transacoes WHERE id=$1 AND membro_id=$2`,[req.params.id,req.membro.id]);
  if(t.rows.length){
    const tr=t.rows[0];
    const jaDisponivel=tr.disponivel_em && new Date(tr.disponivel_em).getTime()<=Date.now();
    if(jaDisponivel && tr.modalidade==='cashback'){
      await pool.query(`UPDATE circulo_transacoes SET modalidade='credito' WHERE id=$1`,[req.params.id]);
    }
  }
  res.redirect('/meu-impacto');
});

// ─── VOZ ──────────────────────────────────────────────────────────────────────
app.get('/sugestoes',authMembro,async(req,res)=>{
  const lista=await pool.query('SELECT * FROM circulo_sugestoes WHERE membro_id=$1 ORDER BY criado_em DESC',[req.membro.id]);
  const itens=lista.rows.map(s=>`<div style="padding:16px 0;border-bottom:1px solid var(--border);"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${esc(s.status)}</span><span style="font-size:11px;color:var(--muted)">${new Date(s.criado_em).toLocaleDateString('pt-BR')}</span></div><p style="font-size:13px;line-height:1.6;">${esc(s.texto)}</p>${s.resposta?`<p style="font-size:12px;color:var(--gold);margin-top:8px;font-style:italic;">↳ ${esc(s.resposta)}</p>`:''}</div>`).join('');
  res.send(html('Voz',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link ativo">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Sua voz no Círculo</h2><p style="color:var(--muted);margin-bottom:32px;">Sugira temas, formatos, ambientes. Anderson lê tudo.</p><div class="card" style="margin-bottom:24px;"><form method="POST" action="/sugestoes"><div class="field"><label>Sua sugestão</label><textarea name="texto" required placeholder="Uma ideia..."></textarea></div><button type="submit" class="btn btn-primary">Enviar</button></form></div>${lista.rows.length?`<div class="card"><h3 style="font-size:16px;margin-bottom:16px;">Anteriores</h3>${itens}</div>`:''}`,true,{nome:req.membro.nome}));
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
  res.send(html('Convidar',`<div class="nav-bar"><a href="/portal" class="nav-link">Passaporte</a><a href="/catalogo" class="nav-link">Obras</a><a href="/meu-impacto" class="nav-link">Impacto</a><a href="/sugestoes" class="nav-link">Voz</a><a href="/minhas-funcoes" class="nav-link">Funções</a><a href="/meu-convite" class="nav-link ativo">Convidar</a></div><h2 style="font-size:28px;margin-bottom:8px;">Seu link de convite</h2><p style="color:var(--muted);margin-bottom:32px;">Compartilhe com quem acredita que pertence ao Círculo.</p><div class="card"><div style="font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;">Link pessoal</div><div style="background:#0d0d0d;border:1px solid var(--border);border-radius:3px;padding:14px;font-size:13px;word-break:break-all;margin-bottom:16px;">${esc(link)}</div><button onclick="navigator.clipboard.writeText('${esc(link)}');this.textContent='Copiado ✓'" class="btn btn-outline">Copiar link</button><div style="margin-top:20px;font-size:12px;color:var(--muted)">${c?c.usos:0} pessoa(s) entrou pela sua indicação</div></div>`,true,{nome:req.membro.nome}));
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
  // Funções pendentes de aprovação (Embaixador, Especificador etc. — não a entrada como Membro, que é livre)
  const pendentes=await pool.query(`
    SELECT mf.id as mf_id, m.nome, m.email, m.codigo_membro, f.nome as funcao, f.slug, m.id as membro_id
    FROM circulo_membro_funcoes mf
    JOIN circulo_membros m ON m.id=mf.membro_id
    JOIN circulo_funcoes f ON f.id=mf.funcao_id
    WHERE mf.ativo=false ORDER BY mf.id ASC`);
  const membros=await pool.query('SELECT * FROM circulo_resumo_membro ORDER BY membro_desde DESC');
  // Indicações de obras recebidas via link pessoal de cada membro
  const indicacoes=await pool.query(`
    SELECT ci.id, ci.nome_lead, ci.contato_lead, ci.mensagem, ci.status, ci.criado_em,
           ol.membro_id, ol.obra_id, m.nome as membro_nome, o.nome as obra_nome
    FROM circulo_indicacoes ci
    JOIN circulo_obra_links ol ON ol.id=ci.obra_link_id
    JOIN circulo_membros m ON m.id=ol.membro_id
    JOIN almare_obras o ON o.id=ol.obra_id
    ORDER BY ci.criado_em DESC LIMIT 200`).catch(()=>({rows:[]}));

  const linhaPendentes=pendentes.rows.map(p=>`
    <tr data-busca="${esc((p.nome+' '+p.email+' '+p.funcao).toLowerCase())}">
      <td><strong>${esc(p.nome)}</strong><br><span style="font-size:11px;color:var(--muted)">${esc(p.email)}</span></td>
      <td><span class="badge badge-gold">${esc(p.funcao)}</span></td>
      <td>
        <form method="POST" action="/admin/funcoes/${p.mf_id}/aprovar" style="display:inline">
          <button class="btn btn-primary" style="padding:6px 14px;font-size:10px;">Aprovar</button>
        </form>
        <form method="POST" action="/admin/funcoes/${p.mf_id}/recusar" style="display:inline;margin-left:6px" onsubmit="return confirm('Recusar esta função?')">
          <button class="btn btn-outline" style="padding:6px 14px;font-size:10px;">Recusar</button>
        </form>
      </td>
    </tr>`).join('');

  const linhaMembros=membros.rows.map(m=>`
    <tr data-busca="${esc((m.nome+' '+m.email+' '+(m.codigo_membro||'')).toLowerCase())}">
      <td>${esc(m.nome)}</td>
      <td style="color:var(--muted)">${esc(m.codigo_membro)||'—'}</td>
      <td style="color:var(--muted)">${esc(m.email)}</td>
      <td style="color:var(--gold)">R$ ${parseFloat(m.credito_disponivel).toFixed(2).replace('.',',')}</td>
      <td>${m.obras_que_encontraram_lar}</td>
      <td>${m.total_indicacoes}</td>
    </tr>`).join('');

  const linhaIndicacoes=indicacoes.rows.map(i=>`
    <tr data-busca="${esc((i.membro_nome+' '+i.obra_nome+' '+(i.nome_lead||'')+' '+(i.contato_lead||'')).toLowerCase())}">
      <td>${esc(i.obra_nome)}</td>
      <td style="color:var(--muted)">${esc(i.membro_nome)}</td>
      <td>${esc(i.nome_lead)||'—'}<br><span style="font-size:11px;color:var(--muted)">${esc(i.contato_lead)||''}</span></td>
      <td>
        <form method="POST" action="/admin/indicacoes/${i.id}/atualizar" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
          <select name="status" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:3px;font-size:12px;">
            <option value="novo" ${i.status==='novo'?'selected':''}>Novo</option>
            <option value="contatado" ${i.status==='contatado'?'selected':''}>Contatado</option>
            <option value="convertido" ${i.status==='convertido'?'selected':''}>Convertido em venda</option>
            <option value="perdido" ${i.status==='perdido'?'selected':''}>Perdido</option>
          </select>
          <input name="valor" type="number" step="0.01" placeholder="Valor da obra (se convertido)" style="width:160px;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:3px;font-size:12px;">
          <select name="modalidade" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:3px;font-size:12px;">
            <option value="cashback">Cashback 10%</option>
            <option value="credito">Crédito 20%</option>
          </select>
          <button type="submit" class="btn btn-outline" style="padding:6px 12px;font-size:10px;">Salvar</button>
        </form>
      </td>
    </tr>`).join('');

  res.send(html('Admin',`
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;">
      <h2 style="font-size:24px;">Painel do Círculo</h2>
      <a href="/admin/logout" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">Sair</a>
    </div>
    <div class="grid-3" style="margin-bottom:32px;">
      <div class="stat-box"><div class="num">${pendentes.rows.length}</div><div class="lbl">Funções pendentes</div></div>
      <div class="stat-box"><div class="num">${membros.rows.length}</div><div class="lbl">Membros ativos</div></div>
      <div class="stat-box"><div class="num">${indicacoes.rows.filter(i=>i.status==='novo').length}</div><div class="lbl">Indicações novas</div></div>
    </div>
    ${pendentes.rows.length?`
    <div class="card" style="margin-bottom:24px;">
      <h3 style="font-size:18px;margin-bottom:20px;color:var(--gold);">Funções aguardando aprovação</h3>
      <table><thead><tr><th>Membro</th><th>Função solicitada</th><th>Ação</th></tr></thead>
      <tbody>${linhaPendentes}</tbody></table>
    </div>`:''}
    <div class="card" style="margin-bottom:24px;">
      <h3 style="font-size:18px;margin-bottom:16px;color:var(--gold);">Indicações de obras</h3>
      <input type="text" placeholder="Buscar por obra, membro ou contato..." oninput="buscarTabela(this,'tabela-indicacoes')" style="width:100%;margin-bottom:16px;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:13px;">
      <table id="tabela-indicacoes"><thead><tr><th>Obra</th><th>Indicada por</th><th>Interessado</th><th>Ação</th></tr></thead>
      <tbody>${linhaIndicacoes||'<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:24px;">Nenhuma indicação ainda</td></tr>'}</tbody></table>
    </div>
    <div class="card" style="margin-bottom:16px;">
      <h3 style="font-size:18px;margin-bottom:16px;">Membros do Círculo</h3>
      <input type="text" placeholder="Buscar por nome, e-mail ou código..." oninput="buscarTabela(this,'tabela-membros')" style="width:100%;margin-bottom:16px;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:13px;">
      <table id="tabela-membros"><thead><tr><th>Nome</th><th>Código</th><th>E-mail</th><th>Crédito</th><th>Obras</th><th>Indicações</th></tr></thead>
      <tbody>${linhaMembros||'<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:24px;">Nenhum membro ainda</td></tr>'}</tbody></table>
    </div>
    <a href="/admin/sugestoes" class="btn btn-outline">Ver sugestões dos membros</a>
    <script>
      function buscarTabela(input,tableId){
        const termo=input.value.toLowerCase();
        document.querySelectorAll('#'+tableId+' tbody tr').forEach(tr=>{
          const alvo=tr.dataset.busca||'';
          tr.style.display=!termo||alvo.includes(termo)?'':'none';
        });
      }
    </script>
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

// ─── INDICAÇÕES — atualizar status / registrar venda ──────────────────────────
app.post('/admin/indicacoes/:id/atualizar',authAdmin,async(req,res)=>{
  const {status,valor,modalidade}=req.body;
  await pool.query('UPDATE circulo_indicacoes SET status=$1 WHERE id=$2',[status,req.params.id]);

  if(status==='convertido' && valor && parseFloat(valor)>0){
    const info=await pool.query(`
      SELECT ol.membro_id, ol.obra_id, o.nome as obra_nome
      FROM circulo_indicacoes ci
      JOIN circulo_obra_links ol ON ol.id=ci.obra_link_id
      JOIN almare_obras o ON o.id=ol.obra_id
      WHERE ci.id=$1`,[req.params.id]);
    if(info.rows.length){
      const {membro_id,obra_id,obra_nome}=info.rows[0];
      const valorObra=parseFloat(valor);
      const mod=modalidade==='credito'?'credito':'cashback';
      const beneficio=mod==='credito'?valorObra*0.20:valorObra*0.10;
      await pool.query(
        `INSERT INTO circulo_transacoes (membro_id,obra_id,valor_obra,modalidade,valor_beneficio,status,criado_em,disponivel_em) VALUES ($1,$2,$3,$4,$5,'pendente',NOW(),NOW() + INTERVAL '10 days')`,
        [membro_id,obra_id,valorObra,mod,beneficio]
      );
      await pool.query(
        `INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'venda_indicacao',$2)`,
        [membro_id, `Sua indicação de "${obra_nome}" virou venda — ${mod==='credito'?'crédito':'cashback'} contabilizado, libera em 10 dias`]
      );
    }
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
  const itens=lista.rows.map(s=>`<div data-busca="${esc((s.mn+' '+s.texto).toLowerCase())}" style="padding:20px;border:1px solid var(--border);border-radius:4px;margin-bottom:12px;"><div style="display:flex;justify-content:space-between;margin-bottom:8px;"><span style="font-size:12px;color:var(--gold)">${esc(s.mn)}</span><span class="badge ${s.status==='incorporada'?'badge-success':s.status==='em_analise'?'badge-pending':'badge-muted'}">${esc(s.status)}</span></div><p style="font-size:13px;margin-bottom:12px;">${esc(s.texto)}</p><form method="POST" action="/admin/sugestoes/${s.id}/responder" style="display:flex;gap:8px;flex-wrap:wrap;"><input name="resposta" placeholder="Resposta" value="${esc(s.resposta||'')}" style="flex:1;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><select name="status" style="background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:3px;font-size:13px;"><option value="aberta" ${s.status==='aberta'?'selected':''}>Aberta</option><option value="em_analise" ${s.status==='em_analise'?'selected':''}>Em análise</option><option value="incorporada" ${s.status==='incorporada'?'selected':''}>Incorporada</option><option value="descartada" ${s.status==='descartada'?'selected':''}>Descartada</option></select><button type="submit" class="btn btn-primary" style="padding:8px 16px;">Salvar</button></form></div>`).join('');
  res.send(html('Sugestões',`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;"><h2 style="font-size:24px;">Sugestões dos membros</h2><a href="/admin" class="btn btn-outline" style="padding:8px 16px;font-size:10px;">← Voltar</a></div>
  <input type="text" placeholder="Buscar por membro ou texto..." oninput="document.querySelectorAll('#lista-sugestoes > div').forEach(d=>{d.style.display=!this.value||d.dataset.busca.includes(this.value.toLowerCase())?'':'none'})" style="width:100%;margin-bottom:20px;background:#0d0d0d;border:1px solid var(--border);color:var(--text);padding:10px 14px;border-radius:3px;font-size:13px;">
  <div id="lista-sugestoes">${itens||'<p style="color:var(--muted)">Nenhuma sugestão ainda.</p>'}</div>`));
});
app.post('/admin/sugestoes/:id/responder',authAdmin,async(req,res)=>{
  const{resposta,status}=req.body;
  await pool.query('UPDATE circulo_sugestoes SET status=$1,resposta=$2,respondido_em=NOW() WHERE id=$3',[status,resposta||null,req.params.id]);
  if(status==='incorporada'){const s=await pool.query('SELECT * FROM circulo_sugestoes WHERE id=$1',[req.params.id]);if(s.rows.length)await pool.query(`INSERT INTO circulo_passaporte_eventos (membro_id,tipo,descricao) VALUES ($1,'sugestao_incorporada','Sua sugestão foi incorporada à curadoria ALMARE')`,[s.rows[0].membro_id]);}
  res.redirect('/admin/sugestoes');
});

const PORT=process.env.PORT||3000;
garantirTabelas()
  .then(()=>{ app.listen(PORT,()=>console.log(`Círculo ALMARE rodando na porta ${PORT}`)); })
  .catch(e=>{ console.error('Erro ao garantir tabelas:', e.message); app.listen(PORT,()=>console.log(`Círculo ALMARE rodando na porta ${PORT} (aviso: tabelas novas não confirmadas)`)); });
