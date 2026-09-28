// Integração com a InfinitePay (checkout hospedado + conferência de pagamento).
// TODA a comunicação com a InfinitePay passa por este arquivo.
//
// Fluxo (API pública deles, sem chave de acesso — só a InfiniteTag da conta):
//   1. criarLinkCheckout()  -> POST /links -> devolve a URL da página de pagamento deles
//   2. o cliente paga lá (PIX ou cartão) e volta pro nosso site (redirectUrl)
//   3. a InfinitePay avisa o nosso servidor (webhookUrl): resposta 200 confirma, 400 faz eles tentarem de novo
//   4. verificarPagamento() -> POST /payment_check -> conferência independente antes de liberar o pedido
//
// Como não existe chave de API, o webhook não pode ser autenticado por token da InfinitePay. A proteção vem
// de duas camadas: (a) um segredo na própria URL do webhook e (b) a conferência do pagamento na API deles
// (e do valor exato) antes de liberar qualquer pedido.
const crypto = require('crypto');

const API_LINKS = 'https://api.checkout.infinitepay.io/links';
const API_CHECK = 'https://api.infinitepay.io/invoices/public/checkout/payment_check';
const TIMEOUT_MS = 15000;

function handle(){
  const h = (process.env.INFINITEPAY_HANDLE || '').trim().replace(/^\$/, '');
  if(!h) throw new Error('INFINITEPAY_HANDLE não está configurado no servidor.');
  return h;
}

// Segredo que vai na URL do webhook. Sem INFINITEPAY_WEBHOOK_SECRET, deriva do JWT_SECRET (estável entre reinícios).
function segredoWebhook(){
  if(process.env.INFINITEPAY_WEBHOOK_SECRET) return process.env.INFINITEPAY_WEBHOOK_SECRET;
  const base = process.env.JWT_SECRET || 'circulo-almare-secret-2026';
  return crypto.createHmac('sha256', base).update('infinitepay-webhook-v1').digest('hex').slice(0, 48);
}

function segredoConfere(recebido){
  if(!recebido || typeof recebido !== 'string') return false;
  const a = crypto.createHash('sha256').update(recebido).digest();
  const b = crypto.createHash('sha256').update(segredoWebhook()).digest();
  return crypto.timingSafeEqual(a, b);
}

// Endereço completo do webhook, já com o segredo. baseUrl = endereço público do sistema.
function urlWebhook(baseUrl, caminho){
  return String(baseUrl).replace(/\/+$/, '') + caminho + '?s=' + segredoWebhook();
}

async function chamar(url, corpo){
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try{
    const resp = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(corpo), signal: ctrl.signal
    });
    const texto = await resp.text();
    let data = null;
    try{ data = JSON.parse(texto); }catch(e){ /* resposta não-JSON */ }
    return { ok: resp.ok, status: resp.status, data, texto };
  }catch(e){
    if(e.name === 'AbortError') throw new Error('A InfinitePay demorou demais para responder.');
    throw e;
  }finally{
    clearTimeout(timer);
  }
}

const centavos = (valor) => Math.round(parseFloat(valor) * 100);

// itens: [{ descricao, subtotal }] — a soma TEM que bater com o total do pedido (senão o cliente pagaria valor
// diferente do combinado): se não bater, cai numa linha única com o total exato.
function montarItens(itens, totalCentavos, numero){
  const linhas = (itens || []).map(i => ({
    quantity: 1, price: centavos(i.subtotal), description: String(i.descricao || 'Item').slice(0, 120)
  }));
  const soma = linhas.reduce((s, l) => s + l.price, 0);
  const validas = linhas.length > 0 && linhas.every(l => Number.isInteger(l.price) && l.price > 0);
  if(validas && soma === totalCentavos) return linhas;
  return [{ quantity: 1, price: totalCentavos, description: ('Pedido ' + numero + ' — ALMARE').slice(0, 120) }];
}

function telefoneE164(fone){
  const d = String(fone || '').replace(/\D/g, '');
  if(d.length === 10 || d.length === 11) return '+55' + d;
  if((d.length === 12 || d.length === 13) && d.startsWith('55')) return '+' + d;
  return null;
}

// Cria o link de pagamento. Devolve { url }.
async function criarLinkCheckout({ orderNsu, numero, total, itens, cliente, redirectUrl, webhookUrl }){
  const totalCentavos = centavos(total);
  if(!Number.isInteger(totalCentavos) || totalCentavos <= 0) throw new Error('Total do pedido inválido.');
  const corpo = {
    handle: handle(),
    order_nsu: String(orderNsu),
    redirect_url: redirectUrl,
    webhook_url: webhookUrl,
    items: montarItens(itens, totalCentavos, numero)
  };
  if(cliente && (cliente.nome || cliente.email)){
    corpo.customer = {};
    if(cliente.nome) corpo.customer.name = cliente.nome;
    if(cliente.email) corpo.customer.email = cliente.email;
    const tel = telefoneE164(cliente.fone);
    if(tel) corpo.customer.phone_number = tel;
  }
  const r = await chamar(API_LINKS, corpo);
  const url = r.data && (r.data.url || r.data.checkout_url || r.data.link);
  if(!r.ok || !url){
    const detalhe = (r.data && (r.data.message || r.data.error)) || r.texto || 'sem detalhe';
    throw new Error('A InfinitePay recusou criar o pagamento (HTTP ' + r.status + '): ' + String(detalhe).slice(0, 300));
  }
  return { url };
}

// Confere na InfinitePay se o pagamento realmente aconteceu. Valores em centavos.
async function verificarPagamento({ orderNsu, transactionNsu, slug }){
  const r = await chamar(API_CHECK, {
    handle: handle(), order_nsu: String(orderNsu), transaction_nsu: String(transactionNsu), slug: String(slug)
  });
  if(!r.ok || !r.data) throw new Error('Falha ao consultar o pagamento na InfinitePay (HTTP ' + r.status + ').');
  return {
    pago: r.data.paid === true,
    valor: Number(r.data.amount),
    valorPago: r.data.paid_amount != null ? Number(r.data.paid_amount) : null,
    parcelas: r.data.installments != null ? Number(r.data.installments) : null,
    metodo: r.data.capture_method || null
  };
}

// capture_method da InfinitePay -> 'PIX' | 'CARTAO'
function mapearMetodo(captureMethod){
  const m = String(captureMethod || '').toLowerCase();
  if(m === 'pix') return 'PIX';
  if(m.includes('credit') || m.includes('debit') || m.includes('card') || m.includes('cart')) return 'CARTAO';
  return null;
}

module.exports = {
  criarLinkCheckout, verificarPagamento, mapearMetodo, segredoConfere, urlWebhook, centavos,
  configurado: () => !!(process.env.INFINITEPAY_HANDLE || '').trim()
};
