// Fila de posts e stories do Instagram da ALMARE (@galeriaalmare).
// Fluxo: enviar o pacote (.zip) -> cada peça entra como PENDENTE -> você aprova -> só peças APROVADAS podem sair.
// Nada é publicado sozinho enquanto o "automático" estiver desligado (padrão).
const multer = require('multer');
const AdmZip = require('adm-zip');
const sharp = require('sharp');
const crypto = require('crypto');

const IG = 'https://graph.instagram.com/v21.0';
const PUBLICO = 'https://almare.art.br';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 150 * 1024 * 1024, files: 1 } });
const POR_PAGINA = 36;

module.exports = function montar(app, { pool, authAdmin, html, esc, instagram }) {
  async function garantirTabelas() {
    await pool.query(`CREATE TABLE IF NOT EXISTS almare_posts (
      id SERIAL PRIMARY KEY,
      chave VARCHAR(40) UNIQUE NOT NULL,
      tipo VARCHAR(8) NOT NULL,
      arquivo TEXT NOT NULL,
      obras TEXT, ambiente TEXT,
      legenda TEXT,
      status VARCHAR(12) NOT NULL DEFAULT 'PENDENTE',
      slot_key VARCHAR(60),
      ig_id TEXT, erro TEXT,
      tentativas INTEGER DEFAULT 0,
      criado_em TIMESTAMP DEFAULT NOW(),
      aprovado_em TIMESTAMP, publicado_em TIMESTAMP,
      imagem BYTEA, mini BYTEA
    )`);
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_almare_posts_arquivo ON almare_posts (tipo, arquivo)`);
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_almare_posts_slot ON almare_posts (slot_key) WHERE slot_key IS NOT NULL`);
  }
  const cfgGet = async (k, padrao) => { const r = await pool.query('SELECT valor FROM almare_instagram_config WHERE chave=$1', [k]); return r.rows.length ? r.rows[0].valor : padrao; };
  const cfgSet = async (k, v) => {
    await pool.query(`INSERT INTO almare_instagram_config (chave, valor, atualizado_em) VALUES ($1,$2,NOW())
      ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor, atualizado_em=NOW()`, [k, String(v)]);
  };

  // ---------- publicação ----------
  async function publicarNoInstagram(post, conn) {
    const url = PUBLICO + '/almare-posts/img/' + post.chave + '.jpg';
    const corpo = post.tipo === 'story'
      ? { image_url: url, media_type: 'STORIES', access_token: conn.token }
      : { image_url: url, caption: post.legenda || '', access_token: conn.token };
    const c = await fetch(IG + '/me/media', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(corpo) });
    const cj = await c.json().catch(() => ({}));
    if (!c.ok || !cj.id) throw new Error('criar mídia: ' + JSON.stringify(cj.error || cj).slice(0, 300));
    for (let i = 0; i < 10; i++) {
      const s = await fetch(IG + '/' + cj.id + '?fields=status_code&access_token=' + encodeURIComponent(conn.token));
      const sj = await s.json().catch(() => ({}));
      if (sj.status_code === 'FINISHED') break;
      if (sj.status_code === 'ERROR' || sj.status_code === 'EXPIRED') throw new Error('processamento: ' + sj.status_code);
      await new Promise((r) => setTimeout(r, 3000));
    }
    const p = await fetch(IG + '/me/media_publish', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ creation_id: cj.id, access_token: conn.token }) });
    const pj = await p.json().catch(() => ({}));
    if (!p.ok || !pj.id) throw new Error('publicar: ' + JSON.stringify(pj.error || pj).slice(0, 300));
    return pj.id;
  }

  async function publicar(id, slotKey) {
    const conn = await instagram.conexao();
    if (!conn) return { ok: false, erro: 'Instagram da ALMARE não está conectado.' };
    const lock = await pool.query(
      `UPDATE almare_posts SET status='PUBLICANDO', tentativas=COALESCE(tentativas,0)+1, slot_key=COALESCE($2, slot_key)
       WHERE id=$1 AND status IN ('APROVADO','ERRO') RETURNING id, chave, tipo, legenda`, [id, slotKey || null]);
    if (!lock.rows.length) return { ok: false, erro: 'A peça precisa estar APROVADA para publicar.' };
    try {
      const igId = await publicarNoInstagram(lock.rows[0], conn);
      await pool.query(`UPDATE almare_posts SET status='PUBLICADO', ig_id=$2, erro=NULL, publicado_em=NOW() WHERE id=$1`, [id, igId]);
      console.log('[IG-ALMARE] publicado', id, igId);
      return { ok: true };
    } catch (e) {
      await pool.query(`UPDATE almare_posts SET status='ERRO', erro=$2 WHERE id=$1`, [id, String(e.message).slice(0, 500)]);
      console.error('[IG-ALMARE] publicar', id, e.message);
      return { ok: false, erro: e.message };
    }
  }

  // ---------- automático (desligado por padrão) ----------
  function agoraBR() {
    const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(new Date());
    const g = (t) => p.find((x) => x.type === t).value;
    return { dia: g('year') + '-' + g('month') + '-' + g('day'), min: (parseInt(g('hour'), 10) % 24) * 60 + parseInt(g('minute'), 10) };
  }
  async function tickAutomatico() {
    try {
      await garantirTabelas();
      if ((await cfgGet('auto', 'nao')) !== 'sim') return;
      if (!(await instagram.conexao())) return;
      const { dia, min } = agoraBR();
      for (const tipo of ['feed', 'story']) {
        const slots = String(await cfgGet('slots_' + tipo, tipo === 'feed' ? '12:00' : '09:00,19:00')).split(',').map((s) => s.trim()).filter((s) => /^\d{1,2}:\d{2}$/.test(s));
        for (const slot of slots) {
          const [h, m] = slot.split(':').map(Number);
          const ini = h * 60 + m;
          if (min < ini || min - ini > 180) continue; // janela de 3 h depois do horário
          const chave = dia + ' ' + slot + ' ' + tipo;
          const ja = await pool.query('SELECT 1 FROM almare_posts WHERE slot_key=$1', [chave]);
          if (ja.rows.length) continue;
          const prox = await pool.query(`SELECT id FROM almare_posts WHERE tipo=$1 AND status='APROVADO' ORDER BY id LIMIT 1`, [tipo]);
          if (!prox.rows.length) continue;
          await publicar(prox.rows[0].id, chave);
        }
      }
    } catch (e) { console.error('[IG-ALMARE] automático:', e.message); }
  }

  // ---------- imagens ----------
  app.get('/almare-posts/img/:chave.jpg', async (req, res) => { // público: o Instagram precisa baixar
    const r = await pool.query(`SELECT imagem FROM almare_posts WHERE chave=$1 AND status IN ('APROVADO','PUBLICANDO','PUBLICADO','ERRO')`, [req.params.chave]);
    if (!r.rows.length || !r.rows[0].imagem) return res.status(404).end();
    res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'public, max-age=3600').send(r.rows[0].imagem);
  });
  app.get('/admin/instagram/fila/mini/:id.jpg', authAdmin, async (req, res) => {
    const r = await pool.query('SELECT mini FROM almare_posts WHERE id=$1', [parseInt(req.params.id, 10) || 0]);
    if (!r.rows.length) return res.status(404).end();
    res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'private, max-age=86400').send(r.rows[0].mini);
  });
  app.get('/admin/instagram/fila/img/:id.jpg', authAdmin, async (req, res) => {
    const r = await pool.query('SELECT imagem FROM almare_posts WHERE id=$1', [parseInt(req.params.id, 10) || 0]);
    if (!r.rows.length) return res.status(404).end();
    res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'private, max-age=86400').send(r.rows[0].imagem);
  });

  // ---------- telas ----------
  const ROT = { PENDENTE: ['Aguardando aprovação', '#c98a0a'], APROVADO: ['Aprovado', '#1e7a45'], PUBLICANDO: ['Publicando…', '#c98a0a'], PUBLICADO: ['Publicado', '#2a6fb0'], ERRO: ['Erro', '#c9463c'], REJEITADO: ['Rejeitado', '#6b6c71'] };
  const voltaPara = (req) => { const v = String((req.body && req.body.volta) || ''); return v.indexOf('/admin/instagram/fila') === 0 ? v : '/admin/instagram/fila'; };

  app.get('/admin/instagram/fila', authAdmin, async (req, res) => {
    await garantirTabelas();
    const tipo = ['feed', 'story'].includes(req.query.tipo) ? req.query.tipo : '';
    const status = ROT[req.query.status] ? req.query.status : '';
    const q = String(req.query.q || '').trim().slice(0, 60);
    const pagina = Math.max(1, parseInt(req.query.p, 10) || 1);
    const where = []; const pr = [];
    if (tipo) { pr.push(tipo); where.push('tipo=$' + pr.length); }
    if (status) { pr.push(status); where.push('status=$' + pr.length); }
    if (q) { pr.push('%' + q.toLowerCase() + '%'); where.push('(LOWER(legenda) LIKE $' + pr.length + ' OR LOWER(obras) LIKE $' + pr.length + ' OR LOWER(arquivo) LIKE $' + pr.length + ')'); }
    const W = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = (await pool.query('SELECT COUNT(*)::int n FROM almare_posts ' + W, pr)).rows[0].n;
    const lista = await pool.query(`SELECT id, tipo, arquivo, obras, ambiente, status, erro FROM almare_posts ${W} ORDER BY id LIMIT ${POR_PAGINA} OFFSET ${(pagina - 1) * POR_PAGINA}`, pr);
    const cont = {}; (await pool.query('SELECT tipo, status, COUNT(*)::int n FROM almare_posts GROUP BY 1,2')).rows.forEach((r) => { cont[r.tipo + '|' + r.status] = r.n; });
    const soma = (t, s) => cont[t + '|' + s] || 0;
    const conn = await instagram.conexao();
    const auto = (await cfgGet('auto', 'nao')) === 'sim';
    const slotsFeed = await cfgGet('slots_feed', '12:00');
    const slotsStory = await cfgGet('slots_story', '09:00,19:00');
    const base = '/admin/instagram/fila?tipo=' + tipo + '&status=' + status + '&q=' + encodeURIComponent(q);
    const aqui = base + '&p=' + pagina;
    const paginas = Math.max(1, Math.ceil(total / POR_PAGINA));
    const msg = req.query.ok ? `<div class="card" style="margin-bottom:16px;background:rgba(0,255,150,0.06);">${esc(req.query.ok)}</div>` : req.query.erro ? `<div class="msg-erro" style="margin-bottom:16px;">${esc(req.query.erro)}</div>` : '';
    const cards = lista.rows.map((p) => {
      const [rot, cor] = ROT[p.status];
      const btn = (acao, txt, estilo) => `<button type="submit" form="lote" formaction="/admin/instagram/fila/${p.id}/${acao}" class="btn ${estilo || 'btn-outline'}" style="padding:4px 10px;font-size:10px;">${txt}</button>`;
      return `<label style="display:block;border:1px solid var(--border);border-radius:10px;padding:8px;position:relative;cursor:pointer;">
        <input type="checkbox" class="sel" name="ids" value="${p.id}" form="lote" style="position:absolute;top:14px;left:14px;width:22px;height:22px;z-index:2;accent-color:#c9a45c;">
        <a href="/admin/instagram/fila/${p.id}"><img loading="lazy" src="/admin/instagram/fila/mini/${p.id}.jpg" alt="" style="width:100%;aspect-ratio:${p.tipo === 'story' ? '9/16' : '4/5'};object-fit:cover;border-radius:6px;display:block;"></a>
        <div style="font-size:11px;margin-top:6px;"><b style="color:${cor}">${rot}</b> · ${p.tipo === 'story' ? 'story' : 'feed'} · obra ${esc(p.obras || '')} · ${esc(p.ambiente || '')}</div>
        ${p.erro ? `<div style="font-size:10px;color:#ff8a8a;">${esc(p.erro).slice(0, 120)}</div>` : ''}
        <div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap;">
          ${p.status === 'PENDENTE' ? btn('aprovar', 'Aprovar', 'btn-primary') + btn('rejeitar', 'Rejeitar') : ''}
          ${['APROVADO', 'REJEITADO', 'ERRO'].includes(p.status) ? btn('pendente', 'Desfazer') : ''}
        </div></label>`;
    }).join('');
    const nums = []; for (let i = 1; i <= paginas; i++) if (i === 1 || i === paginas || Math.abs(i - pagina) <= 2) nums.push(i);
    const pager = paginas > 1 ? `<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:16px 0;">
      ${pagina > 1 ? `<a class="btn btn-outline" style="padding:6px 12px;font-size:11px;" href="${base}&p=${pagina - 1}">← Anterior</a>` : ''}
      ${nums.map((n, i) => (i && n - nums[i - 1] > 1 ? '<span>…</span>' : '') + `<a href="${base}&p=${n}" style="min-width:34px;text-align:center;padding:6px 8px;border:1px solid var(--border);border-radius:6px;${n === pagina ? 'background:var(--gold);color:#000;font-weight:700;' : ''}">${n}</a>`).join('')}
      ${pagina < paginas ? `<a class="btn btn-outline" style="padding:6px 12px;font-size:11px;" href="${base}&p=${pagina + 1}">Próxima →</a>` : ''}
      <form method="GET" action="/admin/instagram/fila" style="display:inline-flex;gap:4px;margin-left:8px;"><input type="hidden" name="tipo" value="${tipo}"><input type="hidden" name="status" value="${status}"><input type="hidden" name="q" value="${esc(q)}"><input name="p" type="number" min="1" max="${paginas}" placeholder="ir p/ pág." style="width:90px;padding:6px;"><button class="btn btn-outline" style="padding:6px 10px;font-size:11px;">Ir</button></form>
    </div>` : '';
    const filtroLink = (t, s, txt) => `<a href="/admin/instagram/fila?tipo=${t}&status=${s}" style="padding:4px 10px;border:1px solid var(--border);border-radius:14px;font-size:12px;${(t === tipo && s === status) ? 'background:var(--gold);color:#000;font-weight:700;' : ''}">${txt}</a>`;
    res.send(html('Fila de posts da ALMARE', `
      <a href="/admin/instagram" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">← Instagram da ALMARE</a>
      <h2 style="font-size:24px;margin:20px 0 16px;">Fila de posts e stories</h2>
      ${msg}
      <div class="card" style="margin-bottom:16px;">
        <div style="display:flex;gap:18px;flex-wrap:wrap;font-size:13px;">
          <div><b>Feed:</b> ${soma('feed', 'PENDENTE')} aguardando · ${soma('feed', 'APROVADO')} aprovados · ${soma('feed', 'PUBLICADO')} publicados</div>
          <div><b>Stories:</b> ${soma('story', 'PENDENTE')} aguardando · ${soma('story', 'APROVADO')} aprovados · ${soma('story', 'PUBLICADO')} publicados</div>
        </div>
        <div style="font-size:12px;margin-top:8px;color:${conn ? '#7fd8a0' : '#ff8a8a'};">${conn ? 'Instagram conectado: @' + esc(conn.usuario || '') : 'Instagram NÃO conectado'}</div>
      </div>
      <div class="card" style="margin-bottom:16px;">
        <strong>Publicação automática: ${auto ? '<span style="color:#7fd8a0">LIGADA</span>' : '<span style="color:var(--muted)">desligada</span>'}</strong>
        <p style="font-size:12px;color:var(--muted);margin:6px 0 12px;">Ligada, o sistema publica sozinho só as peças <b>aprovadas</b>, na ordem, nos horários abaixo (Brasília). Desligada, nada sai sem você clicar em Publicar.</p>
        <form method="POST" action="/admin/instagram/fila/config" style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">
          <div class="field" style="margin:0"><label>Horários do feed</label><input name="slots_feed" value="${esc(slotsFeed)}" style="width:150px"></div>
          <div class="field" style="margin:0"><label>Horários dos stories</label><input name="slots_story" value="${esc(slotsStory)}" style="width:190px"></div>
          <select name="auto" style="padding:10px;"><option value="nao" ${auto ? '' : 'selected'}>Automático desligado</option><option value="sim" ${auto ? 'selected' : ''}>Automático ligado</option></select>
          <button class="btn btn-primary" style="padding:10px 16px;font-size:11px;">Salvar</button>
        </form>
      </div>
      <div class="card" style="margin-bottom:16px;">
        <strong>Enviar pacote de posts</strong>
        <form method="POST" action="/admin/instagram/fila/enviar" enctype="multipart/form-data" style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
          <input type="file" name="zip" accept=".zip" required>
          <label style="font-size:12px;display:flex;gap:6px;align-items:center;"><input type="checkbox" name="limpar" value="sim" style="width:18px;height:18px;"> Antes de importar, tirar da fila tudo que ainda não foi publicado</label>
          <button class="btn btn-outline" style="padding:8px 14px;font-size:11px;" onclick="var c=this.form.limpar.checked;return !c||confirm('Isso remove da fila todas as peças não publicadas (aprovadas, aguardando e rejeitadas) antes de importar o pacote novo. Continuar?')">Enviar</button>
        </form>
        <p style="font-size:11px;color:var(--muted);margin-top:6px;">Peças que já estão na fila não são duplicadas. Todas entram como "aguardando aprovação".</p>
      </div>
      <form method="GET" action="/admin/instagram/fila" style="display:flex;gap:8px;margin-bottom:12px;">
        <input type="hidden" name="tipo" value="${tipo}"><input type="hidden" name="status" value="${status}">
        <input name="q" value="${esc(q)}" placeholder="Buscar por número da obra, nome ou texto da legenda" style="flex:1;padding:10px;">
        <button class="btn btn-outline" style="padding:8px 14px;font-size:11px;">Buscar</button>
      </form>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;">
        ${filtroLink('', '', 'Todos')} ${filtroLink('feed', '', 'Feed')} ${filtroLink('story', '', 'Stories')}
        ${filtroLink('', 'PENDENTE', 'Aguardando')} ${filtroLink('', 'APROVADO', 'Aprovados')} ${filtroLink('', 'PUBLICADO', 'Publicados')} ${filtroLink('', 'ERRO', 'Com erro')} ${filtroLink('', 'REJEITADO', 'Rejeitados')}
      </div>
      <form id="lote" method="POST" action="/admin/instagram/fila/lote/aprovar"><input type="hidden" name="volta" value="${esc(aqui)}"></form>
      <div style="position:sticky;top:0;z-index:5;background:var(--bg,#111);padding:10px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--border);">
        <label style="font-size:13px;display:flex;gap:6px;align-items:center;cursor:pointer;"><input type="checkbox" id="todos" style="width:20px;height:20px;accent-color:#c9a45c;"> Marcar todas desta página</label>
        <span id="cont" style="font-size:12px;color:var(--muted);">0 marcadas</span>
        <button type="submit" form="lote" formaction="/admin/instagram/fila/lote/aprovar" class="btn btn-primary" style="padding:8px 14px;font-size:11px;">Aprovar marcadas</button>
        <button type="submit" form="lote" formaction="/admin/instagram/fila/lote/pendente" class="btn btn-outline" style="padding:8px 14px;font-size:11px;">Voltar marcadas p/ aguardando</button>
        <button type="submit" form="lote" formaction="/admin/instagram/fila/lote/rejeitar" class="btn btn-outline" style="padding:8px 14px;font-size:11px;">Rejeitar marcadas</button>
        <button type="submit" form="lote" formaction="/admin/instagram/fila/desfazer-todas" class="btn btn-outline" style="padding:8px 14px;font-size:11px;margin-left:auto;" onclick="return confirm('Voltar TODAS as peças aprovadas (ainda não publicadas) para aguardando?')">Desfazer todas as aprovações</button>
      </div>
      <div style="font-size:12px;color:var(--muted);margin:10px 0;">${total} peça(s)${paginas > 1 ? ' · página ' + pagina + ' de ' + paginas : ''}</div>
      ${pager}
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;">${cards || '<span style="color:var(--muted)">Nenhuma peça.</span>'}</div>
      ${pager}
      <script>
        var bx=[].slice.call(document.querySelectorAll('.sel')),ct=document.getElementById('cont');
        function atu(){ct.textContent=bx.filter(function(b){return b.checked}).length+' marcadas'}
        bx.forEach(function(b){b.addEventListener('change',atu)});
        document.getElementById('todos').addEventListener('change',function(e){bx.forEach(function(b){b.checked=e.target.checked});atu()});
      </script>
    `));
  });

  app.get('/admin/instagram/fila/:id', authAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.redirect('/admin/instagram/fila');
    const r = await pool.query('SELECT id, tipo, arquivo, obras, ambiente, legenda, status, erro, ig_id, tentativas FROM almare_posts WHERE id=$1', [id]);
    if (!r.rows.length) return res.redirect('/admin/instagram/fila');
    const p = r.rows[0]; const [rot, cor] = ROT[p.status];
    const aqui = '/admin/instagram/fila/' + p.id;
    const f = (acao, txt, estilo, conf) => `<form method="POST" action="/admin/instagram/fila/${p.id}/${acao}" style="display:inline" ${conf ? `onsubmit="return confirm('${conf}')"` : ''}><input type="hidden" name="volta" value="${aqui}"><button class="btn ${estilo || 'btn-outline'}" style="padding:8px 14px;font-size:11px;">${txt}</button></form>`;
    res.send(html('Peça da fila', `
      <a href="/admin/instagram/fila" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">← Voltar à fila</a>
      <div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:20px;">
        <img src="/admin/instagram/fila/img/${p.id}.jpg" alt="" style="width:340px;max-width:100%;border-radius:8px;align-self:flex-start;">
        <div style="flex:1;min-width:280px;">
          <div style="font-size:13px;margin-bottom:8px;"><b style="color:${cor}">${rot}</b> · ${p.tipo === 'story' ? 'story' : 'feed'} · obra ${esc(p.obras || '')} · ${esc(p.ambiente || '')}</div>
          ${p.erro ? `<div class="msg-erro" style="margin-bottom:10px;">${esc(p.erro)}</div>` : ''}
          ${p.tipo === 'story' ? '<p style="font-size:12px;color:var(--muted);">Stories não levam legenda.</p>' : `
          <form method="POST" action="/admin/instagram/fila/${p.id}/legenda">
            <div class="field"><label>Legenda do post</label><textarea name="legenda" rows="9" maxlength="2200" style="width:100%;">${esc(p.legenda || '')}</textarea></div>
            <button class="btn btn-outline" style="padding:8px 14px;font-size:11px;">Salvar legenda</button>
          </form>`}
          <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap;">
            ${p.status === 'PENDENTE' ? f('aprovar', 'Aprovar', 'btn-primary') + f('rejeitar', 'Rejeitar') : ''}
            ${['APROVADO', 'REJEITADO', 'ERRO'].includes(p.status) ? f('pendente', 'Voltar para aguardando') : ''}
            ${['APROVADO', 'ERRO'].includes(p.status) ? f('publicar', 'Publicar agora', 'btn-primary', 'Publicar agora no Instagram da ALMARE?') : ''}
          </div>
          ${p.ig_id ? `<p style="font-size:11px;color:var(--muted);margin-top:12px;">Publicado (id ${esc(p.ig_id)}).</p>` : ''}
        </div>
      </div>
    `));
  });

  const mudar = (de, para) => async (req, res) => {
    const id = parseInt(req.params.id, 10) || 0;
    await pool.query(`UPDATE almare_posts SET status=$2, aprovado_em=${para === 'APROVADO' ? 'NOW()' : 'NULL'}, erro=NULL WHERE id=$1 AND status = ANY($3)`, [id, para, de]);
    res.redirect(voltaPara(req));
  };
  const ACOES = { aprovar: [['PENDENTE'], 'APROVADO'], rejeitar: [['PENDENTE'], 'REJEITADO'], pendente: [['APROVADO', 'REJEITADO', 'ERRO'], 'PENDENTE'] };
  app.post('/admin/instagram/fila/lote/:acao', authAdmin, async (req, res) => {
    const ac = ACOES[req.params.acao];
    const ids = [].concat((req.body && req.body.ids) || []).map((x) => parseInt(x, 10)).filter(Boolean);
    let n = 0;
    if (ac && ids.length) n = (await pool.query(`UPDATE almare_posts SET status=$2, aprovado_em=${ac[1] === 'APROVADO' ? 'NOW()' : 'NULL'}, erro=NULL WHERE id = ANY($1) AND status = ANY($3)`, [ids, ac[1], ac[0]])).rowCount;
    const v = voltaPara(req);
    res.redirect(v + (v.includes('?') ? '&' : '?') + 'ok=' + encodeURIComponent(ids.length ? n + ' peça(s) atualizada(s).' : 'Nenhuma peça marcada.'));
  });
  app.post('/admin/instagram/fila/desfazer-todas', authAdmin, async (req, res) => {
    const r = await pool.query(`UPDATE almare_posts SET status='PENDENTE', aprovado_em=NULL WHERE status='APROVADO'`);
    res.redirect('/admin/instagram/fila?ok=' + encodeURIComponent(r.rowCount + ' aprovação(ões) desfeita(s).'));
  });
  app.post('/admin/instagram/fila/:id/aprovar', authAdmin, mudar(['PENDENTE'], 'APROVADO'));
  app.post('/admin/instagram/fila/:id/rejeitar', authAdmin, mudar(['PENDENTE'], 'REJEITADO'));
  app.post('/admin/instagram/fila/:id/pendente', authAdmin, mudar(['APROVADO', 'REJEITADO', 'ERRO'], 'PENDENTE'));
  app.post('/admin/instagram/fila/:id/legenda', authAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10) || 0;
    await pool.query(`UPDATE almare_posts SET legenda=$2 WHERE id=$1 AND tipo='feed' AND status <> 'PUBLICADO'`, [id, String((req.body && req.body.legenda) || '').slice(0, 2200)]);
    res.redirect('/admin/instagram/fila/' + id);
  });
  app.post('/admin/instagram/fila/:id/publicar', authAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10) || 0;
    const r = await publicar(id);
    res.redirect('/admin/instagram/fila/' + id + '?' + (r.ok ? 'ok=Publicado' : 'erro=' + encodeURIComponent(r.erro)));
  });
  app.post('/admin/instagram/fila/aprovar-todos', authAdmin, async (req, res) => {
    const tipo = ['feed', 'story'].includes(req.body.tipo) ? req.body.tipo : null;
    const q = String(req.body.q || '').trim().toLowerCase();
    const r = await pool.query(
      `UPDATE almare_posts SET status='APROVADO', aprovado_em=NOW() WHERE status='PENDENTE' AND ($1::text IS NULL OR tipo=$1)
       AND ($2 = '' OR LOWER(legenda) LIKE '%'||$2||'%' OR LOWER(obras) LIKE '%'||$2||'%' OR LOWER(arquivo) LIKE '%'||$2||'%')`, [tipo, q]);
    res.redirect('/admin/instagram/fila?ok=' + encodeURIComponent(r.rowCount + ' peça(s) aprovada(s).'));
  });
  app.post('/admin/instagram/fila/config', authAdmin, async (req, res) => {
    const ok = (s) => String(s || '').split(',').map((x) => x.trim()).filter((x) => /^\d{1,2}:\d{2}$/.test(x)).join(',');
    await cfgSet('slots_feed', ok(req.body.slots_feed) || '12:00');
    await cfgSet('slots_story', ok(req.body.slots_story) || '09:00,19:00');
    await cfgSet('auto', req.body.auto === 'sim' ? 'sim' : 'nao');
    res.redirect('/admin/instagram/fila?ok=' + encodeURIComponent('Configuração salva.'));
  });

  app.post('/admin/instagram/fila/enviar', authAdmin, upload.single('zip'), async (req, res) => {
    try {
      await garantirTabelas();
      if (!req.file) throw new Error('Escolha o arquivo .zip.');
      const zip = new AdmZip(req.file.buffer);
      if (req.body && req.body.limpar === 'sim') await pool.query(`DELETE FROM almare_posts WHERE status <> 'PUBLICADO'`);
      const entradas = {}; zip.getEntries().forEach((e) => { if (!e.isDirectory) entradas[e.entryName] = e; });
      const lj = entradas['legendas.json'];
      if (!lj) throw new Error('O pacote não tem o arquivo legendas.json.');
      const meta = JSON.parse(lj.getData().toString('utf8'));
      let novos = 0, ja = 0;
      for (const m of meta) {
        for (const [tipo, pasta] of [['feed', 'posts/'], ['story', 'stories/']]) {
          const e = entradas[pasta + m.arquivo];
          if (!e) continue;
          const existe = await pool.query('SELECT 1 FROM almare_posts WHERE tipo=$1 AND arquivo=$2', [tipo, m.arquivo]);
          if (existe.rows.length) { ja++; continue; }
          const original = e.getData();
          const imagem = await sharp(original).rotate().jpeg({ quality: 88 }).toBuffer();
          const mini = await sharp(imagem).resize({ width: 360 }).jpeg({ quality: 72 }).toBuffer();
          await pool.query(
            `INSERT INTO almare_posts (chave, tipo, arquivo, obras, ambiente, legenda, imagem, mini) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [crypto.randomBytes(14).toString('hex'), tipo, m.arquivo, (m.obras || []).join(' + '), m.ambiente || '', tipo === 'feed' ? m.legenda : null, imagem, mini]);
          novos++;
        }
      }
      res.redirect('/admin/instagram/fila?ok=' + encodeURIComponent(novos + ' peça(s) enviada(s)' + (ja ? ', ' + ja + ' já estavam na fila' : '') + '.'));
    } catch (e) { res.redirect('/admin/instagram/fila?erro=' + encodeURIComponent(e.message)); }
  });

  garantirTabelas().catch((e) => console.error('[IG-ALMARE] tabelas da fila:', e.message));
  setTimeout(tickAutomatico, 2 * 60 * 1000);
  setInterval(tickAutomatico, 5 * 60 * 1000);
};
