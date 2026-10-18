// Conexão do Instagram da ALMARE (@galeriaalmare) no painel admin do Círculo.
// O token é colado uma vez no /admin/instagram, fica guardado só no banco (nunca volta para a tela)
// e é renovado sozinho antes de vencer (o token do Instagram dura 60 dias).
const IG = 'https://graph.instagram.com';

module.exports = function montar(app, { pool, authAdmin, html, esc }) {
  async function garantirTabela() {
    await pool.query(`CREATE TABLE IF NOT EXISTS almare_instagram_config (
      chave VARCHAR(40) PRIMARY KEY,
      valor TEXT,
      atualizado_em TIMESTAMP DEFAULT NOW()
    )`);
  }
  async function cfg(chave) {
    const r = await pool.query('SELECT valor, atualizado_em FROM almare_instagram_config WHERE chave=$1', [chave]);
    return r.rows.length ? r.rows[0] : null;
  }
  async function setCfg(chave, valor) {
    if (valor == null) { await pool.query('DELETE FROM almare_instagram_config WHERE chave=$1', [chave]); return; }
    await pool.query(
      `INSERT INTO almare_instagram_config (chave, valor, atualizado_em) VALUES ($1,$2,NOW())
       ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor, atualizado_em=NOW()`, [chave, String(valor)]);
  }

  // usado pelo futuro publicador de posts: devolve { token, userId, usuario } ou null
  async function conexao() {
    const t = await cfg('token');
    if (!t || !t.valor) return null;
    const u = await cfg('usuario'); const i = await cfg('user_id');
    return { token: t.valor, usuario: u && u.valor, userId: i && i.valor };
  }

  async function renovar() {
    try {
      await garantirTabela();
      const t = await cfg('token');
      if (!t || !t.valor) return;
      const idadeDias = (Date.now() - new Date(t.atualizado_em).getTime()) / 86400000;
      if (idadeDias < 20) return;
      const r = await fetch(IG + '/refresh_access_token?grant_type=ig_refresh_token&access_token=' + encodeURIComponent(t.valor));
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.access_token) { await setCfg('token', j.access_token); await setCfg('erro', null); console.log('[IG-ALMARE] token renovado'); }
      else { await setCfg('erro', JSON.stringify(j.error || j).slice(0, 300)); console.error('[IG-ALMARE] renovar token:', JSON.stringify(j.error || j)); }
    } catch (e) { console.error('[IG-ALMARE] renovar token:', e.message); }
  }

  app.get('/admin/instagram', authAdmin, async (req, res) => {
    await garantirTabela();
    const c = await conexao();
    const erro = await cfg('erro');
    const quando = await cfg('token');
    const fmt = (d) => d ? new Date(d).toLocaleDateString('pt-BR') : '';
    const msg = req.query.ok ? `<div class="card" style="margin-bottom:20px;background:rgba(0,255,150,0.06);">${esc(req.query.ok)}</div>`
      : req.query.erro ? `<div class="msg-erro" style="margin-bottom:20px;">${esc(req.query.erro)}</div>` : '';
    res.send(html('Instagram da ALMARE', `
      <a href="/admin" style="font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);">← Voltar ao admin</a>
      <h2 style="font-size:24px;margin:20px 0 24px;">Instagram da ALMARE</h2>
      ${msg}
      <div class="card" style="margin-bottom:24px;">
        <strong>Conexão</strong><br>
        ${c
          ? `<span style="font-size:13px;color:#7fd8a0">✓ Conectado: @${esc(c.usuario || '')}</span><br>
             <span style="font-size:11px;color:var(--muted)">O acesso é renovado sozinho antes de vencer${quando ? ' · token de ' + fmt(quando.atualizado_em) : ''}. Nada é publicado enquanto você não ligar a publicação.</span>
             ${erro ? `<br><span style="font-size:11px;color:#ff8a8a">Não consegui renovar a conexão (${esc(erro.valor)}). Gere um token novo e cole abaixo.</span>` : ''}`
          : `<span style="font-size:13px;color:var(--muted)">Não conectado.</span>`}
      </div>
      <div class="card" style="margin-bottom:24px;">
        <strong>${c ? 'Trocar o token' : 'Conectar o Instagram'}</strong>
        <p style="font-size:12px;color:var(--muted);margin:8px 0 16px;">Cole o token gerado na Meta para a conta @galeriaalmare. Ele fica guardado só no servidor e não aparece de novo nesta tela.</p>
        <form method="POST" action="/admin/instagram/conectar" autocomplete="off">
          <div class="field"><label>Token do Instagram</label><input type="password" name="token" required autocomplete="off"></div>
          <button type="submit" class="btn btn-primary">Conectar</button>
        </form>
        ${c ? `<form method="POST" action="/admin/instagram/desconectar" style="margin-top:16px" onsubmit="return confirm('Desconectar o Instagram da ALMARE?')"><button type="submit" class="btn btn-outline" style="padding:8px 16px;font-size:11px;">Desconectar</button></form>` : ''}
      </div>
    `));
  });

  app.post('/admin/instagram/conectar', authAdmin, async (req, res) => {
    try {
      await garantirTabela();
      const tk = String((req.body && req.body.token) || '').trim().replace(/\s+/g, '');
      if (tk.length < 40) return res.redirect('/admin/instagram?erro=' + encodeURIComponent('Token muito curto. Cole o código inteiro.'));
      const r = await fetch(IG + '/v21.0/me?fields=user_id,username,account_type&access_token=' + encodeURIComponent(tk));
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.username) return res.redirect('/admin/instagram?erro=' + encodeURIComponent('O Instagram não aceitou esse token: ' + ((j.error && j.error.message) || 'erro desconhecido')));
      await setCfg('token', tk);
      await setCfg('usuario', j.username + (j.account_type ? ' (' + j.account_type + ')' : ''));
      if (j.user_id) await setCfg('user_id', j.user_id);
      await setCfg('erro', null);
      res.redirect('/admin/instagram?ok=' + encodeURIComponent('Conectado como @' + j.username + '.'));
    } catch (e) { res.redirect('/admin/instagram?erro=' + encodeURIComponent(e.message)); }
  });

  app.post('/admin/instagram/desconectar', authAdmin, async (req, res) => {
    await garantirTabela();
    for (const k of ['token', 'usuario', 'user_id', 'erro']) await setCfg(k, null);
    res.redirect('/admin/instagram?ok=' + encodeURIComponent('Instagram desconectado.'));
  });

  garantirTabela().catch((e) => console.error('[IG-ALMARE] tabela:', e.message));
  setTimeout(renovar, 3 * 60 * 1000);
  setInterval(renovar, 24 * 60 * 60 * 1000);

  return { conexao };
};
