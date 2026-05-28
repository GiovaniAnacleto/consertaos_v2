<?php
// politica.php — Página pública da Política de Privacidade (LGPD)
$api_base = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST']
          . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/api.php';
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="robots" content="noindex"/>
  <title>Política de Privacidade</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;padding:24px 16px;color:#222;line-height:1.55}
    .card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.10);max-width:820px;margin:0 auto;overflow:hidden}
    .hdr{background:#1a3a5c;padding:22px 28px;color:#fff}
    .hdr h1{font-size:22px;font-weight:800}
    .hdr p{font-size:13px;opacity:.75;margin-top:4px}
    .body{padding:28px}
    .body h2{font-size:16px;margin:18px 0 8px;color:#1a3a5c}
    .body p, .body li{font-size:14px;margin-bottom:8px}
    .body ul{padding-left:22px}
    .meta{font-size:12px;color:#888;margin-bottom:18px;border-bottom:1px solid #f0f0f0;padding-bottom:10px}
    .dpo{background:#f8fafc;border-left:4px solid #1a3a5c;padding:12px 16px;border-radius:6px;margin-top:18px;font-size:13px}
    .dpo strong{display:block;color:#1a3a5c;margin-bottom:4px}
    .empty{padding:60px 20px;text-align:center;color:#888}
    .spinner{width:32px;height:32px;border:4px solid #e0e0e0;border-top-color:#1a3a5c;border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 14px}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="card">
    <div class="hdr">
      <h1>Política de Privacidade</h1>
      <p>Tratamento de dados pessoais — Lei nº 13.709/2018 (LGPD)</p>
    </div>
    <div class="body" id="conteudo">
      <div class="empty"><div class="spinner"></div>Carregando política...</div>
    </div>
  </div>

<script>
const API = <?= json_encode($api_base) ?>;
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}
fetch(API + '?resource=lgpd&action=politica_ativa').then(r=>r.json()).then(j=>{
  const div = document.getElementById('conteudo');
  const p = j.politica;
  const e = j.empresa || {};
  if (!p) {
    div.innerHTML = '<div class="empty"><p style="font-size:38px;margin-bottom:8px">📄</p><p>A política de privacidade ainda não foi publicada.</p></div>';
    return;
  }
  let html = '';
  html += '<div class="meta">Versão <strong>' + esc(p.versao) + '</strong> · publicada em ' + esc((p.data_criacao||'').substring(0,10)) + '</div>';
  // Conteúdo é texto simples; converte quebras de linha em parágrafos
  const blocks = String(p.conteudo).split(/\n{2,}/);
  blocks.forEach(b => {
    const trimmed = b.trim();
    if (!trimmed) return;
    if (/^#\s/.test(trimmed)) {
      html += '<h2>' + esc(trimmed.replace(/^#\s/,'')) + '</h2>';
    } else {
      html += '<p>' + esc(trimmed).replace(/\n/g,'<br/>') + '</p>';
    }
  });
  if (e.dpo_nome || e.dpo_email || e.dpo_telefone) {
    html += '<div class="dpo"><strong>Encarregado pelo Tratamento de Dados (DPO)</strong>';
    if (e.dpo_nome)     html += 'Nome: ' + esc(e.dpo_nome) + '<br/>';
    if (e.dpo_email)    html += 'E-mail: <a href="mailto:' + esc(e.dpo_email) + '">' + esc(e.dpo_email) + '</a><br/>';
    if (e.dpo_telefone) html += 'Telefone: ' + esc(e.dpo_telefone);
    html += '</div>';
  }
  div.innerHTML = html;
}).catch(()=>{
  document.getElementById('conteudo').innerHTML = '<div class="empty">Falha ao carregar a política.</div>';
});
</script>
</body>
</html>
