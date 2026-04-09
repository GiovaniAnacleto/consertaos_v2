<?php
// consulta.php — Página pública de acompanhamento de OS pelo cliente
// Deve ficar na mesma pasta que api.php, index.html e upload_mobile.php

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$api_base = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST']
          . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/api.php';
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Consulta de OS #<?= $id ?></title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;padding:24px 16px}
    .card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.10);max-width:520px;margin:0 auto;overflow:hidden}
    .card-header{background:#1a3a5c;padding:22px 24px;color:#fff}
    .card-header h1{font-size:20px;font-weight:800;margin-bottom:2px}
    .card-header p{font-size:13px;opacity:.75}
    .card-body{padding:24px}
    .status-badge{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border-radius:30px;font-size:15px;font-weight:700;margin-bottom:20px}
    .status-aberta   {background:#fff3cd;color:#856404}
    .status-andamento{background:#cfe2ff;color:#084298}
    .status-concluida{background:#d1fae5;color:#065f46}
    .status-cancelada{background:#fee2e2;color:#991b1b}
    .status-aguardando{background:#f3e8ff;color:#6b21a8}
    .status-default  {background:#f0f0f0;color:#444}
    .field{margin-bottom:14px}
    .field label{display:block;font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}
    .field span{font-size:14px;color:#222}
    .divider{height:1px;background:#f0f0f0;margin:16px 0}
    .obs-list{list-style:none}
    .obs-item{padding:10px 14px;background:#f8f9fa;border-radius:8px;margin-bottom:8px;font-size:13px;color:#444;border-left:3px solid #e8711a}
    .obs-item time{display:block;font-size:11px;color:#999;margin-top:3px}
    .empty{text-align:center;padding:40px 20px;color:#aaa}
    .empty svg{width:48px;height:48px;margin-bottom:12px;opacity:.4}
    .logo-area{display:flex;align-items:center;gap:12px;margin-bottom:4px}
    .logo-area img{height:40px;max-width:120px;object-fit:contain;filter:brightness(0) invert(1)}
    .section-title{font-size:12px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;border-bottom:1px solid #f0f0f0;padding-bottom:6px}
    #loading{text-align:center;padding:60px 20px}
    .spinner{width:36px;height:36px;border:4px solid #e8711a33;border-top-color:#e8711a;border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 14px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .not-found{text-align:center;padding:40px 20px;color:#666}
  </style>
</head>
<body>
<?php if (!$id): ?>
  <div class="card">
    <div class="card-body not-found">
      <p style="font-size:40px;margin-bottom:12px">🔍</p>
      <p style="font-weight:700;font-size:16px;margin-bottom:6px">OS não encontrada</p>
      <p style="font-size:13px;color:#aaa">Nenhum número de ordem foi informado.</p>
    </div>
  </div>
<?php else: ?>
  <div class="card" id="card">
    <div id="loading">
      <div class="spinner"></div>
      <p style="color:#888;font-size:14px">Buscando informações...</p>
    </div>
  </div>

  <script>
  const OS_ID = <?= $id ?>;
  const API   = <?= json_encode($api_base) ?>;

  function statusClass(s) {
    s = (s||'').toLowerCase();
    if (s.includes('conclu') || s === 'entregue' || s === 'retirada') return 'status-concluida';
    if (s === 'aberta') return 'status-aberta';
    if (s.includes('cancel') || s.includes('não aprov') || s.includes('sem con')) return 'status-cancelada';
    if (s.includes('aguard') || s.includes('peça') || s.includes('avisar') || s.includes('pronto')) return 'status-aguardando';
    return 'status-andamento';
  }

  function statusIcon(s) {
    s = (s||'').toLowerCase();
    if (s.includes('conclu') || s === 'entregue') return '✅';
    if (s === 'aberta') return '📋';
    if (s.includes('cancel')) return '❌';
    if (s.includes('aguard') || s.includes('pronto')) return '⏳';
    return '🔧';
  }

  function fmt(dt) {
    if (!dt) return '—';
    try {
      const d = new Date(dt.replace(' ','T'));
      return d.toLocaleDateString('pt-BR') + ' ' + d.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
    } catch(e) { return dt; }
  }

  async function load() {
    try {
      const res = await fetch(`${API}?resource=consulta_publica&id=${OS_ID}`);
      const os  = await res.json();
      if (!res.ok || os.error) { renderNotFound(); return; }
      render(os);
    } catch(e) { renderNotFound(); }
  }

  function renderNotFound() {
    document.getElementById('card').innerHTML = `
      <div class="card-body not-found">
        <p style="font-size:40px;margin-bottom:12px">😕</p>
        <p style="font-weight:700;font-size:16px;margin-bottom:6px">OS não encontrada</p>
        <p style="font-size:13px;color:#aaa">A ordem #${OS_ID} não existe ou foi removida.</p>
      </div>`;
  }

  function render(os) {
    const orcs = os.orcamentos || [];
    const totalOrc = orcs.reduce((s,o) => s + (+o.valor||0), 0);
    const obsHtml = os.observacoes?.length
      ? os.observacoes.map(o => `
          <li class="obs-item">
            ${o.observacao}
            <time>${fmt(o.data_criacao)}</time>
          </li>`).join('')
      : '<li style="color:#aaa;font-size:13px;padding:8px 0">Nenhuma observação registrada.</li>';

    const orcHtml = orcs.length
      ? `<div class="section-title">Orçamento</div>
         ${orcs.map(o => `
           <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px">
             <span style="color:#444">${o.observacoes||'—'}</span>
             <span style="font-weight:700;color:#1a3a5c">R$ ${(+o.valor).toFixed(2)}</span>
           </div>`).join('')}
         <div style="text-align:right;font-weight:700;font-size:14px;padding-top:8px;color:#e8711a">
           Total: R$ ${totalOrc.toFixed(2)}
         </div>`
      : '';

    document.getElementById('card').innerHTML = `
      <div class="card-header">
        <h1>Ordem de Serviço #${os.id}</h1>
        <p>Acompanhe o status do seu aparelho</p>
      </div>
      <div class="card-body">
        <div class="status-badge ${statusClass(os.status)}">
          ${statusIcon(os.status)} ${os.status || '—'}
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0">
          <div class="field">
            <label>Cliente</label>
            <span>${os.cliente_nome||'—'}</span>
          </div>
          <div class="field">
            <label>Data de Abertura</label>
            <span>${fmt(os.data_abertura)}</span>
          </div>
          <div class="field">
            <label>Aparelho</label>
            <span>${os.tipo_nome||'—'}</span>
          </div>
          <div class="field">
            <label>Marca / Modelo</label>
            <span>${[os.marca_nome,os.modelo_nome].filter(Boolean).join(' / ')||'—'}</span>
          </div>
          ${os.previsao_conclusao ? `
          <div class="field">
            <label>Previsão de Conclusão</label>
            <span>${os.previsao_conclusao}</span>
          </div>` : ''}
        </div>

        <div class="divider"></div>
        <div class="field">
          <label>Defeito Informado</label>
          <span>${os.descricao||'—'}</span>
        </div>

        ${orcHtml ? `<div class="divider"></div>${orcHtml}` : ''}

        <div class="divider"></div>
        <div class="section-title">Observações</div>
        <ul class="obs-list">${obsHtml}</ul>

        <div style="margin-top:20px;padding:12px;background:#fff8f3;border-radius:8px;border-left:3px solid #e8711a;font-size:12px;color:#666">
          ⚠️ Aparelhos não retirados em 90 dias após conclusão poderão ser vendidos para cobrir custos do serviço.
          Retire chip e cartão de memória antes de deixar o aparelho.
        </div>
      </div>`;
  }

  load();
  </script>
<?php endif; ?>
</body>
</html>
