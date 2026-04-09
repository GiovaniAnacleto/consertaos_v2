<?php
// upload_mobile.php — Página de upload via QR Code para celular
// Deve ficar na mesma pasta que api.php e index.html
$token = htmlspecialchars($_GET['token'] ?? '');
$api_base = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http')
          . '://' . $_SERVER['HTTP_HOST']
          . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/api.php';
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0"/>
  <title>Enviar Fotos — consertaOS</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.12);max-width:440px;width:100%;padding:28px 24px}
    h2{font-size:20px;font-weight:700;color:#1a3a5c;margin-bottom:6px}
    p.sub{font-size:13px;color:#666;margin-bottom:24px}
    .btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:14px;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:.15s}
    .btn-primary{background:#e8711a;color:#fff;margin-bottom:10px}
    .btn-secondary{background:#f0f0f0;color:#333}
    .btn:active{opacity:.8}
    .btn svg{width:22px;height:22px;flex-shrink:0}
    #preview{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0;min-height:0}
    .preview-item{position:relative;width:90px;height:90px}
    .preview-item img{width:100%;height:100%;object-fit:cover;border-radius:8px;border:2px solid #e8711a}
    .remove-btn{position:absolute;top:-6px;right:-6px;background:#dc3545;color:#fff;border:none;border-radius:50%;width:20px;height:20px;font-size:12px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-weight:700}
    .btn-submit{background:#1a3a5c;color:#fff;margin-top:4px;display:none}
    .alert{padding:14px;border-radius:10px;margin-bottom:16px;font-size:14px;font-weight:500}
    .alert-success{background:#d1fae5;color:#065f46}
    .alert-error{background:#fee2e2;color:#991b1b}
    .loading{text-align:center;padding:20px;display:none}
    .spinner{width:36px;height:36px;border:4px solid #e8711a33;border-top-color:#e8711a;border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 12px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .counter{font-size:12px;color:#888;margin-bottom:8px}
  </style>
</head>
<body>
<?php if (!$token): ?>
  <div class="card">
    <div class="alert alert-error">Token não fornecido. Gere um novo QR Code no sistema.</div>
  </div>
<?php else: ?>
  <div class="card">
    <h2>📷 Enviar Fotos</h2>
    <p class="sub">Tire fotos ou escolha da galeria para enviar à ordem de serviço.</p>

    <div id="msg"></div>

    <button class="btn btn-primary" id="btn-camera" type="button">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
      Tirar Foto
    </button>
    <button class="btn btn-secondary" id="btn-gallery" type="button">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
      Escolher da Galeria
    </button>

    <input type="file" id="input-camera"  accept="image/*" capture="environment" style="display:none" multiple>
    <input type="file" id="input-gallery" accept="image/*" style="display:none" multiple>

    <div class="counter" id="counter" style="display:none"></div>
    <div id="preview"></div>

    <button class="btn btn-submit" id="btn-submit" type="button">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 2 15 22 11 13 2 9 22 2"/></svg>
      Enviar <?php echo htmlspecialchars($token ? '' : ''); ?><span id="count-label"></span>
    </button>

    <div class="loading" id="loading">
      <div class="spinner"></div>
      <p>Enviando... aguarde.</p>
    </div>
  </div>

  <script>
    const API = <?= json_encode($api_base) ?>;
    const TOKEN = <?= json_encode($token) ?>;
    let fileStore = new DataTransfer();

    const btnCamera  = document.getElementById('btn-camera');
    const btnGallery = document.getElementById('btn-gallery');
    const inputCamera  = document.getElementById('input-camera');
    const inputGallery = document.getElementById('input-gallery');
    const preview    = document.getElementById('preview');
    const btnSubmit  = document.getElementById('btn-submit');
    const loading    = document.getElementById('loading');
    const counter    = document.getElementById('counter');
    const msg        = document.getElementById('msg');

    btnCamera.addEventListener('click',  () => inputCamera.click());
    btnGallery.addEventListener('click', () => inputGallery.click());
    inputCamera.addEventListener('change',  handleFiles);
    inputGallery.addEventListener('change', handleFiles);

    function handleFiles(e) {
      for (const f of e.target.files) { fileStore.items.add(f); addPreview(f); }
      e.target.value = null;
      updateUI();
    }

    function addPreview(file) {
      const reader = new FileReader();
      reader.onload = ev => {
        const wrap = document.createElement('div'); wrap.className = 'preview-item';
        const img  = document.createElement('img');  img.src = ev.target.result;
        const rm   = document.createElement('button'); rm.className = 'remove-btn'; rm.textContent = '×';
        rm.onclick = () => { removeFile(file); wrap.remove(); updateUI(); };
        wrap.appendChild(img); wrap.appendChild(rm); preview.appendChild(wrap);
      };
      reader.readAsDataURL(file);
    }

    function removeFile(target) {
      const dt = new DataTransfer();
      for (const f of fileStore.files) if (f !== target) dt.items.add(f);
      fileStore = dt;
    }

    function updateUI() {
      const n = fileStore.files.length;
      counter.style.display = n > 0 ? '' : 'none';
      counter.textContent = n + (n === 1 ? ' foto selecionada' : ' fotos selecionadas');
      document.getElementById('count-label').textContent = n > 0 ? ` (${n})` : '';
      btnSubmit.style.display = n > 0 ? 'flex' : 'none';
    }

    btnSubmit.addEventListener('click', async () => {
      if (!fileStore.files.length) return;
      btnSubmit.style.display = 'none';
      btnCamera.style.display = 'none';
      btnGallery.style.display = 'none';
      loading.style.display = 'block';
      msg.innerHTML = '';

      const fd = new FormData();
      fd.append('token', TOKEN);
      for (const f of fileStore.files) fd.append('imagens[]', f);

      try {
        const res  = await fetch(API + '?resource=processar_upload_mobile', { method: 'POST', body: fd });
        const data = await res.json();
        loading.style.display = 'none';
        if (data.success) {
          msg.innerHTML = '<div class="alert alert-success">✅ Fotos enviadas com sucesso!</div>';
          preview.innerHTML = '';
          fileStore = new DataTransfer();
          updateUI();
          // Redireciona para novo token após 2s
          setTimeout(() => {
            window.location.href = '?token=' + encodeURIComponent(data.new_token || TOKEN);
          }, 2000);
        } else {
          msg.innerHTML = '<div class="alert alert-error">❌ ' + (data.error || 'Erro ao enviar.') + '</div>';
          btnSubmit.style.display = 'flex'; btnCamera.style.display = 'flex'; btnGallery.style.display = 'flex';
        }
      } catch(err) {
        loading.style.display = 'none';
        msg.innerHTML = '<div class="alert alert-error">❌ Erro de conexão. Tente novamente.</div>';
        btnSubmit.style.display = 'flex'; btnCamera.style.display = 'flex'; btnGallery.style.display = 'flex';
      }
    });
  </script>
<?php endif; ?>
</body>
</html>
