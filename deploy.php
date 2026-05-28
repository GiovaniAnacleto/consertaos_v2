<?php
// =============================================================
// deploy.php — Propaga arquivos do _master para todos os clientes
//
// DEPLOY: enviar para /consertaos/_master/deploy.php
//
// Chamada via POST com JSON:
//   curl -X POST https://seudominio.com.br/_master/deploy.php \
//        -H "Content-Type: application/json" \
//        -d '{"chave_secreta":"SUA_CHAVE"}'
//
// A chave NÃO é mais aceita via GET (?chave=...) para não vazar
// nos logs de acesso do servidor (Apache/Nginx registram a URL completa).
//
// Arquivos propagados (cópia física):
//   politica.php, consulta.php, upload_mobile.php, logos, favicon
//
// O api.php de cada cliente NÃO é tocado — ele é um thin wrapper
// que já aponta para este _master/api.php automaticamente.
// =============================================================
declare(strict_types=1);
date_default_timezone_set('America/Sao_Paulo');

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// ─── Apenas POST é aceito ─────────────────────────────────────
// GET poderia ser usado acidentalmente, expondo a chave nos logs.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    die(render_html('Método não permitido', '
        <p style="color:#ef4444">Este endpoint só aceita requisições <strong>POST</strong>.</p>
        <p style="color:#6b7280;font-size:13px;margin-top:8px">
          Envie um JSON com <code>{"chave_secreta":"SUA_CHAVE"}</code> no corpo da requisição.<br>
          Exemplo via curl:<br>
          <code>curl -X POST ' . htmlspecialchars('https://' . ($_SERVER['HTTP_HOST'] ?? 'seudominio') . $_SERVER['SCRIPT_NAME']) . ' \<br>
          &nbsp;&nbsp;&nbsp;-H "Content-Type: application/json" \<br>
          &nbsp;&nbsp;&nbsp;-d \'{"chave_secreta":"SUA_CHAVE"}\'</code>
        </p>'));
}

// ─── Carrega configuração e valida a chave ────────────────────
$cfg    = file_exists(__DIR__ . '/config.php') ? (array)@require __DIR__ . '/config.php' : [];
$secret = trim((string)($cfg['provisionar_secret'] ?? ''));

if ($secret === '') {
    http_response_code(500);
    header('Content-Type: application/json');
    die(json_encode(['error' => 'provisionar_secret não configurado em config.php']));
}

$raw  = (string)@file_get_contents('php://input');
$body = json_decode($raw, true) ?: [];

// Apenas lê do body — nunca de $_GET
$chave = trim((string)($body['chave_secreta'] ?? ''));

if (!hash_equals($secret, $chave)) {
    http_response_code(403);
    die(render_html('Acesso negado', '<p style="color:#ef4444">Chave inválida ou não informada.</p>'));
}

// ─── Arquivos a propagar ──────────────────────────────────────
// index.html é servido via index.php wrapper — não precisa ser copiado.
$arquivos = ['politica.php', 'consulta.php', 'upload_mobile.php',
             'logo.png', 'logo_login.png', 'logo_sidebar.png', 'favicon.ico'];

// ─── Descobre pastas de clientes ─────────────────────────────
$master_dir = __DIR__;
$base_dir   = dirname($master_dir);

$entradas = scandir($base_dir) ?: [];
$clientes = [];
foreach ($entradas as $nome) {
    if ($nome === '.' || $nome === '..') continue;
    $caminho = $base_dir . '/' . $nome;
    if (!is_dir($caminho)) continue;
    // Ignora pastas que começam com _ (ex.: _master) e pastas ocultas
    if (str_starts_with($nome, '_') || str_starts_with($nome, '.')) continue;
    // Considera cliente somente se houver .db3 ou thin wrapper api.php
    $tem_db  = !empty(glob($caminho . '/*.db3'));
    $tem_api = file_exists($caminho . '/api.php')
               && str_contains((string)@file_get_contents($caminho . '/api.php'), 'SAAS_DIR');
    if ($tem_db || $tem_api) {
        $clientes[] = ['nome' => $nome, 'caminho' => $caminho];
    }
}

if (empty($clientes)) {
    die(render_html('Deploy', '<p style="color:#f59e0b">Nenhuma pasta de cliente encontrada em '
        . htmlspecialchars($base_dir) . '</p>'));
}

// ─── Executa o deploy ─────────────────────────────────────────
$log      = [];
$erros    = 0;
$copiados = 0;

foreach ($clientes as $c) {
    $log[] = ['tipo' => 'cliente', 'nome' => $c['nome']];
    foreach ($arquivos as $arq) {
        $src = $master_dir . '/' . $arq;
        $dst = $c['caminho'] . '/' . $arq;
        if (!file_exists($src)) {
            $log[] = ['tipo' => 'skip', 'arq' => $arq, 'motivo' => 'não existe no master'];
            continue;
        }
        if (@copy($src, $dst)) {
            $log[] = ['tipo' => 'ok', 'arq' => $arq];
            $copiados++;
        } else {
            $log[] = ['tipo' => 'erro', 'arq' => $arq];
            $erros++;
        }
    }
}

// ─── Renderiza resultado ──────────────────────────────────────
$linhas = '';
foreach ($log as $item) {
    if ($item['tipo'] === 'cliente') {
        $linhas .= '<tr><td colspan="2" style="padding:10px 12px 4px;font-weight:600;color:#e2e8f0;background:#1e293b;font-size:13px">
                      📁 ' . htmlspecialchars($item['nome']) . '
                    </td></tr>';
    } elseif ($item['tipo'] === 'ok') {
        $linhas .= '<tr>
            <td style="padding:5px 12px 5px 28px;font-size:13px;color:#94a3b8">' . htmlspecialchars($item['arq']) . '</td>
            <td style="padding:5px 12px;font-size:12px"><span style="color:#34d399">✓ copiado</span></td>
          </tr>';
    } elseif ($item['tipo'] === 'erro') {
        $linhas .= '<tr>
            <td style="padding:5px 12px 5px 28px;font-size:13px;color:#94a3b8">' . htmlspecialchars($item['arq']) . '</td>
            <td style="padding:5px 12px;font-size:12px"><span style="color:#f87171">✗ erro de escrita</span></td>
          </tr>';
    } elseif ($item['tipo'] === 'skip') {
        $linhas .= '<tr>
            <td style="padding:5px 12px 5px 28px;font-size:13px;color:#64748b">' . htmlspecialchars($item['arq']) . '</td>
            <td style="padding:5px 12px;font-size:12px;color:#64748b">— ' . htmlspecialchars($item['motivo']) . '</td>
          </tr>';
    }
}

$resumo_cor   = $erros > 0 ? '#f87171' : '#34d399';
$resumo_texto = $erros > 0
    ? "⚠️ Concluído com {$erros} erro(s). {$copiados} arquivo(s) copiado(s)."
    : "✅ Deploy concluído. {$copiados} arquivo(s) copiado(s) em " . count($clientes) . " cliente(s).";

// Nota: o link "Executar novamente" foi removido intencionalmente.
// Re-executar exige um novo POST com a chave no body — não via link clicável.
$conteudo = '
  <p style="margin-bottom:16px;font-size:14px;color:' . $resumo_cor . '">' . $resumo_texto . '</p>
  <table style="width:100%;border-collapse:collapse;background:#0f172a;border-radius:8px;overflow:hidden">
    <thead>
      <tr style="background:#1e293b">
        <th style="padding:8px 12px;text-align:left;font-size:12px;color:#64748b;font-weight:600">ARQUIVO</th>
        <th style="padding:8px 12px;text-align:left;font-size:12px;color:#64748b;font-weight:600">STATUS</th>
      </tr>
    </thead>
    <tbody>' . $linhas . '</tbody>
  </table>
  <p style="margin-top:16px;font-size:12px;color:#475569">
    Executado em: ' . date('d/m/Y H:i:s') . '
  </p>';

echo render_html('Deploy — consertaOS', $conteudo);

// ─── Helpers ─────────────────────────────────────────────────

function render_html(string $titulo, string $conteudo): string {
    return <<<HTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{$titulo}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#0f172a;color:#e2e8f0;padding:32px 24px;min-height:100vh}
    .container{max-width:680px;margin:0 auto}
    h1{font-size:20px;font-weight:700;margin-bottom:6px;color:#f1f5f9}
    .sub{font-size:13px;color:#64748b;margin-bottom:24px}
    code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:12px;
         white-space:pre-wrap;word-break:break-all;display:inline-block}
    a{color:#60a5fa;text-decoration:none}
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 {$titulo}</h1>
    <p class="sub">Propaga arquivos estáticos do _master para todos os clientes</p>
    {$conteudo}
  </div>
</body>
</html>
HTML;
}
