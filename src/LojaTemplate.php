<?php
class LojaTemplate
{
    /**
     * Gera o código PHP completo do index.php da loja virtual pública.
     * O placeholder __DB_PATH__ é substituído pelo caminho absoluto do banco.
     */
    public static function generate(string $dbPath): string
    {
        $tpl = <<<'LOJA_EOF'
<?php
/* Loja Virtual — gerado automaticamente pelo ConsertaOS. Não edite manualmente. */
define('LOJA_DB', '__DB_PATH__');

try {
    $pdo = new PDO('sqlite:' . LOJA_DB, '', '', [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec("PRAGMA journal_mode=WAL; PRAGMA cache_size=500;");
} catch (\Exception $e) {
    http_response_code(503);
    die('<!DOCTYPE html><html lang="pt-BR"><body style="font-family:sans-serif;text-align:center;padding:80px 20px"><h2 style="color:#555">Loja temporariamente indispon&iacute;vel.</h2><p style="color:#999;margin-top:8px">Tente novamente em alguns instantes.</p></body></html>');
}

$emp  = $pdo->query("SELECT * FROM empresa_dados WHERE id=1")->fetch() ?: [];
$cats = $pdo->query("SELECT * FROM loja_categorias WHERE ativo=1 ORDER BY nome")->fetchAll() ?: [];

$catId       = max(0, (int)($_GET['cat'] ?? 0));
$q           = substr(trim(strip_tags($_GET['q'] ?? '')), 0, 120);
$exibePrecos = (int)($emp['loja_exibir_precos'] ?? 1);
$formato     = $emp['loja_formato'] ?? 'grade';

$where  = "pl.loja_exibir=1 AND p.ativo=1";
$params = [];
if ($catId > 0) {
    $where   .= " AND pl.loja_categoria_id=?";
    $params[] = $catId;
}
if ($q !== '') {
    $like     = '%' . $q . '%';
    $where   .= " AND (LOWER(pl.loja_titulo) LIKE LOWER(?) OR LOWER(p.descricao) LIKE LOWER(?))";
    $params[] = $like;
    $params[] = $like;
}
$stmt = $pdo->prepare(
    "SELECT p.preco_venda, p.descricao AS p_descricao,
            pl.loja_titulo, pl.loja_descricao, pl.loja_fotos, pl.loja_variacoes, pl.loja_categoria_id,
            COALESCE(pl.loja_destaque, 0) AS loja_destaque
     FROM produtos p
     INNER JOIN produto_loja pl ON pl.produto_id = p.id
     WHERE $where
     ORDER BY COALESCE(pl.loja_destaque, 0) DESC, LOWER(COALESCE(NULLIF(TRIM(pl.loja_titulo),''), p.descricao))
     LIMIT 200"
);
$stmt->execute($params);
$produtos = $stmt->fetchAll();

function _esc(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
function _wa(string $tel, string $msg = ''): string {
    $t = preg_replace('/\D/', '', $tel);
    if (!$t) return '#';
    return 'https://wa.me/' . $t . ($msg !== '' ? '?text=' . rawurlencode($msg) : '');
}
function _fmt(float $v): string { return 'R$&nbsp;' . number_format($v, 2, ',', '.'); }

$nomeLoja = trim($emp['loja_nome'] ?: ($emp['razao_social'] ?: ($emp['nome'] ?? 'Loja Virtual')));
$telefone = $emp['telefone'] ?? '';
$logo     = $emp['loja_logo']     ?? '';
$logoPos  = $emp['loja_logo_pos'] ?? '50% 50%';
$capa     = $emp['loja_capa']     ?? '';
$capaPos  = $emp['loja_capa_pos'] ?? '50% 50%';
$bvindas  = $emp['loja_boas_vindas'] ?? '';
$cidade   = $emp['cidade'] ?? '';
$uf       = $emp['uf']     ?? '';
$telefFmt = $emp['telefone'] ?? '';

$catAtual = null;
foreach ($cats as $c) { if ((int)$c['id'] === $catId) { $catAtual = $c; break; } }

$pageTitle = _esc($nomeLoja)
    . ($catAtual ? ' — ' . _esc($catAtual['nome']) : '')
    . ($q        ? ' — ' . _esc($q) : '');

$waBase = _wa($telefone, 'Olá! Gostaria de mais informações sobre os produtos.');

// Prepara dados dos produtos para JS (modal)
$produtosJs = [];
foreach ($produtos as $p) {
    $fotos    = json_decode($p['loja_fotos']    ?? '[]', true) ?: [];
    $variacoes= json_decode($p['loja_variacoes'] ?? '[]', true) ?: [];
    $titulo   = trim($p['loja_titulo'] ?: $p['p_descricao']);
    $produtosJs[] = [
        'titulo'    => $titulo,
        'desc'      => trim($p['loja_descricao'] ?? ''),
        'preco'     => (float)($p['preco_venda'] ?? 0),
        'fotos'     => $fotos,
        'variacoes' => $variacoes,
        'tel'       => preg_replace('/\D/', '', $telefone),
    ];
}

header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#e8711a">
<title><?= $pageTitle ?></title>
<?php if ($logo): ?>
<link rel="icon" href="<?= _esc($logo) ?>">
<?php endif; ?>
<style>
*,::before,::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,sans-serif;background:#f4f4f5;color:#1a1a1a;line-height:1.5;min-height:100vh}
a{color:inherit;text-decoration:none}
img{display:block;max-width:100%}
button{font-family:inherit}

/* ── HEADER ───────────────────────────────────── */
.site-header{background:#fff;border-bottom:1px solid #e5e7eb;position:sticky;top:0;z-index:200;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.header-inner{max-width:1200px;margin:0 auto;padding:0 16px;display:flex;align-items:center;gap:12px;height:62px}
.logo-wrap{display:flex;align-items:center;gap:10px;flex-shrink:0;max-width:200px;min-width:0;cursor:pointer}
.logo-wrap img{height:40px;width:40px;object-fit:cover;border-radius:50%;border:2px solid #f0f0f0;flex-shrink:0}
.logo-nome{font-weight:700;font-size:15px;color:#111;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.search-form{flex:1;display:flex;min-width:0;max-width:480px;margin:0 auto}
.search-input{flex:1;min-width:0;padding:9px 14px;border:1.5px solid #d1d5db;border-right:none;border-radius:8px 0 0 8px;font-size:14px;background:#f9fafb;outline:none;color:#111;transition:border-color .2s,background .2s}
.search-input:focus{border-color:#e8711a;background:#fff}
.search-btn{padding:9px 16px;background:#e8711a;color:#fff;border:none;border-radius:0 8px 8px 0;cursor:pointer;font-size:14px;font-weight:600;white-space:nowrap;transition:background .2s;flex-shrink:0}
.search-btn:hover{background:#c95d12}
.wa-header{display:flex;align-items:center;gap:6px;padding:8px 14px;background:#25d366;color:#fff;border-radius:8px;font-size:13px;font-weight:600;flex-shrink:0;transition:background .2s;white-space:nowrap}
.wa-header:hover{background:#1da851}
.wa-header svg{width:15px;height:15px;flex-shrink:0}
@media(max-width:600px){.wa-header span{display:none}.wa-header{padding:8px 10px}}
@media(max-width:480px){.logo-nome{display:none}}

/* ── BANNER ───────────────────────────────────── */
.banner{width:100%;height:220px;background:#2c2c2c;background-size:cover;background-position:center;position:relative;overflow:hidden}
@media(max-width:600px){.banner{height:160px}}
.banner-overlay{position:absolute;inset:0;background:linear-gradient(160deg,rgba(0,0,0,.6) 0%,rgba(0,0,0,.22) 100%);display:flex;align-items:center;justify-content:center;padding:20px}
.banner-text{color:#fff;text-align:center;max-width:640px}
.banner-title{font-size:clamp(18px,4vw,34px);font-weight:800;margin-bottom:6px;text-shadow:0 2px 10px rgba(0,0,0,.5)}
.banner-sub{font-size:clamp(13px,2vw,16px);opacity:.92;text-shadow:0 1px 6px rgba(0,0,0,.4)}
.bvindas-bar{background:#e8711a;color:#fff;text-align:center;padding:14px 16px;font-size:14px;font-weight:500}

/* ── LAYOUT ───────────────────────────────────── */
.page-wrap{max-width:1200px;margin:0 auto;padding:24px 16px;display:grid;grid-template-columns:210px 1fr;gap:24px;align-items:start}
@media(max-width:800px){.page-wrap{grid-template-columns:1fr;padding:16px 12px}.cat-sidebar{display:none!important}.cat-mobile{display:block!important}}

/* ── SIDEBAR ───────────────────────────────────── */
.cat-sidebar{background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:16px;position:sticky;top:80px}
.cat-sidebar h3{font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px}
.cat-list{list-style:none;display:flex;flex-direction:column;gap:2px}
.cat-list a{display:block;padding:8px 10px;border-radius:7px;font-size:13.5px;color:#374151;transition:background .15s,color .15s}
.cat-list a:hover{background:#fff4ee;color:#e8711a}
.cat-list a.active{background:#e8711a;color:#fff;font-weight:600}

/* ── CAT MOBILE ───────────────────────────────── */
.cat-mobile{display:none;margin-bottom:14px}
.cat-mobile select{width:100%;padding:10px 14px;border:1.5px solid #d1d5db;border-radius:8px;font-size:14px;background:#fff;color:#111;outline:none;cursor:pointer}
.cat-mobile select:focus{border-color:#e8711a}

/* ── SECTION HEADER ─────────────────────────── */
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;gap:12px}
.section-info{font-size:13px;color:#6b7280}
.section-info strong{color:#111}

/* ── GRID ───────────────────────────────────── */
.products-grade{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:14px}
@media(max-width:480px){.products-grade{grid-template-columns:repeat(2,1fr);gap:10px}}
.products-lista{display:flex;flex-direction:column;gap:12px}

/* ── CARD GRADE ─────────────────────────────── */
.card{background:#fff;border-radius:12px;border:1px solid #e5e7eb;overflow:hidden;display:flex;flex-direction:column;transition:box-shadow .2s,transform .2s;cursor:pointer}
.card:hover{box-shadow:0 8px 28px rgba(0,0,0,.10);transform:translateY(-2px)}
.card-foto{aspect-ratio:1;overflow:hidden;background:#f3f4f6;display:flex;align-items:center;justify-content:center}
.card-foto img{width:100%;height:100%;object-fit:cover;transition:transform .35s}
.card:hover .card-foto img{transform:scale(1.05)}
.card-foto-empty{color:#d1d5db}
.card-body{padding:12px;display:flex;flex-direction:column;gap:6px;flex:1}
.card-titulo{font-size:13.5px;font-weight:600;color:#111;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.4}
.card-preco{font-size:16px;font-weight:700;color:#e8711a;margin-top:auto}
.btn-wa{display:flex;align-items:center;justify-content:center;gap:6px;padding:9px 10px;background:#25d366;color:#fff;border-radius:8px;font-size:12.5px;font-weight:600;margin-top:8px;transition:background .2s;text-align:center;border:none;cursor:pointer;width:100%}
.btn-wa:hover{background:#1da851}
.btn-wa svg{width:14px;height:14px;flex-shrink:0}

/* ── CARD LISTA ─────────────────────────────── */
.card-lista{background:#fff;border-radius:12px;border:1px solid #e5e7eb;overflow:hidden;display:grid;grid-template-columns:170px 1fr;transition:box-shadow .2s;cursor:pointer}
@media(max-width:540px){.card-lista{grid-template-columns:110px 1fr}}
.card-lista:hover{box-shadow:0 6px 20px rgba(0,0,0,.09)}
.card-lista .card-foto{aspect-ratio:1;width:100%}
.card-lista .card-body{padding:16px}
.card-lista .card-titulo{font-size:15px;-webkit-line-clamp:3}
.card-lista .card-preco{font-size:20px}
.card-lista .btn-wa{width:fit-content;padding:9px 18px;font-size:13px}

/* ── EMPTY ───────────────────────────────────── */
.empty-state{text-align:center;padding:60px 24px;color:#9ca3af}
.empty-state svg{width:52px;height:52px;margin:0 auto 16px;opacity:.35}
.empty-state p{font-size:15px}
.empty-state a{color:#e8711a;text-decoration:underline}

/* ── FOOTER ───────────────────────────────────── */
.site-footer{background:#fff;border-top:1px solid #e5e7eb;margin-top:48px;padding:24px 16px;text-align:center;color:#6b7280;font-size:13px;line-height:1.8}
.site-footer strong{color:#111}
.footer-powered{margin-top:6px;font-size:11px;opacity:.5}

/* ── MODAL OVERLAY ───────────────────────────── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center;padding:16px;backdrop-filter:blur(3px)}
.modal-overlay.open{display:flex}
.modal-box{background:#fff;border-radius:16px;max-width:800px;width:100%;max-height:90vh;overflow:hidden;position:relative;display:grid;grid-template-columns:1fr 1fr;box-shadow:0 24px 80px rgba(0,0,0,.25)}
@media(max-width:640px){
  .modal-box{grid-template-columns:1fr;max-height:95vh;border-radius:16px 16px 0 0;position:fixed;bottom:0;left:0;right:0;width:100%;margin:0;overflow-y:auto}
  .modal-overlay{padding:0;align-items:flex-end}
}
.modal-close{position:absolute;top:12px;right:12px;background:rgba(0,0,0,.12);border:none;border-radius:50%;width:34px;height:34px;cursor:pointer;font-size:18px;line-height:1;display:flex;align-items:center;justify-content:center;z-index:10;color:#fff;transition:background .2s}
.modal-close:hover{background:rgba(0,0,0,.28)}

/* ── CARROSSEL ───────────────────────────────── */
.carousel{position:relative;aspect-ratio:1;overflow:hidden;background:#f3f4f6}
@media(max-width:640px){.carousel{aspect-ratio:4/3}}
.carousel-track{display:flex;height:100%;transition:transform .35s cubic-bezier(.4,0,.2,1)}
.carousel-slide{flex:0 0 100%;display:flex;align-items:center;justify-content:center;overflow:hidden}
.carousel-slide img{width:100%;height:100%;object-fit:cover}
.carousel-slide-empty{color:#d1d5db;display:flex;align-items:center;justify-content:center;width:100%;height:100%}
.carousel-btn{position:absolute;top:50%;transform:translateY(-50%);background:rgba(255,255,255,.88);border:none;border-radius:50%;width:36px;height:36px;cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:5;box-shadow:0 2px 8px rgba(0,0,0,.18);transition:background .2s}
.carousel-btn:hover{background:#fff}
.carousel-prev{left:10px}
.carousel-next{right:10px}
.carousel-dots{position:absolute;bottom:10px;left:0;right:0;display:flex;justify-content:center;gap:6px;pointer-events:none}
.carousel-dot{width:7px;height:7px;border-radius:50%;background:rgba(255,255,255,.5);border:none;cursor:pointer;padding:0;pointer-events:all;transition:background .2s,transform .2s}
.carousel-dot.active{background:#fff;transform:scale(1.25)}

/* ── MODAL INFO ──────────────────────────────── */
.modal-info{padding:24px;overflow-y:auto;display:flex;flex-direction:column;gap:12px;max-height:90vh}
@media(max-width:640px){.modal-info{max-height:none;padding:20px}}
.modal-titulo{font-size:19px;font-weight:700;color:#111;line-height:1.35}
.modal-preco{font-size:24px;font-weight:800;color:#e8711a}
.modal-desc{font-size:14px;color:#555;line-height:1.65;white-space:pre-line;flex:1}
.modal-var-label{font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.modal-var-sel{width:100%;padding:10px 12px;border:1.5px solid #d1d5db;border-radius:8px;font-size:14px;background:#f9fafb;color:#111;cursor:pointer}
.modal-var-sel:focus{border-color:#e8711a;outline:none}
.modal-wa{display:flex;align-items:center;justify-content:center;gap:8px;padding:13px 18px;background:#25d366;color:#fff;border-radius:10px;font-size:15px;font-weight:700;transition:background .2s;border:none;cursor:pointer;width:100%;margin-top:auto}
.modal-wa:hover{background:#1da851}
.modal-wa svg{width:18px;height:18px;flex-shrink:0}
</style>
</head>
<body>

<!-- HEADER -->
<header class="site-header">
  <div class="header-inner">
    <a class="logo-wrap" href="?">
      <?php if ($logo): ?>
      <img src="<?= _esc($logo) ?>" alt="Logo <?= _esc($nomeLoja) ?>">
      <?php endif; ?>
      <span class="logo-nome"><?= _esc($nomeLoja) ?></span>
    </a>

    <form class="search-form" method="get" action="">
      <?php if ($catId > 0): ?><input type="hidden" name="cat" value="<?= $catId ?>"><?php endif; ?>
      <input class="search-input" type="search" name="q" value="<?= _esc($q) ?>" placeholder="Buscar produtos..." autocomplete="off">
      <button class="search-btn" type="submit">Buscar</button>
    </form>

    <?php if ($telefone): ?>
    <a class="wa-header" href="<?= _esc($waBase) ?>" target="_blank" rel="noopener noreferrer">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
      <span>WhatsApp</span>
    </a>
    <?php endif; ?>
  </div>
</header>

<!-- BANNER / BOAS-VINDAS -->
<?php if ($capa): ?>
<div class="banner" style="background-image:url('<?= _esc($capa) ?>');background-position:<?= _esc($capaPos) ?>">
  <div class="banner-overlay">
    <div class="banner-text">
      <div class="banner-title"><?= _esc($nomeLoja) ?></div>
      <?php if ($bvindas): ?><div class="banner-sub"><?= _esc($bvindas) ?></div><?php endif; ?>
    </div>
  </div>
</div>
<?php elseif ($bvindas): ?>
<div class="bvindas-bar"><?= _esc($bvindas) ?></div>
<?php endif; ?>

<!-- CONTEÚDO PRINCIPAL -->
<div class="page-wrap">

  <!-- CATEGORIAS DESKTOP -->
  <?php if (!empty($cats)): ?>
  <aside class="cat-sidebar">
    <h3>Categorias</h3>
    <ul class="cat-list">
      <li>
        <a href="?<?= $q ? 'q=' . rawurlencode($q) : '' ?>" class="<?= $catId === 0 ? 'active' : '' ?>">
          Todos os produtos
        </a>
      </li>
      <?php foreach ($cats as $c): ?>
      <li>
        <a href="?cat=<?= (int)$c['id'] ?><?= $q ? '&q=' . rawurlencode($q) : '' ?>"
           class="<?= $catId === (int)$c['id'] ? 'active' : '' ?>">
          <?= _esc($c['nome']) ?>
        </a>
      </li>
      <?php endforeach; ?>
    </ul>
  </aside>
  <?php endif; ?>

  <!-- ÁREA DE PRODUTOS -->
  <div>

    <!-- CATEGORIAS MOBILE -->
    <?php if (!empty($cats)): ?>
    <div class="cat-mobile">
      <select onchange="location.href=this.value">
        <option value="?<?= $q ? 'q=' . rawurlencode($q) : '' ?>" <?= $catId === 0 ? 'selected' : '' ?>>
          Todos os produtos
        </option>
        <?php foreach ($cats as $c): ?>
        <option value="?cat=<?= (int)$c['id'] ?><?= $q ? '&q=' . rawurlencode($q) : '' ?>"
                <?= $catId === (int)$c['id'] ? 'selected' : '' ?>>
          <?= _esc($c['nome']) ?>
        </option>
        <?php endforeach; ?>
      </select>
    </div>
    <?php endif; ?>

    <!-- INFO DE RESULTADOS -->
    <div class="section-header">
      <span class="section-info">
        <?php if ($q): ?>
          Resultados para <strong>"<?= _esc($q) ?>"</strong> &mdash;
        <?php elseif ($catAtual): ?>
          <strong><?= _esc($catAtual['nome']) ?></strong> &mdash;
        <?php endif; ?>
        <?= count($produtos) ?> produto<?= count($produtos) !== 1 ? 's' : '' ?>
      </span>
      <?php if ($q || $catId > 0): ?>
      <a href="?" style="font-size:13px;color:#e8711a">Ver todos</a>
      <?php endif; ?>
    </div>

    <!-- PRODUTOS -->
    <?php if (empty($produtos)): ?>
    <div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M20 7H4a2 2 0 00-2 2v10a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2z"/>
        <path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/>
      </svg>
      <p>Nenhum produto encontrado<?= $q ? ' para "<strong>' . _esc($q) . '</strong>"' : '' ?>.</p>
      <?php if ($q || $catId > 0): ?>
      <p style="margin-top:10px"><a href="?">Ver todos os produtos</a></p>
      <?php endif; ?>
    </div>

    <?php else: ?>
    <div class="<?= $formato === 'lista' ? 'products-lista' : 'products-grade' ?>">

    <?php foreach ($produtos as $idx => $p):
      $fotos    = json_decode($p['loja_fotos']    ?? '[]', true) ?: [];
      $variacoes= json_decode($p['loja_variacoes'] ?? '[]', true) ?: [];
      $titulo   = trim($p['loja_titulo'] ?: $p['p_descricao']);
      $preco    = (float)($p['preco_venda'] ?? 0);
      $foto1    = $fotos[0] ?? '';
      // $temVars = verdadeiro apenas se houver pelo menos um tipo com opcoes preenchidas
      $temVars  = (bool)array_filter($variacoes, fn($vt) => !empty($vt['opcoes'] ?? []));
      $waTxt    = 'Olá! Tenho interesse no produto: ' . $titulo;
      $cardCls  = $formato === 'lista' ? 'card card-lista' : 'card';
    ?>
    <div class="<?= $cardCls ?>" onclick="_lojaAbrir(<?= $idx ?>)" role="button" tabindex="0" aria-label="Ver detalhes de <?= _esc($titulo) ?>">

      <!-- Foto (miniatura, 1ª apenas) -->
      <div class="card-foto">
        <?php if ($foto1): ?>
        <img src="<?= _esc($foto1) ?>" alt="<?= _esc($titulo) ?>" loading="lazy">
        <?php else: ?>
        <svg class="card-foto-empty" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" style="width:38%;height:38%">
          <rect x="3" y="3" width="18" height="18" rx="2"/>
          <circle cx="8.5" cy="8.5" r="1.5"/>
          <polyline points="21 15 16 10 5 21"/>
        </svg>
        <?php endif; ?>
      </div>

      <!-- Corpo simplificado: nome + preço + botão WA -->
      <div class="card-body">
        <div class="card-titulo"><?= _esc($titulo) ?></div>

        <?php if ($exibePrecos && $preco > 0): ?>
        <div class="card-preco"><?= _fmt($preco) ?></div>
        <?php endif; ?>

        <?php if ($telefone): ?>
        <?php if ($temVars): ?>
        <!-- Produto com variações: botão abre modal para selecionar variação -->
        <button class="btn-wa" onclick="event.stopPropagation();_lojaAbrir(<?= $idx ?>)">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
          Pedir via WhatsApp
        </button>
        <?php else: ?>
        <!-- Produto sem variações: botão WA direto -->
        <a class="btn-wa" href="<?= _esc(_wa($telefone, $waTxt)) ?>" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
          Pedir via WhatsApp
        </a>
        <?php endif; ?>
        <?php endif; ?>
      </div>
    </div>
    <?php endforeach; ?>

    </div>
    <?php endif; ?>

  </div>
</div>

<!-- FOOTER -->
<footer class="site-footer">
  <strong><?= _esc($nomeLoja) ?></strong>
  <?php if ($telefFmt): ?>&nbsp;&middot;&nbsp;<?= _esc($telefFmt) ?><?php endif; ?>
  <?php if ($cidade): ?>&nbsp;&middot;&nbsp;<?= _esc($cidade) ?><?= $uf ? ' &mdash; ' . _esc($uf) : '' ?><?php endif; ?>
  <div class="footer-powered">Loja gerada por ConsertaOS</div>
</footer>

<!-- MODAL DE PRODUTO -->
<div class="modal-overlay" id="produto-modal" role="dialog" aria-modal="true" aria-label="Detalhes do produto">
  <div class="modal-box" id="produto-modal-box">
    <button class="modal-close" onclick="_lojaFechar()" aria-label="Fechar">&times;</button>

    <!-- Carrossel de fotos -->
    <div class="carousel" id="modal-carousel">
      <div class="carousel-track" id="carousel-track"></div>
      <button class="carousel-btn carousel-prev" id="carousel-prev" onclick="_carouselPrev()" aria-label="Foto anterior">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:16px;height:16px"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
      <button class="carousel-btn carousel-next" id="carousel-next" onclick="_carouselNext()" aria-label="Próxima foto">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:16px;height:16px"><polyline points="9 18 15 12 9 6"/></svg>
      </button>
      <div class="carousel-dots" id="carousel-dots"></div>
    </div>

    <!-- Informações do produto -->
    <div class="modal-info">
      <div class="modal-titulo" id="modal-titulo"></div>
      <div class="modal-preco" id="modal-preco" style="display:none"></div>
      <!-- Variações: populadas dinamicamente pelo JS para cada tipo (Cor, Tamanho...) -->
      <div id="modal-vars-wrap" style="display:none"></div>
      <div class="modal-desc" id="modal-desc" style="display:none"></div>
      <button class="modal-wa btn-wa" id="modal-wa-btn" onclick="_lojaWaClick()">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/></svg>
        Pedir via WhatsApp
      </button>
    </div>
  </div>
</div>

<script>
// Dados dos produtos embutidos
var _LP = <?= json_encode($produtosJs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
var _exibePrecos = <?= $exibePrecos ? 'true' : 'false' ?>;

var _curIdx    = 0;
var _curSlide  = 0;
var _curProd   = null;

/* ── Abrir modal ─────────────────────────────── */
function _lojaAbrir(idx) {
  var p = _LP[idx];
  if (!p) return;
  _curIdx   = idx;
  _curSlide = 0;
  _curProd  = p;

  // Título
  document.getElementById('modal-titulo').textContent = p.titulo;

  // Preço
  var precoEl = document.getElementById('modal-preco');
  if (_exibePrecos && p.preco > 0) {
    precoEl.innerHTML = 'R$ ' + p.preco.toFixed(2).replace('.', ',');
    precoEl.style.display = '';
  } else {
    precoEl.style.display = 'none';
  }
  // Variacoes — estrutura: [{nome:"Cor", opcoes:[{valor:"Azul"},{valor:"Verde"}]}, ...]
  var varsWrap = document.getElementById('modal-vars-wrap');
  varsWrap.innerHTML = '';
  var hasVars = p.variacoes && p.variacoes.some(function(vt) {
    return vt.opcoes && vt.opcoes.length > 0;
  });
  if (hasVars) {
    p.variacoes.forEach(function(vt, ti) {
      if (!vt.opcoes || !vt.opcoes.length) return;
      var lbl = document.createElement('div');
      lbl.className = 'modal-var-label';
      lbl.textContent = 'Selecione um(a) ' + (vt.nome || 'variacao') + ':';
      varsWrap.appendChild(lbl);
      var sel = document.createElement('select');
      sel.className = 'modal-var-sel';
      sel.id = 'modal-var-sel-' + ti;
      sel.dataset.tipo = vt.nome || '';
      sel.addEventListener('change', _lojaVarChange);
      var defOpt = document.createElement('option');
      defOpt.value = '';
      defOpt.textContent = 'Escolha...';
      sel.appendChild(defOpt);
      vt.opcoes.forEach(function(op) {
        var opt = document.createElement('option');
        opt.value = op.valor || '';
        opt.textContent = op.valor || '';
        sel.appendChild(opt);
      });
      varsWrap.appendChild(sel);
    });
    varsWrap.style.display = '';
  } else {
    varsWrap.style.display = 'none';
  }

  // Descrição
  var descEl = document.getElementById('modal-desc');
  if (p.desc) {
    descEl.textContent = p.desc;
    descEl.style.display = '';
  } else {
    descEl.style.display = 'none';
  }

  // Botão WA
  _lojaWaAtualizar();

  // Carrossel
  _carouselInit(p.fotos || []);

  // Exibe modal
  var overlay = document.getElementById('produto-modal');
  overlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

/* ── Fechar modal ────────────────────────────── */
function _lojaFechar() {
  document.getElementById('produto-modal').classList.remove('open');
  document.body.style.overflow = '';
}

/* ── Fechar ao clicar no overlay ─────────────── */
document.getElementById('produto-modal').addEventListener('click', function(e) {
  if (e.target === this) _lojaFechar();
});

/* ── Fechar com Escape ───────────────────────── */
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') _lojaFechar();
});

/* --- Botao WA --- */
function _lojaWaAtualizar() {
  var p = _curProd;
  if (!p || !p.tel) {
    document.getElementById('modal-wa-btn').style.display = 'none';
  } else {
    document.getElementById('modal-wa-btn').style.display = '';
  }
}

function _lojaVarChange() { /* selects dinamicos — nada adicional */ }

function _lojaWaClick() {
  var p = _curProd;
  if (!p || !p.tel) return;
  var sels = document.querySelectorAll('#modal-vars-wrap select');
  var partes = [];
  sels.forEach(function(sel) {
    if (sel.value) {
      var tipo = sel.dataset.tipo || '';
      partes.push(tipo ? tipo + ': ' + sel.value : sel.value);
    }
  });
  var msg = 'Ola! Tenho interesse no produto: ' + p.titulo;
  if (partes.length) msg += ' (' + partes.join(', ') + ')';
  window.open('https://wa.me/' + p.tel + '?text=' + encodeURIComponent(msg), '_blank', 'noopener,noreferrer');
}

/* ── Carrossel ───────────────────────────────── */
function _carouselInit(fotos) {
  var track = document.getElementById('carousel-track');
  var dots  = document.getElementById('carousel-dots');
  var prev  = document.getElementById('carousel-prev');
  var next  = document.getElementById('carousel-next');
  _curSlide = 0;

  track.innerHTML = '';
  dots.innerHTML  = '';

  if (!fotos || fotos.length === 0) {
    var empty = document.createElement('div');
    empty.className = 'carousel-slide';
    empty.innerHTML = '<div class="carousel-slide-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" style="width:30%;height:30%;color:#d1d5db"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>';
    track.appendChild(empty);
    prev.style.display = 'none';
    next.style.display = 'none';
    return;
  }

  fotos.forEach(function(src, i) {
    var slide = document.createElement('div');
    slide.className = 'carousel-slide';
    var img = document.createElement('img');
    img.src = src;
    img.alt = 'Foto ' + (i + 1);
    img.loading = i === 0 ? 'eager' : 'lazy';
    slide.appendChild(img);
    track.appendChild(slide);

    var dot = document.createElement('button');
    dot.className = 'carousel-dot' + (i === 0 ? ' active' : '');
    dot.setAttribute('aria-label', 'Ir para foto ' + (i + 1));
    dot.addEventListener('click', function() { _carouselGoTo(i); });
    dots.appendChild(dot);
  });

  var multi = fotos.length > 1;
  prev.style.display = multi ? '' : 'none';
  next.style.display = multi ? '' : 'none';

  _carouselGoTo(0);
}

function _carouselGoTo(n) {
  var track = document.getElementById('carousel-track');
  var total = track.children.length;
  _curSlide = Math.max(0, Math.min(n, total - 1));
  track.style.transform = 'translateX(-' + (_curSlide * 100) + '%)';
  document.querySelectorAll('.carousel-dot').forEach(function(d, i) {
    d.classList.toggle('active', i === _curSlide);
  });
}
function _carouselPrev() { _carouselGoTo(_curSlide - 1); }
function _carouselNext() { _carouselGoTo(_curSlide + 1); }

/* ── Swipe no carrossel (touch) ──────────────── */
(function() {
  var el = document.getElementById('modal-carousel');
  var sx, sy;
  el.addEventListener('touchstart', function(e) { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, {passive:true});
  el.addEventListener('touchend', function(e) {
    var dx = e.changedTouches[0].clientX - sx;
    var dy = Math.abs(e.changedTouches[0].clientY - sy);
    if (Math.abs(dx) > 40 && dy < 60) {
      dx < 0 ? _carouselNext() : _carouselPrev();
    }
  }, {passive:true});
})();

/* ── Acessibilidade: Enter/Space abre modal ──── */
document.querySelectorAll('.card').forEach(function(card, idx) {
  card.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); _lojaAbrir(idx); }
  });
});
</script>
</body>
</html>
LOJA_EOF;

        return str_replace('__DB_PATH__', addslashes($dbPath), $tpl);
    }
}
