<?php
// =============================================================
// provisionar.php — Endpoint de provisionamento de novos clientes
//
// DEPLOY: enviar para /consertaos/_master/provisionar.php
//         (mesma pasta que api.php e index.html)
//
// Chamado pela landing page (webhook.php) após pagamento autorizado
// no Mercado Pago. Cria a pasta do cliente em /consertaos/{slug}/
// com um thin wrapper de api.php e inicializa o banco de dados.
//
// Segurança: protegido por chave secreta compartilhada (config.php).
// =============================================================
declare(strict_types=1);
date_default_timezone_set('America/Sao_Paulo');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Método não permitido']);
    exit;
}

// ─── Chave secreta ────────────────────────────────────────────
$cfg    = file_exists(__DIR__ . '/config.php') ? (array)@require __DIR__ . '/config.php' : [];
$secret = trim((string)($cfg['provisionar_secret'] ?? ''));
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['error' => 'provisionar_secret não definido em config.php']);
    exit;
}

$raw  = (string)@file_get_contents('php://input');
$data = json_decode($raw, true) ?: [];

if (!hash_equals($secret, (string)($data['chave_secreta'] ?? ''))) {
    http_response_code(403);
    echo json_encode(['error' => 'Acesso não autorizado']);
    exit;
}

// ─── Dados do cliente ─────────────────────────────────────────
$nome                 = trim((string)($data['nome']                 ?? ''));
$email                = trim((string)($data['email']                ?? ''));
$empresa              = trim((string)($data['empresa']              ?? ''));
$telefone             = trim((string)($data['telefone']             ?? ''));
$plano                = trim((string)($data['plano']                ?? 'Lite'));
$slug_req             = trim((string)($data['slug']                 ?? ''));
$slug                 = slug_sanitize($slug_req !== '' ? $slug_req : $empresa);
$mp_preapproval_id    = trim((string)($data['mp_preapproval_id']    ?? ''));
$plano_valor          = (float)($data['plano_valor']                ?? 0);
$plano_data_inicio    = trim((string)($data['plano_data_inicio']    ?? date('Y-m-d H:i:s')));
$plano_landing_url    = trim((string)($data['plano_landing_url']    ?? ''));
$plano_landing_secret = trim((string)($data['plano_landing_secret'] ?? ''));

if ($slug === '' || $nome === '' || $email === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Campos obrigatórios: nome, email e empresa']);
    exit;
}

// ─── Caminhos ─────────────────────────────────────────────────
$master_name = basename(__DIR__);       // ex.: "_master"
$base_dir    = dirname(__DIR__);        // ex.: /home/.../consertaos
$client_dir  = $base_dir . '/' . $slug;

// Já existe: retorna sem re-provisionar
if (is_dir($client_dir)) {
    echo json_encode([
        'ok'       => true,
        'url'      => base_url() . $slug . '/',
        'slug'     => $slug,
        'existente' => true,
    ]);
    exit;
}

// ─── Cria estrutura de diretórios ────────────────────────────
$dirs = [
    $client_dir,
    $client_dir . '/storage',
    $client_dir . '/storage/nfce',
    $client_dir . '/storage/nfe',
    $client_dir . '/storage/nfse',
    $client_dir . '/uploads',
    $client_dir . '/nfce',
    $client_dir . '/nfce/autorizada',
    $client_dir . '/nfce/cancelada',
    $client_dir . '/nfce/pendente',
    $client_dir . '/nfce/rejeitada',
    $client_dir . '/logs',
];
foreach ($dirs as $dir) {
    if (!is_dir($dir) && !mkdir($dir, 0755, true)) {
        cleanup($client_dir);
        http_response_code(500);
        echo json_encode(['error' => 'Falha ao criar diretório: ' . basename($dir)]);
        exit;
    }
}

// ─── Inicializa banco de dados ────────────────────────────────
$db_path    = $client_dir . '/' . $slug . '.db3';
$senha_plain = gen_senha();
try {
    $db = new PDO('sqlite:' . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL');

    // Cria as tabelas mínimas necessárias para o primeiro acesso.
    // O api.php completo cria as demais tabelas + migrações na primeira requisição.
    $db->exec("CREATE TABLE IF NOT EXISTS empresa_dados (
        id              INTEGER PRIMARY KEY DEFAULT 1,
        nome            TEXT DEFAULT '',
        razao_social    TEXT DEFAULT '',
        telefone        TEXT DEFAULT '',
        endereco        TEXT DEFAULT '',
        logo_principal  TEXT DEFAULT '',
        logo_branca     TEXT DEFAULT '',
        favicon         TEXT DEFAULT ''
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS usuarios (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        nome         TEXT NOT NULL,
        email        TEXT DEFAULT '',
        senha        TEXT NOT NULL,
        nivel_acesso TEXT DEFAULT 'tecnico',
        ativo        INTEGER DEFAULT 1,
        data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Colunas de assinatura (adicionadas antes do UPDATE para evitar erro)
    foreach ([
        "ALTER TABLE empresa_dados ADD COLUMN mp_preapproval_id    TEXT DEFAULT ''",
        "ALTER TABLE empresa_dados ADD COLUMN plano_nome           TEXT DEFAULT ''",
        "ALTER TABLE empresa_dados ADD COLUMN plano_valor          REAL DEFAULT 0",
        "ALTER TABLE empresa_dados ADD COLUMN plano_data_inicio    TEXT DEFAULT ''",
        "ALTER TABLE empresa_dados ADD COLUMN plano_landing_url    TEXT DEFAULT ''",
        "ALTER TABLE empresa_dados ADD COLUMN plano_landing_secret TEXT DEFAULT ''",
        "ALTER TABLE empresa_dados ADD COLUMN plano_status         TEXT DEFAULT 'ativo'",
    ] as $sql) { try { $db->exec($sql); } catch (PDOException $e) {} }

    $db->exec("INSERT OR IGNORE INTO empresa_dados (id, nome) VALUES (1, 'Minha Empresa')");
    $db->prepare("UPDATE empresa_dados SET nome=?, razao_social=?, telefone=?,
        mp_preapproval_id=?, plano_nome=?, plano_valor=?, plano_data_inicio=?,
        plano_landing_url=?, plano_landing_secret=?, plano_status=? WHERE id=1")
       ->execute([$empresa ?: $nome, $empresa, $telefone,
                  $mp_preapproval_id, $plano, $plano_valor, $plano_data_inicio,
                  $plano_landing_url, $plano_landing_secret, 'ativo']);
    $db->prepare("INSERT INTO usuarios (nome, email, senha, nivel_acesso) VALUES (?,?,?,?)")
       ->execute([$nome, $email, password_hash($senha_plain, PASSWORD_DEFAULT), 'admin']);
} catch (PDOException $e) {
    cleanup($client_dir);
    http_response_code(500);
    echo json_encode(['error' => 'Erro ao inicializar banco: ' . $e->getMessage()]);
    exit;
}

// ─── Thin wrapper api.php ─────────────────────────────────────
$wrapper_api = <<<PHP
<?php
// Wrapper gerado automaticamente — não editar manualmente.
// Dados do cliente ficam em: storage/, uploads/, agtech.db3
// Código-fonte compartilhado em: ../{$master_name}/api.php
define('SAAS_DIR',     __DIR__);
define('SAAS_DB_PATH', __DIR__ . '/' . basename(__DIR__) . '.db3');
ini_set('session.name',        'CS_' . basename(__DIR__));
ini_set('session.cookie_path', '/' . basename(__DIR__) . '/');
require_once __DIR__ . '/../{$master_name}/api.php';
PHP;

// ─── .htaccess: protege arquivos sensíveis e serve estáticos do master ──
$htaccess = <<<'HTACCESS'
# Serve arquivos estáticos ausentes a partir do _master/
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.+\.(png|jpg|jpeg|gif|ico|svg|webp|woff2?|ttf|otf|eot|css|js|map))$ ../_master/$1 [L]

# Protege banco, logs e configuração
<FilesMatch "\.(db3|db|sqlite|log|lock)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
<FilesMatch "^(config|provisionar|deploy)\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

# Bloqueia execução de PHP/scripts dentro de uploads/ — impede RCE via upload
<IfModule mod_rewrite.c>
    RewriteRule ^uploads/.*\.(php[0-9]?|phtml|phar|shtml|cgi|pl|py|sh|rb|lua)$ - [F,L]
</IfModule>
<FilesMatch "^uploads/.*\.(php[0-9]?|phtml|phar|shtml|cgi|pl|py|sh|rb|lua)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>

Options -Indexes
HTACCESS;

// ─── Escreve arquivos do cliente ─────────────────────────────
$arquivos = [
    $client_dir . '/api.php'    => $wrapper_api,
    $client_dir . '/.htaccess'  => $htaccess,
];
foreach ($arquivos as $path => $content) {
    if (file_put_contents($path, $content) === false) {
        cleanup($client_dir);
        http_response_code(500);
        echo json_encode(['error' => 'Falha ao escrever: ' . basename($path)]);
        exit;
    }
}

// index.php: thin wrapper — serve o index.html do master em tempo real
file_put_contents($client_dir . '/index.php',
    '<?php header(\'Content-Type: text/html; charset=utf-8\'); readfile(__DIR__ . \'/../' . $master_dir_name . '/index.html\');' . "\n");

// Copia arquivos estáticos do master para o cliente
foreach (['politica.php', 'consulta.php', 'upload_mobile.php',
          'logo.png', 'logo_login.png', 'logo_sidebar.png', 'favicon.ico'] as $f) {
    $src = __DIR__ . '/' . $f;
    if (file_exists($src)) {
        copy($src, $client_dir . '/' . $f);
    }
}

// ─── Resposta ─────────────────────────────────────────────────
$url = base_url() . $slug . '/';
echo json_encode([
    'ok'        => true,
    'url'       => $url,
    'slug'      => $slug,
    'senha_temp' => $senha_plain,
], JSON_UNESCAPED_UNICODE);

// ═══════════════════════════════════════════════════════════════
// Funções auxiliares
// ═══════════════════════════════════════════════════════════════

function slug_sanitize(string $texto): string {
    $texto = mb_strtolower(trim($texto), 'UTF-8');
    $mapa  = [
        'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a',
        'é'=>'e','ê'=>'e','è'=>'e','ë'=>'e',
        'í'=>'i','î'=>'i','ì'=>'i','ï'=>'i',
        'ó'=>'o','ô'=>'o','õ'=>'o','ò'=>'o','ö'=>'o',
        'ú'=>'u','û'=>'u','ù'=>'u','ü'=>'u',
        'ç'=>'c','ñ'=>'n',
    ];
    $texto = strtr($texto, $mapa);
    $texto = preg_replace('/[^a-z0-9]+/', '-', $texto) ?? '';
    return trim($texto, '-');
}

function gen_senha(int $bytes = 6): string {
    return bin2hex(random_bytes($bytes)); // 12 chars hex
}

function base_url(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    // Remove /_master/provisionar.php do caminho para obter a URL raiz
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    $base   = rtrim(dirname(dirname($script)), '/') . '/';
    return $scheme . '://' . $host . $base;
}

function cleanup(string $dir): void {
    if (!is_dir($dir)) return;
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getRealPath()) : unlink($item->getRealPath());
    }
    rmdir($dir);
}
