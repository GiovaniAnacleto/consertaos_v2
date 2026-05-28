<?php
// =============================================================
// api.php — Backend único do consertaOS
// =============================================================

// Fuso horário fixo: Brasília (UTC-3)
date_default_timezone_set('America/Sao_Paulo');

set_exception_handler(function($e) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $e->getMessage(), 'file' => basename($e->getFile()), 'line' => $e->getLine()], JSON_UNESCAPED_UNICODE);
    exit;
});
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    throw new \ErrorException($errstr, $errno, 0, $errfile, $errline);
});

// ─── SESSÃO: configurar cookie seguro antes de session_start() ────
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
// LGPD: marcar cookie como Secure quando estiver em HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}
session_start();

// ─── LGPD: cabeçalhos de segurança ────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// ─── CONFIG (chaves de API e configurações sensíveis) ─────────
// SAAS_DIR: diretório de dados do cliente (uploads, storage, DB, config).
// Quando api.php é incluído via thin wrapper de um subfolder de cliente,
// SAAS_DIR é definido pelo wrapper apontando para a pasta do cliente.
// Quando rodado diretamente, usa o próprio diretório.
if (!defined('SAAS_DIR')) define('SAAS_DIR', __DIR__);
if (file_exists(SAAS_DIR . '/config.php')) {
    require_once SAAS_DIR . '/config.php';
}
date_default_timezone_set('America/Sao_Paulo');
header('Content-Type: application/json; charset=utf-8');

// ─── CORS: allowlist de origens autorizadas ───────────────────
// Apenas a mesma origem do servidor é autorizada a fazer requisições
// com credenciais (cookies de sessão). Refletir qualquer Origin seria
// uma vulnerabilidade crítica de CORS que permite roubo de sessão.
$_cors_scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$_cors_host   = $_SERVER['HTTP_HOST'] ?? '';
$_cors_allowed = array_filter([
    $_cors_scheme . '://' . $_cors_host,          // origem exata do servidor
    defined('SAAS_ALLOWED_ORIGIN') ? SAAS_ALLOWED_ORIGIN : '', // override por wrapper
]);
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && in_array($origin, $_cors_allowed, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
} elseif (!$origin) {
    // Requisição sem Origin (ex.: curl, Postman, chamadas server-to-server)
    // Não emite ACAO — o browser não enviaria credentials sem Origin de qualquer forma.
    header('Access-Control-Allow-Origin: ' . $_cors_scheme . '://' . $_cors_host);
}
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ─── HELPERS ─────────────────────────────────────────────────
function resp(int $code, $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Retorna o caminho absoluto do bundle de CAs (cacert.pem).
 *
 * O arquivo deve ser baixado de https://curl.se/ca/cacert.pem e enviado
 * para o mesmo diretório deste api.php (ou para o _master/ no multi-tenant).
 * Ele NÃO deve ser web-acessível — o .htaccess já bloqueia arquivos .pem.
 *
 * Por que isso é necessário na Locaweb (hospedagem compartilhada):
 *   O bundle de CAs do sistema (/etc/ssl/certs/ca-certificates.crt) pode
 *   estar desatualizado. Apontar para um cacert.pem gerenciado manualmente
 *   garante que a verificação TLS funcione sem precisar desabilitar a segurança.
 *
 * @return string|null  Caminho absoluto se o arquivo existir, null caso contrário.
 */
function ssl_cainfo(): ?string {
    // Procura primeiro na mesma pasta deste arquivo, depois na pasta pai (_master/)
    $candidates = [
        __DIR__ . '/cacert.pem',
        dirname(__DIR__) . '/cacert.pem',
    ];
    foreach ($candidates as $path) {
        if (file_exists($path) && is_readable($path)) return $path;
    }
    return null; // Deixa o PHP usar o bundle do sistema (pode falhar em hosts antigos)
}
function auth_required(): array {
    if (!isset($_SESSION['usuario']) || !is_array($_SESSION['usuario'])) {
        resp(401, ['error' => 'Não autenticado']);
    }
    return $_SESSION['usuario'];
}
function get_input(): array {
    $raw = (string)@file_get_contents('php://input');
    $json = ($raw !== '' && $raw !== false) ? (json_decode($raw, true) ?? []) : [];
    return array_merge($_POST, $json);
}

// ─── LGPD: helpers ────────────────────────────────────────────────
function lgpd_client_ip(): string {
    $headers = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'];
    foreach ($headers as $h) {
        if (!empty($_SERVER[$h])) {
            $ip = trim(explode(',', $_SERVER[$h])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '';
}
function admin_required(): array {
    $u = auth_required();
    if (($u['nivel_acesso'] ?? '') !== 'admin') {
        resp(403, ['error' => 'Acesso restrito a administradores']);
    }
    return $u;
}
function audit_log(PDO $db, string $acao, string $entidade = '', $entidade_id = null, array $detalhes = []): void {
    try {
        $u  = $_SESSION['usuario'] ?? null;
        $uid   = is_array($u) ? ($u['id']   ?? null) : null;
        $unome = is_array($u) ? ($u['nome'] ?? '')   : '';
        $ua = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
        $db->prepare("INSERT INTO auditoria_lgpd (usuario_id, usuario_nome, acao, entidade, entidade_id, detalhes, ip, user_agent, data_evento) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
           ->execute([
               $uid,
               $unome,
               $acao,
               $entidade,
               $entidade_id !== null ? (int)$entidade_id : null,
               $detalhes ? json_encode($detalhes, JSON_UNESCAPED_UNICODE) : '',
               lgpd_client_ip(),
               $ua,
               date('Y-m-d H:i:s'),
           ]);
    } catch (\Throwable $e) { /* nunca falha por causa de auditoria */ }
}
function mask_cpf(string $cpf): string {
    $d = preg_replace('/\D/', '', $cpf);
    if (strlen($d) === 11) return substr($d,0,3) . '.***.***-' . substr($d,-2);
    if (strlen($d) === 14) return substr($d,0,2) . '.***.***/****-' . substr($d,-2);
    return $cpf !== '' ? str_repeat('*', max(0, strlen($cpf)-2)) . substr($cpf,-2) : '';
}
function mask_email(string $email): string {
    if (!$email || strpos($email,'@') === false) return $email;
    [$u,$d] = explode('@', $email, 2);
    $u = $u !== '' ? mb_substr($u,0,2) . str_repeat('*', max(1, mb_strlen($u)-2)) : '';
    return $u . '@' . $d;
}
function mask_telefone(string $tel): string {
    $d = preg_replace('/\D/', '', $tel);
    if (strlen($d) < 4) return str_repeat('*', strlen($d));
    return str_repeat('*', strlen($d)-4) . substr($d,-4);
}

// ─── BANCO DE DADOS ──────────────────────────────────────────
$db_path = defined('SAAS_DB_PATH') ? SAAS_DB_PATH : SAAS_DIR . '/agtech.db3';
if (!is_writable(SAAS_DIR)) {
    resp(500, ['error' => 'Sem permissão de escrita no diretório: ' . SAAS_DIR]);
}
try {
    $db = new PDO('sqlite:' . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL');
} catch (PDOException $e) {
    resp(500, ['error' => 'Erro ao conectar: ' . $e->getMessage(), 'path' => $db_path]);
}

// ─── CREATE TABLES (uma por vez) ─────────────────────────────
$tables = [
"CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, email TEXT DEFAULT '', senha TEXT NOT NULL, nivel_acesso TEXT DEFAULT 'tecnico', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS empresa_dados (id INTEGER PRIMARY KEY DEFAULT 1, nome TEXT DEFAULT '', razao_social TEXT DEFAULT '', telefone TEXT DEFAULT '', endereco TEXT DEFAULT '', logo_principal TEXT DEFAULT '', logo_branca TEXT DEFAULT '', favicon TEXT DEFAULT '')",
"CREATE TABLE IF NOT EXISTS clientes (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, email TEXT DEFAULT '', telefone TEXT DEFAULT '', cpf TEXT DEFAULT '', endereco TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS tipos_aparelho (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS marcas (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS modelos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, marca_id INTEGER)",
"CREATE TABLE IF NOT EXISTS produtos (id INTEGER PRIMARY KEY AUTOINCREMENT, tipo_item TEXT DEFAULT 'produto', ativo INTEGER DEFAULT 1, codigo_interno TEXT DEFAULT '', codigo_barras TEXT DEFAULT '', descricao TEXT NOT NULL, descricao_complementar TEXT DEFAULT '', unidade_medida TEXT DEFAULT 'UN', unidade_compra TEXT DEFAULT '', fator_conversao REAL DEFAULT 1, preco_custo REAL DEFAULT 0, preco_venda REAL DEFAULT 0, margem_lucro REAL DEFAULT 0, percentual_desconto_max REAL DEFAULT 0, estoque_atual REAL DEFAULT 0, estoque_minimo REAL DEFAULT 0, estoque_maximo REAL DEFAULT 0, localizacao TEXT DEFAULT '', peso_liquido REAL DEFAULT 0, peso_bruto REAL DEFAULT 0, largura REAL DEFAULT 0, altura REAL DEFAULT 0, profundidade REAL DEFAULT 0, ncm TEXT DEFAULT '', cfop TEXT DEFAULT '', cest TEXT DEFAULT '', origem TEXT DEFAULT '0', cst_icms TEXT DEFAULT '', aliq_icms REAL DEFAULT 0, cst_pis TEXT DEFAULT '', aliq_pis REAL DEFAULT 0, cst_cofins TEXT DEFAULT '', aliq_cofins REAL DEFAULT 0, cst_ipi TEXT DEFAULT '', aliq_ipi REAL DEFAULT 0, percentual_comissao REAL DEFAULT 0, nfse_codigo_servico TEXT DEFAULT '', nfse_municipio TEXT DEFAULT '', nfse_cnae TEXT DEFAULT '', nfse_descricao_servico TEXT DEFAULT '', nfse_deducoes REAL DEFAULT 0, nfse_cofins REAL DEFAULT 0, nfse_ir REAL DEFAULT 0, nfse_outras_deducoes REAL DEFAULT 0, nfse_pis REAL DEFAULT 0, nfse_inss REAL DEFAULT 0, nfse_csll REAL DEFAULT 0, nfse_iss REAL DEFAULT 0, nfse_id_municipal_evento TEXT DEFAULT '', nfse_descricao_evento TEXT DEFAULT '', nfse_data_ini_evento TEXT DEFAULT '', nfse_data_fim_evento TEXT DEFAULT '', nfse_logradouro TEXT DEFAULT '', nfse_numero TEXT DEFAULT '', observacoes TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS produto_fornecedores (id INTEGER PRIMARY KEY AUTOINCREMENT, produto_id INTEGER NOT NULL, fornecedor_nome TEXT DEFAULT '', fornecedor_codigo TEXT DEFAULT '', preco_custo REAL DEFAULT 0, prazo_entrega INTEGER DEFAULT 0, principal INTEGER DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS produto_composicao (id INTEGER PRIMARY KEY AUTOINCREMENT, produto_id INTEGER NOT NULL, componente_id INTEGER, componente_descricao TEXT DEFAULT '', quantidade REAL DEFAULT 1, unidade TEXT DEFAULT 'UN')",
"CREATE TABLE IF NOT EXISTS ordens_servico (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, tipo_aparelho_id INTEGER, marca_id INTEGER, modelo_id INTEGER, descricao TEXT DEFAULT '', informacoes_adicionais TEXT DEFAULT '', senha_aparelho TEXT DEFAULT '', status TEXT DEFAULT 'Aberta', previsao_conclusao DATE, data_abertura DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS orcamentos (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, produto_id INTEGER DEFAULT NULL, observacoes TEXT DEFAULT '', valor REAL DEFAULT 0, status_orcamento TEXT DEFAULT 'Pendente')",
"CREATE TABLE IF NOT EXISTS orcamento_pecas (id INTEGER PRIMARY KEY AUTOINCREMENT, orcamento_id INTEGER NOT NULL, produto_id INTEGER NOT NULL, quantidade REAL DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS midias_os (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, caminho TEXT NOT NULL, tipo TEXT DEFAULT '', comentario TEXT DEFAULT '', data_upload DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS ordem_observacoes (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, usuario_id INTEGER, observacao TEXT NOT NULL, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS notificacoes (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER, novo_status TEXT DEFAULT '', lida INTEGER DEFAULT 0, data_notificacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_bancarias (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, banco TEXT DEFAULT '', agencia TEXT DEFAULT '', conta TEXT DEFAULT '', tipo TEXT DEFAULT 'corrente', ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS operadoras_cartao (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'credito', taxa_padrao REAL DEFAULT 0, prazo_repasse INTEGER DEFAULT 30, ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS formas_pagamento (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'dinheiro', modalidade TEXT DEFAULT 'a_vista', parcelas_padrao INTEGER DEFAULT 1, intervalo_dias INTEGER DEFAULT 30, juros_am REAL DEFAULT 0, taxa_fixa REAL DEFAULT 0, tipo_repeticao TEXT DEFAULT 'mensal', lancar_financeiro INTEGER DEFAULT 1, confirmar_auto INTEGER DEFAULT 0, conta_bancaria TEXT DEFAULT '', operadora TEXT DEFAULT '', taxa_operadora REAL DEFAULT 0, ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS vendas (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER, vendedor_id INTEGER, os_id INTEGER, cpf_cnpj TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_confirmacao DATETIME, status TEXT DEFAULT 'Digitação', total REAL DEFAULT 0, desconto_valor REAL DEFAULT 0, desconto_percentual REAL DEFAULT 0, desconto_tipo TEXT DEFAULT 'valor', acrescimo_valor REAL DEFAULT 0, acrescimo_percentual REAL DEFAULT 0, acrescimo_tipo TEXT DEFAULT 'valor', valor_frete REAL DEFAULT 0, observacoes TEXT DEFAULT '')",
"CREATE TABLE IF NOT EXISTS venda_faturamentos (id INTEGER PRIMARY KEY AUTOINCREMENT, venda_id INTEGER NOT NULL, forma_pagamento_id INTEGER, forma_pagamento_nome TEXT DEFAULT '', valor_total REAL DEFAULT 0, valor_pago REAL DEFAULT 0, num_parcelas INTEGER DEFAULT 1, data_primeira_parcela DATE, intervalo_dias INTEGER DEFAULT 30, juros_am REAL DEFAULT 0, taxa_fixa REAL DEFAULT 0, tipo_repeticao TEXT DEFAULT 'mensal', observacoes TEXT DEFAULT '')",
"CREATE TABLE IF NOT EXISTS venda_parcelas (id INTEGER PRIMARY KEY AUTOINCREMENT, faturamento_id INTEGER NOT NULL, venda_id INTEGER, numero INTEGER DEFAULT 1, valor REAL DEFAULT 0, valor_juros REAL DEFAULT 0, valor_taxa REAL DEFAULT 0, data_vencimento DATE, data_pagamento DATE, status TEXT DEFAULT 'Aberta')",
"CREATE TABLE IF NOT EXISTS venda_items (id INTEGER PRIMARY KEY AUTOINCREMENT, venda_id INTEGER, produto_id INTEGER, descricao TEXT DEFAULT '', quantidade REAL DEFAULT 1, valor_unitario REAL DEFAULT 0, desconto_valor REAL DEFAULT 0, desconto_percentual REAL DEFAULT 0, acrescimo_valor REAL DEFAULT 0, subtotal REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS fornecedores (id INTEGER PRIMARY KEY AUTOINCREMENT, razao_social TEXT NOT NULL, nome_fantasia TEXT DEFAULT '', cpf_cnpj TEXT DEFAULT '', telefone TEXT DEFAULT '', email TEXT DEFAULT '', endereco TEXT DEFAULT '', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS tabelas_preco (id INTEGER PRIMARY KEY AUTOINCREMENT, produto_id INTEGER NOT NULL, nome TEXT NOT NULL, margem_lucro REAL DEFAULT 0, preco_venda REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS ncm_tabela (id INTEGER PRIMARY KEY AUTOINCREMENT, codigo TEXT NOT NULL UNIQUE, descricao TEXT NOT NULL, aliq_ii REAL DEFAULT 0, aliq_ipi REAL DEFAULT 0, aliq_pis REAL DEFAULT 0, aliq_cofins REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS ibpt (ncm TEXT NOT NULL, ex TEXT NOT NULL DEFAULT '', tipo INTEGER NOT NULL DEFAULT 0, descricao TEXT DEFAULT '', nacional REAL DEFAULT 0, importado REAL DEFAULT 0, estadual REAL DEFAULT 0, municipal REAL DEFAULT 0, uf TEXT NOT NULL DEFAULT '', vigencia_inicio TEXT DEFAULT '', vigencia_fim TEXT DEFAULT '', PRIMARY KEY (ncm, ex, tipo, uf))",
"CREATE TABLE IF NOT EXISTS cest_tabela (id INTEGER PRIMARY KEY AUTOINCREMENT, cest TEXT NOT NULL, ncm TEXT NOT NULL, descricao TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS tabelas_servico (id INTEGER PRIMARY KEY AUTOINCREMENT, codigo TEXT NOT NULL, descricao TEXT NOT NULL, cnae TEXT DEFAULT '', cod_trib_municipio TEXT DEFAULT '', aliq_iss REAL DEFAULT 0, cst_pis TEXT DEFAULT '01', aliq_pis REAL DEFAULT 0, cst_cofins TEXT DEFAULT '01', aliq_cofins REAL DEFAULT 0, ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS notas_fiscais_entrada (id INTEGER PRIMARY KEY AUTOINCREMENT, numero TEXT DEFAULT '', serie TEXT DEFAULT '', chave_acesso TEXT NOT NULL DEFAULT '', fornecedor_id INTEGER, fornecedor_nome TEXT DEFAULT '', fornecedor_cnpj TEXT DEFAULT '', data_emissao DATE, data_entrada DATE, valor_total REAL DEFAULT 0, valor_bc_icms REAL DEFAULT 0, valor_icms REAL DEFAULT 0, valor_bc_icms_st REAL DEFAULT 0, valor_icms_st REAL DEFAULT 0, valor_ii REAL DEFAULT 0, valor_pis_st REAL DEFAULT 0, valor_cofins_st REAL DEFAULT 0, comple_icms REAL DEFAULT 0, valor_liquido REAL DEFAULT 0, valor_servico REAL DEFAULT 0, valor_ipi REAL DEFAULT 0, valor_pis REAL DEFAULT 0, valor_cofins REAL DEFAULT 0, valor_frete REAL DEFAULT 0, valor_desconto REAL DEFAULT 0, status TEXT DEFAULT 'Recebida', observacoes TEXT DEFAULT '', xml_conteudo TEXT DEFAULT '', data_importacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS nfe_items (id INTEGER PRIMARY KEY AUTOINCREMENT, nfe_id INTEGER NOT NULL, codigo_produto TEXT DEFAULT '', descricao TEXT NOT NULL, ncm TEXT DEFAULT '', cfop TEXT DEFAULT '', unidade TEXT DEFAULT 'UN', quantidade REAL DEFAULT 1, valor_unitario REAL DEFAULT 0, valor_total REAL DEFAULT 0, valor_icms REAL DEFAULT 0, valor_ipi REAL DEFAULT 0, valor_pis REAL DEFAULT 0, valor_cofins REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS nfce_emitidas (id INTEGER PRIMARY KEY AUTOINCREMENT, os_id INTEGER, venda_id INTEGER, n_prot TEXT DEFAULT '', status TEXT DEFAULT 'Aguardando', numero TEXT DEFAULT '', serie TEXT DEFAULT '', chave_acesso TEXT DEFAULT '', valor_total REAL DEFAULT 0, danfe_url TEXT DEFAULT '', xml_url TEXT DEFAULT '', motivo_rejeicao TEXT DEFAULT '', ambiente TEXT DEFAULT 'Homologacao', payload_json TEXT DEFAULT '', data_emissao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS nfse_emitidas (id INTEGER PRIMARY KEY AUTOINCREMENT, os_id INTEGER, venda_id INTEGER, status TEXT DEFAULT 'Aguardando', numero TEXT DEFAULT '', serie TEXT DEFAULT '1', codigo_verificacao TEXT DEFAULT '', valor_total REAL DEFAULT 0, link_pdf TEXT DEFAULT '', motivo_rejeicao TEXT DEFAULT '', ambiente TEXT DEFAULT 'homologacao', payload_json TEXT DEFAULT '', cliente_nome TEXT DEFAULT '', cliente_cpfcnpj TEXT DEFAULT '', data_emissao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
// ── NF-e (modelo 55) ────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS nfe_emitidas (id INTEGER PRIMARY KEY AUTOINCREMENT, os_id INTEGER, venda_id INTEGER, n_prot TEXT DEFAULT '', status TEXT DEFAULT 'Aguardando', numero INTEGER DEFAULT 0, serie INTEGER DEFAULT 1, chave_acesso TEXT DEFAULT '', valor_total REAL DEFAULT 0, danfe_url TEXT DEFAULT '', xml_url TEXT DEFAULT '', motivo_rejeicao TEXT DEFAULT '', ambiente TEXT DEFAULT 'homologacao', payload_json TEXT DEFAULT '{}', dest_nome TEXT DEFAULT '', dest_cpfcnpj TEXT DEFAULT '', dest_uf TEXT DEFAULT '', natop TEXT DEFAULT 'VENDA DE MERCADORIA', data_emissao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS uploads_temporarios (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, os_id INTEGER, status TEXT DEFAULT 'pendente', data_expiracao DATETIME)",
"CREATE TABLE IF NOT EXISTS reset_senha_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario_id INTEGER NOT NULL, token TEXT NOT NULL UNIQUE, expiracao DATETIME NOT NULL, usado INTEGER DEFAULT 0, criado_em DATETIME DEFAULT CURRENT_TIMESTAMP)",
// ── FINANCEIRO ──────────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS categorias_financeiras (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'ambos', cor TEXT DEFAULT '#7d8590', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_receber (id INTEGER PRIMARY KEY AUTOINCREMENT, origem TEXT DEFAULT 'manual', venda_id INTEGER, parcela_id INTEGER, cliente_id INTEGER, categoria_id INTEGER, conta_bancaria_id INTEGER, descricao TEXT NOT NULL, valor REAL DEFAULT 0, valor_recebido REAL DEFAULT 0, data_emissao DATE, data_vencimento DATE, data_recebimento DATE, status TEXT DEFAULT 'Aberta', documento_ref TEXT DEFAULT '', observacoes TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_pagar (id INTEGER PRIMARY KEY AUTOINCREMENT, origem TEXT DEFAULT 'manual', nfe_id INTEGER, fornecedor_id INTEGER, cliente_id INTEGER, categoria_id INTEGER, conta_bancaria_id INTEGER, descricao TEXT NOT NULL, valor REAL DEFAULT 0, valor_pago REAL DEFAULT 0, data_emissao DATE, data_vencimento DATE, data_pagamento DATE, status TEXT DEFAULT 'Aberta', documento_ref TEXT DEFAULT '', observacoes TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
// ── LOJA VIRTUAL ────────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS loja_categorias (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, descricao TEXT DEFAULT '', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS produto_loja (id INTEGER PRIMARY KEY AUTOINCREMENT, produto_id INTEGER NOT NULL UNIQUE, loja_exibir INTEGER DEFAULT 0, loja_titulo TEXT DEFAULT '', loja_descricao TEXT DEFAULT '', loja_categoria_id INTEGER, loja_fotos TEXT DEFAULT '[]', loja_variacoes TEXT DEFAULT '[]', data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
// ── FUNCIONÁRIOS ────────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS cargos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS funcionarios (id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT DEFAULT 'Ativo', nome TEXT NOT NULL, cpf TEXT DEFAULT '', data_nascimento DATE, telefone TEXT DEFAULT '', cargo_id INTEGER, carga_horaria_semanal REAL DEFAULT 0, salario_mensal REAL DEFAULT 0, valor_hora REAL DEFAULT 0, comissao_venda_ativo INTEGER DEFAULT 0, comissao_venda_percentual REAL DEFAULT 0, comissao_servico_ativo INTEGER DEFAULT 0, comissao_servico_percentual REAL DEFAULT 0, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
// ── LGPD ────────────────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS auditoria_lgpd (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario_id INTEGER, usuario_nome TEXT DEFAULT '', acao TEXT NOT NULL, entidade TEXT DEFAULT '', entidade_id INTEGER, detalhes TEXT DEFAULT '', ip TEXT DEFAULT '', user_agent TEXT DEFAULT '', data_evento DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS consentimentos_lgpd (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER, identificador TEXT DEFAULT '', finalidade TEXT DEFAULT 'cadastro', politica_versao TEXT DEFAULT '', aceito INTEGER DEFAULT 1, ip TEXT DEFAULT '', user_agent TEXT DEFAULT '', origem TEXT DEFAULT '', data_evento DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS politica_privacidade (id INTEGER PRIMARY KEY AUTOINCREMENT, versao TEXT NOT NULL, conteudo TEXT NOT NULL, ativo INTEGER DEFAULT 0, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
];
foreach ($tables as $sql) {
    try { $db->exec($sql); }
    catch (PDOException $e) { resp(500, ['error' => 'Erro ao criar tabela: ' . $e->getMessage()]); }
}

$db->exec("INSERT OR IGNORE INTO empresa_dados (id, nome) VALUES (1, 'Minha Empresa')");

// ─── MIGRAÇÕES: adiciona colunas que podem não existir no banco antigo ─────
$migrations = [
    // tabela           coluna              definição SQL
    ['usuarios',        'ativo',            'INTEGER DEFAULT 1'],
    ['usuarios',        'email',            "TEXT DEFAULT ''"],
    ['usuarios',        'data_criacao',     'DATETIME'],
    ['usuarios',        'funcionario_id',   'INTEGER DEFAULT NULL'],
    ['cargos',          'tecnico',          'INTEGER DEFAULT 0'],
    ['cargos',          'atendente',        'INTEGER DEFAULT 0'],
    ['cargos',          'vendedor',         'INTEGER DEFAULT 0'],
    ['notas_fiscais_entrada','fornecedor_id',  'INTEGER DEFAULT NULL'],
    ['notas_fiscais_entrada','valor_bc_icms',  'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_bc_icms_st','REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_icms_st',  'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_ii',       'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_pis_st',   'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_cofins_st','REAL DEFAULT 0'],
    ['notas_fiscais_entrada','comple_icms',    'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_liquido',  'REAL DEFAULT 0'],
    ['notas_fiscais_entrada','valor_servico',  'REAL DEFAULT 0'],
    ['empresa_dados',        'cnpj',           "TEXT DEFAULT ''"],
    ['empresa_dados',        'nfce_csc',       "TEXT DEFAULT ''"],
    ['empresa_dados',        'nfce_cmun',      "TEXT DEFAULT ''"],
    ['nfce_emitidas',         'n_prot',         "TEXT DEFAULT ''"],
    ['nfce_emitidas',         'cliente_nome',   "TEXT DEFAULT ''"],
    ['nfce_emitidas',         'cfop',           "TEXT DEFAULT '5949'"],
    ['nfce_emitidas',         'serie',          "TEXT DEFAULT '1'"],
    ['nfce_emitidas',         'data_envio',     "DATETIME DEFAULT NULL"],
    ['nfce_emitidas',         'os_vinculada',   "TEXT DEFAULT ''"],
    ['empresa_dados',        'nfce_cuf',       "TEXT DEFAULT '42'"],
    ['empresa_dados',        'nfce_cert_senha',"TEXT DEFAULT ''"],
    ['empresa_dados',        'nfce_csc_id',    "TEXT DEFAULT '01'"],
    ['empresa_dados',        'nfce_ambiente',  "TEXT DEFAULT 'homologacao'"],
    ['empresa_dados',        'nfce_serie',     "TEXT DEFAULT '1'"],
    ['empresa_dados',        'nfce_proximo_numero', "INTEGER DEFAULT 1"],
    // ── NFS-e (IPM/Atende.Net) ──────────────────────────────────────────────
    ['empresa_dados',        'nfse_usuario',         "TEXT DEFAULT ''"],      // CNPJ do prestador (login IPM)
    ['empresa_dados',        'nfse_senha',           "TEXT DEFAULT ''"],      // senha do portal da prefeitura
    ['empresa_dados',        'nfse_cidade_tom',      "TEXT DEFAULT '8416'"], // código TOM de Chapadão do Lageado/SC confirmado
    ['empresa_dados',        'nfse_serie',           "TEXT DEFAULT '1'"],     // série padrão confirmada: 1
    ['empresa_dados',        'nfse_ambiente',        "TEXT DEFAULT 'homologacao'"],
    ['empresa_dados',        'nfse_proximo_numero',  "INTEGER DEFAULT 1"],
    ['empresa_dados',        'nfse_usa_unidade',     "INTEGER DEFAULT 0"],    // 1=envia bloco unidade no XML, 0=omite
    ['empresa_dados',        'enotas_api_key', "TEXT DEFAULT ''"],
    ['empresa_dados',        'enotas_empresa_id', "TEXT DEFAULT ''"],
    ['empresa_dados',        'enotas_ambiente', "TEXT DEFAULT 'Homologacao'"],
    ['empresa_dados',        'ie',             "TEXT DEFAULT ''"],
    ['empresa_dados',        'im',             "TEXT DEFAULT ''"],
    ['empresa_dados',        'regime_tributario', "TEXT DEFAULT 'SimplesNacional'"],
    ['empresa_dados',        'cep',            "TEXT DEFAULT ''"],
    ['empresa_dados',        'logradouro',     "TEXT DEFAULT ''"],
    ['empresa_dados',        'numero',         "TEXT DEFAULT ''"],
    ['empresa_dados',        'complemento',    "TEXT DEFAULT ''"],
    ['empresa_dados',        'bairro',         "TEXT DEFAULT ''"],
    ['empresa_dados',        'cidade',         "TEXT DEFAULT ''"],
    ['empresa_dados',        'uf',             "TEXT DEFAULT 'SC'"],
    ['empresa_dados',        'certificado_pfx',"TEXT DEFAULT ''"],
    ['empresa_dados',        'certificado_nome',"TEXT DEFAULT ''"],
    ['empresa_dados',        'certificado_validade',"TEXT DEFAULT ''"],
    ['empresa_dados',   'razao_social',     "TEXT DEFAULT ''"],
    ['empresa_dados',   'logo_principal',   "TEXT DEFAULT ''"],
    ['empresa_dados',   'logo_branca',      "TEXT DEFAULT ''"],
    ['empresa_dados',   'favicon',          "TEXT DEFAULT ''"],
    ['empresa_dados',   'telefone',         "TEXT DEFAULT ''"],
    ['empresa_dados',   'endereco',         "TEXT DEFAULT ''"],
    // ── Migrações financeiro ─────────────────────────────────────────────
    ['contas_receber',  'parcela_id',       'INTEGER'],
    ['contas_receber',  'valor_recebido',   'REAL DEFAULT 0'],
    ['contas_receber',  'conta_bancaria_id','INTEGER'],
    ['contas_receber',  'documento_ref',    "TEXT DEFAULT ''"],
    ['contas_receber',  'cliente_nome_manual', "TEXT DEFAULT ''"],
    ['contas_pagar',    'valor_pago',       'REAL DEFAULT 0'],
    ['contas_pagar',    'conta_bancaria_id','INTEGER'],
    ['contas_pagar',    'documento_ref',    "TEXT DEFAULT ''"],
    ['contas_pagar',    'cliente_id',       'INTEGER'],
    ['venda_items',     'descricao',        "TEXT DEFAULT ''"],
    ['orcamentos',      'produto_id',       'INTEGER DEFAULT NULL'],
    ['ordens_servico',  'informacoes_adicionais', "TEXT DEFAULT ''"],
    ['ordens_servico',  'senha_aparelho',   "TEXT DEFAULT ''"],
    ['ordens_servico',  'previsao_conclusao', 'DATE'],
    ['ordens_servico',  'data_atualizacao', 'DATETIME'],
    ['orcamentos',      'status_orcamento', "TEXT DEFAULT 'Pendente'"],
    ['midias_os',       'comentario',       "TEXT DEFAULT ''"],
    ['midias_os',       'tipo',             "TEXT DEFAULT ''"],
    ['ordem_observacoes','usuario_id',      'INTEGER'],
    ['ordem_observacoes','data_criacao',    'DATETIME'],
    ['orcamentos',       'data_criacao',    'DATETIME'],
    ['orcamentos',       'peca_id',         'INTEGER DEFAULT NULL'],
    ['midias_os',        'data_upload',     'DATETIME'],
    ['clientes',         'data_criacao',    'DATETIME'],
    ['clientes',         'ativo',           'INTEGER DEFAULT 1'],
    ['clientes',         'telefone_secundario',  "TEXT DEFAULT ''"],
    ['clientes',         'tipo_pessoa',          "TEXT DEFAULT 'fisica'"],
    ['clientes',         'cnpj',                 "TEXT DEFAULT ''"],
    ['clientes',         'inscricao_estadual',   "TEXT DEFAULT ''"],
    ['clientes',         'cep',                  "TEXT DEFAULT ''"],
    ['clientes',         'logradouro',           "TEXT DEFAULT ''"],
    ['clientes',         'numero',               "TEXT DEFAULT ''"],
    ['clientes',         'complemento',          "TEXT DEFAULT ''"],
    ['clientes',         'bairro',               "TEXT DEFAULT ''"],
    ['clientes',         'cidade',               "TEXT DEFAULT ''"],
    ['clientes',         'cod_ibge',             "TEXT DEFAULT ''"],
    ['clientes',         'uf',                   "TEXT DEFAULT ''"],
    // ── LGPD: consentimento e anonimização ─────────────────────────
    ['clientes',         'consentimento_data',    'DATETIME'],
    ['clientes',         'consentimento_ip',      "TEXT DEFAULT ''"],
    ['clientes',         'consentimento_versao',  "TEXT DEFAULT ''"],
    ['clientes',         'anonimizado',           'INTEGER DEFAULT 0'],
    ['clientes',         'anonimizado_data',      'DATETIME'],
    ['empresa_dados',    'dpo_nome',              "TEXT DEFAULT ''"],
    ['empresa_dados',    'dpo_email',             "TEXT DEFAULT ''"],
    ['empresa_dados',    'dpo_telefone',          "TEXT DEFAULT ''"],
    ['empresa_dados',    'politica_versao_atual', "TEXT DEFAULT ''"],
    ['nfe_emitidas',     'rascunho_dados',        "TEXT DEFAULT ''"],
    ['nfe_emitidas',     'data_atualizacao',      "TEXT DEFAULT ''"],
    ['ordens_servico',   'checklist',            "TEXT DEFAULT ''"],
    ['ordens_servico',   'data_abertura',   'DATETIME'],
    ['ordens_servico',   'data_atualizacao','DATETIME'],
    ['produtos',         'data_criacao',    'DATETIME'],
    ['produtos',         'data_atualizacao','DATETIME'],
    ['produtos',         'ativo',           'INTEGER DEFAULT 1'],
    ['produtos',         'codigo_interno',  "TEXT DEFAULT ''"],
    ['produtos',         'codigo_barras',   "TEXT DEFAULT ''"],
    ['produtos',         'unidade_medida',  "TEXT DEFAULT 'UN'"],
    ['produtos',         'preco_custo',     'REAL DEFAULT 0'],
    ['produtos',         'estoque_atual',          'REAL DEFAULT 0'],
    ['produtos',         'descricao_complementar', "TEXT DEFAULT ''"],
    ['produtos',         'unidade_compra',          "TEXT DEFAULT ''"],
    ['produtos',         'fator_conversao',         'REAL DEFAULT 1'],
    ['produtos',         'margem_lucro',             'REAL DEFAULT 0'],
    ['produtos',         'percentual_desconto_max', 'REAL DEFAULT 0'],
    ['produtos',         'estoque_minimo',           'REAL DEFAULT 0'],
    ['produtos',         'estoque_maximo',           'REAL DEFAULT 0'],
    ['produtos',         'localizacao',              "TEXT DEFAULT ''"],
    ['produtos',         'peso_liquido',             'REAL DEFAULT 0'],
    ['produtos',         'peso_bruto',               'REAL DEFAULT 0'],
    ['produtos',         'largura',                  'REAL DEFAULT 0'],
    ['produtos',         'altura',                   'REAL DEFAULT 0'],
    ['produtos',         'profundidade',             'REAL DEFAULT 0'],
    ['produtos',         'ncm',                      "TEXT DEFAULT ''"],
    ['produtos',         'cfop',                     "TEXT DEFAULT ''"],
    ['produtos',         'cest',                     "TEXT DEFAULT ''"],
    ['produtos',         'origem',                   "TEXT DEFAULT '0'"],
    ['produtos',         'csosn',                    "TEXT DEFAULT '102'"],
    ['produtos',         'cst_icms',                 "TEXT DEFAULT ''"],
    ['produtos',         'aliq_icms',                'REAL DEFAULT 0'],
    ['produtos',         'cst_pis',                  "TEXT DEFAULT ''"],
    ['produtos',         'aliq_pis',                 'REAL DEFAULT 0'],
    ['produtos',         'cst_cofins',               "TEXT DEFAULT ''"],
    ['produtos',         'aliq_cofins',              'REAL DEFAULT 0'],
    ['produtos',         'cst_ipi',                  "TEXT DEFAULT ''"],
    ['produtos',         'aliq_ipi',                 'REAL DEFAULT 0'],
    ['produtos',         'percentual_comissao',      'REAL DEFAULT 0'],
    ['produtos',         'nfse_codigo_servico',      "TEXT DEFAULT ''"],
    ['produtos',         'nfse_municipio',           "TEXT DEFAULT ''"],
    ['produtos',         'nfse_cnae',                "TEXT DEFAULT ''"],
    ['produtos',         'nfse_descricao_servico',   "TEXT DEFAULT ''"],
    ['produtos',         'nfse_deducoes',            'REAL DEFAULT 0'],
    ['produtos',         'nfse_cofins',              'REAL DEFAULT 0'],
    ['produtos',         'nfse_ir',                  'REAL DEFAULT 0'],
    ['produtos',         'nfse_outras_deducoes',     'REAL DEFAULT 0'],
    ['produtos',         'nfse_pis',                 'REAL DEFAULT 0'],
    ['produtos',         'nfse_inss',                'REAL DEFAULT 0'],
    ['produtos',         'nfse_csll',                'REAL DEFAULT 0'],
    ['produtos',         'nfse_iss',                 'REAL DEFAULT 0'],
    ['produtos',         'nfse_id_municipal_evento', "TEXT DEFAULT ''"],
    ['produtos',         'nfse_descricao_evento',    "TEXT DEFAULT ''"],
    ['produtos',         'nfse_data_ini_evento',     "TEXT DEFAULT ''"],
    ['produtos',         'nfse_data_fim_evento',     "TEXT DEFAULT ''"],
    ['produtos',         'nfse_logradouro',          "TEXT DEFAULT ''"],
    ['produtos',         'nfse_numero',              "TEXT DEFAULT ''"],
    ['produtos',         'observacoes',              "TEXT DEFAULT ''"],
    ['tabelas_servico',  'cnae',            "TEXT DEFAULT ''"],
    ['tabelas_servico',  'cod_trib_municipio', "TEXT DEFAULT ''"],
    ['tabelas_servico',  'cst_pis',         "TEXT DEFAULT '01'"],
    ['tabelas_servico',  'aliq_pis',        'REAL DEFAULT 0'],
    ['tabelas_servico',  'cst_cofins',      "TEXT DEFAULT '01'"],
    ['tabelas_servico',  'aliq_cofins',     'REAL DEFAULT 0'],
    ['produtos',         'nfse_movimenta',           'INTEGER DEFAULT 0'],
    ['produtos',         'tabela_servico_id',         'INTEGER DEFAULT NULL'],
    ['produtos',         'codigo_nbs',               "TEXT DEFAULT ''"],
    ['produtos',         'iss_percentual',           'REAL DEFAULT 0'],
    ['produtos',         'nfse_natureza',            "TEXT DEFAULT 'tributacao_municipio'"],
    ['produtos',         'nfse_unidade_codigo',      "TEXT DEFAULT '64'"],  // código IPM da unidade (64=UN, 30=HR)
    ['nfse_emitidas',    'serie',                    "TEXT DEFAULT '1'"],    // série corrigida: 1
    ['produtos',         'nfse_incentivo_fiscal',    "TEXT DEFAULT 'nao'"],
    ['produtos',         'despesas_acessorias',      'REAL DEFAULT 0'],
    ['produtos',         'outras_despesas',          'REAL DEFAULT 0'],
    ['produtos',         'custo_final',              'REAL DEFAULT 0'],
    ['produtos',         'percentual_comissao',      'REAL DEFAULT 0'],
    ['produtos',         'estoque_imobilizado',      'REAL DEFAULT 0'],
    ['produtos',         'estoque_uso_consumo',      'REAL DEFAULT 0'],
    ['produtos',         'estoque_revenda',          'REAL DEFAULT 0'],
    ['produtos',         'unidade_saida',            "TEXT DEFAULT ''"],
    ['produtos',         'ncm_descricao',            "TEXT DEFAULT ''"],
    ['produtos',         'condicao_peca',             "TEXT DEFAULT 'nova_original'"],
    ['produtos',         'garantia_fornecedor',        'INTEGER DEFAULT 0'],
    ['produtos',         'garantia_fornecedor_unidade',"TEXT DEFAULT 'meses'"],
    ['produtos',         'garantia_venda',             'INTEGER DEFAULT 0'],
    ['produtos',         'garantia_venda_unidade',     "TEXT DEFAULT 'meses'"],
    ['produtos',         'capacidade_mah',             'INTEGER DEFAULT 0'],
    ['produtos',         'voltagem',                   "TEXT DEFAULT ''"],
    ['produtos',         'tipo_tela',                  "TEXT DEFAULT ''"],
    ['produtos',         'part_number',                "TEXT DEFAULT ''"],
    ['produtos',         'fotos',                      "TEXT DEFAULT '[]'"],
    ['vendas',           'desconto_valor',  'REAL DEFAULT 0'],
    ['vendas',           'desconto_percentual','REAL DEFAULT 0'],
    ['vendas',           'acrescimo_valor', 'REAL DEFAULT 0'],
    ['vendas',           'acrescimo_percentual','REAL DEFAULT 0'],
    ['vendas',           'valor_frete',     'REAL DEFAULT 0'],
    ['vendas',           'os_id',           'INTEGER'],
    ['vendas',           'cpf_cnpj',        "TEXT DEFAULT ''"],
    ['vendas',           'data_criacao',    'DATETIME'],
    ['vendas',           'data_confirmacao','DATETIME'],
    ['vendas',           'desconto_tipo',   "TEXT DEFAULT 'valor'"],
    ['vendas',           'acrescimo_tipo',  "TEXT DEFAULT 'valor'"],
    ['formas_pagamento', 'parcelas_padrao', 'INTEGER'],
    ['formas_pagamento', 'intervalo_dias',  'INTEGER'],
    ['formas_pagamento', 'juros_am',        'REAL'],
    ['formas_pagamento', 'taxa_fixa',       'REAL'],
    ['formas_pagamento', 'tipo_repeticao',  "TEXT DEFAULT 'mensal'"],
    ['formas_pagamento', 'ativo',           'INTEGER'],
    ['formas_pagamento', 'modalidade',      "TEXT DEFAULT 'a_vista'"],
    ['formas_pagamento', 'lancar_financeiro','INTEGER DEFAULT 1'],
    ['formas_pagamento', 'confirmar_auto',  'INTEGER DEFAULT 0'],
    ['formas_pagamento', 'conta_bancaria',  "TEXT DEFAULT ''"],
    ['formas_pagamento', 'operadora',       "TEXT DEFAULT ''"],
    ['formas_pagamento', 'taxa_operadora',  'REAL DEFAULT 0'],
    // ── Migrações contas_bancarias ───────────────────────────────────────
    ['contas_bancarias', 'banco',   "TEXT DEFAULT ''"],
    ['contas_bancarias', 'agencia', "TEXT DEFAULT ''"],
    ['contas_bancarias', 'conta',   "TEXT DEFAULT ''"],
    ['contas_bancarias', 'tipo',    "TEXT DEFAULT 'corrente'"],
    ['contas_bancarias', 'ativo',   'INTEGER DEFAULT 1'],
    // ── Migrações Loja Virtual ────────────────────────────────────────────────
    ['produto_loja', 'loja_exibir',       'INTEGER DEFAULT 0'],
    ['produto_loja', 'loja_titulo',        "TEXT DEFAULT ''"],
    ['produto_loja', 'loja_descricao',     "TEXT DEFAULT ''"],
    ['produto_loja', 'loja_categoria_id',  'INTEGER'],
    ['produto_loja', 'loja_fotos',         "TEXT DEFAULT '[]'"],
    ['produto_loja', 'loja_variacoes',     "TEXT DEFAULT '[]'"],
    ['produto_loja', 'loja_destaque',      'INTEGER DEFAULT 0'],
    ['produto_loja', 'data_atualizacao',   'DATETIME'],
    ['loja_categorias', 'descricao',       "TEXT DEFAULT ''"],
    ['loja_categorias', 'ativo',           'INTEGER DEFAULT 1'],
    // ── NF-e (modelo 55) ─────────────────────────────────────────────────────
    ['empresa_dados', 'nfe_ambiente',        "TEXT DEFAULT 'homologacao'"],
    ['empresa_dados', 'nfe_serie',           "TEXT DEFAULT '1'"],
    ['empresa_dados', 'nfe_proximo_numero',  "INTEGER DEFAULT 1"],
    // ── Aparência da Loja Virtual ─────────────────────────────────────────────
    ['empresa_dados', 'loja_logo',          "TEXT DEFAULT ''"],
    ['empresa_dados', 'loja_logo_pos',      "TEXT DEFAULT '50% 50%'"],
    ['empresa_dados', 'loja_capa',          "TEXT DEFAULT ''"],
    ['empresa_dados', 'loja_capa_pos',      "TEXT DEFAULT '50% 50%'"],
    ['empresa_dados', 'loja_nome',          "TEXT DEFAULT ''"],
    ['empresa_dados', 'loja_boas_vindas',   "TEXT DEFAULT ''"],
    ['empresa_dados', 'loja_formato',       "TEXT DEFAULT 'grade'"],
    ['empresa_dados', 'loja_exibir_precos', "INTEGER DEFAULT 1"],
    ['empresa_dados', 'loja_slug',          "TEXT DEFAULT ''"],
    ['ordens_servico', 'tecnico_id',        'INTEGER DEFAULT NULL'],
    // ── Meu Plano / assinatura ────────────────────────────────────
    ['empresa_dados', 'mp_preapproval_id',    "TEXT DEFAULT ''"],
    ['empresa_dados', 'plano_nome',           "TEXT DEFAULT ''"],
    ['empresa_dados', 'plano_valor',          'REAL DEFAULT 0'],
    ['empresa_dados', 'plano_data_inicio',    "TEXT DEFAULT ''"],
    ['empresa_dados', 'plano_landing_url',    "TEXT DEFAULT ''"],
    ['empresa_dados', 'plano_landing_secret', "TEXT DEFAULT ''"],
    ['empresa_dados', 'plano_status',         "TEXT DEFAULT 'ativo'"],
];
foreach ($migrations as [$tbl, $col, $def]) {
    try {
        $cols = $db->query("PRAGMA table_info({$tbl})")->fetchAll();
        $exists = false;
        foreach ($cols as $c) { if ($c['name'] === $col) { $exists = true; break; } }
        if (!$exists && count($cols) > 0) { // only alter if table actually exists
            $db->exec("ALTER TABLE {$tbl} ADD COLUMN {$col} {$def}");
        }
    } catch (PDOException $e) { /* ignore — column may already exist or table missing */ }
}

// Garante que usuários antigos sem coluna ativo sejam tratados como ativos
try { $db->exec("UPDATE usuarios SET ativo = 1 WHERE ativo IS NULL"); } catch (PDOException $e) {}

// ─── GARANTE COLUNAS CRÍTICAS (fora de transação) ────────────
// ALTER TABLE fora de transação é confiável no SQLite
// SQLite antigo não aceita CURRENT_TIMESTAMP como DEFAULT em ALTER TABLE.
// Usar NULL como default e preencher via query.
$colunas_criticas = [
    "ALTER TABLE ordens_servico ADD COLUMN data_atualizacao DATETIME",
    "ALTER TABLE ordens_servico ADD COLUMN informacoes_adicionais TEXT",
    "ALTER TABLE ordens_servico ADD COLUMN senha_aparelho TEXT",
    "ALTER TABLE ordens_servico ADD COLUMN previsao_conclusao DATE",
    "ALTER TABLE produtos ADD COLUMN data_atualizacao DATETIME",
    "ALTER TABLE produtos ADD COLUMN data_criacao DATETIME",
    "ALTER TABLE ordem_observacoes ADD COLUMN data_criacao DATETIME",
    "ALTER TABLE ordem_observacoes ADD COLUMN usuario_id INTEGER",
    "ALTER TABLE orcamentos ADD COLUMN status_orcamento TEXT",
    "ALTER TABLE midias_os ADD COLUMN comentario TEXT",
    "ALTER TABLE midias_os ADD COLUMN tipo TEXT",
    "ALTER TABLE midias_os ADD COLUMN data_upload DATETIME",
];
foreach ($colunas_criticas as $sql) {
    try { $db->exec($sql); } catch (PDOException $e) { /* coluna já existe — ok */ }
}
// Preencher valores padrão nas colunas recém-adicionadas que têm NULL
try { $db->exec("UPDATE ordens_servico SET informacoes_adicionais='' WHERE informacoes_adicionais IS NULL"); } catch(PDOException $e){}
try { $db->exec("UPDATE ordens_servico SET senha_aparelho='' WHERE senha_aparelho IS NULL"); } catch(PDOException $e){}
try { $db->exec("UPDATE orcamentos SET status_orcamento='Pendente' WHERE status_orcamento IS NULL"); } catch(PDOException $e){}
try { $db->exec("UPDATE midias_os SET comentario='' WHERE comentario IS NULL"); } catch(PDOException $e){}
try { $db->exec("UPDATE midias_os SET tipo='' WHERE tipo IS NULL"); } catch(PDOException $e){}

// ─── PRIMEIRO ACESSO: cria admin somente quando o banco está vazio ──
// NÃO é mais criado um usuário fixo com senha hardcoded a cada request.
// O provisionamento de novos clientes é feito via provisionar.php, que
// gera uma senha aleatória no momento da criação. Este bloco só atua
// em instalações standalone sem banco inicializado (count = 0).
$count = (int)$db->query("SELECT COUNT(*) FROM usuarios")->fetchColumn();
if ($count === 0) {
    // Gera senha aleatória de 12 caracteres — exibida no log local apenas
    $senha_inicial = bin2hex(random_bytes(6));
    $hash_inicial  = password_hash($senha_inicial, PASSWORD_DEFAULT);
    $db->prepare("INSERT INTO usuarios (nome, email, senha, nivel_acesso, ativo) VALUES (?, ?, ?, ?, 1)")
       ->execute(['Administrador', 'admin@sistema.com', $hash_inicial, 'admin']);
    // Grava senha uma única vez em arquivo de log protegido para o operador
    $log_path = SAAS_DIR . '/logs/first_run.log';
    if (!is_dir(dirname($log_path))) @mkdir(dirname($log_path), 0700, true);
    @file_put_contents(
        $log_path,
        '[' . date('Y-m-d H:i:s') . '] Primeiro acesso — usuario: admin@sistema.com  senha: ' . $senha_inicial . "\n"
        . "ATENÇÃO: altere esta senha imediatamente após o primeiro login e remova este arquivo.\n",
        FILE_APPEND | LOCK_EX
    );
}

// ─── ROTEAMENTO ──────────────────────────────────────────────
$method   = $_SERVER['REQUEST_METHOD'];
$resource = $_GET['resource'] ?? '';
$action   = $_GET['action']   ?? '';
$id       = (isset($_GET['id']) && is_numeric($_GET['id'])) ? (int)$_GET['id'] : null;
$data     = get_input();

// ── RESET DE SENHA (público — sem sessão) ────────────────────
if ($resource === 'solicitar_reset' && $method === 'POST') {
    $email = trim(strtolower((string)($data['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) resp(400, ['error' => 'E-mail inválido']);

    // Busca por email OU por nome (mesmo critério do login)
    $u = $db->prepare("SELECT id, nome, email FROM usuarios WHERE (LOWER(TRIM(email))=? OR LOWER(TRIM(nome))=?) AND ativo=1 LIMIT 1");
    $u->execute([$email, $email]);
    $usuario = $u->fetch();
    // Usa o email armazenado no banco para envio (pode diferir do digitado)
    $email_destino = $usuario ? (trim($usuario['email']) ?: $email) : $email;

    // Log sempre — permite diagnóstico sem revelar ao cliente se o email existe
    @file_put_contents(SAAS_DIR . '/logs/reset_senha.log',
        '[' . date('Y-m-d H:i:s') . "] solicitar_reset digitado={$email} banco_email=" . ($usuario['email']??'—') . " banco_nome=" . ($usuario['nome']??'—') . " status=" . ($usuario ? 'encontrado' : 'NAO_ENCONTRADO') . "\n",
        FILE_APPEND);

    if (!$usuario) resp(200, ['ok' => true]);

    $token     = bin2hex(random_bytes(32));
    $expiracao = date('Y-m-d H:i:s', time() + 3600);
    $db->prepare("DELETE FROM reset_senha_tokens WHERE usuario_id=?")->execute([$usuario['id']]);
    $db->prepare("INSERT INTO reset_senha_tokens (usuario_id,token,expiracao) VALUES (?,?,?)")
       ->execute([$usuario['id'], $token, $expiracao]);

    $scheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host    = $_SERVER['HTTP_HOST'] ?? '';
    $pasta   = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    $base    = $scheme . '://' . $host . $pasta . '/';
    $link    = $base . '?reset_token=' . $token;

    $master_cfg = file_exists(__DIR__ . '/config.php') ? (array)@require __DIR__ . '/config.php' : [];
    $nome_curto = explode(' ', trim((string)($usuario['nome'] ?? '')))[0] ?: 'Usuário';
    $corpo = "Olá, {$nome_curto}!\r\n\r\n"
           . "Recebemos uma solicitação de redefinição de senha para sua conta no ConsertaOS.\r\n\r\n"
           . "Clique no link abaixo para criar uma nova senha (válido por 1 hora):\r\n"
           . $link . "\r\n\r\n"
           . "Se você não solicitou isso, ignore este e-mail.\r\n\r\n"
           . "Equipe ConsertaOS";

    $assunto = 'Redefinição de senha — ConsertaOS';
    // Envia sempre via landing page (melhor reputação com provedores como Hotmail)
    $ok_smtp = false;
    if (false) { // SMTP direto desativado — usar fallback da landing
        $ok_smtp = saas_smtp_send($email_destino, $assunto, $corpo, $master_cfg);
    }

    if (!$ok_smtp) {
        $proxy_url      = (string)($master_cfg['email_api_url']       ?? '');
        $landing_secret = (string)($master_cfg['provisionar_secret']  ?? '');
        if ($proxy_url !== '' && $landing_secret !== '') {
            $ch = curl_init($proxy_url);
            curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>15,
                CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
                CURLOPT_POSTFIELDS=>json_encode(['chave_secreta'=>$landing_secret,'para'=>$email,'assunto'=>$assunto,'corpo'=>$corpo])]);
            $ok_smtp = (bool)curl_exec($ch);
            curl_close($ch);
        }
    }

    @file_put_contents(SAAS_DIR . '/logs/reset_senha.log',
        '[' . date('Y-m-d H:i:s') . "] reset solicitado para={$email} smtp=" . ($ok_smtp?'OK':'FALHOU') . " link={$link}\n",
        FILE_APPEND);
    resp(200, ['ok' => true]);
}

if ($resource === 'redefinir_senha' && $method === 'POST') {
    $token = trim((string)($data['token'] ?? ''));
    $senha = (string)($data['senha'] ?? '');
    if ($token === '' || strlen($senha) < 6) resp(400, ['error' => 'Token e senha (mínimo 6 caracteres) são obrigatórios']);

    $st = $db->prepare("SELECT * FROM reset_senha_tokens WHERE token=? AND usado=0 AND expiracao > datetime('now','localtime')");
    $st->execute([$token]);
    $reset = $st->fetch();
    if (!$reset) resp(400, ['error' => 'Link inválido ou expirado. Solicite um novo.']);

    $db->prepare("UPDATE usuarios SET senha=? WHERE id=?")->execute([password_hash($senha, PASSWORD_DEFAULT), $reset['usuario_id']]);
    $db->prepare("UPDATE reset_senha_tokens SET usado=1 WHERE token=?")->execute([$token]);
    resp(200, ['ok' => true]);
}

function saas_smtp_send(string $to, string $subject, string $body, array $cfg): bool
{
    $host=$cfg['smtp_host']??''; $port=(int)($cfg['smtp_porta']??587);
    $user=$cfg['smtp_user']??''; $pass=$cfg['smtp_pass']??'';
    $from_full=$cfg['email_from']??$user;
    if(!$host||!$user||!$pass) return false;
    preg_match('/<([^>]+)>/',$from_full,$m); $from_addr=$m[1]??$from_full;
    try {
        // Verificação TLS habilitada com bundle de CAs atualizado.
        // 'allow_self_signed' removido — certificados auto-assinados não são confiáveis.
        $_smtp_cainfo = ssl_cainfo();
        $ctx=stream_context_create(['ssl'=>[
            'verify_peer'       => true,
            'verify_peer_name'  => true,
            'allow_self_signed' => false,
            'cafile'            => $_smtp_cainfo ?? '',   // '' = usa bundle do sistema
        ]]);
        $errno=$errstr='';
        $addr=($port===465)?"ssl://{$host}:{$port}":"tcp://{$host}:{$port}";
        $sock=@stream_socket_client($addr,$errno,$errstr,10,STREAM_CLIENT_CONNECT,$ctx);
        if(!$sock) return false;
        $r=function()use($sock){return(string)fgets($sock,512);};
        $s=function($l)use($sock){fwrite($sock,$l."\r\n");};
        $r();$s("EHLO consertaos.com.br");
        while(($ln=$r())&&strlen($ln)>3&&$ln[3]==='-');
        if($port===587){$s("STARTTLS");$r();stream_socket_enable_crypto($sock,true,STREAM_CRYPTO_METHOD_TLS_CLIENT);$s("EHLO consertaos.com.br");while(($ln=$r())&&strlen($ln)>3&&$ln[3]==='-');}
        $s("AUTH LOGIN");$r();$s(base64_encode($user));$r();$s(base64_encode($pass));
        if(substr($r(),0,3)!=='235'){fclose($sock);return false;}
        $s("MAIL FROM:<{$from_addr}>");$r();$s("RCPT TO:<{$to}>");$r();$s("DATA");$r();
        $s("From: {$from_full}");$s("To: {$to}");
        $s("Subject: =?UTF-8?B?".base64_encode($subject)."?=");
        $s("MIME-Version: 1.0");$s("Content-Type: text/plain; charset=UTF-8");
        $s("Content-Transfer-Encoding: base64");$s("X-Mailer: PHP/".PHP_VERSION);$s("");
        $s(chunk_split(base64_encode($body)));$s(".");
        $res=$r();$s("QUIT");fclose($sock);
        return substr($res,0,3)==='250';
    } catch(\Throwable $e){return false;}
}

// ─── AUTH ─────────────────────────────────────────────────────
if ($resource === 'auth') {
    if ($action === 'login' && $method === 'POST') {
        $login = trim($data['nome'] ?? $data['login'] ?? $data['email'] ?? '');
        $senha = trim($data['senha'] ?? '');
        if (!$login || !$senha) resp(400, ['error' => 'Usuário e senha são obrigatórios']);
        // Aceita login pelo campo nome OU pelo campo email (case-insensitive)
        $stmt = $db->prepare("SELECT * FROM usuarios WHERE (LOWER(nome) = LOWER(?) OR LOWER(email) = LOWER(?)) AND COALESCE(ativo, 1) = 1");
        $stmt->execute([$login, $login]);
        $user = $stmt->fetch();
        if ($user) {
            // Tenta todas as colunas possíveis onde a senha pode estar gravada
            $hash = $user['senha'] ?? ($user['password'] ?? ($user['pass'] ?? ($user['pwd'] ?? '')));
            $ok = false;
            // 1) bcrypt/argon2 — formato moderno PHP (começa com $2y$, $2b$, $argon2i$, etc.)
            if (!$ok && strlen($hash) >= 55 && $hash[0] === '$') {
                $ok = password_verify($senha, $hash);
            }
            // 2) MD5 puro
            if (!$ok && strlen($hash) === 32 && ctype_xdigit($hash)) {
                $ok = hash_equals(md5($senha), $hash);
            }
            // 3) MD5 maiúsculo
            if (!$ok && strlen($hash) === 32) {
                $ok = hash_equals(strtolower(md5($senha)), strtolower($hash));
            }
            // 4) SHA1
            if (!$ok && strlen($hash) === 40 && ctype_xdigit($hash)) {
                $ok = hash_equals(sha1($senha), $hash);
            }
            // 5) SHA256
            if (!$ok && strlen($hash) === 64 && ctype_xdigit($hash)) {
                $ok = hash_equals(hash('sha256', $senha), $hash);
            }
            // 6) Texto puro (último recurso)
            if (!$ok) {
                $ok = ($senha === $hash);
            }
            if ($ok) {
                // Migra para bcrypt se estiver em formato legado
                if (!(strlen($hash) >= 55 && $hash[0] === '$')) {
                    $novo_hash = password_hash($senha, PASSWORD_DEFAULT);
                    $db->prepare("UPDATE usuarios SET senha = ? WHERE id = ?")
                       ->execute([$novo_hash, $user['id']]);
                }
                unset($user['senha']);
                $_SESSION['usuario'] = $user;
                // LGPD: regenera ID de sessão pra mitigar fixation
                @session_regenerate_id(true);
                audit_log($db, 'login_sucesso', 'usuarios', $user['id'] ?? null, ['login'=>$login]);
                resp(200, ['success' => true, 'usuario' => $user]);
            }
        }
        // LGPD: registra tentativa falha (sem expor se usuário existe)
        audit_log($db, 'login_falha', 'usuarios', null, ['login'=>$login]);
        // Retorna mensagem genérica — não revela se o usuário existe
        resp(401, ['error' => 'Usuário ou senha inválidos']);
    }
    if ($action === 'logout' && $method === 'POST') {
        $u = $_SESSION['usuario'] ?? null;
        if ($u) { audit_log($db, 'logout', 'usuarios', $u['id'] ?? null); }
        session_destroy();
        resp(200, ['success' => true]);
    }
    if ($action === 'me' && $method === 'GET') {
        if (!isset($_SESSION['usuario']) || !is_array($_SESSION['usuario'])) resp(401, ['error' => 'Não autenticado']);
        $uid = (int)($_SESSION['usuario']['id'] ?? 0);
        if (!$uid) resp(401, ['error' => 'Não autenticado']);
        $stmt = $db->prepare("SELECT * FROM usuarios WHERE id=? AND COALESCE(ativo,1)=1");
        $stmt->execute([$uid]);
        $u = $stmt->fetch();
        if (!$u) resp(401, ['error' => 'Sessão inválida']);
        unset($u['senha']);
        $_SESSION['usuario'] = $u;
        resp(200, $u);
    }
    resp(404, ['error' => 'Ação não encontrada']);
}

// ─── EMPRESA ──────────────────────────────────────────────────
if ($resource === 'empresa') {
    auth_required();
    if ($method === 'GET') {
        $r = $db->query("SELECT * FROM empresa_dados WHERE id = 1")->fetch();
        resp(200, $r ?: (object)[]);
    }
    if ($method === 'POST') {
        $atual = $db->query("SELECT * FROM empresa_dados WHERE id = 1")->fetch();
        $nome           = $data['nome']           ?? ($atual['nome']           ?? '');
        $razao_social   = $data['razao_social']   ?? ($atual['razao_social']   ?? '');
        $telefone       = $data['telefone']       ?? ($atual['telefone']       ?? '');
        $endereco       = $data['endereco']       ?? ($atual['endereco']       ?? '');
        $cnpj           = $data['cnpj']           ?? ($atual['cnpj']           ?? '');
        $ie             = $data['ie']             ?? ($atual['ie']             ?? '');
        $cep            = $data['cep']            ?? ($atual['cep']            ?? '');
        $logradouro     = $data['logradouro']     ?? ($atual['logradouro']     ?? '');
        $numero         = $data['numero']         ?? ($atual['numero']         ?? '');
        $complemento    = $data['complemento']    ?? ($atual['complemento']    ?? '');
        $bairro         = $data['bairro']         ?? ($atual['bairro']         ?? '');
        $cidade         = $data['cidade']         ?? ($atual['cidade']         ?? '');
        $uf             = $data['uf']             ?? ($atual['uf']             ?? '');
        $logo_raw = array_key_exists('logo_principal', $data) ? $data['logo_principal'] : null;
        if ($logo_raw !== null) {
            if ($logo_raw === '' || strpos($logo_raw, 'data:image/') === 0) {
                $logo_principal = $logo_raw;
            } else {
                $logo_principal = $atual['logo_principal'] ?? '';
            }
        } else {
            $logo_principal = $atual['logo_principal'] ?? '';
        }
        $cert_pfx  = array_key_exists('certificado_pfx', $data) ? $data['certificado_pfx'] : ($atual['certificado_pfx'] ?? '');
        $cert_nome = $data['certificado_nome']     ?? ($atual['certificado_nome']     ?? '');
        $cert_val  = $data['certificado_validade'] ?? ($atual['certificado_validade'] ?? '');
        // Loja Virtual — aparência
        $loja_logo_raw = array_key_exists('loja_logo', $data) ? $data['loja_logo'] : null;
        $loja_logo = $loja_logo_raw !== null
            ? (($loja_logo_raw === '' || strpos($loja_logo_raw, 'data:image/') === 0) ? $loja_logo_raw : ($atual['loja_logo'] ?? ''))
            : ($atual['loja_logo'] ?? '');
        $loja_capa_raw = array_key_exists('loja_capa', $data) ? $data['loja_capa'] : null;
        $loja_capa = $loja_capa_raw !== null
            ? (($loja_capa_raw === '' || strpos($loja_capa_raw, 'data:image/') === 0) ? $loja_capa_raw : ($atual['loja_capa'] ?? ''))
            : ($atual['loja_capa'] ?? '');
        $loja_logo_pos      = $data['loja_logo_pos']      ?? ($atual['loja_logo_pos']      ?? '50% 50%');
        $loja_capa_pos      = $data['loja_capa_pos']      ?? ($atual['loja_capa_pos']      ?? '50% 50%');
        $loja_nome          = trim($data['loja_nome']          ?? ($atual['loja_nome']          ?? ''));
        $loja_boas_vindas   = $data['loja_boas_vindas']   ?? ($atual['loja_boas_vindas']   ?? '');
        $loja_formato       = $data['loja_formato']       ?? ($atual['loja_formato']       ?? 'grade');
        $loja_exibir_precos = isset($data['loja_exibir_precos']) ? (int)$data['loja_exibir_precos'] : (int)($atual['loja_exibir_precos'] ?? 1);
        $loja_slug_raw = trim($data['loja_slug'] ?? ($atual['loja_slug'] ?? ''));
        // Normaliza slug: apenas a-z, 0-9 e hifens
        $loja_slug = preg_replace('/-+/', '-', preg_replace('/[^a-z0-9\-]/', '-', strtolower($loja_slug_raw)));
        $loja_slug = trim($loja_slug, '-');
        // Renomeia pasta da loja se o slug foi alterado
        $loja_slug_antigo = trim($atual['loja_slug'] ?? '');
        if ($loja_slug_antigo && $loja_slug && $loja_slug_antigo !== $loja_slug) {
            $baseMinhaloja = dirname(dirname(__DIR__)) . '/minhaloja/';
            $oldDir = $baseMinhaloja . $loja_slug_antigo;
            $newDir = $baseMinhaloja . $loja_slug;
            if (is_dir($oldDir) && !is_dir($newDir)) {
                rename($oldDir, $newDir);
            }
        }
        $db->prepare("UPDATE empresa_dados SET nome=?, razao_social=?, telefone=?, endereco=?, logo_principal=?, cnpj=?, ie=?, cep=?, logradouro=?, numero=?, complemento=?, bairro=?, cidade=?, uf=?, certificado_pfx=?, certificado_nome=?, certificado_validade=?, loja_logo=?, loja_logo_pos=?, loja_capa=?, loja_capa_pos=?, loja_nome=?, loja_boas_vindas=?, loja_formato=?, loja_exibir_precos=?, loja_slug=? WHERE id=1")
           ->execute([$nome, $razao_social, $telefone, $endereco, $logo_principal, $cnpj, $ie, $cep, $logradouro, $numero, $complemento, $bairro, $cidade, $uf, $cert_pfx, $cert_nome, $cert_val, $loja_logo, $loja_logo_pos, $loja_capa, $loja_capa_pos, $loja_nome, $loja_boas_vindas, $loja_formato, $loja_exibir_precos, $loja_slug]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── CLIENTES ─────────────────────────────────────────────────

// ─── HELPER: normalizar texto para busca sem acento ──────────────────────
function normalizar_busca($txt) {
    $txt = mb_strtolower(trim($txt), 'UTF-8');
    return strtr($txt, [
        'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a',
        'é'=>'e','è'=>'e','ê'=>'e','ë'=>'e',
        'í'=>'i','ì'=>'i','î'=>'i','ï'=>'i',
        'ó'=>'o','ò'=>'o','õ'=>'o','ô'=>'o','ö'=>'o',
        'ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u',
        'ç'=>'c','ñ'=>'n'
    ]);
}

if ($resource === 'clientes') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $q_raw  = $_GET['q']        ?? '';
        $filtro = $_GET['filtro']    ?? '';  // 'nomes_dup' | 'cpf_dup' | ''
        $limit  = max(1, min(500, (int)($_GET['limit'] ?? 50)));
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $offset = ($page - 1) * $limit;
        $q      = '%' . normalizar_busca($q_raw) . '%';
        $q_orig = '%' . mb_strtolower($q_raw,'UTF-8') . '%';

        // ── Filtro: nomes duplicados ─────────────────────────────
        if ($filtro === 'nomes_dup') {
            // SQL: busca clientes cujo TRIM(LOWER(nome)) aparece em mais de 1 registro
            $where_q = '';
            $params_q = [];
            if ($q_raw !== '') {
                $where_q = "AND LOWER(c.nome) LIKE ?";
                $params_q = [$q];
            }
            // Subquery: nomes que aparecem 2+ vezes
            $sql_dup = "
                SELECT c.*
                FROM clientes c
                WHERE TRIM(LOWER(c.nome)) IN (
                    SELECT TRIM(LOWER(nome))
                    FROM clientes
                    GROUP BY TRIM(LOWER(nome))
                    HAVING COUNT(*) > 1
                )
                $where_q
                ORDER BY TRIM(LOWER(c.nome)), c.id
            ";
            $tc2 = $db->prepare("SELECT COUNT(*) FROM clientes c WHERE TRIM(LOWER(c.nome)) IN (SELECT TRIM(LOWER(nome)) FROM clientes GROUP BY TRIM(LOWER(nome)) HAVING COUNT(*) > 1) $where_q");
            $tc2->execute($params_q);
            $total = (int)$tc2->fetchColumn();
            $s2 = $db->prepare($sql_dup . " LIMIT ? OFFSET ?");
            $s2->execute(array_merge($params_q, [$limit, $offset]));
            $data = $s2->fetchAll();
            resp(200,['data'=>$data,'total'=>$total,'page'=>$page,'pages'=>(int)ceil(max(1,$total)/$limit),'limit'=>$limit,'filtro'=>'nomes_dup']);
        }

        // ── Filtro: CPFs duplicados ──────────────────────────────
        if ($filtro === 'cpf_dup') {
            $where_q = '';
            $params_q = [];
            if ($q_raw !== '') {
                $where_q = "AND LOWER(c.nome) LIKE ?";
                $params_q = [$q];
            }
            // Subquery: CPFs (só dígitos) que aparecem 2+ vezes, excluindo vazios
            $sql_cpf = "
                SELECT c.*
                FROM clientes c
                WHERE c.cpf != ''
                  AND c.cpf IS NOT NULL
                  AND REPLACE(REPLACE(REPLACE(c.cpf,'.',''),'-',''),' ','') IN (
                    SELECT REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),' ','')
                    FROM clientes
                    WHERE cpf != '' AND cpf IS NOT NULL AND LENGTH(TRIM(cpf)) > 0
                    GROUP BY REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),' ','')
                    HAVING COUNT(*) > 1
                )
                $where_q
                ORDER BY c.cpf, c.nome
            ";
            $sql_count_cpf = "
                SELECT COUNT(*) FROM clientes c
                WHERE c.cpf != ''
                  AND c.cpf IS NOT NULL
                  AND REPLACE(REPLACE(REPLACE(c.cpf,'.',''),'-',''),' ','') IN (
                    SELECT REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),' ','')
                    FROM clientes
                    WHERE cpf != '' AND cpf IS NOT NULL AND LENGTH(TRIM(cpf)) > 0
                    GROUP BY REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),' ','')
                    HAVING COUNT(*) > 1
                )
                $where_q
            ";
            $tc3 = $db->prepare($sql_count_cpf);
            $tc3->execute($params_q);
            $total = (int)$tc3->fetchColumn();
            $s3 = $db->prepare($sql_cpf . " LIMIT ? OFFSET ?");
            $s3->execute(array_merge($params_q, [$limit, $offset]));
            $data = $s3->fetchAll();
            resp(200,['data'=>$data,'total'=>$total,'page'=>$page,'pages'=>(int)ceil(max(1,$total)/$limit),'limit'=>$limit,'filtro'=>'cpf_dup']);
        }

        // ── Busca normal (com filtro opcional de ativo) ──────────
        $so_ativo = !empty($_GET['ativo']) ? $_GET['ativo'] : '';
        $ativo_where = ($so_ativo === '1') ? ' AND ativo=1' : '';

        if ($q_raw === '') {
            // Sem texto: busca SQL direta (rápida)
            $tc = $db->prepare("SELECT COUNT(*) FROM clientes WHERE 1=1$ativo_where");
            $tc->execute([]);
            $total = (int)$tc->fetchColumn();
            $s = $db->prepare("SELECT * FROM clientes WHERE 1=1$ativo_where ORDER BY nome LIMIT ? OFFSET ?");
            $s->execute([$limit, $offset]);
            $data = $s->fetchAll();
        } else {
            // Com texto: buscar todos e filtrar em PHP (normaliza acentos corretamente)
            $s = $db->prepare("SELECT * FROM clientes WHERE 1=1$ativo_where ORDER BY nome");
            $s->execute([]);
            $todos = $s->fetchAll();
            $q_norm_busca = normalizar_busca($q_raw);
            $data_filtrada = array_filter($todos, function($r) use ($q_norm_busca) {
                $nome  = normalizar_busca($r['nome']     ?? '');
                $cpf   = normalizar_busca($r['cpf']      ?? '');
                $fone  = normalizar_busca($r['telefone'] ?? '');
                return strpos($nome, $q_norm_busca) !== false
                    || strpos($cpf,  $q_norm_busca) !== false
                    || strpos($fone, $q_norm_busca) !== false;
            });
            $data_filtrada = array_values($data_filtrada);
            $total = count($data_filtrada);
            $data  = array_slice($data_filtrada, $offset, $limit);
        }
        resp(200, ['data'=>$data,'total'=>$total,'page'=>$page,'pages'=>(int)ceil(max(1,$total)/$limit),'limit'=>$limit,'filtro'=>$so_ativo?'ativos':'']);
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM clientes WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        if (empty($data['nome'])) resp(400, ['error' => 'Nome é obrigatório']);
        $nome_upper = mb_strtoupper(trim($data['nome']??''), 'UTF-8');
        $db->prepare("INSERT INTO clientes (nome,email,telefone,telefone_secundario,cpf,cnpj,inscricao_estadual,tipo_pessoa,endereco,cep,logradouro,numero,complemento,bairro,cidade,cod_ibge,uf,ativo) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$nome_upper, $data['email']??'', $data['telefone']??'', $data['telefone_secundario']??'', $data['cpf']??'', $data['cnpj']??'', $data['inscricao_estadual']??'', $data['tipo_pessoa']??'fisica', $data['endereco']??'', $data['cep']??'', $data['logradouro']??'', $data['numero']??'', $data['complemento']??'', $data['bairro']??'', $data['cidade']??'', $data['cod_ibge']??'', $data['uf']??'', (int)($data['ativo']??1)]);
        $new_id = (int)$db->lastInsertId();
        // LGPD: registra consentimento se foi explicitamente coletado no cadastro
        if (!empty($data['consentimento_aceito'])) {
            $versao = (string)($db->query("SELECT versao FROM politica_privacidade WHERE ativo=1 ORDER BY id DESC LIMIT 1")->fetchColumn() ?: '');
            $db->prepare("INSERT INTO consentimentos_lgpd (cliente_id, identificador, finalidade, politica_versao, aceito, ip, user_agent, origem, data_evento) VALUES (?, ?, 'cadastro', ?, 1, ?, ?, 'sistema', ?)")
               ->execute([$new_id, $data['email']??'', $versao, lgpd_client_ip(), substr((string)($_SERVER['HTTP_USER_AGENT']??''),0,255), date('Y-m-d H:i:s')]);
            $db->prepare("UPDATE clientes SET consentimento_data=?, consentimento_ip=?, consentimento_versao=? WHERE id=?")
               ->execute([date('Y-m-d H:i:s'), lgpd_client_ip(), $versao, $new_id]);
        }
        audit_log($db, 'cliente_criar', 'clientes', $new_id, ['nome'=>$nome_upper]);
        resp(201, ['success' => true, 'id' => $new_id]);
    }
    if ($method === 'PUT' && $id !== null) {
        $nome_upper_u = mb_strtoupper(trim($data['nome']??''), 'UTF-8');
        $db->prepare("UPDATE clientes SET nome=?,email=?,telefone=?,telefone_secundario=?,cpf=?,cnpj=?,inscricao_estadual=?,tipo_pessoa=?,endereco=?,cep=?,logradouro=?,numero=?,complemento=?,bairro=?,cidade=?,cod_ibge=?,uf=?,ativo=? WHERE id=?")
           ->execute([$nome_upper_u, $data['email']??'', $data['telefone']??'', $data['telefone_secundario']??'', $data['cpf']??'', $data['cnpj']??'', $data['inscricao_estadual']??'', $data['tipo_pessoa']??'fisica', $data['endereco']??'', $data['cep']??'', $data['logradouro']??'', $data['numero']??'', $data['complemento']??'', $data['bairro']??'', $data['cidade']??'', $data['cod_ibge']??'', $data['uf']??'', (int)($data['ativo']??1), $id]);
        audit_log($db, 'cliente_atualizar', 'clientes', $id, ['nome'=>$nome_upper_u]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM clientes WHERE id=?")->execute([$id]);
        audit_log($db, 'cliente_excluir', 'clientes', $id);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── TIPOS_APARELHO ───────────────────────────────────────────
if ($resource === 'tipos_aparelho') {
    auth_required();
    if ($method === 'GET') resp(200, $db->query("SELECT * FROM tipos_aparelho ORDER BY nome")->fetchAll());
    if ($method === 'POST') {
        if (empty($data['nome'])) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO tipos_aparelho (nome) VALUES (?)")->execute([$data['nome']]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId(), 'nome' => $data['nome']]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE tipos_aparelho SET nome=? WHERE id=?")->execute([$data['nome'], $id]); resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM tipos_aparelho WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── MARCAS ───────────────────────────────────────────────────
if ($resource === 'marcas') {
    auth_required();
    if ($method === 'GET') resp(200, $db->query("SELECT * FROM marcas ORDER BY nome")->fetchAll());
    if ($method === 'POST') {
        if (empty($data['nome'])) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO marcas (nome) VALUES (?)")->execute([$data['nome']]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId(), 'nome' => $data['nome']]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE marcas SET nome=? WHERE id=?")->execute([$data['nome'], $id]); resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM marcas WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── MODELOS ──────────────────────────────────────────────────
if ($resource === 'modelos') {
    auth_required();
    if ($method === 'GET') {
        $mid = $_GET['marca_id'] ?? null;
        if ($mid) {
            $s = $db->prepare("SELECT m.*, ma.nome as marca_nome FROM modelos m LEFT JOIN marcas ma ON m.marca_id=ma.id WHERE m.marca_id=? ORDER BY m.nome");
            $s->execute([$mid]);
        } else {
            $s = $db->query("SELECT m.*, ma.nome as marca_nome FROM modelos m LEFT JOIN marcas ma ON m.marca_id=ma.id ORDER BY m.nome");
        }
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST') {
        if (empty($data['nome'])) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO modelos (nome,marca_id) VALUES (?,?)")->execute([$data['nome'], $data['marca_id']??null]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId(), 'nome' => $data['nome']]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE modelos SET nome=?,marca_id=? WHERE id=?")->execute([$data['nome'], $data['marca_id']??null, $id]); resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM modelos WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── PRODUTOS ─────────────────────────────────────────────────
if ($resource === 'produtos') {
    auth_required();
    if ($method === 'GET' && $id === null) {
    $q_raw_p = $_GET['q'] ?? '';
    $q       = '%' . normalizar_busca($q_raw_p) . '%';
    $tipo_p  = $_GET['tipo'] ?? '';
    $limit   = max(1, min(200, (int)($_GET['limit'] ?? 50)));
    $page    = max(1, (int)($_GET['page'] ?? 1));
    $offset  = ($page - 1) * $limit;

    // Filtro especial: produtos marcados para exibição na loja virtual
    if (isset($_GET['loja_exibir']) && (int)$_GET['loja_exibir'] === 1) {
        $wj = "(LOWER(p.descricao) LIKE ? OR LOWER(p.codigo_interno) LIKE ?) AND p.ativo=1 AND pl.loja_exibir=1";
        $pj = [$q, $q];
        $stC = $db->prepare("SELECT COUNT(*) FROM produtos p INNER JOIN produto_loja pl ON pl.produto_id=p.id WHERE $wj");
        $stC->execute($pj);
        $total = (int)$stC->fetchColumn();
        $pages = (int)ceil(max(1, $total) / $limit);
        $stJ = $db->prepare("SELECT p.*, pl.loja_exibir, pl.loja_destaque, pl.loja_titulo, pl.loja_descricao, pl.loja_fotos, pl.loja_variacoes, pl.loja_categoria_id FROM produtos p INNER JOIN produto_loja pl ON pl.produto_id=p.id WHERE $wj ORDER BY p.descricao LIMIT ? OFFSET ?");
        $stJ->execute(array_merge($pj, [$limit, $offset]));
        $rows = $stJ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$rr) {
            $rr['loja_fotos']     = json_decode($rr['loja_fotos']     ?? '[]', true) ?: [];
            $rr['loja_variacoes'] = json_decode($rr['loja_variacoes'] ?? '[]', true) ?: [];
        }
        resp(200, ['data' => $rows, 'total' => $total, 'page' => $page, 'pages' => $pages, 'limit' => $limit]);
    }

    if ($tipo_p !== '') {
        $where = "(LOWER(descricao) LIKE ? OR LOWER(codigo_interno) LIKE ?) AND ativo=1 AND tipo_item=?";
        $params = [$q, $q, $tipo_p];
    } else {
        $where = "(LOWER(descricao) LIKE ? OR LOWER(codigo_interno) LIKE ?) AND ativo=1";
        $params = [$q, $q];
    }

    $stCount = $db->prepare("SELECT COUNT(*) FROM produtos WHERE $where");
    $stCount->execute($params);
    $total = (int)$stCount->fetchColumn();
    $pages = (int)ceil(max(1, $total) / $limit);

    $st = $db->prepare("SELECT * FROM produtos WHERE $where ORDER BY descricao LIMIT ? OFFSET ?");
    $st->execute(array_merge($params, [$limit, $offset]));
    resp(200, ['data' => $st->fetchAll(), 'total' => $total, 'page' => $page, 'pages' => $pages, 'limit' => $limit]);
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM produtos WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch();
        if ($r) {
            // Incluir dados da aba Loja Virtual
            $sl = $db->prepare("SELECT * FROM produto_loja WHERE produto_id=?");
            $sl->execute([$id]);
            $loja = $sl->fetch();
            if ($loja) {
                $r['loja_exibir']       = (int)($loja['loja_exibir'] ?? 0);
                $r['loja_destaque']     = (int)($loja['loja_destaque'] ?? 0);
                $r['loja_titulo']       = $loja['loja_titulo'] ?? '';
                $r['loja_descricao']    = $loja['loja_descricao'] ?? '';
                $r['loja_categoria_id'] = $loja['loja_categoria_id'] ?? null;
                $r['loja_fotos']        = json_decode($loja['loja_fotos'] ?? '[]', true) ?: [];
                $r['loja_variacoes']    = json_decode($loja['loja_variacoes'] ?? '[]', true) ?: [];
            } else {
                $r['loja_exibir']       = 0;
                $r['loja_destaque']     = 0;
                $r['loja_titulo']       = '';
                $r['loja_descricao']    = '';
                $r['loja_categoria_id'] = null;
                $r['loja_fotos']        = [];
                $r['loja_variacoes']    = [];
            }
        }
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        if (empty($data['descricao'])) resp(400, ['error' => 'Descrição obrigatória']);
        $now = date('Y-m-d H:i:s');
        $fotos_json = json_encode(is_array($data['fotos']??null)?$data['fotos']:[], JSON_UNESCAPED_UNICODE);
        $db->prepare("INSERT INTO produtos (tipo_item,ativo,codigo_interno,codigo_barras,descricao,descricao_complementar,unidade_medida,unidade_compra,unidade_saida,fator_conversao,preco_custo,despesas_acessorias,outras_despesas,custo_final,preco_venda,margem_lucro,percentual_desconto_max,percentual_comissao,estoque_atual,estoque_minimo,estoque_maximo,estoque_imobilizado,estoque_uso_consumo,estoque_revenda,localizacao,peso_liquido,peso_bruto,largura,altura,profundidade,ncm,ncm_descricao,cfop,cest,origem,csosn,cst_icms,aliq_icms,cst_pis,aliq_pis,cst_cofins,aliq_cofins,cst_ipi,aliq_ipi,nfse_movimenta,nfse_codigo_servico,nfse_municipio,nfse_cnae,nfse_descricao_servico,nfse_deducoes,nfse_cofins,nfse_ir,nfse_outras_deducoes,nfse_pis,nfse_inss,nfse_csll,nfse_iss,nfse_id_municipal_evento,nfse_descricao_evento,nfse_data_ini_evento,nfse_data_fim_evento,nfse_logradouro,nfse_numero,tabela_servico_id,codigo_nbs,iss_percentual,nfse_natureza,nfse_incentivo_fiscal,observacoes,condicao_peca,garantia_fornecedor,garantia_fornecedor_unidade,garantia_venda,garantia_venda_unidade,capacidade_mah,voltagem,tipo_tela,part_number,fotos,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$data['tipo_item']??'produto',$data['ativo']??1,$data['codigo_interno']??'',(!empty($data['codigo_barras']) ? $data['codigo_barras'] : null),$data['descricao'],$data['descricao_complementar']??'',$data['unidade_medida']??'UN',$data['unidade_compra']??'',$data['unidade_saida']??'',(float)($data['fator_conversao']??1),(float)($data['preco_custo']??0),(float)($data['despesas_acessorias']??0),(float)($data['outras_despesas']??0),(float)($data['custo_final']??0),(float)($data['preco_venda']??0),(float)($data['margem_lucro']??0),(float)($data['percentual_desconto_max']??0),(float)($data['percentual_comissao']??0),(float)($data['estoque_atual']??0),(float)($data['estoque_minimo']??0),(float)($data['estoque_maximo']??0),(float)($data['estoque_imobilizado']??0),(float)($data['estoque_uso_consumo']??0),(float)($data['estoque_revenda']??0),$data['localizacao']??'',(float)($data['peso_liquido']??0),(float)($data['peso_bruto']??0),(float)($data['largura']??0),(float)($data['altura']??0),(float)($data['profundidade']??0),$data['ncm']??'',$data['ncm_descricao']??'',$data['cfop']??'',$data['cest']??'',$data['origem']??'0',$data['csosn']??'102',$data['cst_icms']??'',(float)($data['aliq_icms']??0),$data['cst_pis']??'',(float)($data['aliq_pis']??0),$data['cst_cofins']??'',(float)($data['aliq_cofins']??0),$data['cst_ipi']??'',(float)($data['aliq_ipi']??0),(int)($data['nfse_movimenta']??0),$data['nfse_codigo_servico']??'',$data['nfse_municipio']??'',$data['nfse_cnae']??'',$data['nfse_descricao_servico']??'',(float)($data['nfse_deducoes']??0),(float)($data['nfse_cofins']??0),(float)($data['nfse_ir']??0),(float)($data['nfse_outras_deducoes']??0),(float)($data['nfse_pis']??0),(float)($data['nfse_inss']??0),(float)($data['nfse_csll']??0),(float)($data['nfse_iss']??0),$data['nfse_id_municipal_evento']??'',$data['nfse_descricao_evento']??'',$data['nfse_data_ini_evento']??'',$data['nfse_data_fim_evento']??'',$data['nfse_logradouro']??'',$data['nfse_numero']??'',$data['tabela_servico_id']??null,$data['codigo_nbs']??'',(float)($data['iss_percentual']??0),$data['nfse_natureza']??'tributacao_municipio',$data['nfse_incentivo_fiscal']??'nao',$data['observacoes']??'',$data['condicao_peca']??'nova_original',(int)($data['garantia_fornecedor']??0),$data['garantia_fornecedor_unidade']??'meses',(int)($data['garantia_venda']??0),$data['garantia_venda_unidade']??'meses',(int)($data['capacidade_mah']??0),$data['voltagem']??'',$data['tipo_tela']??'',$data['part_number']??'',$fotos_json,$now,$now]);
        $newProdId = (int)$db->lastInsertId();
        // Salvar dados da aba Loja Virtual em produto_loja
        if (array_key_exists('loja_exibir', $data) || array_key_exists('loja_titulo', $data)) {
            $loja_fotos_j     = json_encode(is_array($data['loja_fotos'] ?? null)     ? $data['loja_fotos']     : [], JSON_UNESCAPED_UNICODE);
            $loja_vars_j      = json_encode(is_array($data['loja_variacoes'] ?? null) ? $data['loja_variacoes'] : [], JSON_UNESCAPED_UNICODE);
            $loja_cat         = !empty($data['loja_categoria_id']) ? (int)$data['loja_categoria_id'] : null;
            $db->prepare("INSERT OR REPLACE INTO produto_loja (produto_id, loja_exibir, loja_titulo, loja_descricao, loja_categoria_id, loja_fotos, loja_variacoes, data_atualizacao) VALUES (?,?,?,?,?,?,?,?)")
               ->execute([$newProdId, (int)($data['loja_exibir']??0), trim($data['loja_titulo']??''), trim($data['loja_descricao']??''), $loja_cat, $loja_fotos_j, $loja_vars_j, date('Y-m-d H:i:s')]);
        }
        resp(201, ['success' => true, 'id' => $newProdId]);
    }
    if ($method === 'PUT' && $id !== null) {
        // Atualização rápida de loja_destaque (sem necessidade de enviar todos os campos do produto)
        if (array_key_exists('loja_destaque', $data) && !array_key_exists('descricao', $data)) {
            $chk = $db->prepare("SELECT id FROM produto_loja WHERE produto_id=?"); $chk->execute([$id]);
            if ($chk->fetchColumn()) {
                $db->prepare("UPDATE produto_loja SET loja_destaque=?, data_atualizacao=? WHERE produto_id=?")
                   ->execute([(int)$data['loja_destaque'], date('Y-m-d H:i:s'), $id]);
            } else {
                $db->prepare("INSERT INTO produto_loja (produto_id, loja_destaque, data_atualizacao) VALUES (?,?,?)")
                   ->execute([$id, (int)$data['loja_destaque'], date('Y-m-d H:i:s')]);
            }
            resp(200, ['success' => true]);
        }
        $fotos_json = json_encode(is_array($data['fotos']??null)?$data['fotos']:[], JSON_UNESCAPED_UNICODE);
        $db->prepare("UPDATE produtos SET tipo_item=?,ativo=?,codigo_interno=?,codigo_barras=?,descricao=?,descricao_complementar=?,unidade_medida=?,unidade_compra=?,unidade_saida=?,fator_conversao=?,preco_custo=?,despesas_acessorias=?,outras_despesas=?,custo_final=?,preco_venda=?,margem_lucro=?,percentual_desconto_max=?,percentual_comissao=?,estoque_atual=?,estoque_minimo=?,estoque_maximo=?,estoque_imobilizado=?,estoque_uso_consumo=?,estoque_revenda=?,localizacao=?,peso_liquido=?,peso_bruto=?,largura=?,altura=?,profundidade=?,ncm=?,ncm_descricao=?,cfop=?,cest=?,origem=?,csosn=?,cst_icms=?,aliq_icms=?,cst_pis=?,aliq_pis=?,cst_cofins=?,aliq_cofins=?,cst_ipi=?,aliq_ipi=?,nfse_movimenta=?,nfse_codigo_servico=?,nfse_municipio=?,nfse_cnae=?,nfse_descricao_servico=?,nfse_deducoes=?,nfse_cofins=?,nfse_ir=?,nfse_outras_deducoes=?,nfse_pis=?,nfse_inss=?,nfse_csll=?,nfse_iss=?,nfse_id_municipal_evento=?,nfse_descricao_evento=?,nfse_data_ini_evento=?,nfse_data_fim_evento=?,nfse_logradouro=?,nfse_numero=?,tabela_servico_id=?,codigo_nbs=?,iss_percentual=?,nfse_natureza=?,nfse_incentivo_fiscal=?,observacoes=?,condicao_peca=?,garantia_fornecedor=?,garantia_fornecedor_unidade=?,garantia_venda=?,garantia_venda_unidade=?,capacidade_mah=?,voltagem=?,tipo_tela=?,part_number=?,fotos=?,data_atualizacao=? WHERE id=?")
           ->execute([$data['tipo_item']??'produto',$data['ativo']??1,$data['codigo_interno']??'',(!empty($data['codigo_barras']) ? $data['codigo_barras'] : null),$data['descricao'],$data['descricao_complementar']??'',$data['unidade_medida']??'UN',$data['unidade_compra']??'',$data['unidade_saida']??'',(float)($data['fator_conversao']??1),(float)($data['preco_custo']??0),(float)($data['despesas_acessorias']??0),(float)($data['outras_despesas']??0),(float)($data['custo_final']??0),(float)($data['preco_venda']??0),(float)($data['margem_lucro']??0),(float)($data['percentual_desconto_max']??0),(float)($data['percentual_comissao']??0),(float)($data['estoque_atual']??0),(float)($data['estoque_minimo']??0),(float)($data['estoque_maximo']??0),(float)($data['estoque_imobilizado']??0),(float)($data['estoque_uso_consumo']??0),(float)($data['estoque_revenda']??0),$data['localizacao']??'',(float)($data['peso_liquido']??0),(float)($data['peso_bruto']??0),(float)($data['largura']??0),(float)($data['altura']??0),(float)($data['profundidade']??0),$data['ncm']??'',$data['ncm_descricao']??'',$data['cfop']??'',$data['cest']??'',$data['origem']??'0',$data['csosn']??'102',$data['cst_icms']??'',(float)($data['aliq_icms']??0),$data['cst_pis']??'',(float)($data['aliq_pis']??0),$data['cst_cofins']??'',(float)($data['aliq_cofins']??0),$data['cst_ipi']??'',(float)($data['aliq_ipi']??0),(int)($data['nfse_movimenta']??0),$data['nfse_codigo_servico']??'',$data['nfse_municipio']??'',$data['nfse_cnae']??'',$data['nfse_descricao_servico']??'',(float)($data['nfse_deducoes']??0),(float)($data['nfse_cofins']??0),(float)($data['nfse_ir']??0),(float)($data['nfse_outras_deducoes']??0),(float)($data['nfse_pis']??0),(float)($data['nfse_inss']??0),(float)($data['nfse_csll']??0),(float)($data['nfse_iss']??0),$data['nfse_id_municipal_evento']??'',$data['nfse_descricao_evento']??'',$data['nfse_data_ini_evento']??'',$data['nfse_data_fim_evento']??'',$data['nfse_logradouro']??'',$data['nfse_numero']??'',$data['tabela_servico_id']??null,$data['codigo_nbs']??'',(float)($data['iss_percentual']??0),$data['nfse_natureza']??'tributacao_municipio',$data['nfse_incentivo_fiscal']??'nao',$data['observacoes']??'',$data['condicao_peca']??'nova_original',(int)($data['garantia_fornecedor']??0),$data['garantia_fornecedor_unidade']??'meses',(int)($data['garantia_venda']??0),$data['garantia_venda_unidade']??'meses',(int)($data['capacidade_mah']??0),$data['voltagem']??'',$data['tipo_tela']??'',$data['part_number']??'',$fotos_json,date('Y-m-d H:i:s'),$id]);
        // Salvar / atualizar dados da aba Loja Virtual em produto_loja
        if (array_key_exists('loja_exibir', $data) || array_key_exists('loja_titulo', $data)) {
            $loja_fotos_j = json_encode(is_array($data['loja_fotos'] ?? null)     ? $data['loja_fotos']     : [], JSON_UNESCAPED_UNICODE);
            $loja_vars_j  = json_encode(is_array($data['loja_variacoes'] ?? null) ? $data['loja_variacoes'] : [], JSON_UNESCAPED_UNICODE);
            $loja_cat     = !empty($data['loja_categoria_id']) ? (int)$data['loja_categoria_id'] : null;
            $loja_dest    = isset($data['loja_destaque']) ? (int)$data['loja_destaque'] : null;
            $chk = $db->prepare("SELECT id, loja_destaque FROM produto_loja WHERE produto_id=?"); $chk->execute([$id]);
            $existingLoja = $chk->fetch();
            if ($existingLoja) {
                $loja_dest_final = $loja_dest !== null ? $loja_dest : (int)($existingLoja['loja_destaque'] ?? 0);
                $db->prepare("UPDATE produto_loja SET loja_exibir=?, loja_destaque=?, loja_titulo=?, loja_descricao=?, loja_categoria_id=?, loja_fotos=?, loja_variacoes=?, data_atualizacao=? WHERE produto_id=?")
                   ->execute([(int)($data['loja_exibir']??0), $loja_dest_final, trim($data['loja_titulo']??''), trim($data['loja_descricao']??''), $loja_cat, $loja_fotos_j, $loja_vars_j, date('Y-m-d H:i:s'), $id]);
            } else {
                $db->prepare("INSERT INTO produto_loja (produto_id, loja_exibir, loja_destaque, loja_titulo, loja_descricao, loja_categoria_id, loja_fotos, loja_variacoes, data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?)")
                   ->execute([$id, (int)($data['loja_exibir']??0), $loja_dest ?? 0, trim($data['loja_titulo']??''), trim($data['loja_descricao']??''), $loja_cat, $loja_fotos_j, $loja_vars_j, date('Y-m-d H:i:s')]);
            }
        }
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM produtos WHERE id=?")->execute([$id]);
        $db->prepare("DELETE FROM produto_loja WHERE produto_id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── ORDENS DE SERVIÇO ────────────────────────────────────────
if ($resource === 'ordens_servico') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $status = $_GET['status'] ?? '';
        $q_raw  = $_GET['q'] ?? '';
        $q      = '%' . normalizar_busca($q_raw) . '%';
        $atraso = $_GET['atraso'] ?? '';
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $limit  = 20; $offset = ($page - 1) * $limit;
        $where = ['1=1']; $params = [];
        if ($status !== '') { $where[] = 'os.status = ?'; $params[] = $status; }
        if ($atraso === '1') { $where[] = "os.previsao_conclusao IS NOT NULL AND os.previsao_conclusao!='' AND os.previsao_conclusao < DATE('now') AND os.status NOT IN ('Aguardando Aparelho','Aguardando Aprovação','Aguardando Retirada','Cancelada','Faturada') AND os.status NOT LIKE 'Conclu%' AND os.status NOT LIKE 'N_o Aprovada' AND os.status NOT LIKE 'Sem Con%'"; }
        if (($_GET['dash_os_abertas'] ?? '') === '1') { $where[] = "os.status NOT IN ('Cancelada','Faturada') AND os.status NOT LIKE 'Conclu%' AND os.status NOT LIKE 'N_o Aprov%' AND os.status NOT LIKE 'Sem Con%'"; }
        if ($q_raw !== '') { $where[] = '(LOWER(c.nome) LIKE ? OR CAST(os.id AS TEXT) LIKE ?)'; $params = array_merge($params, [$q, $q]); }
        $w = implode(' AND ', $where);
        $tc = $db->prepare("SELECT COUNT(*) FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();
        $s = $db->prepare("SELECT os.*, c.nome AS cliente_nome, c.telefone AS cliente_telefone, ta.nome AS tipo_nome, m.nome AS marca_nome, mo.nome AS modelo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id LEFT JOIN marcas m ON os.marca_id=m.id LEFT JOIN modelos mo ON os.modelo_id=mo.id WHERE $w ORDER BY os.id DESC LIMIT ? OFFSET ?");
        $s->execute(array_merge($params, [$limit, $offset]));
        resp(200, ['data' => $s->fetchAll(), 'total' => $total, 'page' => $page, 'pages' => (int)ceil($total / $limit)]);
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT os.*, c.nome AS cliente_nome, c.telefone AS cliente_telefone, c.telefone_secundario AS cliente_telefone_secundario, c.cpf AS cliente_cpf, c.cnpj AS cliente_cnpj, c.tipo_pessoa AS cliente_tipo_pessoa, ta.nome AS tipo_nome, m.nome AS marca_nome, mo.nome AS modelo_nome, f.nome AS tecnico_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id LEFT JOIN marcas m ON os.marca_id=m.id LEFT JOIN modelos mo ON os.modelo_id=mo.id LEFT JOIN funcionarios f ON f.id=os.tecnico_id WHERE os.id=?");
        $s->execute([$id]); $os = $s->fetch();
        if (!$os) resp(404, ['error' => 'Não encontrado']);
        $s2 = $db->prepare("SELECT o.*, p.descricao AS produto_descricao, p.tipo_item AS produto_tipo, pc.descricao AS peca_nome FROM orcamentos o LEFT JOIN produtos p ON o.produto_id=p.id LEFT JOIN produtos pc ON o.peca_id=pc.id WHERE o.ordem_id=? ORDER BY o.id"); $s2->execute([$id]); $os['orcamentos'] = $s2->fetchAll();
        $s3 = $db->prepare("SELECT * FROM midias_os WHERE ordem_id=? ORDER BY id DESC"); $s3->execute([$id]); $os['midias'] = $s3->fetchAll();
        $s4 = $db->prepare("SELECT o.*, u.nome AS usuario_nome FROM ordem_observacoes o LEFT JOIN usuarios u ON o.usuario_id=u.id WHERE o.ordem_id=? ORDER BY o.id DESC"); $s4->execute([$id]); $os['observacoes'] = $s4->fetchAll();
        resp(200, $os);
    }
    if ($method === 'POST' && !$action) {
        if (empty($data['cliente_id'])) resp(400, ['error' => 'cliente_id obrigatório']);
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO ordens_servico (cliente_id,tipo_aparelho_id,marca_id,modelo_id,descricao,informacoes_adicionais,senha_aparelho,status,checklist,tecnico_id,data_abertura) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([$data['cliente_id'],$data['tipo_aparelho_id']??null,$data['marca_id']??null,$data['modelo_id']??null,$data['descricao']??'',$data['informacoes_adicionais']??'',$data['senha_aparelho']??'',$data['status']??'Aberta',$data['checklist']??'',!empty($data['tecnico_id'])?(int)$data['tecnico_id']:null,date('Y-m-d H:i:s')]);
            $lid = (int)$db->lastInsertId(); $db->commit();
            resp(201, ['success' => true, 'id' => $lid]);
        } catch (Exception $e) { $db->rollBack(); resp(500, ['error' => $e->getMessage()]); }
    }
    // ── POST estornar_faturamento ──────────────────────────────────
    if ($method === 'POST' && $action === 'estornar_faturamento' && $id !== null) {
        $cur = $db->prepare("SELECT * FROM ordens_servico WHERE id=?");
        $cur->execute([$id]); $os = $cur->fetch();
        if (!$os) resp(404, ['error' => 'OS não encontrada']);
        if ($os['status'] !== 'Faturada') resp(400, ['error' => 'Esta OS não está com status Faturada']);

        // Verifica NFC-e vinculada
        $sNfce = $db->prepare("SELECT * FROM nfce_emitidas WHERE os_id=? ORDER BY id DESC LIMIT 1");
        $sNfce->execute([$id]); $nfce = $sNfce->fetch();
        if ($nfce && !in_array($nfce['status'], ['Cancelada','Inutilizada','Rejeitada'], true)) {
            resp(400, ['error' => 'NFC-e nº '.$nfce['numero'].' vinculada não está cancelada. Cancele a nota no módulo Fiscal antes de estornar.', 'tipo' => 'nfce', 'nfce_id' => $nfce['id']]);
        }

        // Verifica NFS-e vinculada
        $sNfse = $db->prepare("SELECT * FROM nfse_emitidas WHERE os_id=? ORDER BY id DESC LIMIT 1");
        $sNfse->execute([$id]); $nfse = $sNfse->fetch();
        if ($nfse && $nfse['status'] !== 'Cancelada') {
            resp(400, ['error' => 'NFS-e nº '.$nfse['numero'].' vinculada não está cancelada. Cancele a nota no módulo Fiscal antes de estornar.', 'tipo' => 'nfse', 'nfse_id' => $nfse['id']]);
        }

        // Busca venda simples vinculada
        $sVenda = $db->prepare("SELECT * FROM vendas WHERE os_id=? AND status='Confirmada' ORDER BY id DESC LIMIT 1");
        $sVenda->execute([$id]); $venda = $sVenda->fetch();

        $db->beginTransaction();
        try {
            $now = date('Y-m-d H:i:s');

            // ── Venda Simples ──────────────────────────────────────
            if ($venda) {
                // Cancela venda
                $db->prepare("UPDATE vendas SET status='Cancelada' WHERE id=?")
                   ->execute([$venda['id']]);

                // Restaura estoque dos itens da venda (produtos com produto_id)
                $siVenda = $db->prepare("SELECT produto_id, quantidade FROM venda_items WHERE venda_id=? AND produto_id IS NOT NULL");
                $siVenda->execute([$venda['id']]);
                $updEst = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual + ? WHERE id=?");
                foreach ($siVenda->fetchAll() as $it) $updEst->execute([(float)$it['quantidade'], (int)$it['produto_id']]);

                // Cancela contas a receber da venda
                $db->prepare("UPDATE contas_receber SET status='Cancelada',data_atualizacao=? WHERE venda_id=? AND origem='venda' AND status NOT IN ('Cancelada','Recebida')")
                   ->execute([$now, $venda['id']]);
            }

            // ── NFC-e (já cancelada pelo usuário) ──────────────────
            if ($nfce) {
                // Cancela contas a receber da NFC-e
                $db->prepare("UPDATE contas_receber SET status='Cancelada',data_atualizacao=? WHERE venda_id=? AND origem='nfce' AND status NOT IN ('Cancelada','Recebida')")
                   ->execute([$now, $nfce['id']]);

                // Restaura estoque dos itens da NFC-e (extraídos do payload_json)
                $payload = json_decode($nfce['payload_json'] ?? '{}', true);
                if (!empty($payload['itens'])) {
                    $updEstNfce = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual + ? WHERE id=?");
                    foreach ($payload['itens'] as $it) {
                        $pid = (int)($it['_produto_id'] ?? 0);
                        $qty = (float)($it['quantidade'] ?? 0);
                        if ($pid > 0 && $qty > 0) $updEstNfce->execute([$qty, $pid]);
                    }
                }
            }

            // ── NFS-e (já cancelada pelo usuário) ──────────────────
            if ($nfse) {
                $db->prepare("UPDATE contas_receber SET status='Cancelada',data_atualizacao=? WHERE venda_id=? AND origem='nfse' AND status NOT IN ('Cancelada','Recebida')")
                   ->execute([$now, $nfse['id']]);
            }

            // ── Restaura estoque das peças dos orçamentos (baixado ao faturar) ──
            $sPecas = $db->prepare("
                SELECT op.produto_id, SUM(op.quantidade) AS total_qtd
                FROM orcamento_pecas op
                JOIN orcamentos o ON op.orcamento_id = o.id
                WHERE o.ordem_id = ?
                GROUP BY op.produto_id
            ");
            $sPecas->execute([$id]);
            $updPeca = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual + ? WHERE id=?");
            foreach ($sPecas->fetchAll() as $row) $updPeca->execute([(float)$row['total_qtd'], (int)$row['produto_id']]);

            // ── Volta OS para Aberta ───────────────────────────────
            $db->prepare("UPDATE ordens_servico SET status='Aberta',data_atualizacao=? WHERE id=?")->execute([$now, $id]);
            $db->prepare("INSERT INTO notificacoes (ordem_id,novo_status) VALUES (?,?)")->execute([$id,'Aberta']);

            $db->commit();
            resp(200, ['success' => true]);
        } catch (Exception $e) { $db->rollBack(); resp(500, ['error' => 'Erro ao estornar: '.$e->getMessage()]); }
    }

    if ($method === 'PUT' && $id !== null) {
        $db->beginTransaction();
        try {
            // Busca dados atuais da OS para fazer merge (evita sobrescrever campos não enviados)
            $cur = $db->prepare("SELECT * FROM ordens_servico WHERE id=?");
            $cur->execute([$id]);
            $cur_os = $cur->fetch();
            if (!$cur_os) { $db->rollBack(); resp(404, ['error' => 'OS não encontrada']); }

            $old_s = $cur_os['status'];
            $new_s = $data['status'] ?? $old_s;

            $db->prepare("UPDATE ordens_servico SET cliente_id=?,tipo_aparelho_id=?,marca_id=?,modelo_id=?,descricao=?,informacoes_adicionais=?,senha_aparelho=?,status=?,previsao_conclusao=?,checklist=?,tecnico_id=?,data_atualizacao=? WHERE id=?")
               ->execute([
                   $data['cliente_id']            ?? $cur_os['cliente_id'],
                   $data['tipo_aparelho_id']       ?? $cur_os['tipo_aparelho_id'],
                   $data['marca_id']               ?? $cur_os['marca_id'],
                   $data['modelo_id']              ?? $cur_os['modelo_id'],
                   $data['descricao']              ?? $cur_os['descricao'],
                   $data['informacoes_adicionais'] ?? $cur_os['informacoes_adicionais'],
                   $data['senha_aparelho']         ?? $cur_os['senha_aparelho'],
                   $new_s,
                   $data['previsao_conclusao']     ?? $cur_os['previsao_conclusao'],
                   $data['checklist']              ?? $cur_os['checklist'],
                   array_key_exists('tecnico_id',$data) ? (!empty($data['tecnico_id'])?(int)$data['tecnico_id']:null) : $cur_os['tecnico_id'],
                   date('Y-m-d H:i:s'),
                   $id
               ]);
            if ($old_s && $old_s !== $new_s) $db->prepare("INSERT INTO notificacoes (ordem_id,novo_status) VALUES (?,?)")->execute([$id,$new_s]);

            // Baixa de estoque ao faturar — deduz peças utilizadas nos orçamentos desta OS
            if ($new_s === 'Faturada' && $old_s !== 'Faturada') {
                $sp = $db->prepare("
                    SELECT op.produto_id, SUM(op.quantidade) AS total_qtd
                    FROM orcamento_pecas op
                    JOIN orcamentos o ON op.orcamento_id = o.id
                    WHERE o.ordem_id = ?
                    GROUP BY op.produto_id
                ");
                $sp->execute([$id]);
                $upd = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual - ? WHERE id = ?");
                foreach ($sp->fetchAll() as $row) {
                    $upd->execute([(float)$row['total_qtd'], (int)$row['produto_id']]);
                }
            }

            $db->commit(); resp(200, ['success' => true]);
        } catch (Exception $e) { $db->rollBack(); resp(500, ['error' => $e->getMessage()]); }
    }
    if ($method === 'DELETE' && $id !== null) {
        $s = $db->prepare("SELECT caminho FROM midias_os WHERE ordem_id=?"); $s->execute([$id]);
        foreach ($s->fetchAll() as $m) { $p = SAAS_DIR . '/' . ltrim($m['caminho'],'/'); if (file_exists($p)) unlink($p); }
        $db->prepare("DELETE FROM midias_os WHERE ordem_id=?")->execute([$id]);
        $db->prepare("DELETE FROM orcamentos WHERE ordem_id=?")->execute([$id]);
        $db->prepare("DELETE FROM ordem_observacoes WHERE ordem_id=?")->execute([$id]);
        $db->prepare("DELETE FROM ordens_servico WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── ORÇAMENTOS ───────────────────────────────────────────────
if ($resource === 'orcamentos') {
    auth_required();
    if ($method === 'POST') {
        $db->prepare("INSERT INTO orcamentos (ordem_id,produto_id,observacoes,valor,status_orcamento,peca_id) VALUES (?,?,?,?,?,?)")
           ->execute([$data['ordem_id'],$data['produto_id']??null,$data['observacoes']??'',$data['valor']??0,$data['status_orcamento']??'Pendente',$data['peca_id']??null]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        // Preserva produto_id se não enviado no payload
        $produto_id_upd = array_key_exists('produto_id', $data) ? ($data['produto_id']??null) : null;
        $peca_id_upd = array_key_exists('peca_id', $data) ? ($data['peca_id'] ?? null) : null;
        if(array_key_exists('produto_id', $data)){
            $db->prepare("UPDATE orcamentos SET produto_id=?,observacoes=?,valor=?,status_orcamento=?,peca_id=? WHERE id=?")
               ->execute([$produto_id_upd,$data['observacoes']??'',$data['valor']??0,$data['status_orcamento']??'Pendente',$peca_id_upd,$id]);
        } else {
            $db->prepare("UPDATE orcamentos SET observacoes=?,valor=?,status_orcamento=?,peca_id=? WHERE id=?")
               ->execute([$data['observacoes']??'',$data['valor']??0,$data['status_orcamento']??'Pendente',$peca_id_upd,$id]);
        }
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM orcamentos WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── PEÇAS DO ORÇAMENTO ───────────────────────────────────────
if ($resource === 'orcamento_pecas') {
    auth_required();
    if ($method === 'GET') {
        $orc_id = (int)($_GET['orcamento_id'] ?? 0);
        if (!$orc_id) resp(400, ['error' => 'orcamento_id obrigatório']);
        $s = $db->prepare("
            SELECT op.id, op.orcamento_id, op.produto_id, op.quantidade,
                   p.descricao AS peca_descricao, p.estoque_atual, p.codigo_interno
            FROM orcamento_pecas op
            LEFT JOIN produtos p ON op.produto_id = p.id
            WHERE op.orcamento_id = ?
            ORDER BY op.id
        ");
        $s->execute([$orc_id]);
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST') {
        $orc_id  = (int)($data['orcamento_id'] ?? 0);
        $prod_id = (int)($data['produto_id']   ?? 0);
        $qtd     = (float)($data['quantidade'] ?? 1);
        if (!$orc_id || !$prod_id) resp(400, ['error' => 'orcamento_id e produto_id obrigatórios']);
        $db->prepare("INSERT INTO orcamento_pecas (orcamento_id, produto_id, quantidade) VALUES (?,?,?)")
           ->execute([$orc_id, $prod_id, $qtd]);
        $new_id = (int)$db->lastInsertId();
        $s = $db->prepare("SELECT op.id, op.orcamento_id, op.produto_id, op.quantidade, p.descricao AS peca_descricao, p.estoque_atual, p.codigo_interno FROM orcamento_pecas op LEFT JOIN produtos p ON op.produto_id=p.id WHERE op.id=?");
        $s->execute([$new_id]);
        resp(201, $s->fetch());
    }
    if ($method === 'PUT' && $id !== null) {
        $qtd = (float)($data['quantidade'] ?? 1);
        if ($qtd <= 0) resp(400, ['error' => 'Quantidade deve ser maior que zero']);
        $db->prepare("UPDATE orcamento_pecas SET quantidade=? WHERE id=?")->execute([$qtd, $id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM orcamento_pecas WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── OBSERVAÇÕES ──────────────────────────────────────────────
if ($resource === 'observacoes') {
    $user = auth_required();
    if ($method === 'POST') {
            $db->prepare("INSERT INTO ordem_observacoes (ordem_id,usuario_id,observacao,data_criacao) VALUES (?,?,?,?)")
           ->execute([$data['ordem_id'],$user['id'],$data['observacao']??'',date('Y-m-d H:i:s')]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM ordem_observacoes WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── NOTIFICAÇÕES ─────────────────────────────────────────────
if ($resource === 'notificacoes') {
    auth_required();
    if ($method === 'GET') {
        $s = $db->query("SELECT n.*, c.nome AS cliente_nome FROM notificacoes n JOIN ordens_servico os ON n.ordem_id=os.id JOIN clientes c ON c.id=os.cliente_id WHERE n.lida=0 ORDER BY n.data_notificacao DESC LIMIT 20");
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST' && $action === 'marcar_lida') {
        $nid = $data['id'] ?? null;
        if ($nid) $db->prepare("UPDATE notificacoes SET lida=1 WHERE id=?")->execute([$nid]);
        else $db->exec("UPDATE notificacoes SET lida=1");
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── USUÁRIOS ─────────────────────────────────────────────────
if ($resource === 'usuarios') {
    auth_required();
    // Redefinir senha de qualquer usuário
    if ($action === 'reset_senha' && $method === 'POST') {
        $uid   = (int)($data['id'] ?? 0);
        $senha = trim($data['senha'] ?? '');
        if (!$uid || !$senha) resp(400, ['error' => 'ID e senha obrigatórios']);
        if (strlen($senha) < 4)  resp(400, ['error' => 'Senha deve ter pelo menos 4 caracteres']);
        $h = password_hash($senha, PASSWORD_DEFAULT);
        $db->prepare("UPDATE usuarios SET senha = ? WHERE id = ?")->execute([$h, $uid]);
        resp(200, ['success' => true]);
    }
    if ($method === 'GET' && $id === null) {
        resp(200, $db->query("SELECT id,nome,email,nivel_acesso,COALESCE(ativo,1) as ativo,funcionario_id FROM usuarios ORDER BY nome")->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT id,nome,email,nivel_acesso,COALESCE(ativo,1) as ativo,funcionario_id FROM usuarios WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        if (empty($data['nome']) || empty($data['senha'])) resp(400, ['error' => 'Nome e senha obrigatórios']);
        $h = password_hash($data['senha'], PASSWORD_DEFAULT);
        $fid = !empty($data['funcionario_id']) ? (int)$data['funcionario_id'] : null;
        $db->prepare("INSERT INTO usuarios (nome,email,senha,nivel_acesso,funcionario_id) VALUES (?,?,?,?,?)")
           ->execute([$data['nome'],$data['email']??'',$h,$data['nivel_acesso']??'tecnico',$fid]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $fid = !empty($data['funcionario_id']) ? (int)$data['funcionario_id'] : null;
        if (!empty($data['senha'])) {
            $h = password_hash($data['senha'], PASSWORD_DEFAULT);
            $db->prepare("UPDATE usuarios SET nome=?,email=?,senha=?,nivel_acesso=?,funcionario_id=? WHERE id=?")->execute([$data['nome'],$data['email']??'',$h,$data['nivel_acesso']??'tecnico',$fid,$id]);
        } else {
            $db->prepare("UPDATE usuarios SET nome=?,email=?,nivel_acesso=?,funcionario_id=? WHERE id=?")->execute([$data['nome'],$data['email']??'',$data['nivel_acesso']??'tecnico',$fid,$id]);
        }
        // Atualiza sessão se o usuário editado for o próprio logado
        if (isset($_SESSION['usuario']['id']) && (int)$_SESSION['usuario']['id'] === (int)$id) {
            $stmt = $db->prepare("SELECT * FROM usuarios WHERE id=?");
            $stmt->execute([$id]);
            $u = $stmt->fetch();
            if ($u) { unset($u['senha']); $_SESSION['usuario'] = $u; }
        }
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM usuarios WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── CARGOS ───────────────────────────────────────────────────
if ($resource === 'cargos') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        resp(200, $db->query("SELECT id, nome, ativo, COALESCE(tecnico,0) AS tecnico, COALESCE(vendedor,0) AS vendedor FROM cargos ORDER BY nome")->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT id, nome, ativo, COALESCE(tecnico,0) AS tecnico, COALESCE(vendedor,0) AS vendedor FROM cargos WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO cargos (nome, ativo, tecnico, vendedor) VALUES (?, 1, ?, ?)")
           ->execute([$nome, (int)($data['tecnico'] ?? 0), (int)($data['vendedor'] ?? 0)]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId(), 'nome' => $nome]);
    }
    if ($method === 'PUT' && $id !== null) {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("UPDATE cargos SET nome=?, ativo=?, tecnico=?, vendedor=? WHERE id=?")
           ->execute([$nome, (int)($data['ativo'] ?? 1), (int)($data['tecnico'] ?? 0), (int)($data['vendedor'] ?? 0), $id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $em_uso = $db->prepare("SELECT COUNT(*) FROM funcionarios WHERE cargo_id=?");
        $em_uso->execute([$id]);
        if ($em_uso->fetchColumn() > 0) resp(400, ['error' => 'Cargo em uso por um ou mais funcionários.']);
        $db->prepare("DELETE FROM cargos WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── FUNCIONÁRIOS ─────────────────────────────────────────────
if ($resource === 'funcionarios') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $where = '1=1'; $params = [];
        if (!empty($_GET['q'])) {
            $q = '%' . $_GET['q'] . '%';
            $where .= ' AND (f.nome LIKE ? OR f.cpf LIKE ? OR f.telefone LIKE ?)';
            $params = array_merge($params, [$q, $q, $q]);
        }
        if (!empty($_GET['cargo_id'])) {
            $where .= ' AND f.cargo_id = ?';
            $params[] = (int)$_GET['cargo_id'];
        }
        if (isset($_GET['status']) && $_GET['status'] !== '') {
            $where .= ' AND f.status = ?';
            $params[] = $_GET['status'];
        }
        $s = $db->prepare("SELECT f.*, c.nome AS cargo_nome, COALESCE(c.tecnico,0) AS cargo_tecnico, COALESCE(c.vendedor,0) AS cargo_vendedor FROM funcionarios f LEFT JOIN cargos c ON c.id=f.cargo_id WHERE $where ORDER BY f.nome");
        $s->execute($params);
        resp(200, $s->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT f.*, c.nome AS cargo_nome FROM funcionarios f LEFT JOIN cargos c ON c.id=f.cargo_id WHERE f.id=?");
        $s->execute([$id]); $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("INSERT INTO funcionarios (status,nome,cpf,data_nascimento,telefone,cargo_id,carga_horaria_semanal,salario_mensal,valor_hora,comissao_venda_ativo,comissao_venda_percentual,comissao_servico_ativo,comissao_servico_percentual,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([
               $data['status']??'Ativo', $nome,
               $data['cpf']??'', $data['data_nascimento']??null, $data['telefone']??'',
               $data['cargo_id']??(int)$data['cargo_id']??null,
               (float)($data['carga_horaria_semanal']??0), (float)($data['salario_mensal']??0),
               (float)($data['valor_hora']??0),
               (int)($data['comissao_venda_ativo']??0), (float)($data['comissao_venda_percentual']??0),
               (int)($data['comissao_servico_ativo']??0), (float)($data['comissao_servico_percentual']??0),
               $now, $now
           ]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $now = date('Y-m-d H:i:s');
        $cargo_id = !empty($data['cargo_id']) ? (int)$data['cargo_id'] : null;
        $db->prepare("UPDATE funcionarios SET status=?,nome=?,cpf=?,data_nascimento=?,telefone=?,cargo_id=?,carga_horaria_semanal=?,salario_mensal=?,valor_hora=?,comissao_venda_ativo=?,comissao_venda_percentual=?,comissao_servico_ativo=?,comissao_servico_percentual=?,data_atualizacao=? WHERE id=?")
           ->execute([
               $data['status']??'Ativo', $nome,
               $data['cpf']??'', $data['data_nascimento']??null, $data['telefone']??'',
               $cargo_id,
               (float)($data['carga_horaria_semanal']??0), (float)($data['salario_mensal']??0),
               (float)($data['valor_hora']??0),
               (int)($data['comissao_venda_ativo']??0), (float)($data['comissao_venda_percentual']??0),
               (int)($data['comissao_servico_ativo']??0), (float)($data['comissao_servico_percentual']??0),
               $now, $id
           ]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM funcionarios WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── DASHBOARD ────────────────────────────────────────────────
// ─── MÍDIAS ───────────────────────────────────────────────────
if ($resource === 'midias') {
    auth_required();
    if ($method === 'POST') {
        $ordem_id = (int)($data['ordem_id'] ?? $_POST['ordem_id'] ?? 0);
        if (!$ordem_id) resp(400, ['error' => 'ordem_id obrigatório']);
        $uploads_dir = SAAS_DIR . '/uploads/';
        if (!is_dir($uploads_dir)) mkdir($uploads_dir, 0755, true);
        $arquivos = $_FILES['midia'] ?? [];
        if (empty($arquivos['name'])) resp(400, ['error' => 'Nenhum arquivo enviado']);
        // Normaliza estrutura (múltiplos arquivos vs único)
        $nomes    = is_array($arquivos['name'])    ? $arquivos['name']    : [$arquivos['name']];
        $tmps     = is_array($arquivos['tmp_name']) ? $arquivos['tmp_name'] : [$arquivos['tmp_name']];
        $erros    = is_array($arquivos['error'])   ? $arquivos['error']   : [$arquivos['error']];
        $comments = isset($_POST['midia_comment']) ? (is_array($_POST['midia_comment']) ? $_POST['midia_comment'] : [$_POST['midia_comment']]) : [];
        // Whitelist de extensões permitidas — apenas fotos e vídeos comuns.
        // NUNCA aceitar .php, .phtml, .phar, .js, .html, etc.
        $ext_permitidas = ['jpg','jpeg','png','gif','webp','heic','heif','bmp','tiff','tif','pdf','mp4','mov','avi','mkv','3gp','wmv','flv'];
        $salvos = [];
        foreach ($nomes as $i => $nome_original) {
            if ($erros[$i] !== UPLOAD_ERR_OK) continue;
            $ext  = strtolower(pathinfo($nome_original, PATHINFO_EXTENSION));
            // Bloqueia extensões não permitidas antes de tocar no disco
            if (!in_array($ext, $ext_permitidas, true)) continue;
            $safe = preg_replace('/[^a-z0-9]/','', strtolower(pathinfo($nome_original, PATHINFO_FILENAME)));
            $nome_arquivo = $ordem_id . '_' . time() . '_' . $i . '_' . $safe . '.' . $ext;
            $destino = $uploads_dir . $nome_arquivo;
            if (move_uploaded_file($tmps[$i], $destino)) {
                $caminho   = 'uploads/' . $nome_arquivo;
                $tipo      = mime_content_type($destino) ?: '';
                $comentario = $comments[$i] ?? '';
                $db->prepare("INSERT INTO midias_os (ordem_id, caminho, tipo, comentario) VALUES (?,?,?,?)")
                   ->execute([$ordem_id, $caminho, $tipo, $comentario]);
                $salvos[] = ['id' => (int)$db->lastInsertId(), 'caminho' => $caminho, 'tipo' => $tipo, 'comentario' => $comentario];
            }
        }
        resp(201, ['success' => true, 'midias' => $salvos]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $m = $db->prepare("SELECT caminho FROM midias_os WHERE id=?"); $m->execute([$id]); $row = $m->fetch();
        if ($row) { $p = SAAS_DIR . '/' . ltrim($row['caminho'],'/'); if (file_exists($p)) unlink($p); }
        $db->prepare("DELETE FROM midias_os WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── GERAR LINK UPLOAD MOBILE (QR Code) ──────────────────────
if ($resource === 'gerar_link_upload' && $method === 'POST') {
    auth_required();
    $os_id = (int)($data['os_id'] ?? 0);
    if (!$os_id) resp(400, ['error' => 'os_id obrigatório']);
    $token = bin2hex(random_bytes(32));
    $expiracao = date('Y-m-d H:i:s', strtotime('+15 minutes'));
    // Garante colunas necessárias na tabela uploads_temporarios
    try { $db->exec("ALTER TABLE uploads_temporarios ADD COLUMN token TEXT"); } catch(PDOException $e){}
    try { $db->exec("ALTER TABLE uploads_temporarios ADD COLUMN os_id INTEGER"); } catch(PDOException $e){}
    try { $db->exec("ALTER TABLE uploads_temporarios ADD COLUMN status TEXT"); } catch(PDOException $e){}
    try { $db->exec("ALTER TABLE uploads_temporarios ADD COLUMN data_expiracao DATETIME"); } catch(PDOException $e){}
    try { $db->exec("ALTER TABLE uploads_temporarios ADD COLUMN caminho_imagem TEXT"); } catch(PDOException $e){}
    $db->prepare("INSERT INTO uploads_temporarios (os_id, token, status, data_expiracao) VALUES (?,?,'pendente',?)")
       ->execute([$os_id, $token, $expiracao]);
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    $upload_url = "{$protocol}://{$host}{$base}/upload_mobile.php?token={$token}";
    resp(200, ['success' => true, 'token' => $token, 'upload_url' => $upload_url]);
}

// ─── VERIFICAR STATUS UPLOAD MOBILE ───────────────────────────
if ($resource === 'verificar_status_upload' && $method === 'POST') {
    auth_required();
    $token = trim($data['token'] ?? '');
    if (!$token) resp(400, ['error' => 'token obrigatório']);
    $stmt = $db->prepare("SELECT * FROM uploads_temporarios WHERE token=?");
    $stmt->execute([$token]);
    $row = $stmt->fetch();
    if (!$row) resp(404, ['error' => 'Token não encontrado']);
    $expirado = strtotime($row['data_expiracao']) < time();
    $status = $expirado ? 'expirado' : ($row['status'] ?? 'pendente');
    $payload = ['success' => true, 'status' => $status];
    if ($status === 'concluido') {
        // Busca novas mídias adicionadas para essa OS após o token ser criado
        $s2 = $db->prepare("SELECT * FROM midias_os WHERE ordem_id=? ORDER BY id DESC LIMIT 10");
        $s2->execute([$row['os_id']]);
        $payload['midias'] = $s2->fetchAll();
        // Cria novo token para envio adicional
        $novo_token = bin2hex(random_bytes(32));
        $nova_exp   = date('Y-m-d H:i:s', strtotime('+15 minutes'));
        $db->prepare("INSERT INTO uploads_temporarios (os_id, token, status, data_expiracao) VALUES (?,?,'pendente',?)")
           ->execute([$row['os_id'], $novo_token, $nova_exp]);
        $payload['new_token'] = $novo_token;
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
        $payload['new_upload_url'] = "{$protocol}://{$host}{$base}/upload_mobile.php?token={$novo_token}";
    }
    resp(200, $payload);
}

// ─── PROCESSAR UPLOAD MOBILE (chamado por upload_mobile.php) ──
if ($resource === 'processar_upload_mobile' && $method === 'POST') {
    $token = trim($_POST['token'] ?? '');
    if (!$token) resp(400, ['error' => 'token obrigatório']);
    $stmt = $db->prepare("SELECT * FROM uploads_temporarios WHERE token=? AND status='pendente'");
    $stmt->execute([$token]);
    $row = $stmt->fetch();
    if (!$row) resp(403, ['error' => 'Token inválido ou expirado']);
    if (strtotime($row['data_expiracao']) < time()) resp(403, ['error' => 'Token expirado']);
    $os_id = (int)$row['os_id'];
    $uploads_dir = SAAS_DIR . '/uploads/';
    if (!is_dir($uploads_dir)) mkdir($uploads_dir, 0755, true);
    $arquivos = $_FILES['imagens'] ?? [];
    if (empty($arquivos['name'])) resp(400, ['error' => 'Nenhum arquivo recebido']);
    $nomes = is_array($arquivos['name']) ? $arquivos['name'] : [$arquivos['name']];
    $tmps  = is_array($arquivos['tmp_name']) ? $arquivos['tmp_name'] : [$arquivos['tmp_name']];
    $erros = is_array($arquivos['error']) ? $arquivos['error'] : [$arquivos['error']];
    // Mesma whitelist do endpoint /midias — bloqueia execução de código via upload
    $ext_permitidas_mob = ['jpg','jpeg','png','gif','webp','heic','heif','bmp','tiff','tif','pdf','mp4','mov','avi','mkv','3gp','wmv','flv'];
    $salvos = [];
    foreach ($nomes as $i => $nome_original) {
        if ($erros[$i] !== UPLOAD_ERR_OK) continue;
        $ext  = strtolower(pathinfo($nome_original, PATHINFO_EXTENSION));
        // Rejeita silenciosamente extensões fora da whitelist
        if (!in_array($ext, $ext_permitidas_mob, true)) continue;
        $nome_arquivo = $os_id . '_' . time() . '_' . $i . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
        $destino = $uploads_dir . $nome_arquivo;
        if (move_uploaded_file($tmps[$i], $destino)) {
            $caminho = 'uploads/' . $nome_arquivo;
            $tipo = mime_content_type($destino) ?: 'image/jpeg';
            $db->prepare("INSERT INTO midias_os (ordem_id, caminho, tipo, comentario) VALUES (?,?,?,'')")
               ->execute([$os_id, $caminho, $tipo]);
            $salvos[] = $caminho;
        }
    }
    if (empty($salvos)) resp(500, ['error' => 'Falha ao salvar arquivos']);
    // Marca token como concluído
    $db->prepare("UPDATE uploads_temporarios SET status='concluido' WHERE token=?")->execute([$token]);
    resp(200, ['success' => true, 'salvos' => count($salvos)]);
}

if ($resource === 'dashboard') {
    auth_required();
    $s = [];
    $s['total_ordens']        = (int)$db->query("SELECT COUNT(*) FROM ordens_servico")->fetchColumn();
    $s['ordens_abertas']      = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE status='Aberta'")->fetchColumn();
    // Usa LIKE para cobrir variações com/sem acento (Concluída, Concluida, etc.)
    $s['ordens_concluidas']   = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE status LIKE 'Conclu%' OR status='Entregue' OR status='Retirada'")->fetchColumn();
    $s['ordens_em_andamento'] = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE status NOT IN ('Aberta','Entregue','Retirada','Cancelada','Faturada') AND status NOT LIKE 'Conclu%' AND status NOT LIKE 'N_o Aprovada' AND status NOT LIKE 'Sem Con%'")->fetchColumn();
    // OS com previsão de conclusão vencida (exclui status finais e de espera)
    $s['ordens_atrasadas']    = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE previsao_conclusao IS NOT NULL AND previsao_conclusao!='' AND previsao_conclusao < DATE('now') AND status NOT IN ('Aguardando Aparelho','Aguardando Aprovação','Aguardando Retirada','Cancelada','Faturada') AND status NOT LIKE 'Conclu%' AND status NOT LIKE 'N_o Aprovada' AND status NOT LIKE 'Sem Con%'")->fetchColumn();
    $s['total_clientes']      = (int)$db->query("SELECT COUNT(*) FROM clientes")->fetchColumn();
    $s['total_produtos']      = (int)$db->query("SELECT COUNT(*) FROM produtos WHERE ativo=1")->fetchColumn();
    $s['notificacoes']        = (int)$db->query("SELECT COUNT(*) FROM notificacoes WHERE lida=0")->fetchColumn();
    // Receita confirmada no dia (contas_receber recebidas hoje)
    $s['receita_dia']         = (float)$db->query("SELECT COALESCE(SUM(valor_recebido),0) FROM contas_receber WHERE status='Recebida' AND DATE(data_recebimento)=DATE('now')")->fetchColumn();
    // Total em aberto ou vencido a receber
    $s['contas_a_receber']    = (float)$db->query("SELECT COALESCE(SUM(valor),0) FROM contas_receber WHERE status IN ('Aberta','Vencida')")->fetchColumn();
    // Ticket médio: faturamento total / número de vendas confirmadas
    $vm = $db->query("SELECT COALESCE(SUM(total),0) as fat, COUNT(*) as cnt FROM vendas WHERE status NOT IN ('Digitação','Cancelada')")->fetch();
    $s['ticket_medio']        = ($vm && $vm['cnt'] > 0) ? round($vm['fat'] / $vm['cnt'], 2) : 0.0;
    $s['por_status']          = $db->query("SELECT status, COUNT(*) as total FROM ordens_servico GROUP BY status ORDER BY total DESC")->fetchAll();
    $s['recentes']            = $db->query("SELECT os.id, os.status, os.data_abertura, c.nome AS cliente_nome, ta.nome AS tipo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id ORDER BY os.id DESC LIMIT 5")->fetchAll();
    $s['recentes_vendas']     = $db->query("
        SELECT descricao, cliente_nome, valor FROM (
            SELECT 'Venda Simples' AS descricao, COALESCE(c.nome,'—') AS cliente_nome, v.total AS valor, COALESCE(v.data_confirmacao,v.data_criacao) AS data_ref
            FROM vendas v LEFT JOIN clientes c ON c.id=v.cliente_id
            WHERE v.status NOT IN ('Digitação','Cancelada')
              AND NOT EXISTS (SELECT 1 FROM nfce_emitidas nx WHERE nx.venda_id=v.id)
              AND NOT EXISTS (SELECT 1 FROM nfse_emitidas ns WHERE ns.venda_id=v.id)
              AND NOT EXISTS (SELECT 1 FROM nfe_emitidas ne WHERE ne.venda_id=v.id)
            UNION ALL
            SELECT 'NFC-e' AS descricao, COALESCE(c.nome,'—') AS cliente_nome, nf.valor_total AS valor, nf.data_emissao AS data_ref
            FROM nfce_emitidas nf LEFT JOIN vendas v ON v.id=nf.venda_id LEFT JOIN clientes c ON c.id=v.cliente_id
            WHERE nf.status NOT IN ('Cancelada')
            UNION ALL
            SELECT 'NFS-e' AS descricao, COALESCE(nf.cliente_nome,'—') AS cliente_nome, nf.valor_total AS valor, nf.data_emissao AS data_ref
            FROM nfse_emitidas nf WHERE nf.status NOT IN ('Cancelada')
            UNION ALL
            SELECT 'NF-e' AS descricao, COALESCE(nf.dest_nome,'—') AS cliente_nome, nf.valor_total AS valor, nf.data_emissao AS data_ref
            FROM nfe_emitidas nf WHERE nf.status NOT IN ('Cancelada')
        ) ORDER BY data_ref DESC LIMIT 10
    ")->fetchAll();
    resp(200, $s);
}

// ─── FATURAMENTO GRÁFICO (dashboard) ─────────────────────────
if ($resource === 'faturamento_grafico' && $method === 'GET') {
    auth_required();
    $data_ini = $_GET['data_ini'] ?? date('Y-m-d', strtotime('-29 days'));
    $data_fim = $_GET['data_fim'] ?? date('Y-m-d');

    // ══════════════════════════════════════════════════════════════
    // VENDAS (Produtos): lançamentos CR com status='Recebida'
    //   1. Origem 'venda'  → proporcional ao valor dos itens tipo 'produto' na venda
    //   2. Origem 'nfce'   → proporcional ao valor dos itens tipo 'produto' na venda vinculada à NFC-e
    // ══════════════════════════════════════════════════════════════
    $sql_vendas = "
        SELECT DATE(cr.data_vencimento) AS dia,
               SUM(
                   cr.valor_recebido
                   * COALESCE(
                       (SELECT SUM(vi.subtotal)
                        FROM venda_items vi
                        JOIN produtos p ON p.id = vi.produto_id
                        WHERE vi.venda_id = venda_ref.id
                          AND p.tipo_item = 'produto')
                       , 0)
                   / NULLIF(
                       (SELECT SUM(vi2.subtotal)
                        FROM venda_items vi2
                        WHERE vi2.venda_id = venda_ref.id)
                       , 0)
               ) AS total
        FROM contas_receber cr
        -- resolve o venda_id correto independente de ser 'venda' ou 'nfce'
        LEFT JOIN vendas        vd  ON cr.venda_id = vd.id  AND cr.origem = 'venda'
        LEFT JOIN nfce_emitidas nf  ON cr.venda_id = nf.id  AND cr.origem = 'nfce'
        -- venda_ref é a venda real que contém os itens
        LEFT JOIN vendas        venda_ref ON venda_ref.id = COALESCE(vd.id, nf.venda_id)
        WHERE cr.status = 'Recebida'
          AND cr.origem IN ('venda','nfce')
          AND DATE(cr.data_vencimento) BETWEEN ? AND ?
        GROUP BY dia ORDER BY dia
    ";
    $st_v = $db->prepare($sql_vendas);
    $st_v->execute([$data_ini, $data_fim]);
    $rows_v = $st_v->fetchAll();

    // ══════════════════════════════════════════════════════════════
    // SERVIÇOS: lançamentos CR com status='Recebida'
    //   1. Origem 'nfse'   → valor total recebido (tudo é serviço)
    //   2. Origem 'venda'  → proporcional ao valor dos itens tipo 'servico' na venda
    //   3. Origem 'nfce'   → proporcional ao valor dos itens tipo 'servico' na venda vinculada
    // ══════════════════════════════════════════════════════════════
    $sql_servicos = "
        SELECT DATE(cr.data_vencimento) AS dia,
               SUM(
                   CASE
                     -- NFS-e: tudo é serviço
                     WHEN cr.origem = 'nfse' THEN cr.valor_recebido
                     -- Venda / NFC-e: proporção dos itens de serviço
                     ELSE
                       cr.valor_recebido
                       * COALESCE(
                           (SELECT SUM(vi.subtotal)
                            FROM venda_items vi
                            JOIN produtos p ON p.id = vi.produto_id
                            WHERE vi.venda_id = venda_ref.id
                              AND p.tipo_item = 'servico')
                           , 0)
                       / NULLIF(
                           (SELECT SUM(vi2.subtotal)
                            FROM venda_items vi2
                            WHERE vi2.venda_id = venda_ref.id)
                           , 0)
                   END
               ) AS total
        FROM contas_receber cr
        LEFT JOIN vendas        vd  ON cr.venda_id = vd.id  AND cr.origem = 'venda'
        LEFT JOIN nfce_emitidas nf  ON cr.venda_id = nf.id  AND cr.origem = 'nfce'
        LEFT JOIN vendas        venda_ref ON venda_ref.id = COALESCE(vd.id, nf.venda_id)
        WHERE cr.status = 'Recebida'
          AND cr.origem IN ('venda','nfce','nfse')
          AND DATE(cr.data_vencimento) BETWEEN ? AND ?
        GROUP BY dia ORDER BY dia
    ";
    $st_s = $db->prepare($sql_servicos);
    $st_s->execute([$data_ini, $data_fim]);
    $rows_s = $st_s->fetchAll();

    // ── Gerar série de datas do intervalo ──
    $dias = [];
    $cur = new DateTime($data_ini);
    $end = new DateTime($data_fim);
    while ($cur <= $end) {
        $dias[] = $cur->format('Y-m-d');
        $cur->modify('+1 day');
    }

    $map_v = array_column($rows_v, 'total', 'dia');
    $map_s = array_column($rows_s, 'total', 'dia');

    $serie = array_map(fn($d) => [
        'dia'     => $d,
        'vendas'  => round((float)($map_v[$d] ?? 0), 2),
        'os'      => round((float)($map_s[$d] ?? 0), 2),
    ], $dias);

    resp(200, [
        'serie'    => $serie,
        'data_ini' => $data_ini,
        'data_fim' => $data_fim,
    ]);
}

// ─── CONSULTA PÚBLICA ─────────────────────────────────────────
// ─── LGPD ─────────────────────────────────────────────────────
// Endpoints para conformidade com a Lei Geral de Proteção de Dados.
// Operações administrativas exigem nível 'admin'.
if ($resource === 'lgpd') {
    // ----- POLÍTICA DE PRIVACIDADE -----
    // GET público: retorna versão ativa
    if ($action === 'politica_ativa' && $method === 'GET') {
        $r = $db->query("SELECT versao, conteudo, data_criacao FROM politica_privacidade WHERE ativo=1 ORDER BY id DESC LIMIT 1")->fetch();
        $emp = $db->query("SELECT dpo_nome, dpo_email, dpo_telefone, nome, razao_social, cnpj FROM empresa_dados WHERE id=1")->fetch() ?: [];
        resp(200, [
            'politica' => $r ?: null,
            'empresa'  => $emp,
        ]);
    }
    // Admin: listar versões
    if ($action === 'politica_lista' && $method === 'GET') {
        admin_required();
        $rs = $db->query("SELECT id, versao, ativo, data_criacao FROM politica_privacidade ORDER BY id DESC")->fetchAll();
        resp(200, $rs);
    }
    // Admin: ler versão
    if ($action === 'politica' && $method === 'GET') {
        admin_required();
        if (!$id) resp(400, ['error' => 'ID obrigatório']);
        $s = $db->prepare("SELECT * FROM politica_privacidade WHERE id=?");
        $s->execute([$id]);
        $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    // Admin: criar nova versão (e marcar como ativa)
    if ($action === 'politica' && $method === 'POST') {
        $u = admin_required();
        $versao   = trim($data['versao']   ?? date('Y-m-d'));
        $conteudo = trim($data['conteudo'] ?? '');
        $ativar   = !empty($data['ativar']);
        if ($conteudo === '') resp(400, ['error' => 'Conteúdo obrigatório']);
        $db->prepare("INSERT INTO politica_privacidade (versao, conteudo, ativo, data_criacao) VALUES (?, ?, ?, ?)")
           ->execute([$versao, $conteudo, $ativar ? 1 : 0, date('Y-m-d H:i:s')]);
        $novo_id = (int)$db->lastInsertId();
        if ($ativar) {
            $db->prepare("UPDATE politica_privacidade SET ativo=0 WHERE id<>?")->execute([$novo_id]);
            $db->prepare("UPDATE empresa_dados SET politica_versao_atual=? WHERE id=1")->execute([$versao]);
        }
        audit_log($db, 'politica_criar', 'politica_privacidade', $novo_id, ['versao'=>$versao,'ativar'=>$ativar]);
        resp(200, ['success' => true, 'id' => $novo_id]);
    }
    // Admin: ativar versão existente
    if ($action === 'politica_ativar' && $method === 'POST') {
        admin_required();
        $pid = (int)($data['id'] ?? 0);
        if (!$pid) resp(400, ['error' => 'ID obrigatório']);
        $s = $db->prepare("SELECT versao FROM politica_privacidade WHERE id=?");
        $s->execute([$pid]); $p = $s->fetch();
        if (!$p) resp(404, ['error' => 'Não encontrado']);
        $db->exec("UPDATE politica_privacidade SET ativo=0");
        $db->prepare("UPDATE politica_privacidade SET ativo=1 WHERE id=?")->execute([$pid]);
        $db->prepare("UPDATE empresa_dados SET politica_versao_atual=? WHERE id=1")->execute([$p['versao']]);
        audit_log($db, 'politica_ativar', 'politica_privacidade', $pid, ['versao'=>$p['versao']]);
        resp(200, ['success' => true]);
    }

    // ----- DPO / ENCARREGADO -----
    if ($action === 'dpo' && $method === 'GET') {
        admin_required();
        $r = $db->query("SELECT dpo_nome, dpo_email, dpo_telefone FROM empresa_dados WHERE id=1")->fetch() ?: [];
        resp(200, $r);
    }
    if ($action === 'dpo' && $method === 'POST') {
        admin_required();
        $db->prepare("UPDATE empresa_dados SET dpo_nome=?, dpo_email=?, dpo_telefone=? WHERE id=1")
           ->execute([
               trim($data['dpo_nome']     ?? ''),
               trim($data['dpo_email']    ?? ''),
               trim($data['dpo_telefone'] ?? ''),
           ]);
        audit_log($db, 'dpo_atualizar', 'empresa_dados', 1, ['email'=>$data['dpo_email']??'']);
        resp(200, ['success' => true]);
    }

    // ----- CONSENTIMENTO (público + autenticado) -----
    // Registra aceite explícito do titular. Usado no /consulta público
    // e também no cadastro de cliente autenticado.
    if ($action === 'consentimento' && $method === 'POST') {
        $cliente_id    = isset($data['cliente_id']) && is_numeric($data['cliente_id']) ? (int)$data['cliente_id'] : null;
        $identificador = trim($data['identificador'] ?? '');
        $finalidade    = trim($data['finalidade']    ?? 'cadastro');
        $origem        = trim($data['origem']        ?? 'sistema');
        $aceito        = isset($data['aceito']) ? (int)!!$data['aceito'] : 1;
        // versão da política em vigor
        $versao = (string)($db->query("SELECT versao FROM politica_privacidade WHERE ativo=1 ORDER BY id DESC LIMIT 1")->fetchColumn() ?: '');
        $ua = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
        $db->prepare("INSERT INTO consentimentos_lgpd (cliente_id, identificador, finalidade, politica_versao, aceito, ip, user_agent, origem, data_evento) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
           ->execute([$cliente_id, $identificador, $finalidade, $versao, $aceito, lgpd_client_ip(), $ua, $origem, date('Y-m-d H:i:s')]);
        if ($cliente_id && $aceito) {
            $db->prepare("UPDATE clientes SET consentimento_data=?, consentimento_ip=?, consentimento_versao=? WHERE id=?")
               ->execute([date('Y-m-d H:i:s'), lgpd_client_ip(), $versao, $cliente_id]);
        }
        resp(200, ['success' => true]);
    }
    if ($action === 'consentimentos' && $method === 'GET') {
        admin_required();
        $cid = isset($_GET['cliente_id']) ? (int)$_GET['cliente_id'] : 0;
        if ($cid) {
            $s = $db->prepare("SELECT * FROM consentimentos_lgpd WHERE cliente_id=? ORDER BY id DESC");
            $s->execute([$cid]);
            resp(200, $s->fetchAll());
        }
        $rs = $db->query("SELECT * FROM consentimentos_lgpd ORDER BY id DESC LIMIT 200")->fetchAll();
        resp(200, $rs);
    }

    // ----- DIREITOS DO TITULAR -----
    // Exportar todos os dados pessoais associados a um cliente (portabilidade/acesso)
    if ($action === 'exportar' && $method === 'GET') {
        admin_required();
        $cid = (int)($_GET['cliente_id'] ?? 0);
        if (!$cid) resp(400, ['error' => 'cliente_id obrigatório']);
        $s = $db->prepare("SELECT * FROM clientes WHERE id=?"); $s->execute([$cid]);
        $cli = $s->fetch();
        if (!$cli) resp(404, ['error' => 'Cliente não encontrado']);
        $os  = $db->prepare("SELECT * FROM ordens_servico WHERE cliente_id=?"); $os->execute([$cid]);
        $ven = $db->prepare("SELECT v.* FROM vendas v WHERE EXISTS (SELECT 1 FROM ordens_servico os WHERE os.id = v.os_id AND os.cliente_id=?) OR v.cliente_id=?");
        try { $ven->execute([$cid, $cid]); $vendas = $ven->fetchAll(); } catch (\Throwable $e) { $vendas = []; }
        $cons = $db->prepare("SELECT * FROM consentimentos_lgpd WHERE cliente_id=?"); $cons->execute([$cid]);
        $payload = [
            'gerado_em' => date('c'),
            'cliente'   => $cli,
            'ordens_servico' => $os->fetchAll(),
            'vendas'    => $vendas,
            'consentimentos' => $cons->fetchAll(),
        ];
        audit_log($db, 'titular_exportar', 'clientes', $cid, ['nome'=>$cli['nome'] ?? '']);
        resp(200, $payload);
    }
    // Anonimizar: preserva registros fiscais mas remove identificadores pessoais
    if ($action === 'anonimizar' && $method === 'POST') {
        $u = admin_required();
        $cid = (int)($data['cliente_id'] ?? 0);
        if (!$cid) resp(400, ['error' => 'cliente_id obrigatório']);
        $s = $db->prepare("SELECT * FROM clientes WHERE id=?"); $s->execute([$cid]);
        $cli = $s->fetch();
        if (!$cli) resp(404, ['error' => 'Cliente não encontrado']);
        $marcador = 'TITULAR ANONIMIZADO #' . $cid;
        $db->prepare("UPDATE clientes SET nome=?, email='', telefone='', telefone_secundario='', cpf='', cnpj='', endereco='', cep='', logradouro='', numero='', complemento='', bairro='', cidade='', uf='', inscricao_estadual='', anonimizado=1, anonimizado_data=? WHERE id=?")
           ->execute([$marcador, date('Y-m-d H:i:s'), $cid]);
        // Limpa senha do aparelho em OSs
        try { $db->prepare("UPDATE ordens_servico SET senha_aparelho='' WHERE cliente_id=?")->execute([$cid]); } catch (\Throwable $e) {}
        audit_log($db, 'titular_anonimizar', 'clientes', $cid, ['nome_original'=>$cli['nome'] ?? '']);
        resp(200, ['success' => true]);
    }
    // Excluir definitivamente quando não houver vínculo fiscal (OS, vendas, NFe)
    if ($action === 'excluir' && $method === 'POST') {
        $u = admin_required();
        $cid = (int)($data['cliente_id'] ?? 0);
        if (!$cid) resp(400, ['error' => 'cliente_id obrigatório']);
        $tem_os    = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE cliente_id=$cid")->fetchColumn();
        $tem_venda = 0;
        try { $tem_venda = (int)$db->query("SELECT COUNT(*) FROM vendas WHERE cliente_id=$cid")->fetchColumn(); } catch (\Throwable $e) {}
        if ($tem_os > 0 || $tem_venda > 0) {
            resp(409, [
                'error' => 'Cliente possui histórico fiscal (OS ou vendas). Utilize a anonimização para preservar a obrigação legal de guarda dos registros.',
                'ordens' => $tem_os,
                'vendas' => $tem_venda,
            ]);
        }
        $s = $db->prepare("SELECT nome FROM clientes WHERE id=?"); $s->execute([$cid]);
        $nome = (string)$s->fetchColumn();
        $db->prepare("DELETE FROM clientes WHERE id=?")->execute([$cid]);
        $db->prepare("DELETE FROM consentimentos_lgpd WHERE cliente_id=?")->execute([$cid]);
        audit_log($db, 'titular_excluir', 'clientes', $cid, ['nome_original'=>$nome]);
        resp(200, ['success' => true]);
    }

    // ----- AUDITORIA -----
    if ($action === 'auditoria' && $method === 'GET') {
        admin_required();
        $limit  = max(1, min(500, (int)($_GET['limit'] ?? 100)));
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $offset = ($page - 1) * $limit;
        $where  = '1=1';
        $params = [];
        if (!empty($_GET['acao']))      { $where .= ' AND acao LIKE ?';      $params[] = '%' . $_GET['acao'] . '%'; }
        if (!empty($_GET['entidade']))  { $where .= ' AND entidade = ?';     $params[] = $_GET['entidade']; }
        if (!empty($_GET['usuario_id'])){ $where .= ' AND usuario_id = ?';   $params[] = (int)$_GET['usuario_id']; }
        if (!empty($_GET['data_de']))   { $where .= ' AND data_evento >= ?'; $params[] = $_GET['data_de'] . ' 00:00:00'; }
        if (!empty($_GET['data_ate']))  { $where .= ' AND data_evento <= ?'; $params[] = $_GET['data_ate'] . ' 23:59:59'; }
        $tc = $db->prepare("SELECT COUNT(*) FROM auditoria_lgpd WHERE $where");
        $tc->execute($params);
        $total = (int)$tc->fetchColumn();
        $sql = "SELECT * FROM auditoria_lgpd WHERE $where ORDER BY id DESC LIMIT ? OFFSET ?";
        $st  = $db->prepare($sql);
        $st->execute(array_merge($params, [$limit, $offset]));
        resp(200, [
            'data'  => $st->fetchAll(),
            'total' => $total,
            'page'  => $page,
            'pages' => (int)ceil(max(1,$total)/$limit),
            'limit' => $limit,
        ]);
    }
    // Endpoint usado pelo frontend para logar o "revelar dados completos"
    if ($action === 'log_revelacao' && $method === 'POST') {
        auth_required();
        $cid = (int)($data['cliente_id'] ?? 0);
        $campo = (string)($data['campo'] ?? '');
        audit_log($db, 'pii_revelar', 'clientes', $cid ?: null, ['campo'=>$campo]);
        resp(200, ['success' => true]);
    }
    resp(404, ['error' => 'Ação LGPD não encontrada']);
}

if ($resource === 'consulta_publica' && $method === 'GET') {
    $oid = $_GET['id'] ?? null;
    if (!$oid || !is_numeric($oid)) resp(400, ['error' => 'ID inv\u00e1lido']);
    $s = $db->prepare("SELECT os.id, os.status, os.descricao, os.data_abertura, os.previsao_conclusao, c.nome AS cliente_nome, ta.nome AS tipo_nome, m.nome AS marca_nome, mo.nome AS modelo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id LEFT JOIN marcas m ON os.marca_id=m.id LEFT JOIN modelos mo ON os.modelo_id=mo.id WHERE os.id=?");
    $s->execute([$oid]); $os = $s->fetch();
    if (!$os) resp(404, ['error' => 'N\u00e3o encontrado']);
    $s2 = $db->prepare("SELECT observacoes,valor,status_orcamento FROM orcamentos WHERE ordem_id=? ORDER BY id");
    $s2->execute([$oid]); $os['orcamentos'] = $s2->fetchAll();
    resp(200, $os);
}

// ─── DIAGNÓSTICO ──────────────────────────────────────────────
// ─── VENDAS ───────────────────────────────────────────────────
if ($resource === 'vendas') {
    auth_required();
    // Garantir colunas da tabela venda_items
    foreach(['desconto_valor REAL DEFAULT 0','desconto_percentual REAL DEFAULT 0','acrescimo_valor REAL DEFAULT 0'] as $col_def) {
        $col = explode(' ', $col_def)[0];
        $cols = array_column($db->query("PRAGMA table_info(venda_items)")->fetchAll(),'name');
        if (!in_array($col,$cols)) try{$db->exec("ALTER TABLE venda_items ADD COLUMN $col_def");}catch(PDOException $e){}
    }
    if ($method === 'GET' && $id === null) {
        $page  = max(1,(int)($_GET['page']??1));
        $limit = 20;
        $offset= ($page-1)*$limit;
        $status_f = $_GET['status'] ?? '';
        $q = '%'.($_GET['q']??'').'%';
        $where = ['1=1']; $params = [];
        if ($status_f) { $where[] = "v.status=?"; $params[] = $status_f; }
        if ($_GET['q']??'') { $where[] = "(c.nome LIKE ? OR CAST(v.id AS TEXT) LIKE ?)"; $params[] = $q; $params[] = $q; }
        $w = implode(' AND ',$where);
        $total = (int)$db->prepare("SELECT COUNT(*) FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE $w")->execute($params) ? $db->prepare("SELECT COUNT(*) FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE $w")->execute($params) : 0;
        $tc = $db->prepare("SELECT COUNT(*) FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();
        $s = $db->prepare("SELECT v.*, COALESCE(v.data_criacao,v.data_confirmacao) as data_venda, c.nome AS cliente_nome FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE $w ORDER BY v.id DESC LIMIT ? OFFSET ?");
        $s->execute(array_merge($params,[$limit,$offset]));
        resp(200,['data'=>$s->fetchAll(),'total'=>$total,'page'=>$page,'pages'=>(int)ceil($total/$limit)]);
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT v.*, COALESCE(v.data_criacao,v.data_confirmacao) as data_venda, c.nome AS cliente_nome FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.id=?");
        $s->execute([$id]); $v = $s->fetch();
        if (!$v) resp(404,['error'=>'Não encontrado']);
        $si = $db->prepare("SELECT vi.*, p.descricao AS produto_nome FROM venda_items vi LEFT JOIN produtos p ON vi.produto_id=p.id WHERE vi.venda_id=?");
        $si->execute([$id]); $v['items'] = $si->fetchAll();
        $sf = $db->prepare("SELECT * FROM venda_faturamentos WHERE venda_id=? ORDER BY id");
        $sf->execute([$id]); $fats = $sf->fetchAll();
        foreach ($fats as &$fat) {
            $sp = $db->prepare("SELECT * FROM venda_parcelas WHERE faturamento_id=? ORDER BY numero");
            $sp->execute([$fat['id']]); $fat['parcelas'] = $sp->fetchAll();
        }
        $v['faturamentos'] = $fats;
        resp(200,$v);
    }
    if ($method === 'POST') {
        $db->beginTransaction();
        try {
            $items = $data['items'] ?? [];
            // Valida produto_id obrigatório em todos os itens
            foreach ($items as $idx => $item) {
                if (empty($item['produto_id']) || (int)$item['produto_id'] <= 0) {
                    $db->rollBack();
                    $num = $idx + 1;
                    resp(400, ['error' => "Item $num: selecione um produto ou serviço do cadastro. O campo produto é obrigatório."]);
                }
            }
            $subtotal_bruto = array_sum(array_map(function($i) {
                $base = (+$i['quantidade']) * (+$i['valor_unitario']);
                $dt   = $i['desconto_tipo_item']  ?? 'valor';
                $at   = $i['acrescimo_tipo_item'] ?? 'valor';
                $dv   = (float)($i['desconto_valor']  ?? 0);
                $av   = (float)($i['acrescimo_valor'] ?? 0);
                $damt = $dt === 'percentual' ? round($base * $dv / 100, 2) : $dv;
                $aamt = $at === 'percentual' ? round($base * $av / 100, 2) : $av;
                return max(0, $base - $damt + $aamt);
            }, $items));
            // Desconto
            $desc_tipo = $data['desconto_tipo'] ?? 'valor';
            $desc_val  = (float)($data['desconto_valor']??0);
            $desc_pct  = (float)($data['desconto_percentual']??0);
            if ($desc_tipo === 'percentual' && $desc_pct > 0) {
                $desc_val = round($subtotal_bruto * $desc_pct / 100, 2);
            } elseif ($desc_tipo === 'valor') {
                $desc_pct = $subtotal_bruto > 0 ? round($desc_val / $subtotal_bruto * 100, 4) : 0;
            }
            // Acréscimo
            $acres_tipo = $data['acrescimo_tipo'] ?? 'valor';
            $acres_val  = (float)($data['acrescimo_valor']??0);
            $acres_pct  = (float)($data['acrescimo_percentual']??0);
            if ($acres_tipo === 'percentual' && $acres_pct > 0) {
                $acres_val = round($subtotal_bruto * $acres_pct / 100, 2);
            } elseif ($acres_tipo === 'valor') {
                $acres_pct = $subtotal_bruto > 0 ? round($acres_val / $subtotal_bruto * 100, 4) : 0;
            }
            $frete  = (float)($data['valor_frete']??0);
            $total  = round($subtotal_bruto - $desc_val + $acres_val + $frete, 2);
            $os_id  = $data['os_id'] ?? null;
            $cpf    = $data['cpf_cnpj'] ?? '';
            $d_cri  = $data['data_criacao'] ?? date('Y-m-d H:i:s');
            $d_conf = $data['data_confirmacao'] ?? null;
            $venda_status = $data['status'] ?? 'Digitação';
            if ($venda_status === 'Confirmada') {
                if (!$d_conf) $d_conf = date('Y-m-d H:i:s');
            } else {
                $d_conf = null; // Não preenche data de confirmação se não for confirmada
            }
            $db->prepare("INSERT INTO vendas (cliente_id,vendedor_id,os_id,cpf_cnpj,data_criacao,data_confirmacao,status,total,desconto_valor,desconto_percentual,desconto_tipo,acrescimo_valor,acrescimo_percentual,acrescimo_tipo,valor_frete,observacoes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([$data['cliente_id']??null,null,$os_id,$cpf,$d_cri,$d_conf,$venda_status,$total,$desc_val,$desc_pct,$desc_tipo,$acres_val,$acres_pct,$acres_tipo,$frete,$data['observacoes']??'']);
            $vid = (int)$db->lastInsertId();
            foreach ($items as $item) {
                $qty      = (float)($item['quantidade']??1);
                $vu       = (float)($item['valor_unitario']??0);
                $desc_item_val  = (float)($item['desconto_valor']??0);
                $acres_item_val = (float)($item['acrescimo_valor']??0);
                $desc_item_tipo  = $item['desconto_tipo_item'] ?? 'valor';
                $acres_item_tipo = $item['acrescimo_tipo_item'] ?? 'valor';
                $base     = $qty * $vu;
                $desc_amt  = $desc_item_tipo  === 'percentual' ? round($base * $desc_item_val  / 100, 2) : $desc_item_val;
                $acres_amt = $acres_item_tipo === 'percentual' ? round($base * $acres_item_val / 100, 2) : $acres_item_val;
                $sub      = round(max(0, $base - $desc_amt + $acres_amt), 2);
                $desc_item_str = trim($item['descricao_manual'] ?? $item['descricao'] ?? '');
                $pid = isset($item['produto_id']) && (int)$item['produto_id'] > 0 ? (int)$item['produto_id'] : null;
                $db->prepare("INSERT INTO venda_items (venda_id,produto_id,descricao,quantidade,valor_unitario,desconto_valor,acrescimo_valor,subtotal) VALUES (?,?,?,?,?,?,?,?)")
                   ->execute([$vid,$pid,$desc_item_str,$qty,$vu,$desc_amt,$acres_amt,$sub]);
            }
            // Baixa de estoque (apenas para vendas confirmadas)
            if ($venda_status === 'Confirmada') {
                $stBaixa = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual - ? WHERE id=?");
                foreach ($items as $item) {
                    $pid = isset($item['produto_id']) && (int)$item['produto_id'] > 0 ? (int)$item['produto_id'] : 0;
                    $qty = (float)($item['quantidade'] ?? 1);
                    if ($pid > 0 && $qty > 0) $stBaixa->execute([$qty, $pid]);
                }
            }
            // Faturamentos e parcelas
            foreach (($data['faturamentos']??[]) as $fat) {
                $fp_id   = $fat['forma_pagamento_id'] ?? null;
                $fp_nome = $fat['forma_pagamento_nome'] ?? '';
                $v_total = (float)($fat['valor_total'] ?? $total);
                $v_pago  = (float)($fat['valor_pago'] ?? 0);
                $nparcelas = (int)($fat['num_parcelas'] ?? 1);
                $d1prc   = $fat['data_primeira_parcela'] ?? date('Y-m-d');
                $intdias = (int)($fat['intervalo_dias'] ?? 30);
                $juros   = (float)($fat['juros_am'] ?? 0);
                $taxa    = (float)($fat['taxa_fixa'] ?? 0);
                $trep    = $fat['tipo_repeticao'] ?? 'mensal';
                $db->prepare("INSERT INTO venda_faturamentos (venda_id,forma_pagamento_id,forma_pagamento_nome,valor_total,valor_pago,num_parcelas,data_primeira_parcela,intervalo_dias,juros_am,taxa_fixa,tipo_repeticao) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
                   ->execute([$vid,$fp_id,$fp_nome,$v_total,$v_pago,$nparcelas,$d1prc,$intdias,$juros,$taxa,$trep]);
                $fat_id = (int)$db->lastInsertId();
                // Gera parcelas
                $parcelas = $fat['parcelas'] ?? [];
                foreach ($parcelas as $pi => $p) {
                    $db->prepare("INSERT INTO venda_parcelas (faturamento_id,venda_id,numero,valor,valor_juros,valor_taxa,data_vencimento,status) VALUES (?,?,?,?,?,?,?,?)")
                       ->execute([$fat_id,$vid,$pi+1,(float)($p['valor']??0),(float)($p['valor_juros']??0),(float)($p['valor_taxa']??0),$p['data_vencimento']??null,'Aberta']);
                }
            }
            if ($os_id) {
                try { $db->exec("ALTER TABLE ordens_servico ADD COLUMN data_atualizacao DATETIME"); } catch(PDOException $e) {}
                $db->prepare("UPDATE ordens_servico SET status='Concluída',data_atualizacao=? WHERE id=?")
                   ->execute([date('Y-m-d H:i:s'),$os_id]);
            }

            // ── Gerar contas a receber automaticamente (somente para vendas Confirmadas) ──
            if ($venda_status === 'Confirmada') {
                $sf2 = $db->prepare("
                    SELECT f.*, p.id as parc_id, p.numero as parc_num, p.valor as parc_val, p.data_vencimento as parc_venc
                    FROM venda_faturamentos f
                    JOIN venda_parcelas p ON p.faturamento_id=f.id
                    WHERE f.venda_id=?");
                $sf2->execute([$vid]);
                $parcelas_geradas = $sf2->fetchAll();
                $now_cr    = date('Y-m-d H:i:s');
                $cli_id_cr = $data['cliente_id'] ?? null;
                foreach ($parcelas_geradas as $parc) {
                    $nparcelas_fat = (int)$parc['num_parcelas'];
                    $desc_cr   = $nparcelas_fat > 1
                        ? "Venda #{$vid} — Parcela {$parc['parc_num']}/{$nparcelas_fat} ({$parc['forma_pagamento_nome']})"
                        : "Venda #{$vid} — {$parc['forma_pagamento_nome']}";
                    $doc_ref_cr = $os_id ? "OS #{$os_id}" : '';
                    // Busca conta_bancaria_id vinculada à forma de pagamento
                    $cb_id_cr = null;
                    if (!empty($parc['forma_pagamento_id'])) {
                        $fpRow = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                        $fpRow->execute([$parc['forma_pagamento_id']]);
                        $fpData = $fpRow->fetch();
                        if ($fpData && !empty($fpData['conta_bancaria'])) {
                            $cbRow = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                            $cbRow->execute([$fpData['conta_bancaria']]);
                            $cb_id_cr = $cbRow->fetchColumn() ?: null;
                        }
                    }
                    // Lançamento sempre em Aberto — recebimento deve ser confirmado no financeiro
                    $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,documento_ref,data_criacao,data_atualizacao) VALUES ('venda',?,?,?,?,?,?,0,?,?,NULL,'Aberta',?,?,?)")
                       ->execute([$vid, $parc['parc_id'], $cli_id_cr, $cb_id_cr, $desc_cr, (float)$parc['parc_val'], date('Y-m-d'), $parc['parc_venc'], $doc_ref_cr, $now_cr, $now_cr]);
                }
            }

            $db->commit();
            resp(201,['success'=>true,'id'=>$vid,'total'=>$total,'status'=>$venda_status]);
        } catch(Exception $e){$db->rollBack();resp(500,['error'=>$e->getMessage()]);}
    }
    if ($method === 'PUT' && $id !== null) {
        // Ação especial: confirmar venda em digitação
        if (isset($data['action']) && $data['action'] === 'confirmar') {
            $db->beginTransaction();
            try {
                $sv = $db->prepare("SELECT * FROM vendas WHERE id=?"); $sv->execute([$id]); $venda = $sv->fetch();
                if (!$venda) { $db->rollBack(); resp(404,['error'=>'Venda não encontrada']); }
                $d_conf_now = date('Y-m-d H:i:s');
                $db->prepare("UPDATE vendas SET status='Confirmada', data_confirmacao=? WHERE id=?")->execute([$d_conf_now, $id]);
                // Gera financeiro se ainda não existe
                $sf_check = $db->prepare("SELECT COUNT(*) FROM contas_receber WHERE venda_id=?"); $sf_check->execute([$id]);
                if ((int)$sf_check->fetchColumn() === 0) {
                    $sf2 = $db->prepare("
                        SELECT f.*, p.id as parc_id, p.numero as parc_num, p.valor as parc_val, p.data_vencimento as parc_venc
                        FROM venda_faturamentos f
                        JOIN venda_parcelas p ON p.faturamento_id=f.id
                        WHERE f.venda_id=?");
                    $sf2->execute([$id]);
                    $parcelas_geradas = $sf2->fetchAll();
                    $now_cr = date('Y-m-d H:i:s');
                    $cli_id_cr = $venda['cliente_id'];
                    $total_v = (float)$venda['total'];
                    $os_id_v = $venda['os_id'];
                    foreach ($parcelas_geradas as $parc) {
                        $nparcelas_fat = (int)$parc['num_parcelas'];
                        $desc_cr = $nparcelas_fat > 1
                            ? "Venda #{$id} — Parcela {$parc['parc_num']}/{$nparcelas_fat} ({$parc['forma_pagamento_nome']})"
                            : "Venda #{$id} — {$parc['forma_pagamento_nome']}";
                        $doc_ref_cr = $os_id_v ? "OS #{$os_id_v}" : '';
                        // Busca conta_bancaria_id vinculada à forma de pagamento
                        $cb_id_cr = null;
                        if (!empty($parc['forma_pagamento_id'])) {
                            $fpRow = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                            $fpRow->execute([$parc['forma_pagamento_id']]);
                            $fpData = $fpRow->fetch();
                            if ($fpData && !empty($fpData['conta_bancaria'])) {
                                $cbRow = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                                $cbRow->execute([$fpData['conta_bancaria']]);
                                $cb_id_cr = $cbRow->fetchColumn() ?: null;
                            }
                        }
                        // Lançamento sempre em Aberto — recebimento deve ser confirmado no financeiro
                        $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,documento_ref,data_criacao,data_atualizacao) VALUES ('venda',?,?,?,?,?,?,0,?,?,NULL,'Aberta',?,?,?)")
                           ->execute([$id, $parc['parc_id'], $cli_id_cr, $cb_id_cr, $desc_cr, (float)$parc['parc_val'], date('Y-m-d'), $parc['parc_venc'], $doc_ref_cr, $now_cr, $now_cr]);
                    }
                }
                $db->commit();
                resp(200,['success'=>true,'message'=>'Venda confirmada e financeiro gerado.']);
            } catch(Exception $e){ $db->rollBack(); resp(500,['error'=>$e->getMessage()]); }
        }
        // Ação especial: cancelar venda (apaga financeiro e estoque, mantém registro)
        if (isset($data['action']) && $data['action'] === 'cancelar') {
            $db->beginTransaction();
            try {
                $sv = $db->prepare("SELECT * FROM vendas WHERE id=?"); $sv->execute([$id]); $venda = $sv->fetch();
                if (!$venda) { $db->rollBack(); resp(404,['error'=>'Venda não encontrada']); }
                // Remove contas a receber vinculadas
                $db->prepare("DELETE FROM contas_receber WHERE venda_id=? AND origem='venda'")->execute([$id]);
                // Remove movimentações de estoque vinculadas (se existir tabela)
                $tables = array_column($db->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(), 'name');
                if (in_array('estoque_movimentacoes', $tables)) {
                    $db->prepare("DELETE FROM estoque_movimentacoes WHERE venda_id=?")->execute([$id]);
                }
                // Atualiza status para Cancelada
                $db->prepare("UPDATE vendas SET status='Cancelada' WHERE id=?")->execute([$id]);
                $db->commit();
                resp(200,['success'=>true,'message'=>'Venda cancelada. Lançamentos financeiros removidos.']);
            } catch(Exception $e){ $db->rollBack(); resp(500,['error'=>$e->getMessage()]); }
        }
        if (isset($data['action']) && $data['action'] === 'estornar') {
            $db->beginTransaction();
            try {
                $sv = $db->prepare("SELECT * FROM vendas WHERE id=?"); $sv->execute([$id]); $venda = $sv->fetch();
                if (!$venda) { $db->rollBack(); resp(404,['error'=>'Venda não encontrada']); }
                if ($venda['status'] !== 'Confirmada') { $db->rollBack(); resp(400,['error'=>'Apenas vendas Confirmadas podem ser estornadas.']); }
                // Remove lançamentos financeiros (contas a receber) vinculados
                $db->prepare("DELETE FROM contas_receber WHERE venda_id=? AND origem='venda'")->execute([$id]);
                // Volta status para Digitação e limpa data de confirmação
                $db->prepare("UPDATE vendas SET status='Digitação', data_confirmacao=NULL WHERE id=?")->execute([$id]);
                $db->commit();
                resp(200,['success'=>true,'message'=>'Confirmação estornada. Venda voltou para Digitação e lançamentos financeiros foram removidos.']);
            } catch(Exception $e){ $db->rollBack(); resp(500,['error'=>$e->getMessage()]); }
        }
        // PUT simples ou edição completa da venda
        $db->beginTransaction();
        try {
            $sv = $db->prepare("SELECT * FROM vendas WHERE id=?"); $sv->execute([$id]); $vendaAtual = $sv->fetch();
            if (!$vendaAtual) { $db->rollBack(); resp(404,['error'=>'Venda não encontrada']); }

            $novo_status = $data['status'] ?? $vendaAtual['status'];

            // Se enviou itens, recalcula o total e substitui
            if (isset($data['items'])) {
                $items = $data['items'] ?? [];
                // Valida produto_id obrigatório em todos os itens
                foreach ($items as $idx => $item) {
                    if (empty($item['produto_id']) || (int)$item['produto_id'] <= 0) {
                        $db->rollBack();
                        $num = $idx + 1;
                        resp(400, ['error' => "Item $num: selecione um produto ou serviço do cadastro. O campo produto é obrigatório."]);
                    }
                }
                $subtotal_bruto = array_sum(array_map(function($i) {
                    $base = (+$i['quantidade']) * (+$i['valor_unitario']);
                    $dt   = $i['desconto_tipo_item']  ?? 'valor';
                    $at   = $i['acrescimo_tipo_item'] ?? 'valor';
                    $dv   = (float)($i['desconto_valor']  ?? 0);
                    $av   = (float)($i['acrescimo_valor'] ?? 0);
                    $damt = $dt === 'percentual' ? round($base * $dv / 100, 2) : $dv;
                    $aamt = $at === 'percentual' ? round($base * $av / 100, 2) : $av;
                    return max(0, $base - $damt + $aamt);
                }, $items));
                $desc_tipo = $data['desconto_tipo'] ?? 'valor';
                $desc_val  = (float)($data['desconto_valor'] ?? 0);
                if ($desc_tipo === 'percentual') $desc_val = round($subtotal_bruto * $desc_val / 100, 2);
                $acres_tipo = $data['acrescimo_tipo'] ?? 'valor';
                $acres_val  = (float)($data['acrescimo_valor'] ?? 0);
                if ($acres_tipo === 'percentual') $acres_val = round($subtotal_bruto * $acres_val / 100, 2);
                $frete = (float)($data['valor_frete'] ?? 0);
                $total = round($subtotal_bruto - $desc_val + $acres_val + $frete, 2);
                $desc_pct  = $subtotal_bruto > 0 ? round($desc_val / $subtotal_bruto * 100, 4) : 0;
                $acres_pct = $subtotal_bruto > 0 ? round($acres_val / $subtotal_bruto * 100, 4) : 0;
                $d_conf = $data['data_confirmacao'] ?? null;
                if ($novo_status === 'Confirmada' && !$d_conf) $d_conf = date('Y-m-d H:i:s');
                if ($novo_status !== 'Confirmada') $d_conf = $vendaAtual['data_confirmacao'];
                $db->prepare("UPDATE vendas SET cliente_id=?,cpf_cnpj=?,data_criacao=?,data_confirmacao=?,status=?,total=?,desconto_valor=?,desconto_percentual=?,desconto_tipo=?,acrescimo_valor=?,acrescimo_percentual=?,acrescimo_tipo=?,valor_frete=?,observacoes=? WHERE id=?")
                   ->execute([
                       $data['cliente_id'] ?? $vendaAtual['cliente_id'],
                       $data['cpf_cnpj'] ?? $vendaAtual['cpf_cnpj'],
                       $data['data_criacao'] ?? $vendaAtual['data_criacao'],
                       $d_conf,
                       $novo_status,
                       $total,
                       $desc_val, $desc_pct, $desc_tipo,
                       $acres_val, $acres_pct, $acres_tipo,
                       $frete,
                       $data['observacoes'] ?? $vendaAtual['observacoes'],
                       $id
                   ]);
                // Substitui itens
                $db->prepare("DELETE FROM venda_items WHERE venda_id=?")->execute([$id]);
                foreach ($items as $item) {
                    $qty      = (float)($item['quantidade'] ?? 1);
                    $vu       = (float)($item['valor_unitario'] ?? 0);
                    $desc_item_val  = (float)($item['desconto_valor']  ?? 0);
                    $acres_item_val = (float)($item['acrescimo_valor'] ?? 0);
                    $dt_item  = $item['desconto_tipo_item']  ?? 'valor';
                    $at_item  = $item['acrescimo_tipo_item'] ?? 'valor';
                    $base_it  = $qty * $vu;
                    $damt_it  = $dt_item === 'percentual' ? round($base_it * $desc_item_val  / 100, 2) : $desc_item_val;
                    $aamt_it  = $at_item === 'percentual' ? round($base_it * $acres_item_val / 100, 2) : $acres_item_val;
                    $sub_it   = round(max(0, $base_it - $damt_it + $aamt_it), 2);
                    $desc_it_str = trim($item['descricao_manual'] ?? $item['descricao'] ?? '');
                    $pid = isset($item['produto_id']) && (int)$item['produto_id'] > 0 ? (int)$item['produto_id'] : null;
                    $db->prepare("INSERT INTO venda_items (venda_id,produto_id,descricao,quantidade,valor_unitario,desconto_valor,acrescimo_valor,subtotal) VALUES (?,?,?,?,?,?,?,?)")
                       ->execute([$id, $pid, $desc_it_str, $qty, $vu, $damt_it, $aamt_it, $sub_it]);
                }
                // Se confirmada e não tinha financeiro, gera agora
                if ($novo_status === 'Confirmada' && $vendaAtual['status'] !== 'Confirmada') {
                    $db->prepare("DELETE FROM contas_receber WHERE venda_id=? AND origem='venda'")->execute([$id]);
                    // Substitui faturamentos se enviados
                    if (isset($data['faturamentos'])) {
                        $db->prepare("DELETE FROM venda_faturamentos WHERE venda_id=?")->execute([$id]);
                        $db->prepare("DELETE FROM venda_parcelas WHERE venda_id=?")->execute([$id]);
                        foreach (($data['faturamentos'] ?? []) as $fat) {
                            $fp_id   = $fat['forma_pagamento_id'] ?? null;
                            $fp_nome = $fat['forma_pagamento_nome'] ?? '';
                            $v_total = (float)($fat['valor_total'] ?? $total);
                            $v_pago  = (float)($fat['valor_pago'] ?? 0);
                            $nparcelas = (int)($fat['num_parcelas'] ?? 1);
                            $d1prc   = $fat['data_primeira_parcela'] ?? date('Y-m-d');
                            $intdias = (int)($fat['intervalo_dias'] ?? 30);
                            $juros   = (float)($fat['juros_am'] ?? 0);
                            $taxa    = (float)($fat['taxa_fixa'] ?? 0);
                            $trep    = $fat['tipo_repeticao'] ?? 'mensal';
                            $db->prepare("INSERT INTO venda_faturamentos (venda_id,forma_pagamento_id,forma_pagamento_nome,valor_total,valor_pago,num_parcelas,data_primeira_parcela,intervalo_dias,juros_am,taxa_fixa,tipo_repeticao) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
                               ->execute([$id,$fp_id,$fp_nome,$v_total,$v_pago,$nparcelas,$d1prc,$intdias,$juros,$taxa,$trep]);
                            $fat_id = (int)$db->lastInsertId();
                            foreach (($fat['parcelas'] ?? []) as $pi => $p) {
                                $db->prepare("INSERT INTO venda_parcelas (faturamento_id,venda_id,numero,valor,valor_juros,valor_taxa,data_vencimento,status) VALUES (?,?,?,?,?,?,?,?)")
                                   ->execute([$fat_id,$id,$pi+1,(float)($p['valor']??0),(float)($p['valor_juros']??0),(float)($p['valor_taxa']??0),$p['data_vencimento']??null,'Aberta']);
                            }
                        }
                    }
                    // Gera contas a receber
                    $sf2 = $db->prepare("SELECT f.*, p.id as parc_id, p.numero as parc_num, p.valor as parc_val, p.data_vencimento as parc_venc FROM venda_faturamentos f JOIN venda_parcelas p ON p.faturamento_id=f.id WHERE f.venda_id=?");
                    $sf2->execute([$id]); $parcelas_geradas = $sf2->fetchAll();
                    $now_cr = date('Y-m-d H:i:s'); $cli_id_cr = $data['cliente_id'] ?? $vendaAtual['cliente_id'];
                    foreach ($parcelas_geradas as $parc) {
                        $npf = (int)$parc['num_parcelas'];
                        $desc_cr = $npf > 1 ? "Venda #{$id} — Parcela {$parc['parc_num']}/{$npf} ({$parc['forma_pagamento_nome']})" : "Venda #{$id} — {$parc['forma_pagamento_nome']}";
                        // Busca conta_bancaria_id vinculada à forma de pagamento
                        $cb_id_cr = null;
                        if (!empty($parc['forma_pagamento_id'])) {
                            $fpRow = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                            $fpRow->execute([$parc['forma_pagamento_id']]);
                            $fpData = $fpRow->fetch();
                            if ($fpData && !empty($fpData['conta_bancaria'])) {
                                $cbRow = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                                $cbRow->execute([$fpData['conta_bancaria']]);
                                $cb_id_cr = $cbRow->fetchColumn() ?: null;
                            }
                        }
                        // Lançamento sempre em Aberto — recebimento deve ser confirmado no financeiro
                        $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,data_criacao,data_atualizacao) VALUES ('venda',?,?,?,?,?,?,0,?,?,NULL,'Aberta',?,?)")
                           ->execute([$id,$parc['parc_id'],$cli_id_cr,$cb_id_cr,$desc_cr,(float)$parc['parc_val'],date('Y-m-d'),$parc['parc_venc'],$now_cr,$now_cr]);
                    }
                }
            } else {
                // PUT simples — só status/observações
                $db->prepare("UPDATE vendas SET status=?,observacoes=? WHERE id=?")
                   ->execute([$novo_status, $data['observacoes'] ?? $vendaAtual['observacoes'], $id]);
            }
            $db->commit();
            resp(200,['success'=>true,'status'=>$novo_status]);
        } catch(Exception $e){ $db->rollBack(); resp(500,['error'=>$e->getMessage()]); }
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM venda_items WHERE venda_id=?")->execute([$id]);
        $db->prepare("DELETE FROM vendas WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── FINANCEIRO (resumo) ───────────────────────────────────────
if ($resource === 'financeiro') {
    auth_required();
    $periodo = $_GET['periodo'] ?? 'mes'; // mes, semana, ano, custom
    $data_ini = $_GET['data_ini'] ?? null;
    $data_fim = $_GET['data_fim'] ?? null;
    switch($periodo){
        case 'semana': $data_ini=date('Y-m-d',strtotime('monday this week')); $data_fim=date('Y-m-d'); break;
        case 'mes':    $data_ini=date('Y-m-01'); $data_fim=date('Y-m-d'); break;
        case 'ano':    $data_ini=date('Y-01-01'); $data_fim=date('Y-m-d'); break;
        default: if(!$data_ini) $data_ini=date('Y-m-01'); if(!$data_fim) $data_fim=date('Y-m-d');
    }
    $d1 = $data_ini.' 00:00:00'; $d2 = $data_fim.' 23:59:59';

    // Receita de vendas no período
    $receita = (float)$db->prepare("SELECT COALESCE(SUM(total),0) FROM vendas WHERE status='Paga' AND COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ?")->execute([$d1,$d2]) ? 0 : 0;
    $st = $db->prepare("SELECT COALESCE(SUM(total),0) FROM vendas WHERE status='Paga' AND COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ?");
    $st->execute([$d1,$d2]); $receita = (float)$st->fetchColumn();

    $st2 = $db->prepare("SELECT COALESCE(SUM(total),0) FROM vendas WHERE status='Pendente' AND COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ?");
    $st2->execute([$d1,$d2]); $pendente = (float)$st2->fetchColumn();

    $st3 = $db->prepare("SELECT COALESCE(SUM(total),0) FROM vendas WHERE status='Cancelada' AND COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ?");
    $st3->execute([$d1,$d2]); $cancelada = (float)$st3->fetchColumn();

    $st4 = $db->prepare("SELECT COUNT(*) FROM vendas WHERE COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ?");
    $st4->execute([$d1,$d2]); $total_vendas = (int)$st4->fetchColumn();

    // Ticket médio
    $ticket = $total_vendas > 0 ? round($receita / $total_vendas, 2) : 0;

    // Vendas por dia no período
    $sg = $db->prepare("SELECT DATE(COALESCE(data_criacao, data_confirmacao)) as dia, SUM(total) as total, COUNT(*) as qtd FROM vendas WHERE status='Paga' AND COALESCE(data_criacao, data_confirmacao) BETWEEN ? AND ? GROUP BY dia ORDER BY dia");
    $sg->execute([$d1,$d2]); $por_dia = $sg->fetchAll();

    // Top produtos no período
    $sp = $db->prepare("SELECT p.descricao, SUM(vi.quantidade) as qty, SUM(vi.subtotal) as total FROM venda_items vi JOIN vendas v ON vi.venda_id=v.id LEFT JOIN produtos p ON vi.produto_id=p.id WHERE v.status='Paga' AND COALESCE(v.data_criacao,v.data_confirmacao) BETWEEN ? AND ? GROUP BY vi.produto_id ORDER BY total DESC LIMIT 10");
    $sp->execute([$d1,$d2]); $top_produtos = $sp->fetchAll();

    // Últimas vendas
    $sl = $db->prepare("SELECT v.id, v.status, v.total, COALESCE(v.data_criacao, v.data_confirmacao) as data_venda, c.nome AS cliente_nome FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE COALESCE(v.data_criacao,v.data_confirmacao) BETWEEN ? AND ? ORDER BY v.id DESC LIMIT 10");
    $sl->execute([$d1,$d2]); $ultimas = $sl->fetchAll();

    resp(200,[
        'periodo'     => ['inicio'=>$data_ini,'fim'=>$data_fim],
        'receita'     => $receita,
        'pendente'    => $pendente,
        'cancelada'   => $cancelada,
        'total_vendas'=> $total_vendas,
        'ticket_medio'=> $ticket,
        'por_dia'     => $por_dia,
        'top_produtos'=> $top_produtos,
        'ultimas'     => $ultimas,
    ]);
}

// ─── FORMAS DE PAGAMENTO ──────────────────────────────────────
if ($resource === 'formas_pagamento') {
    auth_required();
    if ($method === 'GET') {
        $rows = $db->query("SELECT * FROM formas_pagamento WHERE ativo=1 ORDER BY nome")->fetchAll();
        resp(200, $rows);
    }
    if ($method === 'POST') {
        $n = $data['nome'] ?? ''; if (!$n) resp(400,['error'=>'Nome obrigatório']);
        $modalidade = $data['modalidade'] ?? 'a_vista';
        $db->prepare("INSERT INTO formas_pagamento (nome,tipo,modalidade,parcelas_padrao,intervalo_dias,juros_am,taxa_fixa,tipo_repeticao,lancar_financeiro,confirmar_auto,conta_bancaria,operadora,taxa_operadora) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$n,$data['tipo']??'dinheiro',$modalidade,
             $modalidade==='a_prazo'?(int)($data['parcelas_padrao']??1):1,
             $modalidade==='a_prazo'?(int)($data['intervalo_dias']??30):0,
             (float)($data['juros_am']??0),(float)($data['taxa_fixa']??0),
             $data['tipo_repeticao']??'mensal',
             isset($data['lancar_financeiro'])?(int)$data['lancar_financeiro']:1,
             isset($data['confirmar_auto'])?(int)$data['confirmar_auto']:0,
             $data['conta_bancaria']??'',
             $data['operadora']??'',(float)($data['taxa_operadora']??0)]);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $modalidade = $data['modalidade'] ?? 'a_vista';
        $db->prepare("UPDATE formas_pagamento SET nome=?,tipo=?,modalidade=?,parcelas_padrao=?,intervalo_dias=?,juros_am=?,taxa_fixa=?,tipo_repeticao=?,lancar_financeiro=?,confirmar_auto=?,conta_bancaria=?,operadora=?,taxa_operadora=?,ativo=? WHERE id=?")
           ->execute([$data['nome'],$data['tipo']??'dinheiro',$modalidade,
             $modalidade==='a_prazo'?(int)($data['parcelas_padrao']??1):1,
             $modalidade==='a_prazo'?(int)($data['intervalo_dias']??30):0,
             (float)($data['juros_am']??0),(float)($data['taxa_fixa']??0),
             $data['tipo_repeticao']??'mensal',
             isset($data['lancar_financeiro'])?(int)$data['lancar_financeiro']:1,
             isset($data['confirmar_auto'])?(int)$data['confirmar_auto']:0,
             $data['conta_bancaria']??'',$data['operadora']??'',(float)($data['taxa_operadora']??0),
             (int)($data['ativo']??1),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE formas_pagamento SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── CONTAS BANCÁRIAS ─────────────────────────────────────────
if ($resource === 'contas_bancarias') {
    auth_required();
    if ($method === 'GET') {
        $rows = $db->query("SELECT * FROM contas_bancarias WHERE ativo=1 ORDER BY nome")->fetchAll();
        resp(200, $rows);
    }
    if ($method === 'POST') {
        $n = trim($data['nome'] ?? ''); if (!$n) resp(400,['error'=>'Nome obrigatório']);
        $db->prepare("INSERT INTO contas_bancarias (nome,banco,agencia,conta,tipo) VALUES (?,?,?,?,?)")
           ->execute([$n,$data['banco']??'',$data['agencia']??'',$data['conta']??'',$data['tipo']??'corrente']);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE contas_bancarias SET nome=?,banco=?,agencia=?,conta=?,tipo=?,ativo=? WHERE id=?")
           ->execute([$data['nome'],$data['banco']??'',$data['agencia']??'',$data['conta']??'',$data['tipo']??'corrente',(int)($data['ativo']??1),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE contas_bancarias SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── OPERADORAS DE CARTÃO ──────────────────────────────────────
if ($resource === 'operadoras_cartao') {
    auth_required();
    if ($method === 'GET') {
        $rows = $db->query("SELECT * FROM operadoras_cartao WHERE ativo=1 ORDER BY nome")->fetchAll();
        resp(200, $rows);
    }
    if ($method === 'POST') {
        $n = trim($data['nome'] ?? ''); if (!$n) resp(400,['error'=>'Nome obrigatório']);
        $db->prepare("INSERT INTO operadoras_cartao (nome,tipo,taxa_padrao,prazo_repasse) VALUES (?,?,?,?)")
           ->execute([$n,$data['tipo']??'credito',(float)($data['taxa_padrao']??0),(int)($data['prazo_repasse']??30)]);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE operadoras_cartao SET nome=?,tipo=?,taxa_padrao=?,prazo_repasse=?,ativo=? WHERE id=?")
           ->execute([$data['nome'],$data['tipo']??'credito',(float)($data['taxa_padrao']??0),(int)($data['prazo_repasse']??30),(int)($data['ativo']??1),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE operadoras_cartao SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── GERAR CÓDIGO INTERNO ─────────────────────────────────────
// ─── FORNECEDORES ─────────────────────────────────────────────
if ($resource === 'fornecedores') {
    auth_required();
    if ($method === 'GET') {
        $q = '%' . ($_GET['q'] ?? '') . '%';
        $limit = (int)($_GET['limit'] ?? 50);
        $s = $db->prepare("SELECT * FROM fornecedores WHERE (razao_social LIKE ? OR nome_fantasia LIKE ? OR cpf_cnpj LIKE ?) AND ativo=1 ORDER BY razao_social LIMIT ?");
        $s->execute([$q, $q, $q, $limit]);
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST') {
        $n = trim($data['razao_social'] ?? ''); if (!$n) resp(400,['error'=>'Razão Social obrigatória']);
        $db->prepare("INSERT INTO fornecedores (razao_social,nome_fantasia,cpf_cnpj,telefone,email,endereco) VALUES (?,?,?,?,?,?)")
           ->execute([$n,$data['nome_fantasia']??'',$data['cpf_cnpj']??'',$data['telefone']??'',$data['email']??'',$data['endereco']??'']);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId(),'razao_social'=>$n]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE fornecedores SET razao_social=?,nome_fantasia=?,cpf_cnpj=?,telefone=?,email=?,endereco=?,ativo=? WHERE id=?")
           ->execute([$data['razao_social'],$data['nome_fantasia']??'',$data['cpf_cnpj']??'',$data['telefone']??'',$data['email']??'',$data['endereco']??'',(int)($data['ativo']??1),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE fornecedores SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── NCM ──────────────────────────────────────────────────────
if ($resource === 'ncm') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $q = '%' . ($_GET['q'] ?? '') . '%';
        $s = $db->prepare("SELECT * FROM ncm_tabela WHERE codigo LIKE ? OR descricao LIKE ? ORDER BY codigo LIMIT 50");
        $s->execute([$q, $q]);
        resp(200, $s->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM ncm_tabela WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error'=>'Não encontrado']);
    }
    if ($method === 'POST') {
        $cod = trim($data['codigo'] ?? ''); $desc = trim($data['descricao'] ?? '');
        if (!$cod || !$desc) resp(400,['error'=>'Código e descrição obrigatórios']);
        $db->prepare("INSERT OR REPLACE INTO ncm_tabela (codigo,descricao,aliq_ii,aliq_ipi,aliq_pis,aliq_cofins) VALUES (?,?,?,?,?,?)")
           ->execute([$cod,$desc,(float)($data['aliq_ii']??0),(float)($data['aliq_ipi']??0),(float)($data['aliq_pis']??0),(float)($data['aliq_cofins']??0)]);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE ncm_tabela SET codigo=?,descricao=?,aliq_ii=?,aliq_ipi=?,aliq_pis=?,aliq_cofins=? WHERE id=?")
           ->execute([$data['codigo'],$data['descricao'],(float)($data['aliq_ii']??0),(float)($data['aliq_ipi']??0),(float)($data['aliq_pis']??0),(float)($data['aliq_cofins']??0),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM ncm_tabela WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── CEST ─────────────────────────────────────────────────────
if ($resource === 'cest') {
    auth_required();
    if ($method === 'GET') {
        $ncm_filter = $_GET['ncm'] ?? '';
        if ($ncm_filter) {
            $s = $db->prepare("SELECT * FROM cest_tabela WHERE ncm LIKE ? ORDER BY cest");
            $s->execute(['%'.$ncm_filter.'%']);
        } else {
            $q = '%'.($_GET['q']??'').'%';
            $s = $db->prepare("SELECT * FROM cest_tabela WHERE cest LIKE ? OR descricao LIKE ? ORDER BY cest LIMIT 50");
            $s->execute([$q,$q]);
        }
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST') {
        $db->prepare("INSERT OR REPLACE INTO cest_tabela (cest,ncm,descricao) VALUES (?,?,?)")
           ->execute([trim($data['cest']??''),trim($data['ncm']??''),trim($data['descricao']??'')]);
        resp(201,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM cest_tabela WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── TABELAS DE PREÇO ─────────────────────────────────────────
if ($resource === 'tabelas_preco') {
    auth_required();
    if ($method === 'GET') {
        $pid = (int)($_GET['produto_id'] ?? 0);
        if ($pid) {
            $s = $db->prepare("SELECT * FROM tabelas_preco WHERE produto_id=? ORDER BY nome");
            $s->execute([$pid]); resp(200,$s->fetchAll());
        }
        resp(200,[]);
    }
    if ($method === 'POST') {
        $db->prepare("INSERT INTO tabelas_preco (produto_id,nome,margem_lucro,preco_venda) VALUES (?,?,?,?)")
           ->execute([$data['produto_id'],$data['nome'],(float)($data['margem_lucro']??0),(float)($data['preco_venda']??0)]);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE tabelas_preco SET nome=?,margem_lucro=?,preco_venda=? WHERE id=?")
           ->execute([$data['nome'],(float)($data['margem_lucro']??0),(float)($data['preco_venda']??0),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM tabelas_preco WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── LOJA VIRTUAL: CATEGORIAS ────────────────────────────────
if ($resource === 'loja_categorias') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $q = '%' . ($data['q'] ?? $_GET['q'] ?? '') . '%';
        $limit = max(1, min(500, (int)($_GET['limit'] ?? 200)));
        $s = $db->prepare("SELECT * FROM loja_categorias WHERE nome LIKE ? AND ativo=1 ORDER BY nome LIMIT ?");
        $s->execute([$q, $limit]);
        resp(200, $s->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM loja_categorias WHERE id=?");
        $s->execute([$id]);
        $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO loja_categorias (nome, descricao, ativo, data_criacao) VALUES (?,?,1,?)")
           ->execute([$nome, $data['descricao'] ?? '', date('Y-m-d H:i:s')]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $nome = trim($data['nome'] ?? '');
        if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("UPDATE loja_categorias SET nome=?, descricao=? WHERE id=?")
           ->execute([$nome, $data['descricao'] ?? '', $id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        // Inativa em vez de deletar para não quebrar vínculos com produtos
        $db->prepare("UPDATE loja_categorias SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── LOJA VIRTUAL: DADOS DO PRODUTO (aba Loja Virtual) ───────
// Os campos de loja ficam em tabela separada (produto_loja) para
// não poluir a tabela produtos, que já é muito larga.
// O frontend envia/lê via resource='produto_loja'&produto_id=X
if ($resource === 'produto_loja') {
    auth_required();
    $pid = (int)($_GET['produto_id'] ?? $data['produto_id'] ?? 0);

    // Helper: lê registro da loja para um produto, retornando array com defaults
    $getLoja = function(int $pid) use ($db): array {
        $s = $db->prepare("SELECT * FROM produto_loja WHERE produto_id=?");
        $s->execute([$pid]);
        $r = $s->fetch();
        if (!$r) {
            return [
                'produto_id'        => $pid,
                'loja_exibir'       => 0,
                'loja_titulo'       => '',
                'loja_descricao'    => '',
                'loja_categoria_id' => null,
                'loja_fotos'        => [],
                'loja_variacoes'    => [],
            ];
        }
        // Desserializa JSON dos arrays
        $r['loja_fotos']     = json_decode($r['loja_fotos'] ?? '[]', true) ?: [];
        $r['loja_variacoes'] = json_decode($r['loja_variacoes'] ?? '[]', true) ?: [];
        return $r;
    };

    if ($method === 'GET') {
        if (!$pid) resp(400, ['error' => 'produto_id obrigatório']);
        resp(200, $getLoja($pid));
    }

    // POST ou PUT: salva os dados da loja para o produto (upsert)
    if ($method === 'POST' || $method === 'PUT') {
        if (!$pid) resp(400, ['error' => 'produto_id obrigatório']);

        // Serializa arrays para JSON
        $fotos_raw     = $data['loja_fotos']     ?? [];
        $variacoes_raw = $data['loja_variacoes'] ?? [];
        $fotos_json     = is_array($fotos_raw)     ? json_encode($fotos_raw,     JSON_UNESCAPED_UNICODE) : (string)$fotos_raw;
        $variacoes_json = is_array($variacoes_raw) ? json_encode($variacoes_raw, JSON_UNESCAPED_UNICODE) : (string)$variacoes_raw;

        $loja_exibir      = (int)($data['loja_exibir']       ?? 0);
        $loja_titulo      = trim($data['loja_titulo']        ?? '');
        $loja_descricao   = trim($data['loja_descricao']     ?? '');
        $loja_cat_id      = !empty($data['loja_categoria_id']) ? (int)$data['loja_categoria_id'] : null;
        $now              = date('Y-m-d H:i:s');

        // Testa se já existe registro para este produto
        $check = $db->prepare("SELECT id FROM produto_loja WHERE produto_id=?");
        $check->execute([$pid]);
        $existe = $check->fetchColumn();

        if ($existe) {
            $db->prepare("UPDATE produto_loja
                SET loja_exibir=?, loja_titulo=?, loja_descricao=?,
                    loja_categoria_id=?, loja_fotos=?, loja_variacoes=?, data_atualizacao=?
                WHERE produto_id=?")
               ->execute([$loja_exibir, $loja_titulo, $loja_descricao,
                           $loja_cat_id, $fotos_json, $variacoes_json, $now, $pid]);
        } else {
            $db->prepare("INSERT INTO produto_loja
                (produto_id, loja_exibir, loja_titulo, loja_descricao,
                 loja_categoria_id, loja_fotos, loja_variacoes, data_atualizacao)
                VALUES (?,?,?,?,?,?,?,?)")
               ->execute([$pid, $loja_exibir, $loja_titulo, $loja_descricao,
                           $loja_cat_id, $fotos_json, $variacoes_json, $now]);
        }
        resp(200, ['success' => true]);
    }

    if ($method === 'DELETE' && $pid) {
        $db->prepare("DELETE FROM produto_loja WHERE produto_id=?")->execute([$pid]);
        resp(200, ['success' => true]);
    }

    resp(405, ['error' => 'Método não permitido']);
}

// ─── TABELAS DE SERVIÇO ───────────────────────────────────────
// ─── NOTAS FISCAIS DE ENTRADA ────────────────────────────────
if ($resource === 'nfe_entrada') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $q     = '%'.($_GET['q']??'').'%';
        $limit = max(1,min(200,(int)($_GET['limit']??30)));
        $page  = max(1,(int)($_GET['page']??1));
        $offset = ($page-1)*$limit;
        $tc = $db->prepare("SELECT COUNT(*) FROM notas_fiscais_entrada WHERE numero LIKE ? OR fornecedor_nome LIKE ? OR chave_acesso LIKE ?");
        $tc->execute([$q,$q,$q]);
        $total = (int)$tc->fetchColumn();
        $s = $db->prepare("SELECT * FROM notas_fiscais_entrada WHERE numero LIKE ? OR fornecedor_nome LIKE ? OR chave_acesso LIKE ? ORDER BY data_emissao DESC, id DESC LIMIT ? OFFSET ?");
        $s->execute([$q,$q,$q,$limit,$offset]);
        resp(200,['data'=>$s->fetchAll(),'total'=>$total,'pages'=>(int)ceil($total/$limit),'page'=>$page]);
    }
    if ($method === 'GET' && $id !== null) {
        $s=$db->prepare("SELECT * FROM notas_fiscais_entrada WHERE id=?"); $s->execute([$id]);
        $nf=$s->fetch();
        if(!$nf) resp(404,['error'=>'Não encontrada']);
        $items=$db->prepare("SELECT * FROM nfe_items WHERE nfe_id=?"); $items->execute([$id]);
        $nf['items']=$items->fetchAll();
        resp(200,$nf);
    }
    if ($method === 'POST') {
        $now=date('Y-m-d H:i:s');
        $chave=trim($data['chave_acesso']??'');
        if(!$chave) resp(400,['error'=>'Chave de acesso obrigatória']);
        $db->prepare("INSERT INTO notas_fiscais_entrada (numero,serie,chave_acesso,fornecedor_id,fornecedor_nome,fornecedor_cnpj,data_emissao,data_entrada,valor_total,valor_bc_icms,valor_icms,valor_bc_icms_st,valor_icms_st,valor_ii,valor_pis_st,valor_cofins_st,comple_icms,valor_liquido,valor_servico,valor_ipi,valor_pis,valor_cofins,valor_frete,valor_desconto,status,observacoes,xml_conteudo,data_importacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$data['numero']??'',$data['serie']??'',$chave,$data['fornecedor_id']??null,$data['fornecedor_nome']??'',$data['fornecedor_cnpj']??'',$data['data_emissao']??null,$data['data_entrada']??null,(float)($data['valor_total']??0),(float)($data['valor_bc_icms']??0),(float)($data['valor_icms']??0),(float)($data['valor_bc_icms_st']??0),(float)($data['valor_icms_st']??0),(float)($data['valor_ii']??0),(float)($data['valor_pis_st']??0),(float)($data['valor_cofins_st']??0),(float)($data['comple_icms']??0),(float)($data['valor_liquido']??0),(float)($data['valor_servico']??0),(float)($data['valor_ipi']??0),(float)($data['valor_pis']??0),(float)($data['valor_cofins']??0),(float)($data['valor_frete']??0),(float)($data['valor_desconto']??0),$data['status']??'Recebida',$data['observacoes']??'',$data['xml_conteudo']??'',$now]);
        $nfeId = (int)$db->lastInsertId();
        // Salvar itens
        if(!empty($data['items'])){
            $si=$db->prepare("INSERT INTO nfe_items (nfe_id,codigo_produto,descricao,ncm,cfop,unidade,quantidade,valor_unitario,valor_total,valor_icms,valor_ipi,valor_pis,valor_cofins) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)");
            foreach($data['items'] as $it){
                $si->execute([$nfeId,$it['codigo_produto']??'',$it['descricao']??'',$it['ncm']??'',$it['cfop']??'',$it['unidade']??'UN',(float)($it['quantidade']??1),(float)($it['valor_unitario']??0),(float)($it['valor_total']??0),(float)($it['valor_icms']??0),(float)($it['valor_ipi']??0),(float)($it['valor_pis']??0),(float)($it['valor_cofins']??0)]);
            }
        }
        // ── Atualizar estoque dos produtos ────────────────────────────────
        if (!empty($data['items'])) {
            $sqEstoque = $db->prepare(
                "UPDATE produtos SET estoque_atual = estoque_atual + ?, data_atualizacao=? WHERE id=?"
            );
            $nowEst = date('Y-m-d H:i:s');
            foreach ($data['items'] as $it) {
                $pid = isset($it['produto_id']) ? (int)$it['produto_id'] : 0;
                $qty = (float)($it['quantidade'] ?? 1);
                if ($pid > 0 && $qty > 0) {
                    $sqEstoque->execute([$qty, $nowEst, $pid]);
                }
            }
        }
        // ── Gerar conta a pagar automaticamente ──────────────────────────
        $valor_nfe = (float)($data['valor_total'] ?? 0);
        if ($valor_nfe > 0) {
            $forn_id_cp = $data['fornecedor_id'] ?? null;
            $forn_nome_cp = $data['fornecedor_nome'] ?? 'Fornecedor';
            $num_nfe_cp  = $data['numero'] ?? '';
            $desc_cp = "NF-e #{$num_nfe_cp} — {$forn_nome_cp}";
            $venc_cp = $data['data_vencimento_cp'] ?? $data['data_entrada'] ?? date('Y-m-d', strtotime('+30 days'));
            $now_cp  = date('Y-m-d H:i:s');
            $db->prepare("INSERT INTO contas_pagar (origem,nfe_id,fornecedor_id,descricao,valor,valor_pago,data_emissao,data_vencimento,status,documento_ref,data_criacao,data_atualizacao) VALUES ('nfe',?,?,?,?,0,?,?,'Aberta',?,?,?)")
               ->execute([$nfeId, $forn_id_cp, $desc_cp, $valor_nfe, $data['data_emissao']??date('Y-m-d'), $venc_cp, "NF-e {$num_nfe_cp}", $now_cp, $now_cp]);
        }
        resp(201,['success'=>true,'id'=>$nfeId]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE notas_fiscais_entrada SET numero=?,serie=?,fornecedor_nome=?,fornecedor_cnpj=?,data_emissao=?,data_entrada=?,valor_total=?,status=?,observacoes=? WHERE id=?")
           ->execute([$data['numero'],$data['serie'],$data['fornecedor_nome'],$data['fornecedor_cnpj'],$data['data_emissao'],$data['data_entrada'],(float)($data['valor_total']??0),$data['status']??'Recebida',$data['observacoes']??'',$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM nfe_items WHERE nfe_id=?")->execute([$id]);
        $db->prepare("DELETE FROM notas_fiscais_entrada WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── IBPT ─────────────────────────────────────────────────────
if ($resource === 'ibpt') {
    auth_required();
    if ($method === 'GET') {
        $total = (int)$db->query("SELECT COUNT(*) FROM ibpt")->fetchColumn();
        $ufs   = $db->query("SELECT DISTINCT uf FROM ibpt ORDER BY uf")->fetchAll(PDO::FETCH_COLUMN);
        $vigs  = $db->query("SELECT DISTINCT vigencia_fim FROM ibpt ORDER BY vigencia_fim DESC LIMIT 1")->fetchColumn();
        resp(200, ['total' => $total, 'ufs' => $ufs, 'vigencia_fim' => $vigs ?: '']);
    }
    if ($method === 'POST') {
        $csv     = $data['csv']     ?? '';
        $uf      = strtoupper(trim($data['uf'] ?? ''));
        $limpar  = !empty($data['limpar']);
        if (!$csv)    resp(400, ['error' => 'CSV não informado']);
        if (!$uf || strlen($uf) !== 2) resp(400, ['error' => 'UF inválida']);
        // Remove BOM UTF-8
        $csv = ltrim($csv, "\xEF\xBB\xBF");
        // Detecta separador (; ou ,)
        $sep = strpos(substr($csv, 0, 200), ';') !== false ? ';' : ',';
        $lines = preg_split('/\r\n|\r|\n/', trim($csv));
        if (count($lines) < 2) resp(400, ['error' => 'CSV sem dados']);
        // Descarta cabeçalho
        array_shift($lines);
        if ($limpar) {
            $db->prepare("DELETE FROM ibpt WHERE uf=?")->execute([$uf]);
        }
        $db->beginTransaction();
        $ins = $db->prepare("INSERT OR REPLACE INTO ibpt (ncm,ex,tipo,descricao,nacional,importado,estadual,municipal,uf,vigencia_inicio,vigencia_fim) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
        $count = 0;
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;
            $cols = str_getcsv($line, $sep);
            if (count($cols) < 8) continue;
            $ncm  = preg_replace('/\D/', '', $cols[0] ?? '');
            if (strlen($ncm) < 7) continue; // ignora linhas inválidas
            $ncm  = str_pad($ncm, 8, '0', STR_PAD_LEFT);
            $ex   = trim($cols[1] ?? '');
            $tipo = (int)($cols[2] ?? 0);
            $desc = trim($cols[3] ?? '');
            $nac  = (float)str_replace(',', '.', $cols[4] ?? 0);
            $imp  = (float)str_replace(',', '.', $cols[5] ?? 0);
            $est  = (float)str_replace(',', '.', $cols[6] ?? 0);
            $mun  = (float)str_replace(',', '.', $cols[7] ?? 0);
            $vini = trim($cols[8]  ?? '');
            $vfim = trim($cols[9]  ?? '');
            $ins->execute([$ncm,$ex,$tipo,$desc,$nac,$imp,$est,$mun,$uf,$vini,$vfim]);
            $count++;
        }
        $db->commit();
        resp(200, ['importados' => $count, 'uf' => $uf]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── IMPORTAR XML NF-e ────────────────────────────────────────
if ($resource === 'nfe_importar_xml' && $method === 'POST') {
    auth_required();
    $xml_str = $data['xml'] ?? '';
    if(!$xml_str) resp(400,['error'=>'XML não informado']);
    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($xml_str);
    if(!$xml){
        $xmls = preg_replace('/xmlns[^=]*="[^"]*"/i','', $xml_str);
        $xml  = simplexml_load_string($xmls);
        if(!$xml) resp(400,['error'=>'XML inválido ou malformado']);
    }
    // Normalizar namespace
    $nf = null;
    if(isset($xml->NFe->infNFe))       { $nf=$xml->NFe->infNFe; }
    elseif(isset($xml->infNFe))        { $nf=$xml->infNFe; }
    else {
        $xmls=preg_replace('/xmlns[^=]*="[^"]*"/i','', $xml_str);
        $xml2=simplexml_load_string($xmls);
        if(isset($xml2->NFe->infNFe))  { $nf=$xml2->NFe->infNFe; }
        elseif(isset($xml2->infNFe))   { $nf=$xml2->infNFe; }
        else resp(400,['error'=>'Estrutura NF-e não reconhecida']);
    }
    $emit = $nf->emit ?? null;
    $dest = $nf->dest ?? null;
    $ide  = $nf->ide  ?? null;
    $totXml = $nf->total->ICMSTot ?? null;

    // ── Validar CNPJ destinatário vs empresa ─────────────────
    $emp = $db->query("SELECT cnpj FROM empresa_dados WHERE id=1")->fetch();
    $cnpj_empresa = preg_replace('/\D/','', $emp['cnpj'] ?? '');
    $cnpj_dest    = preg_replace('/\D/','', (string)($dest->CNPJ ?? $dest->CPF ?? ''));
    if($cnpj_empresa && $cnpj_dest && $cnpj_empresa !== $cnpj_dest){
        resp(400,['error'=>"Esta NF-e é destinada ao CNPJ {$cnpj_dest}, mas o CNPJ configurado é {$cnpj_empresa}. Verifique em Configurações → Dados da Empresa."]);
    }

    $chave=(string)($xml->protNFe->infProt->chNFe ?? $xml->NFe->infNFe->attributes()['Id'] ?? $nf->attributes()['Id'] ?? '');
    if(preg_match('/^NFe_?/', $chave)) $chave=preg_replace('/^NFe_?/','', $chave);

    $avisos = [];
    $forn_id = null;

    // ── Auto-cadastrar fornecedor ─────────────────────────────
    $emit_razao  = (string)($emit->xNome ?? '');
    $emit_fant   = (string)($emit->xFant ?? '');
    $emit_cnpj   = (string)($emit->CNPJ  ?? $emit->CPF ?? '');
    $emit_end    = $emit->enderEmit ?? null;
    $emit_fone   = (string)($emit_end->fone ?? '');
    if($emit_cnpj){
        $cnpj_clean = preg_replace('/\D/','', $emit_cnpj);
        $existeForn = $db->prepare("SELECT id FROM fornecedores WHERE cpf_cnpj=? AND ativo=1");
        $existeForn->execute([$cnpj_clean]);
        $fornRow = $existeForn->fetch();
        if($fornRow){
            $forn_id = (int)$fornRow['id'];
        } else {
            $db->prepare("INSERT INTO fornecedores (razao_social,nome_fantasia,cpf_cnpj,telefone,ativo) VALUES (?,?,?,?,1)")
               ->execute([$emit_razao, $emit_fant, $cnpj_clean, $emit_fone]);
            $forn_id = (int)$db->lastInsertId();
            $avisos[] = "✅ Fornecedor cadastrado automaticamente: {$emit_razao} (CNPJ: {$cnpj_clean})";
        }
    }

    $result = [
        'fornecedor_id'  => $forn_id,
        'fornecedor_nome'=> $emit_fant ?: $emit_razao,
        'fornecedor_cnpj'=> preg_replace('/\D/','', $emit_cnpj),
        'numero'         => (string)($ide->nNF ?? ''),
        'serie'          => (string)($ide->serie ?? ''),
        'chave_acesso'   => $chave,
        'data_emissao'   => substr((string)($ide->dhEmi ?? $ide->dEmi ?? ''),0,10),
        'valor_total'    => (float)($totXml->vNF    ?? 0),
        'valor_bc_icms'  => (float)($totXml->vBC    ?? 0),
        'valor_icms'     => (float)($totXml->vICMS  ?? 0),
        'valor_bc_icms_st'=> (float)($totXml->vBCST ?? 0),
        'valor_icms_st'  => (float)($totXml->vST    ?? 0),
        'valor_ii'       => (float)($totXml->vII    ?? 0),
        'valor_cofins'   => (float)($totXml->vCOFINS?? 0),
        'valor_ipi'      => (float)($totXml->vIPI   ?? 0),
        'valor_pis'      => (float)($totXml->vPIS   ?? 0),
        'valor_pis_st'   => (float)($totXml->vPISST ?? 0),
        'valor_cofins_st'=> (float)($totXml->vCOFINSST ?? 0),
        'comple_icms'    => (float)($totXml->vFCPUFDest ?? 0),
        'valor_liquido'  => (float)($totXml->vNF    ?? 0),
        'valor_servico'  => 0,
        'valor_frete'    => (float)($totXml->vFrete ?? 0),
        'valor_desconto' => (float)($totXml->vDesc  ?? 0),
        'items'          => [],
        'avisos'         => $avisos,
    ];

    // ── Processar itens + auto-cadastrar produtos ─────────────
    foreach(($nf->det ?? []) as $det){
        $prod=$det->prod ?? null;
        $imp =$det->imposto ?? null;
        $cod =(string)($prod->cProd ?? '');
        $desc=(string)($prod->xProd ?? '');
        $ncm =(string)($prod->NCM   ?? '');
        $un  =(string)($prod->uCom  ?? 'UN');
        $vUnit=(float)($prod->vUnCom?? 0);

        // ── Dados fiscais extraídos do XML ────────────────────
        $ean_xml   = preg_replace('/\D/', '', (string)($prod->cEAN  ?? ''));
        $ean_xml   = in_array(strlen($ean_xml), [8,12,13,14]) ? $ean_xml : '';
        $cest_xml  = preg_replace('/\D/', '', (string)($prod->CEST  ?? ''));

        // origem e CSOSN/CST ficam dentro das tags de ICMS
        $orig_xml      = '0';
        $csosn_xml     = '';
        $cst_icms_xml  = '';
        $aliq_icms_xml = 0.0;
        $icmsGroup = $imp->ICMS ?? null;
        if ($icmsGroup) {
            foreach ($icmsGroup->children() as $icmsTag) {
                $o = (string)($icmsTag->orig ?? '');
                if ($o !== '') { $orig_xml = $o; }
                $cs = (string)($icmsTag->CSOSN ?? ''); // Simples Nacional
                if ($cs !== '') { $csosn_xml = $cs; }
                $cst = (string)($icmsTag->CST ?? '');  // Regime Normal
                if ($cst !== '') { $cst_icms_xml = $cst; $aliq_icms_xml = (float)($icmsTag->pICMS ?? 0); }
                break; // primeiro grupo de ICMS é o relevante
            }
        }

        // PIS
        $cst_pis_xml  = '';
        $aliq_pis_xml = 0.0;
        $pisGroup = $imp->PIS ?? null;
        if ($pisGroup) {
            foreach ($pisGroup->children() as $pisTag) {
                $cs = (string)($pisTag->CST ?? '');
                if ($cs !== '') { $cst_pis_xml = $cs; $aliq_pis_xml = (float)($pisTag->pPIS ?? 0); break; }
            }
        }

        // COFINS
        $cst_cofins_xml  = '';
        $aliq_cofins_xml = 0.0;
        $cofinsGroup = $imp->COFINS ?? null;
        if ($cofinsGroup) {
            foreach ($cofinsGroup->children() as $cofinsTag) {
                $cs = (string)($cofinsTag->CST ?? '');
                if ($cs !== '') { $cst_cofins_xml = $cs; $aliq_cofins_xml = (float)($cofinsTag->pCOFINS ?? 0); break; }
            }
        }

        // Verificar se produto existe pelo código ou descrição
        $prodId = null;
        if($cod){
            $pq=$db->prepare("SELECT id FROM produtos WHERE codigo_interno=? OR codigo_barras=? LIMIT 1");
            $pq->execute([$cod,$cod]);
            $pr=$pq->fetch();
            $prodId=$pr ? (int)$pr['id'] : null;
        }
        if(!$prodId && $desc){
            $pq2=$db->prepare("SELECT id FROM produtos WHERE descricao=? LIMIT 1");
            $pq2->execute([$desc]);
            $pr2=$pq2->fetch();
            $prodId=$pr2 ? (int)$pr2['id'] : null;
        }
        if(!$prodId){
            $now2=date('Y-m-d H:i:s');
            // Gerar código interno automático
            $lastCod=$db->query("SELECT MAX(CAST(SUBSTR(codigo_interno,2) AS INTEGER)) FROM produtos WHERE codigo_interno LIKE 'P%' AND LENGTH(codigo_interno)=7")->fetchColumn();
            $newCod='P'.str_pad((($lastCod?:(0))+1),6,'0',STR_PAD_LEFT);
            $cod_barras_xml = $ean_xml ?: (!empty($cod) ? $cod : null);
            $db->prepare("INSERT INTO produtos (tipo_item,codigo_interno,codigo_barras,descricao,unidade_medida,preco_custo,preco_venda,ncm,cest,origem,csosn,cst_icms,aliq_icms,cst_pis,aliq_pis,cst_cofins,aliq_cofins,estoque_atual,ativo,data_criacao,data_atualizacao) VALUES ('produto',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,1,?,?)")
               ->execute([$newCod,$cod_barras_xml,$desc,$un,$vUnit,$vUnit,$ncm,$cest_xml,$orig_xml,$csosn_xml,$cst_icms_xml,$aliq_icms_xml,$cst_pis_xml,$aliq_pis_xml,$cst_cofins_xml,$aliq_cofins_xml,$now2,$now2]);
            $prodId=(int)$db->lastInsertId();
            $avisos[]="✅ Produto cadastrado automaticamente: {$desc} (Cód: {$newCod})";
        } else {
            // ── Atualiza campos fiscais vazios/padrão no produto existente ──
            $pa=$db->prepare("SELECT codigo_barras,ncm,cest,origem,csosn,cst_icms,aliq_icms,cst_pis,aliq_pis,cst_cofins,aliq_cofins FROM produtos WHERE id=?");
            $pa->execute([$prodId]);
            $atual=$pa->fetch();

            $sets=[]; $vals=[];
            if (empty($atual['codigo_barras']) && $ean_xml)                       { $sets[]='codigo_barras=?'; $vals[]=$ean_xml; }
            if (empty($atual['ncm'])           && $ncm)                           { $sets[]='ncm=?';           $vals[]=$ncm; }
            if (empty($atual['cest'])          && $cest_xml)                      { $sets[]='cest=?';          $vals[]=$cest_xml; }
            if ($orig_xml !== '0'              && ($atual['origem']??'0') === '0'){ $sets[]='origem=?';        $vals[]=$orig_xml; }
            if (empty($atual['csosn'])         && $csosn_xml)                     { $sets[]='csosn=?';         $vals[]=$csosn_xml; }
            if (empty($atual['cst_icms'])      && $cst_icms_xml)                  { $sets[]='cst_icms=?';      $vals[]=$cst_icms_xml;
                                                                                    $sets[]='aliq_icms=?';     $vals[]=$aliq_icms_xml; }
            if (empty($atual['cst_pis'])       && $cst_pis_xml)                   { $sets[]='cst_pis=?';       $vals[]=$cst_pis_xml;
                                                                                    $sets[]='aliq_pis=?';      $vals[]=$aliq_pis_xml; }
            if (empty($atual['cst_cofins'])    && $cst_cofins_xml)                { $sets[]='cst_cofins=?';    $vals[]=$cst_cofins_xml;
                                                                                    $sets[]='aliq_cofins=?';   $vals[]=$aliq_cofins_xml; }
            if (!empty($sets)) {
                $sets[]='data_atualizacao=?'; $vals[]=date('Y-m-d H:i:s'); $vals[]=$prodId;
                $db->prepare("UPDATE produtos SET ".implode(',',$sets)." WHERE id=?")->execute($vals);
                $avisos[]="🔄 Dados fiscais atualizados: {$desc}";
            }
        }

        $result['items'][] = [
            'produto_id'     => $prodId,
            'codigo_produto' => $cod,
            'descricao'      => $desc,
            'ncm'            => $ncm,
            'cfop'           => (string)($prod->CFOP ?? ''),
            'unidade'        => $un,
            'quantidade'     => (float)($prod->qCom ?? 1),
            'valor_unitario' => $vUnit,
            'valor_total'    => (float)($prod->vProd ?? 0),
            'valor_icms'     => (float)($imp->ICMS->ICMS00->vICMS ?? $imp->ICMS->ICMS10->vICMS ?? $imp->ICMS->ICMS20->vICMS ?? 0),
            'valor_ipi'      => (float)($imp->IPI->IPITrib->vIPI ?? 0),
            'valor_pis'      => (float)($imp->PIS->PISAliq->vPIS ?? $imp->PIS->PISNT->vPIS ?? 0),
            'valor_cofins'   => (float)($imp->COFINS->COFINSAliq->vCOFINS ?? $imp->COFINS->COFINSNT->vCOFINS ?? 0),
        ];
    }
    $result['avisos'] = $avisos;
    resp(200, $result);
}

// ════════════════════════════════════════════════════════════════════════════
// ─── MÓDULO FINANCEIRO ───────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════════

// ─── CATEGORIAS FINANCEIRAS ──────────────────────────────────────────────
if ($resource === 'categorias_financeiras') {
    auth_required();
    if ($method === 'GET') {
        $tipo_f = $_GET['tipo'] ?? '';
        if ($tipo_f && in_array($tipo_f, ['pagar','receber','ambos'])) {
            $s = $db->prepare("SELECT * FROM categorias_financeiras WHERE (tipo=? OR tipo='ambos') AND ativo=1 ORDER BY nome");
            $s->execute([$tipo_f]);
        } else {
            $s = $db->query("SELECT * FROM categorias_financeiras WHERE ativo=1 ORDER BY nome");
        }
        resp(200, $s->fetchAll());
    }
    if ($method === 'POST') {
        $nome = trim($data['nome'] ?? ''); if (!$nome) resp(400, ['error' => 'Nome obrigatório']);
        $db->prepare("INSERT INTO categorias_financeiras (nome,tipo,cor) VALUES (?,?,?)")
           ->execute([$nome, $data['tipo'] ?? 'ambos', $data['cor'] ?? '#7d8590']);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE categorias_financeiras SET nome=?,tipo=?,cor=?,ativo=? WHERE id=?")
           ->execute([trim($data['nome']??''), $data['tipo']??'ambos', $data['cor']??'#7d8590', (int)($data['ativo']??1), $id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE categorias_financeiras SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── CONTAS A RECEBER ─────────────────────────────────────────────────────
if ($resource === 'contas_receber') {
    auth_required();

    // ── GET lista ─────────────────────────────────────────────────────────
    if ($method === 'GET' && $id === null) {
        $page   = max(1,(int)($_GET['page']??1));
        $limit  = max(1,min(100,(int)($_GET['limit']??30)));
        $offset = ($page-1)*$limit;
        $status_f = $_GET['status'] ?? '';
        $q_raw    = $_GET['q']     ?? '';
        $data_ini = $_GET['data_ini'] ?? '';
        $data_fim = $_GET['data_fim'] ?? '';
        $vencidas = $_GET['vencidas'] ?? '';

        $where = ['1=1']; $params = [];
        if ($status_f) { $where[] = 'cr.status=?'; $params[] = $status_f; }
        $status_list_raw = $_GET['status_list'] ?? '';
        if ($status_list_raw) {
            $statuses = array_values(array_filter(array_map('trim', explode(',', $status_list_raw))));
            if ($statuses) {
                $phs = implode(',', array_fill(0, count($statuses), '?'));
                $where[] = "cr.status IN ($phs)";
                $params = array_merge($params, $statuses);
            }
        }
        if ($q_raw)    { $where[] = '(cr.descricao LIKE ? OR c.nome LIKE ? OR cr.documento_ref LIKE ?)'; $q = '%'.$q_raw.'%'; $params[] = $q; $params[] = $q; $params[] = $q; }
        if ($data_ini) { $where[] = 'cr.data_vencimento >= ?'; $params[] = $data_ini; }
        if ($data_fim) { $where[] = 'cr.data_vencimento <= ?'; $params[] = $data_fim; }
        if ($vencidas === '1') { $where[] = "cr.data_vencimento < DATE('now') AND cr.status='Aberta'"; }
        $cb_filter = $_GET['conta_bancaria_id'] ?? '';
        if ($cb_filter !== '') { $where[] = 'cr.conta_bancaria_id=?'; $params[] = (int)$cb_filter; }
        $w = implode(' AND ', $where);

        // Ordenação dinâmica com whitelist de colunas seguras
        $allowed_cols = ['id','data_vencimento','data_emissao','valor','valor_recebido','status','descricao'];
        $order_by  = in_array($_GET['order_by']??'', $allowed_cols) ? 'cr.'.($_GET['order_by']) : 'cr.id';
        $order_dir = strtoupper($_GET['order_dir']??'DESC') === 'ASC' ? 'ASC' : 'DESC';

        $tc = $db->prepare("SELECT COUNT(*) FROM contas_receber cr LEFT JOIN clientes c ON cr.cliente_id=c.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();

        $s = $db->prepare("
            SELECT cr.*,
                   COALESCE(c.nome, cr.cliente_nome_manual) AS cliente_nome,
                   cf.nome AS categoria_nome, cf.cor AS categoria_cor,
                   cb.nome AS conta_bancaria_nome
            FROM contas_receber cr
            LEFT JOIN clientes c          ON cr.cliente_id=c.id
            LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id
            LEFT JOIN contas_bancarias cb  ON cr.conta_bancaria_id=cb.id
            WHERE $w
            ORDER BY $order_by $order_dir
            LIMIT ? OFFSET ?
        ");
        $s->execute(array_merge($params, [$limit, $offset]));
        $rows = $s->fetchAll();

        // Totalizadores
        $st = $db->prepare("SELECT
            COALESCE(SUM(CASE WHEN status='Aberta' THEN valor ELSE 0 END),0) AS total_aberto,
            COALESCE(SUM(CASE WHEN status='Recebida' THEN valor_recebido ELSE 0 END),0) AS total_recebido,
            COALESCE(SUM(CASE WHEN status='Aberta' AND data_vencimento < DATE('now') THEN valor ELSE 0 END),0) AS total_vencido
            FROM contas_receber cr LEFT JOIN clientes c ON cr.cliente_id=c.id WHERE $w");
        $st->execute($params); $totais = $st->fetch();

        resp(200, ['data'=>$rows,'total'=>$total,'page'=>$page,'pages'=>(int)ceil(max(1,$total)/$limit),'totais'=>$totais]);
    }

    // ── GET individual ────────────────────────────────────────────────────
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT cr.*, COALESCE(c.nome, cr.cliente_nome_manual) AS cliente_nome, cf.nome AS categoria_nome FROM contas_receber cr LEFT JOIN clientes c ON cr.cliente_id=c.id LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id WHERE cr.id=?");
        $s->execute([$id]); $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }

    // ── POST criar manual ─────────────────────────────────────────────────
    if ($method === 'POST' && $action === '' && $id === null) {
        $desc = trim($data['descricao'] ?? ''); if (!$desc) resp(400, ['error' => 'Descrição obrigatória']);
        $valor = (float)($data['valor'] ?? 0); if ($valor <= 0) resp(400, ['error' => 'Valor deve ser maior que zero']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,categoria_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,documento_ref,observacoes,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([
                $data['origem']           ?? 'manual',
                $data['venda_id']         ?? null,
                $data['parcela_id']       ?? null,
                $data['cliente_id']       ?? null,
                $data['categoria_id']     ?? null,
                $data['conta_bancaria_id']?? null,
                $desc,
                $valor,
                (float)($data['valor_recebido'] ?? 0),
                $data['data_emissao']     ?? date('Y-m-d'),
                $data['data_vencimento']  ?? null,
                $data['data_recebimento'] ?? null,
                $data['status']           ?? 'Aberta',
                $data['documento_ref']    ?? '',
                $data['observacoes']      ?? '',
                $now, $now
           ]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }

    // ── POST /contas_receber/{id}?action=receber — baixa do recebimento ───
    if ($method === 'POST' && $action === 'receber' && $id !== null) {
        $valor_rec = (float)($data['valor_recebido'] ?? 0);
        $dt_rec    = $data['data_recebimento'] ?? date('Y-m-d');
        $cb_id     = $data['conta_bancaria_id'] ?? null;
        $s = $db->prepare("SELECT * FROM contas_receber WHERE id=?"); $s->execute([$id]); $cr = $s->fetch();
        if (!$cr) resp(404, ['error' => 'Conta não encontrada']);
        if ($cr['status'] === 'Cancelada') resp(400, ['error' => 'Conta cancelada não pode ser baixada']);
        $novo_status = ($valor_rec >= $cr['valor']) ? 'Recebida' : 'Parcial';
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_receber SET valor_recebido=?,data_recebimento=?,status=?,conta_bancaria_id=COALESCE(?,conta_bancaria_id),data_atualizacao=? WHERE id=?")
           ->execute([$valor_rec, $dt_rec, $novo_status, $cb_id, $now, $id]);
        resp(200, ['success' => true, 'status' => $novo_status]);
    }

    // ── POST /contas_receber/{id}?action=cancelar ─────────────────────────
    if ($method === 'POST' && $action === 'cancelar' && $id !== null) {
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_receber SET status='Cancelada',data_atualizacao=? WHERE id=?")->execute([$now, $id]);
        resp(200, ['success' => true]);
    }

    // ── POST /contas_receber/{id}?action=estornar — estorno do recebimento ─
    if ($method === 'POST' && $action === 'estornar' && $id !== null) {
        $s = $db->prepare("SELECT * FROM contas_receber WHERE id=?"); $s->execute([$id]); $cr = $s->fetch();
        if (!$cr) resp(404, ['error' => 'Conta não encontrada']);
        if (!in_array($cr['status'], ['Recebida', 'Parcial'], true)) {
            resp(400, ['error' => 'Apenas lançamentos recebidos podem ser estornados']);
        }
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_receber SET valor_recebido=0, data_recebimento=NULL, status='Aberta', data_atualizacao=? WHERE id=?")
           ->execute([$now, $id]);
        resp(200, ['success' => true]);
    }

    // ── POST /contas_receber/{id}?action=parcelar — divide em N parcelas ──
    if ($method === 'POST' && $action === 'parcelar' && $id !== null) {
        $s = $db->prepare("SELECT * FROM contas_receber WHERE id=?"); $s->execute([$id]); $cr = $s->fetch();
        if (!$cr) resp(404, ['error' => 'Conta não encontrada']);
        if (in_array($cr['status'], ['Cancelada','Recebida'], true)) {
            resp(400, ['error' => 'Este lançamento não pode ser parcelado']);
        }
        $parcelas = $data['parcelas'] ?? [];
        if (!is_array($parcelas) || count($parcelas) < 2) {
            resp(400, ['error' => 'Informe ao menos 2 parcelas']);
        }
        $em_aberto = (float)$cr['valor'] - (float)($cr['valor_recebido'] ?? 0);
        if ($em_aberto <= 0) resp(400, ['error' => 'Não há valor em aberto para parcelar']);
        foreach ($parcelas as $i => $p) {
            $v = (float)($p['valor'] ?? 0);
            $dt = trim((string)($p['data_vencimento'] ?? ''));
            if ($v <= 0) resp(400, ['error' => 'Valor inválido na parcela '.($i+1)]);
            if (!$dt) resp(400, ['error' => 'Data inválida na parcela '.($i+1)]);
        }

        $now = date('Y-m-d H:i:s');
        $desc_base = preg_replace('/\s*\(Parcela\s+\d+\/\d+\)\s*$/u', '', (string)$cr['descricao']);
        $n = count($parcelas);
        $db->beginTransaction();
        try {
            $ja_pago = (float)($cr['valor_recebido'] ?? 0);
            if ($ja_pago > 0) {
                // Preserva o valor já recebido: original vira "Recebida" pelo valor recebido
                $db->prepare("UPDATE contas_receber SET valor=?,status='Recebida',descricao=?,data_atualizacao=? WHERE id=?")
                   ->execute([$ja_pago, $desc_base.' (Pagamento parcial)', $now, $id]);
            } else {
                // Aberta: remove o original
                $db->prepare("DELETE FROM contas_receber WHERE id=?")->execute([$id]);
            }

            $ins = $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,categoria_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,documento_ref,observacoes,cliente_nome_manual,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,0,?,?,NULL,'Aberta',?,?,?,?,?)");
            $ids = [];
            foreach ($parcelas as $i => $p) {
                $desc_i = $desc_base.' (Parcela '.($i+1).'/'.$n.')';
                $ins->execute([
                    'manual',
                    $cr['venda_id']           ?? null,
                    $cr['parcela_id']         ?? null,
                    $cr['cliente_id']         ?? null,
                    $cr['categoria_id']       ?? null,
                    $cr['conta_bancaria_id']  ?? null,
                    $desc_i,
                    (float)$p['valor'],
                    $cr['data_emissao']       ?? date('Y-m-d'),
                    $p['data_vencimento'],
                    $cr['documento_ref']      ?? '',
                    $cr['observacoes']        ?? '',
                    $cr['cliente_nome_manual']?? '',
                    $now, $now
                ]);
                $ids[] = (int)$db->lastInsertId();
            }
            $db->commit();
            resp(201, ['success' => true, 'ids' => $ids]);
        } catch (Throwable $e) {
            $db->rollBack();
            resp(500, ['error' => 'Falha ao parcelar: '.$e->getMessage()]);
        }
    }

    // ── PUT editar ────────────────────────────────────────────────────────
    if ($method === 'PUT' && $id !== null) {
        $desc = trim($data['descricao'] ?? ''); if (!$desc) resp(400, ['error' => 'Descrição obrigatória']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_receber SET cliente_id=?,categoria_id=?,conta_bancaria_id=?,descricao=?,valor=?,data_emissao=?,data_vencimento=?,documento_ref=?,observacoes=?,data_atualizacao=? WHERE id=?")
           ->execute([
                $data['cliente_id']       ?? null,
                $data['categoria_id']     ?? null,
                $data['conta_bancaria_id']?? null,
                $desc,
                (float)($data['valor'] ?? 0),
                $data['data_emissao']     ?? null,
                $data['data_vencimento']  ?? null,
                $data['documento_ref']    ?? '',
                $data['observacoes']      ?? '',
                $now, $id
           ]);
        resp(200, ['success' => true]);
    }

    // ── DELETE ────────────────────────────────────────────────────────────
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM contas_receber WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── CONTAS A PAGAR ───────────────────────────────────────────────────────
if ($resource === 'contas_pagar') {
    auth_required();

    // ── GET lista ─────────────────────────────────────────────────────────
    if ($method === 'GET' && $id === null) {
        $page   = max(1,(int)($_GET['page']??1));
        $limit  = max(1,min(100,(int)($_GET['limit']??30)));
        $offset = ($page-1)*$limit;
        $status_f = $_GET['status'] ?? '';
        $q_raw    = $_GET['q']     ?? '';
        $data_ini = $_GET['data_ini'] ?? '';
        $data_fim = $_GET['data_fim'] ?? '';
        $vencidas = $_GET['vencidas'] ?? '';

        $where = ['1=1']; $params = [];
        if ($status_f) { $where[] = 'cp.status=?'; $params[] = $status_f; }
        if ($q_raw)    { $where[] = '(cp.descricao LIKE ? OR f.razao_social LIKE ? OR cp.documento_ref LIKE ?)'; $q = '%'.$q_raw.'%'; $params[] = $q; $params[] = $q; $params[] = $q; }
        if ($data_ini) { $where[] = 'cp.data_vencimento >= ?'; $params[] = $data_ini; }
        if ($data_fim) { $where[] = 'cp.data_vencimento <= ?'; $params[] = $data_fim; }
        if ($vencidas === '1') { $where[] = "cp.data_vencimento < DATE('now') AND cp.status='Aberta'"; }
        $cb_filter_p = $_GET['conta_bancaria_id'] ?? '';
        if ($cb_filter_p !== '') { $where[] = 'cp.conta_bancaria_id=?'; $params[] = (int)$cb_filter_p; }
        $w = implode(' AND ', $where);

        // Ordenação dinâmica com whitelist de colunas seguras
        $allowed_cols_p = ['id','data_vencimento','data_emissao','valor','valor_pago','status','descricao'];
        $order_by  = in_array($_GET['order_by']??'', $allowed_cols_p) ? 'cp.'.($_GET['order_by']) : 'cp.id';
        $order_dir = strtoupper($_GET['order_dir']??'DESC') === 'ASC' ? 'ASC' : 'DESC';

        $tc = $db->prepare("SELECT COUNT(*) FROM contas_pagar cp LEFT JOIN fornecedores f ON cp.fornecedor_id=f.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();

        $s = $db->prepare("
            SELECT cp.*,
                   f.razao_social AS fornecedor_nome,
                   cf.nome AS categoria_nome, cf.cor AS categoria_cor,
                   cb.nome AS conta_bancaria_nome
            FROM contas_pagar cp
            LEFT JOIN fornecedores f               ON cp.fornecedor_id=f.id
            LEFT JOIN categorias_financeiras cf    ON cp.categoria_id=cf.id
            LEFT JOIN contas_bancarias cb          ON cp.conta_bancaria_id=cb.id
            WHERE $w
            ORDER BY $order_by $order_dir
            LIMIT ? OFFSET ?
        ");
        $s->execute(array_merge($params, [$limit, $offset]));
        $rows = $s->fetchAll();

        // Totalizadores
        $st = $db->prepare("SELECT
            COALESCE(SUM(CASE WHEN status='Aberta' THEN valor ELSE 0 END),0) AS total_aberto,
            COALESCE(SUM(CASE WHEN status='Paga' THEN valor_pago ELSE 0 END),0) AS total_pago,
            COALESCE(SUM(CASE WHEN status='Aberta' AND data_vencimento < DATE('now') THEN valor ELSE 0 END),0) AS total_vencido
            FROM contas_pagar cp LEFT JOIN fornecedores f ON cp.fornecedor_id=f.id WHERE $w");
        $st->execute($params); $totais = $st->fetch();

        resp(200, ['data'=>$rows,'total'=>$total,'page'=>$page,'pages'=>(int)ceil(max(1,$total)/$limit),'totais'=>$totais]);
    }

    // ── GET individual ────────────────────────────────────────────────────
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT cp.*, f.razao_social AS fornecedor_nome, cf.nome AS categoria_nome FROM contas_pagar cp LEFT JOIN fornecedores f ON cp.fornecedor_id=f.id LEFT JOIN categorias_financeiras cf ON cp.categoria_id=cf.id WHERE cp.id=?");
        $s->execute([$id]); $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }

    // ── POST criar manual ─────────────────────────────────────────────────
    if ($method === 'POST' && $action === '' && $id === null) {
        $desc = trim($data['descricao'] ?? ''); if (!$desc) resp(400, ['error' => 'Descrição obrigatória']);
        $valor = (float)($data['valor'] ?? 0); if ($valor <= 0) resp(400, ['error' => 'Valor deve ser maior que zero']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("INSERT INTO contas_pagar (origem,nfe_id,fornecedor_id,categoria_id,conta_bancaria_id,descricao,valor,valor_pago,data_emissao,data_vencimento,data_pagamento,status,documento_ref,observacoes,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([
                $data['origem']           ?? 'manual',
                $data['nfe_id']           ?? null,
                $data['fornecedor_id']    ?? null,
                $data['categoria_id']     ?? null,
                $data['conta_bancaria_id']?? null,
                $desc,
                $valor,
                (float)($data['valor_pago'] ?? 0),
                $data['data_emissao']     ?? date('Y-m-d'),
                $data['data_vencimento']  ?? null,
                $data['data_pagamento']   ?? null,
                $data['status']           ?? 'Aberta',
                $data['documento_ref']    ?? '',
                $data['observacoes']      ?? '',
                $now, $now
           ]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }

    // ── POST /contas_pagar/{id}?action=pagar — baixa do pagamento ─────────
    if ($method === 'POST' && $action === 'pagar' && $id !== null) {
        $valor_pago = (float)($data['valor_pago'] ?? 0);
        $dt_pag     = $data['data_pagamento'] ?? date('Y-m-d');
        $cb_id      = $data['conta_bancaria_id'] ?? null;
        $s = $db->prepare("SELECT * FROM contas_pagar WHERE id=?"); $s->execute([$id]); $cp = $s->fetch();
        if (!$cp) resp(404, ['error' => 'Conta não encontrada']);
        if ($cp['status'] === 'Cancelada') resp(400, ['error' => 'Conta cancelada não pode ser baixada']);
        $novo_status = ($valor_pago >= $cp['valor']) ? 'Paga' : 'Parcial';
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_pagar SET valor_pago=?,data_pagamento=?,status=?,conta_bancaria_id=COALESCE(?,conta_bancaria_id),data_atualizacao=? WHERE id=?")
           ->execute([$valor_pago, $dt_pag, $novo_status, $cb_id, $now, $id]);
        resp(200, ['success' => true, 'status' => $novo_status]);
    }

    // ── POST /contas_pagar/{id}?action=cancelar ───────────────────────────
    if ($method === 'POST' && $action === 'cancelar' && $id !== null) {
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_pagar SET status='Cancelada',data_atualizacao=? WHERE id=?")->execute([$now, $id]);
        resp(200, ['success' => true]);
    }

    // ── POST /contas_pagar/{id}?action=estornar — estorno do pagamento ────
    if ($method === 'POST' && $action === 'estornar' && $id !== null) {
        $s = $db->prepare("SELECT * FROM contas_pagar WHERE id=?"); $s->execute([$id]); $cp = $s->fetch();
        if (!$cp) resp(404, ['error' => 'Conta não encontrada']);
        if (!in_array($cp['status'], ['Paga', 'Parcial'], true)) {
            resp(400, ['error' => 'Apenas lançamentos pagos podem ser estornados']);
        }
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_pagar SET valor_pago=0, data_pagamento=NULL, status='Aberta', data_atualizacao=? WHERE id=?")
           ->execute([$now, $id]);
        resp(200, ['success' => true]);
    }

    // ── POST /contas_pagar/{id}?action=parcelar — divide em N parcelas ────
    if ($method === 'POST' && $action === 'parcelar' && $id !== null) {
        $s = $db->prepare("SELECT * FROM contas_pagar WHERE id=?"); $s->execute([$id]); $cp = $s->fetch();
        if (!$cp) resp(404, ['error' => 'Conta não encontrada']);
        if (in_array($cp['status'], ['Cancelada','Paga'], true)) {
            resp(400, ['error' => 'Este lançamento não pode ser parcelado']);
        }
        $parcelas = $data['parcelas'] ?? [];
        if (!is_array($parcelas) || count($parcelas) < 2) {
            resp(400, ['error' => 'Informe ao menos 2 parcelas']);
        }
        $em_aberto = (float)$cp['valor'] - (float)($cp['valor_pago'] ?? 0);
        if ($em_aberto <= 0) resp(400, ['error' => 'Não há valor em aberto para parcelar']);
        foreach ($parcelas as $i => $p) {
            $v = (float)($p['valor'] ?? 0);
            $dt = trim((string)($p['data_vencimento'] ?? ''));
            if ($v <= 0) resp(400, ['error' => 'Valor inválido na parcela '.($i+1)]);
            if (!$dt) resp(400, ['error' => 'Data inválida na parcela '.($i+1)]);
        }

        $now = date('Y-m-d H:i:s');
        $desc_base = preg_replace('/\s*\(Parcela\s+\d+\/\d+\)\s*$/u', '', (string)$cp['descricao']);
        $n = count($parcelas);
        $db->beginTransaction();
        try {
            $ja_pago = (float)($cp['valor_pago'] ?? 0);
            if ($ja_pago > 0) {
                $db->prepare("UPDATE contas_pagar SET valor=?,status='Paga',descricao=?,data_atualizacao=? WHERE id=?")
                   ->execute([$ja_pago, $desc_base.' (Pagamento parcial)', $now, $id]);
            } else {
                $db->prepare("DELETE FROM contas_pagar WHERE id=?")->execute([$id]);
            }

            $ins = $db->prepare("INSERT INTO contas_pagar (origem,nfe_id,fornecedor_id,categoria_id,conta_bancaria_id,descricao,valor,valor_pago,data_emissao,data_vencimento,data_pagamento,status,documento_ref,observacoes,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,0,?,?,NULL,'Aberta',?,?,?,?)");
            $ids = [];
            foreach ($parcelas as $i => $p) {
                $desc_i = $desc_base.' (Parcela '.($i+1).'/'.$n.')';
                $ins->execute([
                    'manual',
                    $cp['nfe_id']             ?? null,
                    $cp['fornecedor_id']      ?? null,
                    $cp['categoria_id']       ?? null,
                    $cp['conta_bancaria_id']  ?? null,
                    $desc_i,
                    (float)$p['valor'],
                    $cp['data_emissao']       ?? date('Y-m-d'),
                    $p['data_vencimento'],
                    $cp['documento_ref']      ?? '',
                    $cp['observacoes']        ?? '',
                    $now, $now
                ]);
                $ids[] = (int)$db->lastInsertId();
            }
            $db->commit();
            resp(201, ['success' => true, 'ids' => $ids]);
        } catch (Throwable $e) {
            $db->rollBack();
            resp(500, ['error' => 'Falha ao parcelar: '.$e->getMessage()]);
        }
    }

    // ── PUT editar ────────────────────────────────────────────────────────
    if ($method === 'PUT' && $id !== null) {
        $desc = trim($data['descricao'] ?? ''); if (!$desc) resp(400, ['error' => 'Descrição obrigatória']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("UPDATE contas_pagar SET fornecedor_id=?,categoria_id=?,conta_bancaria_id=?,descricao=?,valor=?,data_emissao=?,data_vencimento=?,documento_ref=?,observacoes=?,data_atualizacao=? WHERE id=?")
           ->execute([
                $data['fornecedor_id']    ?? null,
                $data['categoria_id']     ?? null,
                $data['conta_bancaria_id']?? null,
                $desc,
                (float)($data['valor'] ?? 0),
                $data['data_emissao']     ?? null,
                $data['data_vencimento']  ?? null,
                $data['documento_ref']    ?? '',
                $data['observacoes']      ?? '',
                $now, $id
           ]);
        resp(200, ['success' => true]);
    }

    // ── DELETE ────────────────────────────────────────────────────────────
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM contas_pagar WHERE id=?")->execute([$id]);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── FLUXO DE CAIXA ───────────────────────────────────────────────────────
if ($resource === 'fluxo_caixa') {
    auth_required();
    $periodo  = $_GET['periodo']  ?? 'mes';
    $data_ini = $_GET['data_ini'] ?? null;
    $data_fim = $_GET['data_fim'] ?? null;
    switch ($periodo) {
        case 'semana': $data_ini = date('Y-m-d', strtotime('monday this week')); $data_fim = date('Y-m-d'); break;
        case 'mes':    $data_ini = date('Y-m-01'); $data_fim = date('Y-m-t'); break;
        case 'trimestre': $data_ini = date('Y-m-01', strtotime('-2 months')); $data_fim = date('Y-m-t'); break;
        case 'ano':    $data_ini = date('Y-01-01'); $data_fim = date('Y-12-31'); break;
        default: if (!$data_ini) $data_ini = date('Y-m-01'); if (!$data_fim) $data_fim = date('Y-m-t');
    }

    // Entradas por dia (contas recebidas)
    $se = $db->prepare("
        SELECT DATE(data_recebimento) AS dia,
               COALESCE(SUM(valor_recebido),0) AS total
        FROM contas_receber
        WHERE status IN ('Recebida','Parcial')
          AND data_recebimento BETWEEN ? AND ?
        GROUP BY dia ORDER BY dia
    ");
    $se->execute([$data_ini, $data_fim]);
    $entradas_por_dia = [];
    foreach ($se->fetchAll() as $r) $entradas_por_dia[$r['dia']] = (float)$r['total'];

    // Saídas por dia (contas pagas)
    $ss = $db->prepare("
        SELECT DATE(data_pagamento) AS dia,
               COALESCE(SUM(valor_pago),0) AS total
        FROM contas_pagar
        WHERE status IN ('Paga','Parcial')
          AND data_pagamento BETWEEN ? AND ?
        GROUP BY dia ORDER BY dia
    ");
    $ss->execute([$data_ini, $data_fim]);
    $saidas_por_dia = [];
    foreach ($ss->fetchAll() as $r) $saidas_por_dia[$r['dia']] = (float)$r['total'];

    // Montar série de dias completa
    $dias = []; $dt = new DateTime($data_ini); $dtFim = new DateTime($data_fim);
    while ($dt <= $dtFim) { $dias[] = $dt->format('Y-m-d'); $dt->modify('+1 day'); }

    $serie = [];
    $saldo_acumulado = 0;
    foreach ($dias as $dia) {
        $e = $entradas_por_dia[$dia] ?? 0;
        $s2 = $saidas_por_dia[$dia] ?? 0;
        $saldo_acumulado += $e - $s2;
        $serie[] = ['dia' => $dia, 'entradas' => $e, 'saidas' => $s2, 'saldo' => round($saldo_acumulado, 2)];
    }

    // Totais gerais do período
    $te = $db->prepare("SELECT COALESCE(SUM(valor_recebido),0) FROM contas_receber WHERE status IN ('Recebida','Parcial') AND data_recebimento BETWEEN ? AND ?");
    $te->execute([$data_ini, $data_fim]); $total_entradas = (float)$te->fetchColumn();

    $ts = $db->prepare("SELECT COALESCE(SUM(valor_pago),0) FROM contas_pagar WHERE status IN ('Paga','Parcial') AND data_pagamento BETWEEN ? AND ?");
    $ts->execute([$data_ini, $data_fim]); $total_saidas = (float)$ts->fetchColumn();

    // A vencer no período (abertos)
    $tv_e = $db->prepare("SELECT COALESCE(SUM(valor),0) FROM contas_receber WHERE status='Aberta' AND data_vencimento BETWEEN ? AND ?");
    $tv_e->execute([$data_ini, $data_fim]); $previsto_entradas = (float)$tv_e->fetchColumn();

    $tv_s = $db->prepare("SELECT COALESCE(SUM(valor),0) FROM contas_pagar WHERE status='Aberta' AND data_vencimento BETWEEN ? AND ?");
    $tv_s->execute([$data_ini, $data_fim]); $previsto_saidas = (float)$tv_s->fetchColumn();

    // Entradas por categoria
    $sc = $db->prepare("
        SELECT COALESCE(cf.nome,'Sem categoria') AS categoria, cf.cor,
               COALESCE(SUM(cr.valor_recebido),0) AS total
        FROM contas_receber cr
        LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id
        WHERE cr.status IN ('Recebida','Parcial') AND cr.data_recebimento BETWEEN ? AND ?
        GROUP BY cr.categoria_id ORDER BY total DESC
    ");
    $sc->execute([$data_ini, $data_fim]); $por_categoria_entrada = $sc->fetchAll();

    // Saídas por categoria
    $sc2 = $db->prepare("
        SELECT COALESCE(cf.nome,'Sem categoria') AS categoria, cf.cor,
               COALESCE(SUM(cp.valor_pago),0) AS total
        FROM contas_pagar cp
        LEFT JOIN categorias_financeiras cf ON cp.categoria_id=cf.id
        WHERE cp.status IN ('Paga','Parcial') AND cp.data_pagamento BETWEEN ? AND ?
        GROUP BY cp.categoria_id ORDER BY total DESC
    ");
    $sc2->execute([$data_ini, $data_fim]); $por_categoria_saida = $sc2->fetchAll();

    resp(200, [
        'periodo'            => ['inicio' => $data_ini, 'fim' => $data_fim],
        'total_entradas'     => $total_entradas,
        'total_saidas'       => $total_saidas,
        'saldo_periodo'      => round($total_entradas - $total_saidas, 2),
        'previsto_entradas'  => $previsto_entradas,
        'previsto_saidas'    => $previsto_saidas,
        'serie'              => $serie,
        'por_categoria_entrada' => $por_categoria_entrada,
        'por_categoria_saida'   => $por_categoria_saida,
    ]);
}

// ════════════════════════════════════════════════════════════════════════════
// ─── FIM DO MÓDULO FINANCEIRO ─────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════════

if ($resource === 'tabelas_servico') {
    auth_required();
    if ($method === 'GET' && $id === null) {
        $q = '%'.($_GET['q']??'').'%';
        $s = $db->prepare("SELECT * FROM tabelas_servico WHERE (codigo LIKE ? OR descricao LIKE ?) AND ativo=1 ORDER BY codigo LIMIT 50");
        $s->execute([$q,$q]);
        resp(200, $s->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s=$db->prepare("SELECT * FROM tabelas_servico WHERE id=?"); $s->execute([$id]);
        $r=$s->fetch(); resp($r?200:404,$r?:['error'=>'Não encontrado']);
    }
    if ($method === 'POST') {
        $cod=trim($data['codigo']??''); $desc=trim($data['descricao']??'');
        if(!$cod||!$desc) resp(400,['error'=>'Código e descrição obrigatórios']);
        $db->prepare("INSERT INTO tabelas_servico (codigo,descricao,cnae,cod_trib_municipio,aliq_iss,cst_pis,aliq_pis,cst_cofins,aliq_cofins) VALUES (?,?,?,?,?,?,?,?,?)")
           ->execute([$cod,$desc,$data['cnae']??'',$data['cod_trib_municipio']??'',(float)($data['aliq_iss']??0),$data['cst_pis']??'01',(float)($data['aliq_pis']??0),$data['cst_cofins']??'01',(float)($data['aliq_cofins']??0)]);
        resp(201,['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE tabelas_servico SET codigo=?,descricao=?,cnae=?,cod_trib_municipio=?,aliq_iss=?,cst_pis=?,aliq_pis=?,cst_cofins=?,aliq_cofins=?,ativo=? WHERE id=?")
           ->execute([$data['codigo'],$data['descricao'],$data['cnae']??'',$data['cod_trib_municipio']??'',(float)($data['aliq_iss']??0),$data['cst_pis']??'01',(float)($data['aliq_pis']??0),$data['cst_cofins']??'01',(float)($data['aliq_cofins']??0),(int)($data['ativo']??1),$id]);
        resp(200,['success'=>true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("UPDATE tabelas_servico SET ativo=0 WHERE id=?")->execute([$id]);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ─── CERTIFICADO DIGITAL ─────────────────────────────────────
if ($resource === 'empresa_certificado' && $method === 'POST') {
    auth_required();
    $pfx_b64 = $data['pfx_b64'] ?? '';
    $senha   = $data['senha']   ?? '';
    $nome_arq= $data['nome_arquivo'] ?? 'certificado.pfx';
    if(!$pfx_b64 || !$senha) resp(400,['error'=>'Certificado e senha obrigatórios']);

    $pfx_bin = base64_decode($pfx_b64);
    if($pfx_bin === false || strlen($pfx_bin) < 10)
        resp(400,['error'=>'Arquivo inválido ou corrompido']);

    // Helper: garante que o valor de um campo do subject seja string
    $strVal = function($v) {
        if(is_array($v)) return implode(' ', array_map('strval', array_filter($v, 'is_scalar')));
        return is_scalar($v) ? (string)$v : '';
    };

    $cert_info = [];
    if(function_exists('openssl_pkcs12_read')){
        if(!openssl_pkcs12_read($pfx_bin, $cert_info, $senha)){
            resp(400,['error'=>'Senha incorreta ou arquivo .pfx inválido. Verifique a senha e tente novamente.']);
        }
    } else {
        resp(500,['error'=>'OpenSSL não disponível no servidor. Não é possível processar o certificado.']);
    }

    $cert_nome=$nome_arq; $cert_validade=''; $razao=''; $cnpj_cert=''; $fantasia='';

    if(!empty($cert_info['cert'])){
        $parsed = openssl_x509_parse($cert_info['cert']);
        if($parsed === false) resp(400,['error'=>'Não foi possível ler os dados do certificado.']);

        $subject = $parsed['subject'] ?? [];

        // Campos do subject podem ser arrays quando há múltiplos valores — converter para string
        $razao    = $strVal($subject['O']  ?? $subject['CN'] ?? '');
        $fantasia = $strVal($subject['OU'] ?? '');
        $cn_raw   = $strVal($subject['CN'] ?? '');
        $cnpj_cert= preg_replace('/\D/', '', $cn_raw);
        // CN de cert e-CPF tem 11 dígitos; cert e-CNPJ tem 14+8 — pegar só os 14 primeiros
        if(strlen($cnpj_cert) > 14) $cnpj_cert = substr($cnpj_cert, 0, 14);

        $valid_to = $parsed['validTo_time_t'] ?? 0;
        $cert_validade = $valid_to ? date('d/m/Y', (int)$valid_to) : '';
        $cert_nome = $razao ?: $nome_arq;
    }

    $emp = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
    $divergencias = [];
    $update = [
        'certificado_pfx'      => base64_encode($pfx_bin),
        'certificado_nome'     => $cert_nome,
        'certificado_validade' => $cert_validade,
        'nfce_cert_senha'      => $senha,
    ];

    $razao_emp = (string)($emp['razao_social'] ?? '');
    $nome_emp  = (string)($emp['nome']         ?? '');
    $cnpj_emp  = preg_replace('/\D/', '', (string)($emp['cnpj'] ?? ''));

    if($razao && $razao !== $razao_emp){
        $divergencias[] = "Razão Social atualizada: '$razao_emp' → '$razao'";
        $update['razao_social'] = $razao;
    }
    if($fantasia && $fantasia !== $nome_emp){
        $divergencias[] = "Nome Fantasia atualizado: '$nome_emp' → '$fantasia'";
        $update['nome'] = $fantasia;
    }
    if($cnpj_cert && strlen($cnpj_cert) === 14 && $cnpj_cert !== $cnpj_emp){
        $divergencias[] = "CNPJ atualizado: '$cnpj_emp' → '$cnpj_cert'";
        $update['cnpj'] = $cnpj_cert;
    }

    $sets = implode(',', array_map(fn($k) => "$k=?", array_keys($update)));
    $vals = array_values($update);
    $vals[] = 1;
    $db->prepare("UPDATE empresa_dados SET $sets WHERE id=?")->execute($vals);

    resp(200,[
        'success'      => true,
        'divergencias' => $divergencias,
        'cert_nome'    => $cert_nome,
        'cert_validade'=> $cert_validade,
    ]);
}

if ($resource === 'gerar_codigo' && $method === 'GET') {
    auth_required();
    $tipo = $_GET['tipo'] ?? 'P';
    $prefix = strtoupper(substr($tipo, 0, 1));
    $last = $db->query("SELECT MAX(CAST(SUBSTR(codigo_interno,2) AS INTEGER)) FROM produtos WHERE codigo_interno LIKE '{$prefix}%' AND LENGTH(codigo_interno)=7")->fetchColumn();
    $next = ($last ? (int)$last : 0) + 1;
    resp(200, ['codigo' => $prefix . str_pad($next, 6, '0', STR_PAD_LEFT)]);
}

// ─── PADRONIZAR NOMES DE CLIENTES ────────────────────────────
// ─── NFC-e: CONFIGURAÇÕES ──────────────────────────────────────
// ─── NFC-e STATUS — verifica se NFePHP está instalado ───────────
if ($resource === 'nfce_status' && $method === 'GET') {
    auth_required();
    $autoload = __DIR__ . '/nfephp/vendor/autoload.php';
    $instalado = file_exists($autoload);
    $pacotes = [];
    if ($instalado) {
        $vendor_nfe = __DIR__ . '/nfephp/vendor/nfephp-org';
        if (is_dir($vendor_nfe)) {
            $pacotes = array_values(array_filter(scandir($vendor_nfe), fn($d) => $d[0] !== '.'));
        }
    }
    resp(200, [
        'instalado' => $instalado,
        'pacotes'   => $pacotes,
        'autoload'  => $autoload,
    ]);
}

// ─── VERIFICAÇÃO DE ATUALIZAÇÕES NFEPHP ───────────────────────────────────────
if ($resource === 'nfce_updates' && $method === 'GET') {
    auth_required();

    $pacotes_monitorados = [
        'nfephp-org/sped-nfe',
        'nfephp-org/sped-da',
        'nfephp-org/sped-common',
    ];

    // ── Lê as versões instaladas do composer.lock ────────────────────
    $lock_path = __DIR__ . '/nfephp/composer.lock';
    $instalados = [];
    if (file_exists($lock_path)) {
        $lock = json_decode(file_get_contents($lock_path), true);
        foreach (($lock['packages'] ?? []) as $pkg) {
            $nome = $pkg['name'] ?? '';
            if (in_array($nome, $pacotes_monitorados)) {
                // Remove o "v" prefixo se existir (ex: "v5.1.2" → "5.1.2")
                $instalados[$nome] = ltrim($pkg['version'] ?? '', 'v');
            }
        }
    }

    // ── Consulta Packagist para cada pacote ──────────────────────────
    $resultado = [];
    foreach ($pacotes_monitorados as $nome) {
        $entrada = [
            'nome'       => $nome,
            'instalado'  => $instalados[$nome] ?? null,
            'disponivel' => null,
            'desatualizado' => false,
            'erro'       => null,
        ];

        // GET https://packagist.org/packages/{vendor}/{package}.json
        $url = 'https://packagist.org/packages/' . $nome . '.json';
        $_packagist_cainfo = ssl_cainfo();
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 8,
                'method'  => 'GET',
                'header'  => "User-Agent: ConsertaOS/1.0\r\n",
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
                'cafile'           => $_packagist_cainfo ?? '',
            ],
        ]);

        $resposta = @file_get_contents($url, false, $ctx);
        if ($resposta === false) {
            $entrada['erro'] = 'Não foi possível consultar o Packagist (sem conexão ou timeout).';
            $resultado[] = $entrada;
            continue;
        }

        $json = json_decode($resposta, true);
        if (!$json) {
            $entrada['erro'] = 'Resposta inválida do Packagist.';
            $resultado[] = $entrada;
            continue;
        }

        // Extrai a versão estável mais recente
        // O Packagist retorna versões no formato: "package.versions"
        $versoes = $json['package']['versions'] ?? [];
        $estavel_mais_recente = null;
        foreach ($versoes as $tag => $info) {
            // Ignora dev, alpha, beta, RC e branches
            if (strpos($tag, 'dev') !== false) continue;
            if (strpos($tag, 'alpha') !== false) continue;
            if (strpos($tag, 'beta') !== false) continue;
            if (strpos($tag, 'RC') !== false) continue;
            if (strpos($tag, '#') !== false) continue; // branch hash
            $limpa = ltrim($tag, 'v');
            if (!preg_match('/^\d+\.\d+/', $limpa)) continue; // apenas x.y...
            if ($estavel_mais_recente === null || version_compare($limpa, $estavel_mais_recente, '>')) {
                $estavel_mais_recente = $limpa;
            }
        }

        $entrada['disponivel'] = $estavel_mais_recente;

        // Compara versões
        if ($entrada['instalado'] && $estavel_mais_recente) {
            $entrada['desatualizado'] = version_compare($entrada['instalado'], $estavel_mais_recente, '<');
        } elseif (!$entrada['instalado']) {
            $entrada['erro'] = 'Pacote não encontrado no composer.lock (não instalado?).';
        }

        $resultado[] = $entrada;
    }

    resp(200, [
        'pacotes'       => $resultado,
        'verificado_em' => date('d/m/Y H:i:s'),
    ]);
}

// ── SUPORTE — proxy para a central em consertaos.com.br ──────
if ($resource === 'suporte') {
    auth_required();
    $master_cfg  = file_exists(__DIR__ . '/config.php') ? (array)@require __DIR__ . '/config.php' : [];
    $suporte_url = rtrim((string)($master_cfg['centralsuporte_url'] ?? ''), '/');
    $secret      = (string)($master_cfg['provisionar_secret'] ?? '');
    if ($suporte_url === '') resp(503, ['error' => 'Central de suporte não configurada']);

    $u         = auth_required();
    $loja_slug = basename(SAAS_DIR);
    $emp       = $db->query("SELECT nome FROM empresa_dados WHERE id=1")->fetch() ?: [];
    $loja_nome = trim((string)($emp['nome'] ?? $loja_slug));

    // Determina action pelo método + parâmetros
    if      ($method === 'GET' && $id === null)          $a = 'listar';
    elseif  ($method === 'GET' && $id !== null)          $a = 'detalhes';
    elseif  ($method === 'POST' && $action === 'mensagem') $a = 'mensagem';
    else                                                  $a = $data['action'] ?? 'criar';

    $payload = array_merge($data, [
        'action'        => $a,
        'chave_secreta' => $secret,
        'loja_slug'     => $loja_slug,
        'loja_nome'     => $loja_nome,
        'usuario_nome'  => $u['nome']  ?? '',
        'usuario_email' => $u['email'] ?? '',
    ]);
    if ($id !== null) $payload['id'] = $id;

    $ch = curl_init($suporte_url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    ]);
    $resp     = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    http_response_code($httpCode ?: 500);
    echo $resp ?: json_encode(['error' => 'Erro ao conectar com a central de suporte']);
    exit;
}

// ── MEU PLANO ────────────────────────────────────────────────
if ($resource === 'meu_plano' && $method === 'GET') {
    auth_required();
    $emp = $db->query("SELECT plano_nome,plano_valor,plano_data_inicio,plano_status,mp_preapproval_id,plano_landing_url,plano_landing_secret FROM empresa_dados WHERE id=1")->fetch() ?: [];
    $resultado = [
        'plano_nome'        => $emp['plano_nome']        ?? '',
        'plano_valor'       => (float)($emp['plano_valor']   ?? 0),
        'plano_data_inicio' => $emp['plano_data_inicio']  ?? '',
        'plano_status'      => $emp['plano_status']       ?? 'ativo',
        'mp_preapproval_id' => $emp['mp_preapproval_id']  ?? '',
        'mp_status'         => null,
        'next_payment'      => null,
    ];
    $landing_url    = $emp['plano_landing_url']    ?? '';
    $landing_secret = $emp['plano_landing_secret'] ?? '';
    $mp_id          = $emp['mp_preapproval_id']    ?? '';
    if ($landing_url !== '' && $landing_secret !== '' && $mp_id !== '') {
        $ch = curl_init($landing_url);
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>10, CURLOPT_SSL_VERIFYPEER=>true,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
            CURLOPT_POSTFIELDS=>json_encode(['chave_secreta'=>$landing_secret,'action'=>'status','mp_preapproval_id'=>$mp_id])]);
        $resp = curl_exec($ch); curl_close($ch);
        if ($resp) {
            $mp = json_decode($resp, true) ?: [];
            $resultado['mp_status']    = $mp['status']       ?? null;
            $resultado['next_payment'] = $mp['next_payment'] ?? null;
        }
    }
    resp(200, $resultado);
}

if ($resource === 'cancelar_plano' && $method === 'POST') {
    $u = auth_required();
    if (($u['nivel_acesso'] ?? '') !== 'admin') resp(403, ['error' => 'Somente administradores podem cancelar o plano']);
    $emp = $db->query("SELECT plano_landing_url,plano_landing_secret,mp_preapproval_id FROM empresa_dados WHERE id=1")->fetch() ?: [];
    $landing_url    = $emp['plano_landing_url']    ?? '';
    $landing_secret = $emp['plano_landing_secret'] ?? '';
    $mp_id          = $emp['mp_preapproval_id']    ?? '';
    if ($landing_url === '' || $landing_secret === '' || $mp_id === '') {
        resp(400, ['error' => 'Configuração de assinatura não encontrada. Entre em contato com o suporte.']);
    }
    $ch = curl_init($landing_url);
    curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>30, CURLOPT_SSL_VERIFYPEER=>true,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_POSTFIELDS=>json_encode(['chave_secreta'=>$landing_secret,'action'=>'cancelar','mp_preapproval_id'=>$mp_id])]);
    $resp     = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$resp || $httpCode !== 200) resp(500, ['error' => 'Erro ao processar cancelamento. Entre em contato com o suporte.']);
    $r = json_decode($resp, true) ?: [];
    if (!empty($r['ok'])) {
        $db->prepare("UPDATE empresa_dados SET plano_status='cancelado' WHERE id=1")->execute();
    }
    resp(200, $r);
}

if ($resource === 'nfce_config') {
    auth_required();
    if ($method === 'GET') {
        $r = $db->query("SELECT nfce_csc,nfce_csc_id,nfce_ambiente,nfce_serie,nfce_proximo_numero,nfce_cmun,nfce_cuf,cnpj,razao_social,nome,ie,im,regime_tributario,cep,logradouro,numero,complemento,bairro,cidade,uf,telefone,certificado_nome,certificado_validade FROM empresa_dados WHERE id=1")->fetch();
        $r['tem_certificado'] = !empty($db->query("SELECT certificado_pfx FROM empresa_dados WHERE id=1")->fetchColumn());
        resp(200, $r ?: []);
    }
    if ($method === 'POST') {
        $fields = ['nfce_csc','nfce_csc_id','nfce_ambiente','nfce_serie','nfce_proximo_numero','nfce_cmun','nfce_cuf','nfce_cert_senha','ie','im','regime_tributario','cep','logradouro','numero','complemento','bairro','cidade','uf'];
        $sets = implode(',', array_map(fn($f)=>"$f=?", $fields));
        $vals = array_map(fn($f)=>$data[$f]??'', $fields);
        $vals[] = 1;
        $db->prepare("UPDATE empresa_dados SET $sets WHERE id=?")->execute($vals);
        resp(200, ['success'=>true]);
    }
    resp(405, ['error'=>'Método não permitido']);
}

// ─── NFC-e: EMISSÃO via NFePHP ──────────────────────────────────
if ($resource === 'nfce') {
    auth_required();
    $emp = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
    $autoload  = __DIR__ . '/nfephp/vendor/autoload.php';
    $nfephp_ok = file_exists($autoload);

    if ($method === 'GET' && $id === null) {
        $where = '1=1'; $params_n = [];
        if(!empty($_GET['os_id']))    { $where.=' AND os_id=?';    $params_n[]=(int)$_GET['os_id']; }
        if(!empty($_GET['venda_id'])) { $where.=' AND venda_id=?'; $params_n[]=(int)$_GET['venda_id']; }
        if(!empty($_GET['status']))   { $where.=' AND status=?';   $params_n[]=$_GET['status']; }
        if(!empty($_GET['q'])){
            $q='%'.$_GET['q'].'%';
            $where.=' AND (numero LIKE ? OR chave_acesso LIKE ? OR cliente_nome LIKE ?)';
            $params_n[]=$q; $params_n[]=$q; $params_n[]=$q;
        }
        $limit = min((int)($_GET['limit']??100), 200);
        $s=$db->prepare("SELECT * FROM nfce_emitidas WHERE $where ORDER BY id DESC LIMIT $limit");
        $s->execute($params_n); resp(200, $s->fetchAll());
    }

    if ($method === 'GET' && $id !== null) {
        $s=$db->prepare("SELECT * FROM nfce_emitidas WHERE id=?"); $s->execute([$id]);
        $nf=$s->fetch(); resp($nf ? 200 : 404, $nf ?: ['error'=>'NFC-e não encontrada']);
    }

    // Correção manual de status — usado quando a SEFAZ processou mas o banco ficou desatualizado
    if ($method === 'POST' && ($data['action'] ?? '') === 'marcar_cancelada') {
        auth_required();
        $fix_id   = (int)($data['id'] ?? 0);
        $fix_prot = trim($data['n_prot'] ?? '');
        if (!$fix_id) resp(400, ['error' => 'ID não informado.']);
        $s = $db->prepare("SELECT id,status,numero FROM nfce_emitidas WHERE id=?");
        $s->execute([$fix_id]);
        $nfFix = $s->fetch();
        if (!$nfFix) resp(404, ['error' => 'NFC-e não encontrada.']);
        $sets = ['status=?', 'data_atualizacao=?'];
        $vals = ['Cancelada', date('Y-m-d H:i:s')];
        if ($fix_prot) { $sets[] = 'n_prot=?'; $vals[] = $fix_prot; }
        $vals[] = $fix_id;
        $db->prepare("UPDATE nfce_emitidas SET " . implode(',', $sets) . " WHERE id=?")->execute($vals);
        resp(200, ['success' => true, 'message' => "NFC-e #{$nfFix['numero']} marcada como Cancelada."]);
    }

    // Cancelamento via POST body (evita bloqueio de DELETE e query strings no Locaweb)
    if ($method === 'POST' && ($data['action'] ?? '') === 'cancelar_nfce') {
        if(!$nfephp_ok) resp(400,['error'=>'NFePHP nao instalado']);
        $cancel_id = (int)($data['id'] ?? $id ?? 0);
        if(!$cancel_id) resp(400,['error'=>'ID da NFC-e nao informado']);
        $s=$db->prepare('SELECT * FROM nfce_emitidas WHERE id=?'); $s->execute([$cancel_id]); $nf=$s->fetch();
        if(!$nf) resp(404,['error'=>'NFC-e nao encontrada']);
        if($nf['status'] !== 'Autorizada') resp(400,['error'=>'Apenas NFC-e Autorizada pode ser cancelada. Status atual: '.$nf['status']]);
        if(empty($nf['chave_acesso']) || strlen($nf['chave_acesso']) !== 44) resp(400,['error'=>'Chave de acesso inválida ou ausente para esta NFC-e (chave: '.($nf['chave_acesso']??'vazia').').']);
        if(empty($nf['n_prot'])) resp(400,['error'=>'Protocolo de autorização (nProt) não encontrado para esta NFC-e. Não é possível cancelar sem o protocolo da SEFAZ.']);
        $just = trim($data['justificativa'] ?? '');
        if(strlen($just) < 15) resp(400,['error'=>'Justificativa minimo 15 caracteres']);
        try {
            require_once $autoload;
            require_once __DIR__.'/src/NfceService.php';
            $emp2 = $db->query('SELECT * FROM empresa_dados WHERE id=1')->fetch();
            $cert_senha_cancel = $data['cert_senha'] ?? ($emp2['nfce_cert_senha'] ?? '');
            if (!$cert_senha_cancel) resp(400,['error'=>'Informe a senha do certificado digital para cancelar.']);
            $cfg2 = ['ambiente'=>$emp2['nfce_ambiente']??'homologacao','csc'=>$emp2['nfce_csc'],'csc_id'=>$emp2['nfce_csc_id'],'certificado_pfx'=>$emp2['certificado_pfx'],'certificado_senha'=>$cert_senha_cancel,'storage_dir'=>__DIR__.'/storage/nfce','empresa'=>['cnpj'=>$emp2['cnpj'],'razao_social'=>$emp2['razao_social'],'nome_fantasia'=>$emp2['nome'],'ie'=>$emp2['ie'],'cMun'=>$emp2['nfce_cmun']??'','cUF'=>(int)($emp2['nfce_cuf']??42),'uf'=>$emp2['uf'],'logradouro'=>$emp2['logradouro'],'numero'=>$emp2['numero'],'bairro'=>$emp2['bairro'],'cidade'=>$emp2['cidade'],'cep'=>$emp2['cep'],'telefone'=>$emp2['telefone']]];
            $svc = new \ConsertaOS\NfcE\NfceService($cfg2);
            $resultado = $svc->cancelar($nf['chave_acesso'], $just, $nf['n_prot'] ?? '');
            if (!$resultado['autorizada']) {
                $cstat_info = $resultado['cStat'] ? " [cStat {$resultado['cStat']}]" : '';
                resp(400,['error'=>'SEFAZ recusou: '.($resultado['xMotivo'] ?? 'Sem retorno').$cstat_info]);
            }
            $nProt_cancel = $resultado['nProt'] ?: ($nf['n_prot'] ?? '');
            $db->prepare('UPDATE nfce_emitidas SET status=?,n_prot=?,data_atualizacao=? WHERE id=?')
               ->execute(['Cancelada', $nProt_cancel, date('Y-m-d H:i:s'), $cancel_id]);
            resp(200,['success'=>true,'xMotivo'=>$resultado['xMotivo']??'Cancelada com sucesso','nProt'=>$nProt_cancel]);
        } catch(\Exception $e){ resp(500,['error'=>$e->getMessage()]); }
    }

    if ($method === 'POST' && !isset($_GET['action'])) {
        if (!$nfephp_ok) resp(400,['error'=>'NFePHP não instalado. Execute: bash instalar.sh no servidor via SSH.']);
        $csc    = $emp['nfce_csc']    ?? '';
        $pfx_b64= $emp['certificado_pfx'] ?? '';
        if (!$csc)     resp(400,['error'=>'CSC não configurado. Vá em Configurações → NFC-e.']);
        if (!$pfx_b64) resp(400,['error'=>'Certificado digital não cadastrado.']);

        $cert_senha = $data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? '');
        if (!$cert_senha) resp(400,['error'=>'Informe a senha do certificado digital.']);

        $config = [
            'ambiente'          => $emp['nfce_ambiente'] ?? 'homologacao',
            'csc'               => $csc,
            'csc_id'            => $emp['nfce_csc_id'] ?? '01',
            'certificado_pfx'   => $pfx_b64,
            'certificado_senha' => $cert_senha,
            'storage_dir'       => SAAS_DIR . '/storage/nfce',
            'empresa' => [
                'cnpj'         => $emp['cnpj'],
                'razao_social' => $emp['razao_social'],
                'nome_fantasia'=> $emp['nome'],
                'ie'           => $emp['ie'],
                'cMun'         => $emp['nfce_cmun'] ?? '',
                'cUF'          => (int)($emp['nfce_cuf'] ?? 42),
                'uf'           => $emp['uf'],
                'logradouro'   => $emp['logradouro'],
                'numero'       => $emp['numero'],
                'bairro'       => $emp['bairro'],
                'cidade'       => $emp['cidade'],
                'cep'          => $emp['cep'],
                'telefone'     => $emp['telefone'],
            ],
        ];

        // Próximo número com lock
        $db->beginTransaction();
        $numero=(int)$db->query("SELECT nfce_proximo_numero FROM empresa_dados WHERE id=1")->fetchColumn();
        $db->exec("UPDATE empresa_dados SET nfce_proximo_numero=nfce_proximo_numero+1 WHERE id=1");
        $db->commit();

        $dadosNfce = array_merge($data, [
            'numero' => $numero,
            'serie'  => (int)($emp['nfce_serie'] ?? 1),
        ]);

        // ── Enriquecer itens com vTotTrib via tabela IBPT ──────────
        $uf_emp = strtoupper($emp['uf'] ?? '');
        if ($uf_emp && !empty($dadosNfce['itens'])) {
            $ibptStmt = $db->prepare(
                "SELECT nacional, importado FROM ibpt WHERE ncm=? AND tipo=0 AND uf=? ORDER BY ex ASC LIMIT 1"
            );
            foreach ($dadosNfce['itens'] as &$it_nfce) {
                $ncm_it = preg_replace('/\D/', '', $it_nfce['ncm'] ?? '');
                if (strlen($ncm_it) !== 8) continue;
                $ibptStmt->execute([$ncm_it, $uf_emp]);
                $ibpt_row = $ibptStmt->fetch();
                if (!$ibpt_row) continue;
                $orig_it  = (int)($it_nfce['origem'] ?? 0);
                $aliq_it  = ($orig_it > 0) ? (float)$ibpt_row['importado'] : (float)$ibpt_row['nacional'];
                $it_nfce['vTotTrib'] = round((float)($it_nfce['valor_total'] ?? 0) * $aliq_it / 100, 2);
            }
            unset($it_nfce);
        }

        try {
            require_once $autoload;
            require_once __DIR__ . '/src/NfceService.php';
            $svc = new \ConsertaOS\NfcE\NfceService($config);
            $resultado = $svc->emitir($dadosNfce);
            $now = date('Y-m-d H:i:s');
            $status = $resultado['autorizada'] ? 'Autorizada' : 'Rejeitada';
            $cliente_nome_ins = $data['cliente_nome'] ?? '';
            $cfop_ins         = $data['itens'][0]['cfop'] ?? '5949';
            $serie_ins        = (string)($emp['nfce_serie'] ?? '1');
            $n_prot_ins       = $resultado['nProt'] ?? '';
            $os_vinc_ins      = $data['os_vinculada'] ?? '';
            $data_envio_ins   = $resultado['autorizada'] ? $now : null;
            $db->prepare("INSERT INTO nfce_emitidas (os_id,venda_id,status,numero,serie,chave_acesso,valor_total,motivo_rejeicao,n_prot,ambiente,cliente_nome,cfop,payload_json,os_vinculada,data_envio,data_emissao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([$data['os_id']??null,$data['venda_id']??null,$status,$numero,$serie_ins,$resultado['chave']??'',$data['valor_total']??0,$resultado['xMotivo']??'',$n_prot_ins,$config['ambiente'],$cliente_nome_ins,$cfop_ins,json_encode($data),$os_vinc_ins,$data_envio_ins,$now,$now]);
            $local_id=(int)$db->lastInsertId();
            if(!$resultado['autorizada'])
                {} // Número rejeitado é pulado — deve ser inutilizado pelo usuário via Configurações → NFC-e
            // Baixa de estoque (apenas NFC-e autorizada)
            if ($resultado['autorizada']) {
                $stBaixa = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual - ? WHERE id=?");
                foreach ($data['itens'] ?? [] as $it) {
                    $pid = isset($it['_produto_id']) ? (int)$it['_produto_id'] : 0;
                    $qty = (float)($it['quantidade'] ?? 1);
                    if ($pid > 0 && $qty > 0) $stBaixa->execute([$qty, $pid]);
                }
            }
            // Gerar conta a receber apenas se autorizada e se o usuário optou por gerar lançamentos
            $gerar_lancamentos = isset($data['gerar_lancamentos']) ? (bool)$data['gerar_lancamentos'] : true;
            if ($resultado['autorizada'] && $gerar_lancamentos) {
                // Tenta vincular cliente_id pelo CPF/CNPJ ou pelo nome
                $cli_id_nfce   = $data['cliente_id'] ?? null;
                $cli_cpf_nfce  = preg_replace('/\D/', '', $data['cliente_cpf']  ?? '');
                $cli_cnpj_nfce = preg_replace('/\D/', '', $data['cliente_cnpj'] ?? '');
                if (!$cli_id_nfce && $cli_cpf_nfce) {
                    $sq = $db->prepare("SELECT id FROM clientes WHERE REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),'/','')=? LIMIT 1");
                    $sq->execute([$cli_cpf_nfce]);
                    $cli_id_nfce = $sq->fetchColumn() ?: null;
                }
                if (!$cli_id_nfce && $cli_cnpj_nfce) {
                    $sq = $db->prepare("SELECT id FROM clientes WHERE REPLACE(REPLACE(REPLACE(cpf,'.',''),'-',''),'/','')=? LIMIT 1");
                    $sq->execute([$cli_cnpj_nfce]);
                    $cli_id_nfce = $sq->fetchColumn() ?: null;
                }
                if (!$cli_id_nfce && $cliente_nome_ins && $cliente_nome_ins !== 'CONSUMIDOR') {
                    $sq = $db->prepare("SELECT id FROM clientes WHERE LOWER(nome)=LOWER(?) LIMIT 1");
                    $sq->execute([$cliente_nome_ins]);
                    $cli_id_nfce = $sq->fetchColumn() ?: null;
                }
                // Nome manual como fallback (exibido quando cliente_id não é encontrado)
                $cli_nome_manual = ($cliente_nome_ins && $cliente_nome_ins !== 'CONSUMIDOR') ? $cliente_nome_ins : '';

                $val_nfce  = (float)($data['valor_total'] ?? 0);
                $desc_nfce = "NFC-e #{$numero}" . ($cliente_nome_ins && $cliente_nome_ins !== 'CONSUMIDOR' ? " — {$cliente_nome_ins}" : '');
                // Busca conta_bancaria_id da forma de pagamento informada
                $cb_id_nfce = null;
                $fp_id_nfce = $data['forma_pagamento_id'] ?? null;
                if ($fp_id_nfce) {
                    $fpRow = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                    $fpRow->execute([$fp_id_nfce]);
                    $fpData = $fpRow->fetch();
                    if ($fpData && !empty($fpData['conta_bancaria'])) {
                        $cbRow = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                        $cbRow->execute([$fpData['conta_bancaria']]);
                        $cb_id_nfce = $cbRow->fetchColumn() ?: null;
                    }
                }
                // Fallback: tenta via faturamentos se houver
                if (!$cb_id_nfce && !empty($data['faturamentos'])) {
                    $fp_id_fat = $data['faturamentos'][0]['forma_pagamento_id'] ?? null;
                    if ($fp_id_fat) {
                        $fpRow2 = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                        $fpRow2->execute([$fp_id_fat]);
                        $fpData2 = $fpRow2->fetch();
                        if ($fpData2 && !empty($fpData2['conta_bancaria'])) {
                            $cbRow2 = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                            $cbRow2->execute([$fpData2['conta_bancaria']]);
                            $cb_id_nfce = $cbRow2->fetchColumn() ?: null;
                        }
                    }
                }
                $db->prepare("INSERT INTO contas_receber (origem,venda_id,cliente_id,cliente_nome_manual,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,data_criacao,data_atualizacao) VALUES ('nfce',?,?,?,?,?,?,?,?,?,?,?,?,?)")
                   ->execute([$local_id,$cli_id_nfce,$cli_nome_manual,$cb_id_nfce,$desc_nfce,$val_nfce,$val_nfce,date('Y-m-d'),date('Y-m-d'),date('Y-m-d'),'Recebida',$now,$now]);
            }
            // Sempre retorna 200 para que o frontend leia xMotivo/cStat mesmo em rejeição
            resp(200, array_merge($resultado, ['id'=>$local_id,'numero'=>$numero]));
        } catch(\Exception $e) {
            $db->exec("UPDATE empresa_dados SET nfce_proximo_numero=nfce_proximo_numero-1 WHERE id=1");
            resp(500,['error'=>$e->getMessage()]);
        }
    }

    // DELETE desativado (bloqueado pelo Locaweb). Cancelamento via POST body action=cancelar_nfce.
    if ($method === 'DELETE' && $id !== null) {
        resp(405,['error'=>'Use POST para cancelar NFC-e neste servidor.']);
    }

    // ── POST action=inutilizar — inutiliza faixa de numeração na SEFAZ ──
    if ($method === 'POST' && isset($_GET['action']) && $_GET['action'] === 'inutilizar') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado.']);
        $pfx_b64 = $emp['certificado_pfx'] ?? '';
        if (!$pfx_b64) resp(400, ['error' => 'Certificado digital não cadastrado.']);

        $nIni  = (int)($data['n_ini']  ?? 0);
        $nFin  = (int)($data['n_fin']  ?? $nIni);
        $just  = trim($data['justificativa'] ?? '');
        $serie = (int)($data['serie'] ?? ($emp['nfce_serie'] ?? 1));
        $certSenha = $data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? '');

        if ($nIni <= 0)          resp(400, ['error' => 'Número inicial inválido.']);
        if ($nFin < $nIni)       resp(400, ['error' => 'Número final deve ser >= número inicial.']);
        if (strlen($just) < 15)  resp(400, ['error' => 'Justificativa deve ter no mínimo 15 caracteres.']);
        if (!$certSenha)         resp(400, ['error' => 'Informe a senha do certificado.']);

        $config_inut = [
            'ambiente'          => $emp['nfce_ambiente'] ?? 'homologacao',
            'csc'               => $emp['nfce_csc']    ?? '',
            'csc_id'            => $emp['nfce_csc_id'] ?? '01',
            'certificado_pfx'   => $pfx_b64,
            'certificado_senha' => $certSenha,
            'storage_dir'       => SAAS_DIR . '/storage/nfce',
            'empresa' => [
                'cnpj'         => $emp['cnpj'],
                'razao_social' => $emp['razao_social'],
                'nome_fantasia'=> $emp['nome'],
                'ie'           => $emp['ie'],
                'cMun'         => $emp['nfce_cmun'] ?? '',
                'cUF'          => (int)($emp['nfce_cuf'] ?? 42),
                'uf'           => $emp['uf'],
                'logradouro'   => $emp['logradouro'],
                'numero'       => $emp['numero'],
                'bairro'       => $emp['bairro'],
                'cidade'       => $emp['cidade'],
                'cep'          => $emp['cep'],
                'telefone'     => $emp['telefone'],
            ],
        ];

        try {
            require_once $autoload;
            require_once __DIR__ . '/src/NfceService.php';
            $svc     = new \ConsertaOS\NfcE\NfceService($config_inut);
            $resultado = $svc->inutilizar($nIni, $nFin, $just, $serie);

            if ($resultado['inutilizado']) {
                // Registra inutilização no banco para controle
                $now = date('Y-m-d H:i:s');
                foreach (range($nIni, $nFin) as $num) {
                    // Atualiza se já existe como Rejeitada, senão insere
                    $stEx = $db->prepare("SELECT id FROM nfce_emitidas WHERE numero=? AND serie=? AND status='Rejeitada' LIMIT 1");
                    $stEx->execute([$num, $serie]);
                    $idEx = $stEx->fetchColumn();
                    if ($idEx) {
                        $db->prepare("UPDATE nfce_emitidas SET status='Inutilizada', motivo_rejeicao=?, data_atualizacao=? WHERE id=?")
                           ->execute([$just, $now, $idEx]);
                    } else {
                        $db->prepare("INSERT INTO nfce_emitidas (status,numero,serie,motivo_rejeicao,ambiente,data_emissao,data_atualizacao) VALUES ('Inutilizada',?,?,?,?,?,?)")
                           ->execute([$num, $serie, $just, $emp['nfce_ambiente'] ?? 'homologacao', $now, $now]);
                    }
                }
            }

            resp(200, $resultado);
        } catch (\Exception $e) {
            resp(500, ['error' => $e->getMessage()]);
        }
    }

    // ── POST action=salvar — salva NFC-e em Digitação sem transmitir ──────────
    if ($method === 'POST' && isset($_GET['action']) && $_GET['action'] === 'salvar') {
        $now       = date('Y-m-d H:i:s');
        $cli_nome  = $data['cliente_nome']  ?? '';
        $val_total = (float)($data['valor_total'] ?? 0);
        $os_vinc   = $data['os_vinculada']  ?? '';
        $ambiente  = $data['ambiente']      ?? 'homologacao';
        $serie     = $data['serie']         ?? ($emp['nfce_serie'] ?? '1');
        $cfop      = $data['itens'][0]['cfop'] ?? '5949';
        $payload   = json_encode($data);
        $db->prepare("INSERT INTO nfce_emitidas (os_id,venda_id,status,numero,serie,chave_acesso,valor_total,motivo_rejeicao,n_prot,ambiente,cliente_nome,cfop,payload_json,os_vinculada,data_emissao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$data['os_id']??null,$data['venda_id']??null,'Digitação','',$serie,'',$val_total,'','',$ambiente,$cli_nome,$cfop,$payload,$os_vinc,$now,$now]);
        $local_id = (int)$db->lastInsertId();
        resp(201,['success'=>true,'id'=>$local_id,'status'=>'Digitação']);
    }

    // ── PUT — atualiza NFC-e em Digitação (rascunho) ─────────────────────────
    if ($method === 'PUT' && $id !== null) {
        $s = $db->prepare("SELECT status FROM nfce_emitidas WHERE id=?"); $s->execute([$id]);
        $nfAtual = $s->fetch();
        if (!$nfAtual) resp(404,['error'=>'NFC-e não encontrada']);
        if ($nfAtual['status'] !== 'Digitação') resp(400,['error'=>'Só é possível editar NFC-e em Digitação']);
        $now     = date('Y-m-d H:i:s');
        $fields  = ['cliente_nome','valor_total','ambiente','serie','cfop','os_vinculada','payload_json'];
        $sets    = []; $vals = [];
        foreach ($fields as $f) {
            if (array_key_exists($f, $data)) { $sets[] = "$f=?"; $vals[] = $data[$f]; }
        }
        if (isset($data['payload'])) { $sets[] = 'payload_json=?'; $vals[] = json_encode($data['payload']); }
        $sets[] = 'data_atualizacao=?'; $vals[] = $now;
        $vals[] = $id;
        $db->prepare("UPDATE nfce_emitidas SET ".implode(',',$sets)." WHERE id=?")->execute($vals);
        resp(200,['success'=>true,'id'=>$id]);
    }

    resp(405,['error'=>'Método não permitido']);
}


// ═══════════════════════════════════════════════════════════════════════════
// NFS-e — Emissão via WebService IPM/Atende.Net (Chapadão do Lageado/SC)
// Recurso: ?resource=nfse
// ═══════════════════════════════════════════════════════════════════════════

// ── nfe_exportar — gera ZIP com XMLs e/ou DANFEs de NF-e filtrados ──────────
if ($resource === 'nfe_exportar') {
    auth_required();
    $status_f  = $_GET['status']    ?? '';
    $dt_ini_f  = $_GET['dt_inicio'] ?? '';
    $dt_fim_f  = $_GET['dt_fim']    ?? '';
    $inc_xml   = ($_GET['xml']   ?? '0') === '1';
    $inc_danfe = ($_GET['danfe'] ?? '0') === '1';
    $emails_f  = trim($_GET['emails'] ?? '');
    $modo      = $_GET['modo']      ?? 'download';
    $id_unico  = isset($_GET['id_unico']) && is_numeric($_GET['id_unico']) ? (int)$_GET['id_unico'] : null;
    if (!$inc_xml && !$inc_danfe) resp(400, ['error' => 'Selecione ao menos XML ou DANFE para exportar.']);
    $where = "status NOT IN ('Em Digitação','Aguardando')";
    $params_e = [];
    if ($id_unico !== null) { $where .= ' AND id = ?'; $params_e[] = $id_unico; }
    if ($status_f) { $where .= ' AND status = ?'; $params_e[] = $status_f; }
    if ($dt_ini_f) { $where .= ' AND DATE(data_emissao) >= ?'; $params_e[] = $dt_ini_f; }
    if ($dt_fim_f) { $where .= ' AND DATE(data_emissao) <= ?'; $params_e[] = $dt_fim_f; }
    $stmt = $db->prepare("SELECT * FROM nfe_emitidas WHERE $where ORDER BY id DESC LIMIT 500");
    $stmt->execute($params_e);
    $notas = $stmt->fetchAll();
    if (empty($notas)) resp(404, ['error' => 'Nenhuma NF-e encontrada com os filtros informados.']);
    $storageDir = SAAS_DIR . '/storage/nfe';
    $tmpDir     = sys_get_temp_dir() . '/nfe_exp_' . uniqid();
    mkdir($tmpDir, 0755, true);
    $adicionados = 0;
    foreach ($notas as $nf) {
        $num    = (string)($nf['numero'] ?? '');
        $status = strtolower($nf['status'] ?? '');
        $subDir = ($status === 'autorizada') ? 'autorizada' : 'rejeitada';
        if ($inc_xml) {
            $xmlPath = "$storageDir/$subDir/{$num}.xml";
            if (file_exists($xmlPath)) {
                copy($xmlPath, "$tmpDir/NF-e_{$num}.xml");
                $adicionados++;
            } else {
                $xmlFallback  = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
                $xmlFallback .= '<!-- NF-e #' . $num . ' | Chave: ' . ($nf['chave_acesso'] ?? '') . ' | Status: ' . ($nf['status'] ?? '') . ' -->' . "\n";
                $xmlFallback .= '<NFe numero="' . $num . '" chave="' . ($nf['chave_acesso'] ?? '') . '" status="' . ($nf['status'] ?? '') . '" valor="' . ($nf['valor_total'] ?? 0) . '"/>';
                file_put_contents("$tmpDir/NF-e_{$num}.xml", $xmlFallback);
                $adicionados++;
            }
        }
        if ($inc_danfe) {
            $xmlPath  = "$storageDir/$subDir/{$num}.xml";
            $autoload = __DIR__ . '/nfephp/vendor/autoload.php';
            $pdfGerado = false;
            if (file_exists($xmlPath) && file_exists($autoload)) {
                try {
                    require_once $autoload;
                    if (class_exists('NFePHP\DA\NFe\Danfe')) {
                        $danfe = new \NFePHP\DA\NFe\Danfe(file_get_contents($xmlPath));
                        $pdfContent = $danfe->render();
                        file_put_contents("$tmpDir/DANFE_{$num}.pdf", $pdfContent);
                        $pdfGerado = true; $adicionados++;
                    }
                } catch (\Exception $e) { $pdfGerado = false; }
            }
            if (!$pdfGerado) error_log('nfe_exportar: nao foi possivel gerar DANFE para NF-e #' . $num);
        }
    }
    if ($adicionados === 0) {
        array_map('unlink', glob("$tmpDir/*")); rmdir($tmpDir);
        resp(404, ['error' => 'Nenhum arquivo encontrado no storage para as notas filtradas.']);
    }
    $zipPath = sys_get_temp_dir() . '/nfe_exportacao_' . date('Ymd_His') . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) resp(500, ['error' => 'Erro ao criar arquivo ZIP.']);
    foreach (glob("$tmpDir/*") as $f) { $zip->addFile($f, basename($f)); }
    $zip->close();
    array_map('unlink', glob("$tmpDir/*")); rmdir($tmpDir);
    if ($modo === 'email') {
        if (!$emails_f) resp(400, ['error' => 'E-mail não informado.']);
        // TODO: enviar e-mail com anexo ZIP
        resp(200, ['success' => true, 'total_notas' => count($notas), 'mensagem' => 'Envio de e-mail não configurado neste servidor.']);
    }
    $zipName = 'NF-e_exportacao_' . date('Ymd_His') . '.zip';
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $zipName . '"');
    header('Content-Length: ' . filesize($zipPath));
    readfile($zipPath);
    unlink($zipPath);
    exit;
}

// ── nfce_exportar — gera ZIP com XMLs e/ou DANFEs filtrados ──────────────────
if ($resource === 'nfce_exportar') {
    auth_required();

    // Parâmetros de filtro
    $status_f   = $_GET['status']      ?? '';
    $cliente_f  = $_GET['cliente_id']  ?? '';
    $dt_ini_f   = $_GET['dt_inicio']   ?? '';
    $dt_fim_f   = $_GET['dt_fim']      ?? '';
    $inc_xml    = ($_GET['xml']   ?? '0') === '1';
    $inc_danfe  = ($_GET['danfe'] ?? '0') === '1';
    $emails_f   = trim($_GET['emails'] ?? '');
    $modo       = $_GET['modo']        ?? 'download'; // 'download' | 'email'
    $id_unico   = isset($_GET['id_unico']) && is_numeric($_GET['id_unico']) ? (int)$_GET['id_unico'] : null;

    if (!$inc_xml && !$inc_danfe) {
        resp(400, ['error' => 'Selecione ao menos XML ou DANFE para exportar.']);
    }

    // Monta query com filtros
    $where = "status NOT IN ('Aguardando','Processando','Digitação','Erro')";
    $params_e = [];

    if ($id_unico !== null) { $where .= ' AND id = ?'; $params_e[] = $id_unico; }
    if ($status_f) {
        $where .= ' AND status = ?';
        $params_e[] = $status_f;
    }
    if ($cliente_f) {
        // Filtra pelo nome do cliente a partir do id informado
        $cliRow = $db->prepare("SELECT nome FROM clientes WHERE id = ?");
        $cliRow->execute([(int)$cliente_f]);
        $cliNome = $cliRow->fetchColumn();
        if ($cliNome) {
            $where .= ' AND cliente_nome = ?';
            $params_e[] = $cliNome;
        }
    }
    if ($dt_ini_f) {
        $where .= ' AND DATE(data_emissao) >= ?';
        $params_e[] = $dt_ini_f;
    }
    if ($dt_fim_f) {
        $where .= ' AND DATE(data_emissao) <= ?';
        $params_e[] = $dt_fim_f;
    }

    $stmt = $db->prepare("SELECT * FROM nfce_emitidas WHERE $where ORDER BY id DESC LIMIT 500");
    $stmt->execute($params_e);
    $notas = $stmt->fetchAll();

    if (empty($notas)) {
        resp(404, ['error' => 'Nenhuma NFC-e encontrada com os filtros informados.']);
    }

    $storageDir = SAAS_DIR . '/storage/nfce';
    $tmpDir     = sys_get_temp_dir() . '/nfce_exp_' . uniqid();
    mkdir($tmpDir, 0755, true);

    $adicionados = 0;
    foreach ($notas as $nf) {
        $num    = (string)($nf['numero'] ?? '');
        $status = strtolower($nf['status'] ?? '');
        $subDir = ($status === 'autorizada' || $status === 'aprovada') ? 'autorizada' : 'rejeitada';

        if ($inc_xml) {
            $xmlPath = "$storageDir/$subDir/{$num}.xml";
            if (file_exists($xmlPath)) {
                copy($xmlPath, "$tmpDir/NFC-e_{$num}.xml");
                $adicionados++;
            } else {
                // Fallback: XML minimo gerado a partir do payload_json
                $payload = json_decode($nf['payload_json'] ?? '{}', true);
                if ($payload) {
                    $xmlFallback  = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
                    $xmlFallback .= '<!-- NFC-e #' . $num . ' | Chave: ' . ($nf['chave_acesso'] ?? '') . ' | Status: ' . ($nf['status'] ?? '') . ' -->' . "\n";
                    $xmlFallback .= '<NFC-e numero="' . $num . '" chave="' . ($nf['chave_acesso'] ?? '') . '" status="' . ($nf['status'] ?? '') . '" valor="' . ($nf['valor_total'] ?? 0) . '"/>';
                    file_put_contents("$tmpDir/NFC-e_{$num}.xml", $xmlFallback);
                    $adicionados++;
                }
            }
        }

        if ($inc_danfe) {
            $pdfGerado = false;

            // Tenta gerar DANFE em PDF usando sped-da (NFePHP\DA\NFe\Danfce)
            $xmlPath   = "$storageDir/$subDir/{$num}.xml";
            $autoload  = __DIR__ . '/nfephp/vendor/autoload.php';
            if (file_exists($xmlPath) && file_exists($autoload)) {
                try {
                    require_once $autoload;
                    // sped-da >= 1.1: classe para NFC-e
                    if (class_exists('NFePHP\DA\NFe\Danfce')) {
                        $xmlContent = file_get_contents($xmlPath);
                        $danfce = new \NFePHP\DA\NFe\Danfce($xmlContent);
                        $pdfContent = $danfce->render();
                        file_put_contents("$tmpDir/DANFE_{$num}.pdf", $pdfContent);
                        $pdfGerado = true;
                        $adicionados++;
                    }
                } catch (\Exception $eDanfe) {
                    // falha na geracao do PDF — cai no fallback abaixo
                    $pdfGerado = false;
                }
            }

            // Fallback: gera PDF simples via FPDF (dependencia interna do sped-da)
            if (!$pdfGerado && file_exists($autoload)) {
                try {
                    require_once $autoload;
                    if (class_exists('FPDF') || class_exists('tFPDF')) {
                        $fpdf = class_exists('tFPDF') ? new \tFPDF('P', 'mm', [80, 200]) : new \FPDF('P', 'mm', [80, 200]);
                        $fpdf->AddPage();
                        $fpdf->SetFont('Arial', 'B', 10);
                        $fpdf->Cell(0, 6, 'DANFE NFC-e #' . $num, 0, 1, 'C');
                        $fpdf->SetFont('Arial', '', 7);
                        $fpdf->Cell(0, 5, 'Status: ' . ($nf['status'] ?? '-'), 0, 1);
                        $fpdf->Cell(0, 5, 'Cliente: ' . mb_substr($nf['cliente_nome'] ?? 'Consumidor Final', 0, 40), 0, 1);
                        $fpdf->Cell(0, 5, 'Emissao: ' . substr($nf['data_emissao'] ?? '-', 0, 16), 0, 1);
                        $fpdf->Cell(0, 5, 'Valor: R$ ' . number_format((float)($nf['valor_total'] ?? 0), 2, ',', '.'), 0, 1);
                        $fpdf->Ln(2);
                        $payload = json_decode($nf['payload_json'] ?? '{}', true);
                        foreach (($payload['itens'] ?? []) as $it) {
                            $linha = mb_substr($it['descricao'] ?? '', 0, 30) . ' x' . ($it['quantidade'] ?? 1) . ' R$' . number_format((float)($it['valor_total'] ?? 0), 2, ',', '.');
                            $fpdf->Cell(0, 4, $linha, 0, 1);
                        }
                        $fpdf->Ln(2);
                        $chaveFormatada = wordwrap($nf['chave_acesso'] ?? '', 11, ' ', true);
                        $fpdf->SetFont('Arial', '', 6);
                        $fpdf->MultiCell(0, 3, 'Chave: ' . $chaveFormatada, 0, 'C');
                        $pdfContent = $fpdf->Output('S');
                        file_put_contents("$tmpDir/DANFE_{$num}.pdf", $pdfContent);
                        $pdfGerado = true;
                        $adicionados++;
                    }
                } catch (\Exception $eFpdf) {
                    $pdfGerado = false;
                }
            }

            // Ultimo fallback: se nao conseguiu PDF, pula esta nota (nao gera .txt)
            if (!$pdfGerado) {
                // Registra no log mas nao interrompe a exportacao das demais notas
                error_log('nfce_exportar: nao foi possivel gerar PDF para NFC-e #' . $num);
            }
        }
    }

    if ($adicionados === 0) {
        // Limpa pasta temp
        array_map('unlink', glob("$tmpDir/*"));
        rmdir($tmpDir);
        resp(404, ['error' => 'Nenhum arquivo encontrado no storage para as notas filtradas.']);
    }

    // Item único + apenas um formato selecionado → retorna o arquivo diretamente (sem ZIP)
    if ($id_unico !== null && ($inc_xml xor $inc_danfe)) {
        $arquivos = glob("$tmpDir/*");
        if (!empty($arquivos)) {
            $arq = $arquivos[0];
            $ext = strtolower(pathinfo($arq, PATHINFO_EXTENSION));
            $ct  = $ext === 'xml' ? 'application/xml' : 'application/pdf';
            header('Content-Type: ' . $ct);
            header('Content-Disposition: attachment; filename="' . basename($arq) . '"');
            header('Content-Length: ' . filesize($arq));
            header('Cache-Control: no-cache');
            readfile($arq);
            array_map('unlink', glob("$tmpDir/*"));
            rmdir($tmpDir);
            exit;
        }
    }

    // Compacta tudo em ZIP
    $zipPath = sys_get_temp_dir() . '/nfce_exportacao_' . date('Ymd_His') . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        resp(500, ['error' => 'Erro ao criar arquivo ZIP.']);
    }
    foreach (glob("$tmpDir/*") as $f) {
        $zip->addFile($f, basename($f));
    }
    $zip->close();

    // Limpa pasta temp
    array_map('unlink', glob("$tmpDir/*"));
    rmdir($tmpDir);

    if ($modo === 'email') {
        // Envia por e-mail
        if (empty($emails_f)) {
            resp(400, ['error' => 'Informe o e-mail do destinatário para envio.']);
        }
        $destinatarios = array_filter(array_map('trim', explode(',', $emails_f)));
        $empresa       = $db->query("SELECT nome, razao_social FROM empresa_dados WHERE id=1")->fetch();
        $nomeEmp       = $empresa['nome'] ?: ($empresa['razao_social'] ?: 'ConsertaOS');
        $zipBase64     = base64_encode(file_get_contents($zipPath));
        $zipNome       = 'NFC-e_exportacao_' . date('d-m-Y') . '.zip';

        $crlf      = "\r\n";
        $boundary  = md5(uniqid());
        $headers   = 'From: ' . $nomeEmp . ' <no-reply@consertaos.com.br>' . $crlf;
        $headers  .= 'MIME-Version: 1.0' . $crlf;
        $headers  .= 'Content-Type: multipart/mixed; boundary="' . $boundary . '"' . $crlf;

        $body  = '--' . $boundary . $crlf;
        $body .= 'Content-Type: text/plain; charset=UTF-8' . $crlf . $crlf;
        $body .= 'Segue em anexo a exportacao de NFC-e gerada em ' . date('d/m/Y H:i') . '.' . $crlf;
        $body .= 'Total de arquivos: ' . $adicionados . ' | Notas: ' . count($notas) . $crlf . $crlf;
        $body .= '--' . $boundary . $crlf;
        $body .= 'Content-Type: application/zip; name="' . $zipNome . '"' . $crlf;
        $body .= 'Content-Transfer-Encoding: base64' . $crlf;
        $body .= 'Content-Disposition: attachment; filename="' . $zipNome . '"' . $crlf . $crlf;
        $body .= chunk_split($zipBase64) . $crlf;
        $body .= '--' . $boundary . '--';

        $enviados = 0;
        foreach ($destinatarios as $dest) {
            if (filter_var($dest, FILTER_VALIDATE_EMAIL)) {
                $assunto = "Exportação NFC-e — " . date('d/m/Y');
                if (mail($dest, $assunto, $body, $headers)) {
                    $enviados++;
                }
            }
        }

        @unlink($zipPath);
        resp(200, ['ok' => true, 'enviados' => $enviados, 'total_notas' => count($notas)]);
    }

    // Modo download — envia o ZIP diretamente
    $zipNome = 'NFC-e_exportacao_' . date('Ymd_His') . '.zip';
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $zipNome . '"');
    header('Content-Length: ' . filesize($zipPath));
    header('Cache-Control: no-cache');
    readfile($zipPath);
    @unlink($zipPath);
    exit;
}


// ── GET nfse_cfg — lê/salva configurações NFS-e ─────────────────────────────
if ($resource === 'nfse_cfg') {
    auth_required();
    if ($method === 'GET') {
        $r = $db->query("SELECT nfse_usuario,nfse_senha,nfse_cidade_tom,nfse_serie,nfse_ambiente,nfse_proximo_numero,nfse_usa_unidade,cnpj,razao_social,nome,ie,im,regime_tributario,cep,logradouro,numero,complemento,bairro,cidade,uf,telefone FROM empresa_dados WHERE id=1")->fetch();
        resp(200, $r ?: []);
    }
    if ($method === 'POST') {
        $fields = ['nfse_usuario','nfse_senha','nfse_cidade_tom','nfse_serie','nfse_ambiente','nfse_proximo_numero','nfse_usa_unidade'];
        $sets=[]; $vals=[];
        foreach($fields as $f){ if(isset($data[$f])){ $sets[]="$f=?"; $vals[]=$data[$f]; } }
        if(empty($sets)) resp(400,['error'=>'Nenhum campo enviado']);
        $vals[]=1;
        $db->prepare("UPDATE empresa_dados SET ".implode(',',$sets)." WHERE id=?")->execute($vals);
        resp(200,['success'=>true]);
    }
    resp(405,['error'=>'Método não permitido']);
}

// ── GET/POST/DELETE nfse — listagem, emissão e cancelamento ────────────────
if ($resource === 'nfse') {
    auth_required();

    // ── GET: listagem ou nota individual ──────────────────────────────────
    if ($method === 'GET') {
        if ($id !== null) {
            $s = $db->prepare("SELECT * FROM nfse_emitidas WHERE id=?");
            $s->execute([$id]);
            $nf = $s->fetch();
            if (!$nf) resp(404, ['error' => 'NFS-e não encontrada']);
            resp(200, $nf);
        }
        // Listagem com filtros opcionais
        $where  = '1=1';
        $params = [];
        if (!empty($_GET['status']))  { $where .= " AND status=?";  $params[] = $_GET['status']; }
        if (!empty($_GET['q'])) {
            $where .= " AND (numero LIKE ? OR cliente_nome LIKE ? OR cliente_cpfcnpj LIKE ?)";
            $q = '%'.$_GET['q'].'%';
            $params = array_merge($params, [$q, $q, $q]);
        }
        $limit = max(1, min(200, (int)($_GET['limit'] ?? 100)));
        $page  = max(1, (int)($_GET['page']  ?? 1));
        $offset = ($page - 1) * $limit;
        $s = $db->prepare("SELECT * FROM nfse_emitidas WHERE $where ORDER BY id DESC LIMIT $limit OFFSET $offset");
        $s->execute($params);
        resp(200, $s->fetchAll());
    }

    // ── POST: emitir nova NFS-e ────────────────────────────────────────────
    if ($method === 'POST' && $action === 'emitir') {
        // Valida campos mínimos
        if (empty($data['itens']) || !is_array($data['itens'])) {
            resp(400, ['error' => 'Itens da nota são obrigatórios']);
        }
        if (empty($data['valor_total']) || (float)$data['valor_total'] <= 0) {
            resp(400, ['error' => 'Valor total inválido']);
        }

        $emp = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();

        $nfseUsuario   = $emp['nfse_usuario']    ?? '';
        $nfseSenha     = $emp['nfse_senha']       ?? '';
        $nfseCidadeTom = $emp['nfse_cidade_tom']  ?? '';

        if (empty($nfseUsuario) || empty($nfseSenha)) {
            resp(400, ['error' => 'Configure o usuário e senha NFS-e em Configurações → NFS-e antes de emitir.']);
        }
        if (empty($nfseCidadeTom)) {
            resp(400, ['error' => 'Configure o Código TOM da cidade em Configurações → NFS-e antes de emitir.']);
        }

        $config = [
            'nfse_usuario'    => $nfseUsuario,
            'nfse_senha'      => $nfseSenha,
            'nfse_cidade_tom' => $nfseCidadeTom,
            'nfse_serie'      => $emp['nfse_serie']       ?? '1',
            'nfse_ambiente'   => $emp['nfse_ambiente']    ?? 'homologacao',
            'nfse_usa_unidade'=> (int)($emp['nfse_usa_unidade'] ?? 0),
            'storage_dir'     => SAAS_DIR . '/storage/nfse',
            'empresa' => [
                'cnpj'        => $emp['cnpj']         ?? '',
                'razao_social'=> $emp['razao_social']  ?? '',
                'im'          => $emp['im']            ?? '',
                'cidade_tom'  => $nfseCidadeTom,
            ],
        ];

        // Incrementa número com lock
        $db->beginTransaction();
        $numero = (int)$db->query("SELECT nfse_proximo_numero FROM empresa_dados WHERE id=1")->fetchColumn();
        $db->exec("UPDATE empresa_dados SET nfse_proximo_numero=nfse_proximo_numero+1 WHERE id=1");
        $db->commit();

        try {
            require_once __DIR__ . '/src/NfseService.php';
            $svc       = new \ConsertaOS\NfsE\NfseService($config);
            $resultado = $svc->emitir($data);

            $now          = date('Y-m-d H:i:s');
            $status       = $resultado['autorizada'] ? 'Autorizada' : 'Rejeitada';
            $clienteNome  = $data['cliente_nome']    ?? '';
            $clienteDoc   = preg_replace('/\D/', '', $data['cliente_cpfcnpj'] ?? '');

            $db->prepare("INSERT INTO nfse_emitidas
                (os_id,venda_id,status,numero,serie,codigo_verificacao,valor_total,link_pdf,motivo_rejeicao,ambiente,payload_json,cliente_nome,cliente_cpfcnpj,data_emissao,data_atualizacao)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([
                    $data['os_id']     ?? null,
                    $data['venda_id']  ?? null,
                    $status,
                    $resultado['numero']              ?? '',
                    $resultado['serie']               ?? ($emp['nfse_serie'] ?? '1'),
                    $resultado['codigo_verificacao']  ?? '',
                    $data['valor_total'],
                    $resultado['link_pdf']            ?? '',
                    $resultado['xMotivo']             ?? '',
                    $config['nfse_ambiente'],
                    json_encode($data),
                    $clienteNome,
                    $clienteDoc,
                    $now, $now,
               ]);

            $local_id = (int)$db->lastInsertId();

            // Se rejeitada, devolve o contador
            if (!$resultado['autorizada']) {
                $db->exec("UPDATE empresa_dados SET nfse_proximo_numero=nfse_proximo_numero-1 WHERE id=1");
            }
            // Gerar conta a receber apenas se autorizada
            if ($resultado['autorizada']) {
                $cli_id_nfse  = $data['cliente_id']    ?? null;
                $val_nfse     = (float)($data['valor_total'] ?? 0);
                $num_nfse     = $resultado['numero']    ?? $numero;
                $cli_nome_nfse= $data['cliente_nome']   ?? '';
                $desc_nfse    = "NFS-e #{$num_nfse} — {$cli_nome_nfse}";
                // Busca conta_bancaria_id da forma de pagamento informada
                $cb_id_nfse = null;
                $fp_id_nfse = $data['forma_pagamento_id'] ?? null;
                if ($fp_id_nfse) {
                    $fpRow = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                    $fpRow->execute([$fp_id_nfse]);
                    $fpData = $fpRow->fetch();
                    if ($fpData && !empty($fpData['conta_bancaria'])) {
                        $cbRow = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                        $cbRow->execute([$fpData['conta_bancaria']]);
                        $cb_id_nfse = $cbRow->fetchColumn() ?: null;
                    }
                }
                // Fallback: tenta via faturamentos se houver
                if (!$cb_id_nfse && !empty($data['faturamentos'])) {
                    $fp_id_fat = $data['faturamentos'][0]['forma_pagamento_id'] ?? null;
                    if ($fp_id_fat) {
                        $fpRow2 = $db->prepare("SELECT conta_bancaria FROM formas_pagamento WHERE id=?");
                        $fpRow2->execute([$fp_id_fat]);
                        $fpData2 = $fpRow2->fetch();
                        if ($fpData2 && !empty($fpData2['conta_bancaria'])) {
                            $cbRow2 = $db->prepare("SELECT id FROM contas_bancarias WHERE nome=? AND ativo=1 LIMIT 1");
                            $cbRow2->execute([$fpData2['conta_bancaria']]);
                            $cb_id_nfse = $cbRow2->fetchColumn() ?: null;
                        }
                    }
                }
                $db->prepare("INSERT INTO contas_receber (origem,venda_id,cliente_id,conta_bancaria_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,data_criacao,data_atualizacao) VALUES ('nfse',?,?,?,?,?,?,?,?,?,?,?,?)")
                   ->execute([$local_id,$cli_id_nfse,$cb_id_nfse,$desc_nfse,$val_nfse,$val_nfse,date('Y-m-d'),date('Y-m-d'),date('Y-m-d'),'Recebida',$now,$now]);
            }

            resp(200, array_merge($resultado, ['id' => $local_id, 'numero_seq' => $numero]));

        } catch (\Exception $e) {
            $db->exec("UPDATE empresa_dados SET nfse_proximo_numero=nfse_proximo_numero-1 WHERE id=1");
            resp(500, ['error' => $e->getMessage()]);
        }
    }

    // ── DELETE: cancelar NFS-e ─────────────────────────────────────────────
    if ($method === 'DELETE' && $id !== null) {
        $s = $db->prepare("SELECT * FROM nfse_emitidas WHERE id=?");
        $s->execute([$id]);
        $nf = $s->fetch();
        if (!$nf) resp(404, ['error' => 'NFS-e não encontrada']);

        $motivo = trim($data['motivo'] ?? '');
        if (strlen($motivo) < 10) resp(400, ['error' => 'Motivo do cancelamento deve ter ao menos 10 caracteres']);

        $emp    = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
        $config = [
            'nfse_usuario'    => $emp['nfse_usuario']    ?? '',
            'nfse_senha'      => $emp['nfse_senha']       ?? '',
            'nfse_cidade_tom' => $emp['nfse_cidade_tom']  ?? '',
            'nfse_serie'      => $emp['nfse_serie']       ?? '1',
            'nfse_ambiente'   => $emp['nfse_ambiente']    ?? 'homologacao',
            'storage_dir'     => SAAS_DIR . '/storage/nfse',
            'empresa' => [
                'cnpj'      => $emp['cnpj']        ?? '',
                'cidade_tom'=> $emp['nfse_cidade_tom'] ?? '',
            ],
        ];

        try {
            require_once __DIR__ . '/src/NfseService.php';
            $svc       = new \ConsertaOS\NfsE\NfseService($config);
            // Tenta cancelamento direto; se retornar erro de prazo, tenta solicitação
            $resultado = $svc->cancelar($nf['numero'], $nf['serie'], $motivo, false);

            if (!$resultado['autorizada'] && isset($resultado['codigo']) && $resultado['codigo'] !== 'CURL_ERROR') {
                // Segunda tentativa: solicitação de cancelamento
                $resultado = $svc->cancelar($nf['numero'], $nf['serie'], $motivo, true);
            }

            if ($resultado['autorizada']) {
                $db->prepare("UPDATE nfse_emitidas SET status='Cancelada', data_atualizacao=? WHERE id=?")
                   ->execute([date('Y-m-d H:i:s'), $id]);
            }

            resp(200, $resultado);

        } catch (\Exception $e) {
            resp(500, ['error' => $e->getMessage()]);
        }
    }

    resp(405, ['error' => 'Método não permitido']);
}

// ─── NFS-e UNIDADES — tabela completa de Chapadão do Lageado (relatório 10/04/2026) ───
if ($resource === 'nfse_unidades' && $method === 'GET') {
    auth_required();
    $unidades = [
        ['codigo'=>1,  'sigla'=>'PTO',      'descricao'=>'PONTO'],
        ['codigo'=>2,  'sigla'=>'AMP',      'descricao'=>'AMPOLAS'],
        ['codigo'=>3,  'sigla'=>'B',        'descricao'=>'BARRAS'],
        ['codigo'=>4,  'sigla'=>'BDJ',      'descricao'=>'BANDEIJA'],
        ['codigo'=>5,  'sigla'=>'BLD',      'descricao'=>'BALDE'],
        ['codigo'=>6,  'sigla'=>'BLO',      'descricao'=>'BLOCOS'],
        ['codigo'=>7,  'sigla'=>'BSN',      'descricao'=>'BISNAGA'],
        ['codigo'=>8,  'sigla'=>'CAPS',     'descricao'=>'CAPSULAS'],
        ['codigo'=>9,  'sigla'=>'CART',     'descricao'=>'CARTELAS'],
        ['codigo'=>10, 'sigla'=>'CJ',       'descricao'=>'CONJUNTO'],
        ['codigo'=>11, 'sigla'=>'CM/C',     'descricao'=>'CENTÍMETRO/COLUNA'],
        ['codigo'=>12, 'sigla'=>'CM²',      'descricao'=>'CENTIMETRO QUADRADO'],
        ['codigo'=>13, 'sigla'=>'COL',      'descricao'=>'COLEÇÃO'],
        ['codigo'=>14, 'sigla'=>'COMP',     'descricao'=>'COMPRIMIDO'],
        ['codigo'=>15, 'sigla'=>'CON',      'descricao'=>'CONSULTA'],
        ['codigo'=>16, 'sigla'=>'CR',       'descricao'=>'CARGA'],
        ['codigo'=>17, 'sigla'=>'CX',       'descricao'=>'CAIXA'],
        ['codigo'=>18, 'sigla'=>'DIA',      'descricao'=>'DIA'],
        ['codigo'=>19, 'sigla'=>'DR',       'descricao'=>'DIARIA'],
        ['codigo'=>20, 'sigla'=>'DZ',       'descricao'=>'DUZIAS'],
        ['codigo'=>21, 'sigla'=>'ENV',      'descricao'=>'ENVELOPE'],
        ['codigo'=>22, 'sigla'=>'EPG',      'descricao'=>'ESPIGA'],
        ['codigo'=>23, 'sigla'=>'EXE.',     'descricao'=>'EXEMPLARES'],
        ['codigo'=>24, 'sigla'=>'FLS',      'descricao'=>'FOLHAS'],
        ['codigo'=>25, 'sigla'=>'FRD',      'descricao'=>'FARDO'],
        ['codigo'=>26, 'sigla'=>'FRS',      'descricao'=>'FRASCO'],
        ['codigo'=>27, 'sigla'=>'FX',       'descricao'=>'FEIXE'],
        ['codigo'=>28, 'sigla'=>'GL',       'descricao'=>'GALÃO'],
        ['codigo'=>29, 'sigla'=>'GR',       'descricao'=>'GRAMAS'],
        ['codigo'=>30, 'sigla'=>'HR',       'descricao'=>'HORAS'],
        ['codigo'=>31, 'sigla'=>'JG',       'descricao'=>'JOGOS'],
        ['codigo'=>32, 'sigla'=>'KG',       'descricao'=>'KILOGRAMA'],
        ['codigo'=>33, 'sigla'=>'KIT',      'descricao'=>'KIT'],
        ['codigo'=>34, 'sigla'=>'KM',       'descricao'=>'KILOMETRO'],
        ['codigo'=>35, 'sigla'=>'KM/DI',    'descricao'=>'KILOMETRO/DIA'],
        ['codigo'=>36, 'sigla'=>'LT',       'descricao'=>'LITRO'],
        ['codigo'=>37, 'sigla'=>'LTA',      'descricao'=>'LATA'],
        ['codigo'=>38, 'sigla'=>'MLH',      'descricao'=>'MILHEIRO'],
        ['codigo'=>39, 'sigla'=>'MT',       'descricao'=>'METRO'],
        ['codigo'=>40, 'sigla'=>'M²',       'descricao'=>'METRO QUADRADO'],
        ['codigo'=>41, 'sigla'=>'M³',       'descricao'=>'METRO CUBICO'],
        ['codigo'=>42, 'sigla'=>'MÇS',      'descricao'=>'MAÇOS'],
        ['codigo'=>43, 'sigla'=>'MÊS',      'descricao'=>'MÊS'],
        ['codigo'=>44, 'sigla'=>'P',        'descricao'=>'PERÍODO'],
        ['codigo'=>45, 'sigla'=>'PARES',    'descricao'=>'PARES'],
        ['codigo'=>46, 'sigla'=>'PART.',    'descricao'=>'PARTIDA'],
        ['codigo'=>47, 'sigla'=>'PCT',      'descricao'=>'PACOTE'],
        ['codigo'=>48, 'sigla'=>'PG',       'descricao'=>'PÁGINA'],
        ['codigo'=>49, 'sigla'=>'PT',       'descricao'=>'POTE'],
        ['codigo'=>50, 'sigla'=>'PÁ',       'descricao'=>'PÁ'],
        ['codigo'=>51, 'sigla'=>'PÇ',       'descricao'=>'PEÇA'],
        ['codigo'=>52, 'sigla'=>'RL',       'descricao'=>'ROLO'],
        ['codigo'=>53, 'sigla'=>'RS',       'descricao'=>'RESMA'],
        ['codigo'=>54, 'sigla'=>'SC',       'descricao'=>'SACA'],
        ['codigo'=>55, 'sigla'=>'SERV',     'descricao'=>'SERVIÇO'],
        ['codigo'=>56, 'sigla'=>'SM',       'descricao'=>'SEMANAL'],
        ['codigo'=>57, 'sigla'=>'TB',       'descricao'=>'TUBO'],
        ['codigo'=>58, 'sigla'=>'TBR',      'descricao'=>'TAMBOR'],
        ['codigo'=>59, 'sigla'=>'TON',      'descricao'=>'TONELADA'],
        ['codigo'=>60, 'sigla'=>'TR',       'descricao'=>'TIRAS'],
        ['codigo'=>61, 'sigla'=>'FCNT',     'descricao'=>'FLACONETE'],
        ['codigo'=>62, 'sigla'=>'SA',       'descricao'=>'SACHE'],
        ['codigo'=>63, 'sigla'=>'SS',       'descricao'=>'SESSÃO'],
        ['codigo'=>64, 'sigla'=>'UN',       'descricao'=>'UNIDADE'],
        ['codigo'=>71, 'sigla'=>'UNI',      'descricao'=>'UNIDADE INSERIDA'],
        ['codigo'=>72, 'sigla'=>'CX AMP',   'descricao'=>'CAIXA COM 4 AMPOLAS'],
        ['codigo'=>73, 'sigla'=>'LOCAÇÃO',  'descricao'=>'LOCAÇÃO'],
        ['codigo'=>75, 'sigla'=>'PESSOAS',  'descricao'=>'PESSOAS'],
        ['codigo'=>76, 'sigla'=>'resma',    'descricao'=>'Resma'],
        ['codigo'=>80, 'sigla'=>'UN.',      'descricao'=>'IMPLEMENTO'],
        ['codigo'=>81, 'sigla'=>'aux',      'descricao'=>'Auxílio'],
        ['codigo'=>82, 'sigla'=>'HA',       'descricao'=>'HECTARE'],
        ['codigo'=>83, 'sigla'=>'1',        'descricao'=>'item'],
        ['codigo'=>84, 'sigla'=>'VB',       'descricao'=>'Verba'],
        ['codigo'=>85, 'sigla'=>'M³xKM',    'descricao'=>'Metro cubico x Quilometro rodado'],
        ['codigo'=>86, 'sigla'=>'M',        'descricao'=>'METRO'],
        ['codigo'=>88, 'sigla'=>'vidro',    'descricao'=>'Vidro'],
        ['codigo'=>89, 'sigla'=>'PACOTE',   'descricao'=>'PACOTE COM 12 UNIDADES'],
        ['codigo'=>90, 'sigla'=>'KM/Rod',   'descricao'=>'Quilometro rodado'],
        ['codigo'=>91, 'sigla'=>'GRF',      'descricao'=>'GARRAFA'],
        ['codigo'=>92, 'sigla'=>'CJDIA',    'descricao'=>'CJDIA'],
        ['codigo'=>93, 'sigla'=>'saco',     'descricao'=>'saco'],
        ['codigo'=>94, 'sigla'=>'EMB',      'descricao'=>'Embalagem'],
        ['codigo'=>95, 'sigla'=>'TKM',      'descricao'=>'TONELADA KILOMETRO'],
    ];
    resp(200, $unidades);
}

// ─────────────────────────────────────────────────────────────────────────────
// IDENTIFICAR APARELHO VIA GEMINI AI
// POST api.php?resource=identificar_aparelho
// Body JSON: { "imagem_base64": "...", "mime_type": "image/jpeg" }
// ─────────────────────────────────────────────────────────────────────────────
// ─── LOJA VIRTUAL: PUBLICAR ──────────────────────────────────────────────────
// GET  → retorna status (slug configurado, arquivo publicado)
// POST → cria/atualiza o index.php em /public_html/minhaloja/{slug}/
if ($resource === 'publicar_loja') {
    auth_required();

    $emp  = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
    $slug = trim($emp['loja_slug'] ?? '');

    if ($method === 'GET') {
        if (!$slug) {
            resp(200, ['slug' => '', 'publicada' => false, 'msg' => 'Nenhum link configurado.']);
        }
        $storeDir  = dirname(dirname(__DIR__)) . '/minhaloja/' . $slug;
        $indexFile = $storeDir . '/index.php';
        resp(200, [
            'slug'       => $slug,
            'publicada'  => file_exists($indexFile),
            'store_dir'  => $storeDir,
        ]);
    }

    if ($method === 'POST') {
        if (!$slug) {
            resp(400, ['error' => 'Configure e salve o link da loja antes de publicar.']);
        }

        $storeDir  = dirname(dirname(__DIR__)) . '/minhaloja/' . $slug;
        $indexFile = $storeDir . '/index.php';

        // Cria a pasta se não existir
        if (!is_dir($storeDir)) {
            if (!@mkdir($storeDir, 0755, true)) {
                resp(500, ['error' => 'Não foi possível criar a pasta da loja: ' . $storeDir . '. Verifique as permissões do servidor.']);
            }
        }

        if (!is_writable($storeDir)) {
            resp(500, ['error' => 'Sem permissão de escrita em: ' . $storeDir]);
        }

        // Gera o index.php da loja (invalida OPcache para garantir versão atualizada)
        $tplFile = __DIR__ . '/src/LojaTemplate.php';
        if (!file_exists($tplFile)) {
            resp(500, ['error' => 'Arquivo de template não encontrado no servidor: ' . $tplFile . '. Envie o arquivo src/LojaTemplate.php para o servidor.']);
        }
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($tplFile, true);
        }
        ob_start();
        require_once $tplFile;
        ob_end_clean();
        $phpContent = LojaTemplate::generate($db_path);

        if (file_put_contents($indexFile, $phpContent) === false) {
            resp(500, ['error' => 'Erro ao escrever o arquivo da loja em: ' . $indexFile]);
        }

        resp(200, [
            'success'   => true,
            'slug'      => $slug,
            'store_dir' => $storeDir,
            'msg'       => 'Loja publicada com sucesso em ' . $storeDir,
        ]);
    }
}

if ($resource === 'identificar_aparelho' && $method === 'POST') {
    auth_required();

    // ⚠️  COLOQUE SUA CHAVE AQUI (copie do Google AI Studio)
    $gemini_api_key = defined('GEMINI_API_KEY') ? GEMINI_API_KEY : '';

    $imagem_base64 = trim($data['imagem_base64'] ?? '');
    $mime_type     = trim($data['mime_type']     ?? 'image/jpeg');

    if ($imagem_base64 === '') {
        resp(400, ['success' => false, 'error' => 'Imagem não recebida.']);
    }

    // Tipos MIME permitidos
    $mimes_permitidos = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
    if (!in_array(strtolower($mime_type), $mimes_permitidos)) {
        resp(400, ['success' => false, 'error' => 'Tipo de imagem não suportado: ' . $mime_type]);
    }

    // ── Lista de modelos em ordem de preferência (fallback automático) ──────────
    // Se o primeiro estiver sobrecarregado ou indisponível, tenta o próximo.
    $modelos_fallback = [
        'gemini-3.1-flash-lite-preview',  // Maior cota — 500 RPD grátis
        'gemini-3-flash-preview',          // Fallback 1 — 20 RPD grátis
        'gemini-2.5-flash',                // Fallback 2 — 20 RPD grátis
    ];

    $prompt = <<<PROMPT
Você é um especialista em identificação de aparelhos eletrônicos.
Analise esta imagem e identifique o modelo do celular/smartphone.

Responda APENAS com um objeto JSON válido, sem nenhum texto antes ou depois, sem blocos de código markdown.

Formato exato:
{"marca":"Samsung","modelo":"Galaxy A54 5G","confianca":"alta","observacoes":"Logotipo Samsung camera tripla"}

Regras:
- "marca": nome da fabricante (Samsung, Apple, Motorola, Xiaomi, etc). null se não identificado.
- "modelo": modelo específico do aparelho. null se não identificado.
- "confianca": "alta" se tem certeza, "media" se razoavelmente certo, "baixa" se incerto.
- "observacoes": explicação curtíssima, máximo 40 caracteres, sem vírgulas nem pontuação especial.
- Se não for um celular/smartphone, retorne: {"marca":null,"modelo":null,"confianca":"baixa","observacoes":"Imagem nao parece ser celular"}
PROMPT;

    // Função auxiliar: verifica se um erro indica sobrecarga/indisponibilidade
    $eh_erro_transitorio = function(int $code, string $raw): bool {
        if ($code === 503 || $code === 429) return true;
        if ($raw === '') return false;
        $dec = json_decode($raw, true);
        $msg = strtolower($dec['error']['message'] ?? '');
        return (
            str_contains($msg, 'high demand')   ||
            str_contains($msg, 'overloaded')     ||
            str_contains($msg, 'try again')      ||
            str_contains($msg, 'unavailable')    ||
            str_contains($msg, 'not found')      ||
            str_contains($msg, 'not supported')  ||
            str_contains($msg, 'quota')
        );
    };

    $response_raw     = '';
    $http_code        = 0;
    $curl_error       = '';
    $modelo_usado     = '';
    $sucesso          = false;

    foreach ($modelos_fallback as $modelo) {
        $url_modelo = "https://generativelanguage.googleapis.com/v1beta/models/{$modelo}:generateContent?key={$gemini_api_key}";

        $payload = [
            'contents' => [[
                'parts' => [
                    [
                        'inline_data' => [
                            'mime_type' => $mime_type,
                            'data'      => $imagem_base64,
                        ]
                    ],
                    ['text' => $prompt]
                ]
            ]],
            'generationConfig' => [
                'temperature'     => 0.1,
                'maxOutputTokens' => 2048,
            ]
        ];

        // Tenta 2 vezes por modelo antes de passar para o próximo
        for ($t = 1; $t <= 2; $t++) {
            $ch = curl_init($url_modelo);
            $_gemini_cainfo = ssl_cainfo();
            $curl_opts_gemini = [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
                CURLOPT_TIMEOUT        => 45,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ];
            if ($_gemini_cainfo) $curl_opts_gemini[CURLOPT_CAINFO] = $_gemini_cainfo;
            curl_setopt_array($ch, $curl_opts_gemini);

            $response_raw = curl_exec($ch);
            $http_code    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curl_error   = curl_error($ch);
            curl_close($ch);

            if (!$curl_error && $http_code === 200) {
                $modelo_usado = $modelo;
                $sucesso      = true;
                break 2; // sai do loop de tentativas E do loop de modelos
            }

            // Se não é erro transitório, não adianta tentar de novo nem trocar de modelo
            if (!$eh_erro_transitorio($http_code, (string)$response_raw)) break;

            // Pequena pausa antes de tentar novamente no mesmo modelo
            if ($t < 2) sleep(2);
        }

        // Se chegou aqui, esse modelo falhou — tenta o próximo sem pausa extra
    }

    if ($curl_error) {
        resp(500, ['success' => false, 'error' => 'Erro de conexão com Gemini: ' . $curl_error]);
    }

    if (!$sucesso) {
        $detalhe = json_decode((string)$response_raw, true);
        $msg = $detalhe['error']['message'] ?? 'Erro HTTP ' . $http_code;
        resp(500, ['success' => false, 'error' => 'Todos os modelos de IA estão indisponíveis no momento. Tente novamente em alguns instantes. (Detalhe: ' . mb_substr($msg, 0, 120) . ')']);
    }

    $response_data = json_decode($response_raw, true);
    $texto_gemini  = $response_data['candidates'][0]['content']['parts'][0]['text'] ?? null;

    if (!$texto_gemini) {
        resp(500, ['success' => false, 'error' => 'Resposta vazia do Gemini.']);
    }

    // O Gemini 2.5 retorna texto de pensamento antes do JSON em alguns casos.
    // Tenta varios metodos de extracao em ordem.
    $texto_limpo = trim($texto_gemini);

    // 1) Remove blocos markdown ```json ... ```
    $sem_md = preg_replace('/```(?:json)?\s*([\s\S]*?)```/i', '$1', $texto_limpo);
    $sem_md = trim($sem_md !== null ? $sem_md : $texto_limpo);

    // 2) Tenta decodificar apos remover markdown
    $resultado = json_decode($sem_md, true);

    // 3) Se ainda falhou, extrai o primeiro { ... } do texto bruto
    if (json_last_error() !== JSON_ERROR_NONE) {
        if (preg_match('/\{[\s\S]*\}/u', $texto_limpo, $matches)) {
            $resultado = json_decode($matches[0], true);
        }
    }

    if (json_last_error() !== JSON_ERROR_NONE || !is_array($resultado)) {
        resp(500, ['success' => false, 'error' => 'Resposta invalida. Recebido: ' . mb_substr($texto_gemini, 0, 400)]);
    }

    resp(200, ['success' => true, 'dados' => $resultado, 'modelo' => $modelo_usado]);
}

// ─── NF-e: lista de CFOPs ────────────────────────────────────────────────────
if ($resource === 'nfe_cfop') {
    require_once __DIR__ . '/src/NfeService.php';
    resp(200, \ConsertaOS\NFe\NfeService::listaCfops());
}

// ─── NF-e: configuração (empresa_dados) ─────────────────────────────────────
if ($resource === 'nfe_cfg') {
    auth_required();
    if ($method === 'GET') {
        $emp = $db->query("SELECT nfe_ambiente, nfe_serie, nfe_proximo_numero FROM empresa_dados WHERE id=1")->fetch();
        resp(200, $emp ?: []);
    }
    if ($method === 'POST') {
        $fields = ['nfe_ambiente', 'nfe_serie', 'nfe_proximo_numero'];
        $sets   = implode(',', array_map(fn($f) => "$f=?", $fields));
        $vals   = array_map(fn($f) => $data[$f] ?? '', $fields);
        $vals[] = 1;
        $db->prepare("UPDATE empresa_dados SET $sets WHERE id=?")->execute($vals);
        resp(200, ['success' => true]);
    }
    resp(405, ['error' => 'Método não permitido']);
}

// ─── NF-e (modelo 55): emissão via NFePHP ───────────────────────────────────
if ($resource === 'nfe') {
    auth_required();
    $emp      = $db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
    $autoload = __DIR__ . '/nfephp/vendor/autoload.php';
    $nfephp_ok = file_exists($autoload);

    // ── GET: gerar DANFE PDF de NF-e ──────────────────────────────────────
    if ($method === 'GET' && !empty($_GET['action']) && $_GET['action'] === 'danfe_pdf') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado.']);
        $nfe_id = (int)($_GET['id'] ?? 0);
        if (!$nfe_id) resp(400, ['error' => 'ID não informado.']);
        $s = $db->prepare("SELECT * FROM nfe_emitidas WHERE id=?");
        $s->execute([$nfe_id]);
        $nf = $s->fetch();
        if (!$nf) resp(404, ['error' => 'NF-e não encontrada.']);
        $num = (string)($nf['numero'] ?? '');
        $storageDir = SAAS_DIR . '/storage/nfe';
        $xmlPath = null;
        foreach (['autorizada', 'rejeitada', 'enviados'] as $sub) {
            $p = "$storageDir/$sub/{$num}.xml";
            if (file_exists($p)) { $xmlPath = $p; break; }
        }
        if (!$xmlPath) resp(404, ['error' => 'XML da NF-e não encontrado no storage. A nota pode ter sido emitida antes do armazenamento local estar configurado.']);
        try {
            require_once $autoload;
            $xmlContent = file_get_contents($xmlPath);
            $danfe = new \NFePHP\DA\NFe\Danfe($xmlContent);
            $pdf = $danfe->render();
            header('Content-Type: application/pdf');
            header('Content-Disposition: inline; filename="DANFE_NF-e_' . $num . '.pdf"');
            header('Content-Length: ' . strlen($pdf));
            echo $pdf;
            exit;
        } catch (\Throwable $e) {
            resp(500, ['error' => 'Erro ao gerar DANFE: ' . $e->getMessage()]);
        }
    }

    // ── GET: listar NF-e emitidas ──────────────────────────────────────────
    if ($method === 'GET' && $id === null) {
        $where = '1=1'; $params_n = [];
        if (!empty($_GET['os_id']))    { $where .= ' AND os_id=?';    $params_n[] = (int)$_GET['os_id']; }
        if (!empty($_GET['venda_id'])) { $where .= ' AND venda_id=?'; $params_n[] = (int)$_GET['venda_id']; }
        if (!empty($_GET['status']))   { $where .= ' AND status=?';   $params_n[] = $_GET['status']; }
        if (!empty($_GET['q'])) {
            $q = '%' . $_GET['q'] . '%';
            $where .= ' AND (numero LIKE ? OR chave_acesso LIKE ? OR dest_nome LIKE ?)';
            $params_n[] = $q; $params_n[] = $q; $params_n[] = $q;
        }
        $limit = min((int)($_GET['limit'] ?? 100), 200);
        $s = $db->prepare("SELECT * FROM nfe_emitidas WHERE $where ORDER BY id DESC LIMIT $limit");
        $s->execute($params_n);
        resp(200, $s->fetchAll());
    }

    // ── GET: buscar NF-e por ID ────────────────────────────────────────────
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM nfe_emitidas WHERE id=?");
        $s->execute([$id]);
        $nf = $s->fetch();
        resp($nf ? 200 : 404, $nf ?: ['error' => 'NF-e não encontrada']);
    }

    // ── POST: cancelar NF-e ────────────────────────────────────────────────
    if ($method === 'POST' && ($data['action'] ?? '') === 'cancelar_nfe') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado. Acesse /instalar_nfephp.php']);
        $nfe_id = (int)($data['id'] ?? 0);
        $just   = trim($data['justificativa'] ?? '');
        if (!$nfe_id) resp(400, ['error' => 'ID da NF-e não informado.']);
        if (strlen($just) < 15) resp(400, ['error' => 'Justificativa deve ter no mínimo 15 caracteres.']);
        $s = $db->prepare("SELECT * FROM nfe_emitidas WHERE id=?");
        $s->execute([$nfe_id]);
        $nf = $s->fetch();
        if (!$nf) resp(404, ['error' => 'NF-e não encontrada.']);
        if ($nf['status'] !== 'Autorizada') resp(400, ['error' => 'Apenas NF-e autorizadas podem ser canceladas.']);
        if (empty($nf['n_prot'])) resp(400, ['error' => 'Protocolo de autorização não encontrado.']);
        $cert_senha = trim($data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? ''));
        if (!$cert_senha) resp(400, ['error' => 'Senha do certificado não informada.']);
        require_once $autoload;
        require_once __DIR__ . '/src/NfeService.php';
        $config = [
            'ambiente'          => $emp['nfe_ambiente'] ?? 'homologacao',
            'certificado_pfx'   => $emp['certificado_pfx'] ?? '',
            'certificado_senha' => $cert_senha,
            'storage_dir'       => __DIR__ . '/storage/nfe',
            'empresa' => [
                'cnpj'         => $emp['cnpj']         ?? '',
                'razao_social' => $emp['razao_social']  ?? '',
                'nome_fantasia'=> $emp['nome']          ?? '',
                'ie'           => $emp['ie']            ?? '',
                'cMun'         => $emp['nfce_cmun']     ?? '',
                'cUF'          => $emp['nfce_cuf']      ?? '42',
                'uf'           => $emp['uf']            ?? 'SC',
                'logradouro'   => $emp['logradouro']    ?? '',
                'numero'       => $emp['numero']        ?? '',
                'bairro'       => $emp['bairro']        ?? '',
                'cidade'       => $emp['cidade']        ?? '',
                'cep'          => $emp['cep']           ?? '',
                'telefone'     => $emp['telefone']      ?? '',
            ],
        ];
        try {
            $svc = new \ConsertaOS\NFe\NfeService($config);
            $ret = $svc->cancelar($nf['chave_acesso'], $just, $nf['n_prot']);
        } catch (\Throwable $e) {
            resp(500, ['error' => $e->getMessage()]);
        }
        if ($ret['autorizada']) {
            $db->prepare("UPDATE nfe_emitidas SET status='Cancelada', motivo_rejeicao=?, n_prot=?, data_atualizacao=? WHERE id=?")
               ->execute([$ret['xMotivo'], $ret['nProt'] ?: $nf['n_prot'], date('Y-m-d H:i:s'), $nfe_id]);
        }
        resp($ret['autorizada'] ? 200 : 400, $ret);
    }

    // ── POST: consultar NF-e na SEFAZ ─────────────────────────────────────
    if ($method === 'POST' && ($data['action'] ?? '') === 'consultar_nfe') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado.']);
        $nfe_id = (int)($data['id'] ?? 0);
        if (!$nfe_id) resp(400, ['error' => 'ID da NF-e não informado.']);
        $s = $db->prepare("SELECT * FROM nfe_emitidas WHERE id=?");
        $s->execute([$nfe_id]);
        $nf = $s->fetch();
        if (!$nf) resp(404, ['error' => 'NF-e não encontrada.']);
        if (empty($nf['chave_acesso'])) resp(400, ['error' => 'NF-e sem chave de acesso registrada.']);
        $cert_senha = trim($data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? ''));
        if (!$cert_senha) resp(400, ['error' => 'Senha do certificado não informada.']);
        require_once $autoload;
        require_once __DIR__ . '/src/NfeService.php';
        $config = [
            'ambiente'          => $emp['nfe_ambiente'] ?? 'homologacao',
            'certificado_pfx'   => $emp['certificado_pfx'] ?? '',
            'certificado_senha' => $cert_senha,
            'storage_dir'       => __DIR__ . '/storage/nfe',
            'empresa' => [
                'cnpj'         => $emp['cnpj']         ?? '',
                'razao_social' => $emp['razao_social']  ?? '',
                'nome_fantasia'=> $emp['nome']          ?? '',
                'ie'           => $emp['ie']            ?? '',
                'cMun'         => $emp['nfce_cmun']     ?? '',
                'cUF'          => $emp['nfce_cuf']      ?? '42',
                'uf'           => $emp['uf']            ?? 'SC',
                'logradouro'   => $emp['logradouro']    ?? '',
                'numero'       => $emp['numero']        ?? '',
                'bairro'       => $emp['bairro']        ?? '',
                'cidade'       => $emp['cidade']        ?? '',
                'cep'          => $emp['cep']           ?? '',
                'telefone'     => $emp['telefone']      ?? '',
            ],
        ];
        try {
            $svc = new \ConsertaOS\NFe\NfeService($config);
            $ret = $svc->consultar($nf['chave_acesso']);
        } catch (\Throwable $e) {
            resp(500, ['error' => $e->getMessage()]);
        }
        // Atualiza status local se a SEFAZ retornou estado diferente
        if (!empty($ret['cStat'])) {
            $novoStatus = null;
            if (in_array($ret['cStat'], ['100','150'])) $novoStatus = 'Autorizada';
            elseif ($ret['cStat'] === '101') $novoStatus = 'Cancelada';
            elseif ($ret['cStat'] === '110') $novoStatus = 'Denegada';
            if ($novoStatus && $novoStatus !== $nf['status']) {
                $db->prepare("UPDATE nfe_emitidas SET status=?, data_atualizacao=? WHERE id=?")
                   ->execute([$novoStatus, date('Y-m-d H:i:s'), $nfe_id]);
            }
        }
        resp(200, $ret);
    }

    // ── POST: inutilizar numeração NF-e ──────────────────────────────────
    if ($method === 'POST' && ($data['action'] ?? '') === 'inutilizar_nfe') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado.']);
        $nIni  = (int)($data['n_ini'] ?? 0);
        $nFim  = (int)($data['n_fim'] ?? $nIni);
        $serie = (int)($data['serie'] ?? 1);
        $just  = trim($data['justificativa'] ?? '');
        $cert_senha = trim($data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? ''));
        if (!$nIni)            resp(400, ['error' => 'Número inicial inválido.']);
        if ($nFim < $nIni)     resp(400, ['error' => 'Número final deve ser >= número inicial.']);
        if (strlen($just) < 15) resp(400, ['error' => 'Justificativa muito curta (mínimo 15 caracteres).']);
        if (!$cert_senha)      resp(400, ['error' => 'Senha do certificado não informada.']);
        require_once $autoload;
        require_once __DIR__ . '/src/NfeService.php';
        $config = [
            'ambiente'          => $emp['nfe_ambiente'] ?? 'homologacao',
            'certificado_pfx'   => $emp['certificado_pfx'] ?? '',
            'certificado_senha' => $cert_senha,
            'storage_dir'       => __DIR__ . '/storage/nfe',
            'empresa' => [
                'cnpj'         => $emp['cnpj']         ?? '',
                'razao_social' => $emp['razao_social']  ?? '',
                'nome_fantasia'=> $emp['nome']          ?? '',
                'ie'           => $emp['ie']            ?? '',
                'cMun'         => $emp['nfce_cmun']     ?? '',
                'cUF'          => $emp['nfce_cuf']      ?? '42',
                'uf'           => $emp['uf']            ?? 'SC',
                'logradouro'   => $emp['logradouro']    ?? '',
                'numero'       => $emp['numero']        ?? '',
                'bairro'       => $emp['bairro']        ?? '',
                'cidade'       => $emp['cidade']        ?? '',
                'cep'          => $emp['cep']           ?? '',
                'telefone'     => $emp['telefone']      ?? '',
            ],
        ];
        try {
            $svc = new \ConsertaOS\NFe\NfeService($config);
            $ret = $svc->inutilizar($serie, $nIni, $nFim, $just);
        } catch (\Throwable $e) {
            resp(500, ['error' => $e->getMessage()]);
        }
        resp($ret['inutilizado'] ? 200 : 422, $ret);
    }

    // ── POST: salvar rascunho de NF-e ─────────────────────────────────────
    if ($method === 'POST' && ($data['action'] ?? '') === 'salvar_rascunho') {
        $id_rascunho   = (int)($data['id'] ?? 0);
        $natop         = trim($data['natop']     ?? 'VENDA DE MERCADORIA');
        $dest_nome     = trim($data['dest_nome'] ?? '');
        $valor_total   = (float)($data['valor_total'] ?? 0);
        $rascunho_json = $data['rascunho_dados'] ?? '';
        $agora         = date('Y-m-d H:i:s');
        if ($id_rascunho > 0) {
            $chk = $db->prepare("SELECT id FROM nfe_emitidas WHERE id=? AND status='Em Digitação'");
            $chk->execute([$id_rascunho]);
            if ($chk->fetch()) {
                $db->prepare("UPDATE nfe_emitidas SET natop=?,dest_nome=?,valor_total=?,rascunho_dados=?,data_atualizacao=? WHERE id=?")
                   ->execute([$natop,$dest_nome,$valor_total,$rascunho_json,$agora,$id_rascunho]);
                resp(200, ['success'=>true,'id'=>$id_rascunho]);
            }
        }
        $db->prepare("INSERT INTO nfe_emitidas (status,natop,dest_nome,valor_total,rascunho_dados,data_emissao,data_atualizacao) VALUES (?,?,?,?,?,?,?)")
           ->execute(['Em Digitação',$natop,$dest_nome,$valor_total,$rascunho_json,$agora,$agora]);
        resp(201, ['success'=>true,'id'=>(int)$db->lastInsertId()]);
    }

    // ── POST: emitir NF-e ──────────────────────────────────────────────────
    if ($method === 'POST') {
        if (!$nfephp_ok) resp(400, ['error' => 'NFePHP não instalado. Acesse /instalar_nfephp.php']);
        $cert_senha = trim($data['cert_senha'] ?? ($emp['nfce_cert_senha'] ?? ''));
        if (!$cert_senha) resp(400, ['error' => 'Senha do certificado não informada.']);
        if (empty($data['itens'])) resp(400, ['error' => 'Pelo menos um item é obrigatório.']);

        // Usa próximo número salvo e incrementa
        $numero = (int)($emp['nfe_proximo_numero'] ?? 1);
        $serie  = (int)($emp['nfe_serie'] ?? 1);
        $data['numero'] = $numero;
        $data['serie']  = $serie;

        require_once $autoload;
        require_once __DIR__ . '/src/NfeService.php';
        $config = [
            'ambiente'          => $emp['nfe_ambiente'] ?? 'homologacao',
            'certificado_pfx'   => $emp['certificado_pfx'] ?? '',
            'certificado_senha' => $cert_senha,
            'storage_dir'       => __DIR__ . '/storage/nfe',
            'empresa' => [
                'cnpj'         => $emp['cnpj']         ?? '',
                'razao_social' => $emp['razao_social']  ?? '',
                'nome_fantasia'=> $emp['nome']          ?? '',
                'ie'           => $emp['ie']            ?? '',
                'cMun'         => $emp['nfce_cmun']     ?? '',
                'cUF'          => $emp['nfce_cuf']      ?? '42',
                'uf'           => $emp['uf']            ?? 'SC',
                'logradouro'   => $emp['logradouro']    ?? '',
                'numero'       => $emp['numero']        ?? '',
                'bairro'       => $emp['bairro']        ?? '',
                'cidade'       => $emp['cidade']        ?? '',
                'cep'          => $emp['cep']           ?? '',
                'telefone'     => $emp['telefone']      ?? '',
            ],
        ];

        try {
            $svc = new \ConsertaOS\NFe\NfeService($config);
            $ret = $svc->emitir($data);
        } catch (\Throwable $e) {
            resp(500, ['error' => $e->getMessage()]);
        }

        // Resolve destinatário para gravar no banco
        $destDoc = preg_replace('/\D/', '', $data['dest_cnpj'] ?? $data['dest_cpf'] ?? '');
        $destNome = mb_strtoupper(trim($data['dest_nome'] ?? 'CONSUMIDOR'));
        $destUF   = strtoupper($data['dest_uf'] ?? '');

        // Grava no banco
        $status = $ret['autorizada'] ? 'Autorizada' : 'Rejeitada';
        $db->prepare("INSERT INTO nfe_emitidas
            (os_id, venda_id, n_prot, status, numero, serie, chave_acesso, valor_total,
             motivo_rejeicao, ambiente, payload_json, dest_nome, dest_cpfcnpj, dest_uf, natop, data_emissao, data_atualizacao)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([
               (int)($data['os_id']    ?? 0),
               (int)($data['venda_id'] ?? 0),
               $ret['nProt']   ?? '',
               $status,
               $numero,
               $serie,
               $ret['chave']   ?? '',
               (float)($data['valor_total'] ?? 0),
               $ret['xMotivo'] ?? '',
               $emp['nfe_ambiente'] ?? 'homologacao',
               json_encode($data),
               $destNome,
               $destDoc,
               $destUF,
               $data['natop'] ?? 'VENDA DE MERCADORIA',
               date('Y-m-d H:i:s'),
               date('Y-m-d H:i:s'),
           ]);
        $nfe_id = (int)$db->lastInsertId();

        // Remove rascunho "Em Digitação" correspondente (evita duplicação na listagem)
        $rascunho_id = (int)($data['rascunho_id'] ?? 0);
        if ($rascunho_id > 0) {
            $db->prepare("DELETE FROM nfe_emitidas WHERE id=? AND status='Em Digitação'")->execute([$rascunho_id]);
        }

        // Incrementa próximo número somente se autorizada
        if ($ret['autorizada']) {
            $db->prepare("UPDATE empresa_dados SET nfe_proximo_numero=? WHERE id=1")
               ->execute([$numero + 1]);
            // Baixa de estoque
            $stBaixa = $db->prepare("UPDATE produtos SET estoque_atual = estoque_atual - ? WHERE id=?");
            foreach ($data['itens'] ?? [] as $it) {
                $pid = isset($it['produto_id']) ? (int)$it['produto_id'] : 0;
                $qty = (float)($it['quantidade'] ?? 1);
                if ($pid > 0 && $qty > 0) $stBaixa->execute([$qty, $pid]);
            }
        }

        resp($ret['autorizada'] ? 200 : 422, array_merge($ret, ['nfe_id' => $nfe_id, 'numero' => $numero]));
    }

    resp(405, ['error' => 'Método não permitido']);
}

// ════════════════════════════════════════════════════════════════════════════
// ─── RELATÓRIOS ────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════════
if ($resource === 'relatorios' && $method === 'GET') {
    auth_required();
    $tipo     = $_GET['tipo'] ?? 'overview';
    $periodo  = $_GET['periodo']  ?? 'mes';
    $data_ini = $_GET['data_ini'] ?? null;
    $data_fim = $_GET['data_fim'] ?? null;
    switch ($periodo) {
        case 'hoje':      $data_ini = date('Y-m-d'); $data_fim = date('Y-m-d'); break;
        case 'semana':    $data_ini = date('Y-m-d', strtotime('monday this week')); $data_fim = date('Y-m-d'); break;
        case 'mes':       $data_ini = date('Y-m-01'); $data_fim = date('Y-m-t'); break;
        case 'mes_ant':   $data_ini = date('Y-m-01', strtotime('first day of last month')); $data_fim = date('Y-m-t', strtotime('last day of last month')); break;
        case 'trimestre': $data_ini = date('Y-m-01', strtotime('-2 months')); $data_fim = date('Y-m-t'); break;
        case 'ano':       $data_ini = date('Y-01-01'); $data_fim = date('Y-12-31'); break;
        case 'tudo':      $data_ini = '1970-01-01'; $data_fim = '2999-12-31'; break;
        default:
            if (!$data_ini) $data_ini = date('Y-m-01');
            if (!$data_fim) $data_fim = date('Y-m-t');
    }
    $d1 = $data_ini . ' 00:00:00';
    $d2 = $data_fim . ' 23:59:59';

    if ($tipo === 'overview') {
        $rec = $db->prepare("SELECT COALESCE(SUM(total),0) FROM vendas WHERE status='Paga' AND COALESCE(data_criacao,data_confirmacao) BETWEEN ? AND ?");
        $rec->execute([$d1, $d2]); $receita = (float)$rec->fetchColumn();

        $qv = $db->prepare("SELECT COUNT(*) FROM vendas WHERE COALESCE(data_criacao,data_confirmacao) BETWEEN ? AND ?");
        $qv->execute([$d1, $d2]); $qtd_vendas = (int)$qv->fetchColumn();

        $qos = $db->prepare("SELECT COUNT(*) FROM ordens_servico WHERE data_abertura BETWEEN ? AND ?");
        $qos->execute([$d1, $d2]); $qtd_os = (int)$qos->fetchColumn();

        $qcli = $db->prepare("SELECT COUNT(*) FROM clientes WHERE data_criacao BETWEEN ? AND ?");
        $qcli->execute([$d1, $d2]); $novos_clientes = (int)$qcli->fetchColumn();

        $qe = (float)$db->query("SELECT COALESCE(SUM(estoque_atual),0) FROM produtos WHERE ativo=1 AND tipo_item='produto'")->fetchColumn();
        $qpb = (int)$db->query("SELECT COUNT(*) FROM produtos WHERE ativo=1 AND tipo_item='produto' AND estoque_atual<=estoque_minimo AND estoque_minimo>0")->fetchColumn();

        $cr = $db->prepare("SELECT COALESCE(SUM(valor_recebido),0) FROM contas_receber WHERE status IN ('Recebida','Parcial') AND data_recebimento BETWEEN ? AND ?");
        $cr->execute([$data_ini, $data_fim]); $entradas = (float)$cr->fetchColumn();
        $cp = $db->prepare("SELECT COALESCE(SUM(valor_pago),0) FROM contas_pagar WHERE status IN ('Paga','Parcial') AND data_pagamento BETWEEN ? AND ?");
        $cp->execute([$data_ini, $data_fim]); $saidas = (float)$cp->fetchColumn();

        resp(200, [
            'periodo'        => ['inicio' => $data_ini, 'fim' => $data_fim],
            'receita'        => $receita,
            'qtd_vendas'     => $qtd_vendas,
            'qtd_os'         => $qtd_os,
            'novos_clientes' => $novos_clientes,
            'estoque_total'  => $qe,
            'produtos_baixos'=> $qpb,
            'entradas'       => $entradas,
            'saidas'         => $saidas,
            'saldo'          => round($entradas - $saidas, 2),
        ]);
    }

    if ($tipo === 'vendas') {
        $status = $_GET['status'] ?? '';
        $cliente_id = isset($_GET['cliente_id']) && $_GET['cliente_id'] !== '' ? (int)$_GET['cliente_id'] : 0;

        $where = "COALESCE(v.data_criacao,v.data_confirmacao) BETWEEN ? AND ?";
        $params = [$d1, $d2];
        if ($status !== '') { $where .= " AND v.status = ?"; $params[] = $status; }
        if ($cliente_id > 0) { $where .= " AND v.cliente_id = ?"; $params[] = $cliente_id; }

        $sql = "SELECT v.id, v.status, v.total, v.desconto_valor, v.acrescimo_valor,
                       COALESCE(v.data_criacao,v.data_confirmacao) AS data_venda,
                       c.nome AS cliente_nome,
                       f.nome AS vendedor_nome
                FROM vendas v
                LEFT JOIN clientes c ON v.cliente_id=c.id
                LEFT JOIN funcionarios f ON v.vendedor_id=f.id
                WHERE $where
                ORDER BY data_venda DESC, v.id DESC";
        $st = $db->prepare($sql); $st->execute($params);
        $rows = $st->fetchAll();

        // Agregados por status
        $agg = [];
        foreach ($rows as $r) {
            $s = $r['status'] ?: 'Indefinido';
            if (!isset($agg[$s])) $agg[$s] = ['qtd' => 0, 'total' => 0];
            $agg[$s]['qtd']++; $agg[$s]['total'] += (float)$r['total'];
        }
        $por_status = [];
        foreach ($agg as $s => $a) $por_status[] = ['status' => $s, 'qtd' => $a['qtd'], 'total' => round($a['total'], 2)];

        // Por dia
        $sd = $db->prepare("SELECT DATE(COALESCE(v.data_criacao,v.data_confirmacao)) AS dia,
                                  COUNT(*) AS qtd,
                                  COALESCE(SUM(v.total),0) AS total
                           FROM vendas v WHERE $where
                           GROUP BY dia ORDER BY dia");
        $sd->execute($params); $por_dia = $sd->fetchAll();

        // Top produtos
        $whereTP = str_replace('v.data_criacao', 'v.data_criacao', $where);
        $sql_tp = "SELECT COALESCE(p.descricao, vi.descricao, '—') AS descricao,
                          SUM(vi.quantidade) AS qty,
                          SUM(vi.subtotal) AS total
                   FROM venda_items vi
                   JOIN vendas v ON vi.venda_id=v.id
                   LEFT JOIN produtos p ON vi.produto_id=p.id
                   WHERE $whereTP AND v.status NOT IN ('Cancelada','Digitação')
                   GROUP BY vi.produto_id, vi.descricao
                   ORDER BY total DESC LIMIT 20";
        $stp = $db->prepare($sql_tp); $stp->execute($params);
        $top_produtos = $stp->fetchAll();

        $totais = [
            'qtd'          => count($rows),
            'total_bruto'  => array_sum(array_map(fn($r) => (float)$r['total'], $rows)),
            'total_pago'   => array_sum(array_map(fn($r) => $r['status'] === 'Paga' ? (float)$r['total'] : 0, $rows)),
            'total_pendente' => array_sum(array_map(fn($r) => $r['status'] === 'Pendente' ? (float)$r['total'] : 0, $rows)),
            'total_cancelado' => array_sum(array_map(fn($r) => $r['status'] === 'Cancelada' ? (float)$r['total'] : 0, $rows)),
        ];
        $totais = array_map(fn($v) => is_float($v) ? round($v, 2) : $v, $totais);

        resp(200, [
            'periodo'      => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'       => $totais,
            'por_status'   => $por_status,
            'por_dia'      => $por_dia,
            'top_produtos' => $top_produtos,
            'rows'         => $rows,
        ]);
    }

    if ($tipo === 'servicos') {
        $status = $_GET['status'] ?? '';
        $tipo_aparelho_id = isset($_GET['tipo_aparelho_id']) && $_GET['tipo_aparelho_id'] !== '' ? (int)$_GET['tipo_aparelho_id'] : 0;

        $where = "os.data_abertura BETWEEN ? AND ?";
        $params = [$d1, $d2];
        if ($status !== '') { $where .= " AND os.status = ?"; $params[] = $status; }
        if ($tipo_aparelho_id > 0) { $where .= " AND os.tipo_aparelho_id = ?"; $params[] = $tipo_aparelho_id; }

        $sql = "SELECT os.id, os.status, os.descricao, os.data_abertura, os.previsao_conclusao,
                       c.nome AS cliente_nome,
                       ta.nome AS tipo_nome,
                       m.nome AS marca_nome,
                       mo.nome AS modelo_nome,
                       (SELECT COALESCE(SUM(o.valor),0) FROM orcamentos o WHERE o.ordem_id=os.id) AS valor_orcado
                FROM ordens_servico os
                LEFT JOIN clientes c ON os.cliente_id=c.id
                LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id
                LEFT JOIN marcas m ON os.marca_id=m.id
                LEFT JOIN modelos mo ON os.modelo_id=mo.id
                WHERE $where
                ORDER BY os.data_abertura DESC, os.id DESC";
        $st = $db->prepare($sql); $st->execute($params);
        $rows = $st->fetchAll();

        $por_status = [];
        $agg = [];
        foreach ($rows as $r) {
            $s = $r['status'] ?: 'Indefinido';
            if (!isset($agg[$s])) $agg[$s] = ['qtd' => 0, 'total' => 0];
            $agg[$s]['qtd']++; $agg[$s]['total'] += (float)$r['valor_orcado'];
        }
        foreach ($agg as $s => $a) $por_status[] = ['status' => $s, 'qtd' => $a['qtd'], 'total' => round($a['total'], 2)];

        // Por tipo de aparelho
        $sql_ta = "SELECT COALESCE(ta.nome,'Não informado') AS tipo_nome,
                          COUNT(*) AS qtd
                   FROM ordens_servico os
                   LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id
                   WHERE $where
                   GROUP BY os.tipo_aparelho_id ORDER BY qtd DESC LIMIT 15";
        $sta = $db->prepare($sql_ta); $sta->execute($params);
        $por_tipo = $sta->fetchAll();

        $valor_total = array_sum(array_map(fn($r) => (float)$r['valor_orcado'], $rows));
        $atrasadas = 0; $hoje = date('Y-m-d');
        foreach ($rows as $r) {
            $finais = ['Cancelada', 'Faturada', 'Aguardando Aparelho', 'Aguardando Aprovação', 'Aguardando Retirada'];
            if (!empty($r['previsao_conclusao']) && $r['previsao_conclusao'] < $hoje
                && stripos($r['status'], 'Conclu') === false
                && stripos($r['status'], 'Sem Con') === false
                && stripos($r['status'], 'Não Aprov') === false
                && !in_array($r['status'], $finais)) $atrasadas++;
        }

        resp(200, [
            'periodo'   => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'    => [
                'qtd'          => count($rows),
                'valor_total'  => round($valor_total, 2),
                'atrasadas'    => $atrasadas,
                'concluidas'   => count(array_filter($rows, fn($r) => stripos($r['status'], 'Conclu') !== false)),
            ],
            'por_status'=> $por_status,
            'por_tipo'  => $por_tipo,
            'rows'      => $rows,
        ]);
    }

    if ($tipo === 'financeiro') {
        // Contas a Receber + Pagar no período
        $cr_sql = "SELECT cr.id, cr.descricao, cr.valor, cr.valor_recebido, cr.data_emissao,
                          cr.data_vencimento, cr.data_recebimento, cr.status,
                          COALESCE(c.nome, cr.cliente_nome_manual,'—') AS cliente_nome,
                          cf.nome AS categoria
                   FROM contas_receber cr
                   LEFT JOIN clientes c ON cr.cliente_id=c.id
                   LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id
                   WHERE cr.data_vencimento BETWEEN ? AND ?
                   ORDER BY cr.data_vencimento DESC";
        $st = $db->prepare($cr_sql); $st->execute([$data_ini, $data_fim]);
        $contas_receber = $st->fetchAll();

        $cp_sql = "SELECT cp.id, cp.descricao, cp.valor, cp.valor_pago, cp.data_emissao,
                          cp.data_vencimento, cp.data_pagamento, cp.status,
                          COALESCE(f.razao_social,'—') AS fornecedor_nome,
                          cf.nome AS categoria
                   FROM contas_pagar cp
                   LEFT JOIN fornecedores f ON cp.fornecedor_id=f.id
                   LEFT JOIN categorias_financeiras cf ON cp.categoria_id=cf.id
                   WHERE cp.data_vencimento BETWEEN ? AND ?
                   ORDER BY cp.data_vencimento DESC";
        $st2 = $db->prepare($cp_sql); $st2->execute([$data_ini, $data_fim]);
        $contas_pagar = $st2->fetchAll();

        $tot_receber  = array_sum(array_map(fn($r) => (float)$r['valor'], $contas_receber));
        $tot_recebido = array_sum(array_map(fn($r) => (float)$r['valor_recebido'], $contas_receber));
        $tot_pagar    = array_sum(array_map(fn($r) => (float)$r['valor'], $contas_pagar));
        $tot_pago     = array_sum(array_map(fn($r) => (float)$r['valor_pago'], $contas_pagar));

        $em_aberto_receber = array_sum(array_map(fn($r) => $r['status'] === 'Aberta' ? (float)$r['valor'] : 0, $contas_receber));
        $vencido_receber   = array_sum(array_map(fn($r) => ($r['status'] === 'Aberta' && $r['data_vencimento'] < date('Y-m-d')) ? (float)$r['valor'] : 0, $contas_receber));
        $em_aberto_pagar   = array_sum(array_map(fn($r) => $r['status'] === 'Aberta' ? (float)$r['valor'] : 0, $contas_pagar));
        $vencido_pagar     = array_sum(array_map(fn($r) => ($r['status'] === 'Aberta' && $r['data_vencimento'] < date('Y-m-d')) ? (float)$r['valor'] : 0, $contas_pagar));

        // Categorias de receita/despesa
        $cat_rec_sql = "SELECT COALESCE(cf.nome,'Sem categoria') AS categoria,
                              COALESCE(SUM(cr.valor_recebido),0) AS total
                       FROM contas_receber cr
                       LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id
                       WHERE cr.status IN ('Recebida','Parcial') AND cr.data_recebimento BETWEEN ? AND ?
                       GROUP BY cr.categoria_id ORDER BY total DESC";
        $stcr = $db->prepare($cat_rec_sql); $stcr->execute([$data_ini, $data_fim]);
        $por_categoria_receita = $stcr->fetchAll();

        $cat_desp_sql = "SELECT COALESCE(cf.nome,'Sem categoria') AS categoria,
                               COALESCE(SUM(cp.valor_pago),0) AS total
                        FROM contas_pagar cp
                        LEFT JOIN categorias_financeiras cf ON cp.categoria_id=cf.id
                        WHERE cp.status IN ('Paga','Parcial') AND cp.data_pagamento BETWEEN ? AND ?
                        GROUP BY cp.categoria_id ORDER BY total DESC";
        $stcp = $db->prepare($cat_desp_sql); $stcp->execute([$data_ini, $data_fim]);
        $por_categoria_despesa = $stcp->fetchAll();

        resp(200, [
            'periodo' => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'  => [
                'a_receber'         => round($tot_receber, 2),
                'recebido'          => round($tot_recebido, 2),
                'a_pagar'           => round($tot_pagar, 2),
                'pago'              => round($tot_pago, 2),
                'saldo'             => round($tot_recebido - $tot_pago, 2),
                'em_aberto_receber' => round($em_aberto_receber, 2),
                'vencido_receber'   => round($vencido_receber, 2),
                'em_aberto_pagar'   => round($em_aberto_pagar, 2),
                'vencido_pagar'     => round($vencido_pagar, 2),
            ],
            'por_categoria_receita' => $por_categoria_receita,
            'por_categoria_despesa' => $por_categoria_despesa,
            'contas_receber'        => $contas_receber,
            'contas_pagar'          => $contas_pagar,
        ]);
    }

    if ($tipo === 'estoque') {
        $alerta = $_GET['alerta'] ?? ''; // 'baixo', 'zerado', '' = todos

        $where = "ativo=1 AND tipo_item='produto'";
        if ($alerta === 'baixo')   $where .= " AND estoque_atual <= estoque_minimo AND estoque_minimo > 0";
        if ($alerta === 'zerado')  $where .= " AND estoque_atual <= 0";

        $sql = "SELECT id, codigo_interno, codigo_barras, descricao, unidade_medida,
                       estoque_atual, estoque_minimo, estoque_maximo,
                       preco_custo, preco_venda, localizacao
                FROM produtos WHERE $where ORDER BY descricao";
        $rows = $db->query($sql)->fetchAll();

        $valor_custo  = 0; $valor_venda = 0; $qtd_baixo = 0; $qtd_zerado = 0;
        foreach ($rows as $r) {
            $valor_custo += (float)$r['estoque_atual'] * (float)$r['preco_custo'];
            $valor_venda += (float)$r['estoque_atual'] * (float)$r['preco_venda'];
            if ((float)$r['estoque_atual'] <= 0) $qtd_zerado++;
            elseif ((float)$r['estoque_minimo'] > 0 && (float)$r['estoque_atual'] <= (float)$r['estoque_minimo']) $qtd_baixo++;
        }

        // Itens mais movimentados no período
        $sql_mov = "SELECT COALESCE(p.descricao, vi.descricao, '—') AS descricao,
                           SUM(vi.quantidade) AS qtd_vendida,
                           SUM(vi.subtotal) AS total
                    FROM venda_items vi
                    JOIN vendas v ON vi.venda_id=v.id
                    LEFT JOIN produtos p ON vi.produto_id=p.id
                    WHERE COALESCE(v.data_criacao,v.data_confirmacao) BETWEEN ? AND ?
                      AND v.status NOT IN ('Cancelada','Digitação')
                    GROUP BY vi.produto_id, vi.descricao
                    ORDER BY qtd_vendida DESC LIMIT 20";
        $stm = $db->prepare($sql_mov); $stm->execute([$d1, $d2]);
        $mais_vendidos = $stm->fetchAll();

        resp(200, [
            'periodo' => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'  => [
                'qtd_itens'       => count($rows),
                'valor_custo'     => round($valor_custo, 2),
                'valor_venda'     => round($valor_venda, 2),
                'margem_potencial'=> round($valor_venda - $valor_custo, 2),
                'qtd_baixo'       => $qtd_baixo,
                'qtd_zerado'      => $qtd_zerado,
            ],
            'rows'           => $rows,
            'mais_vendidos'  => $mais_vendidos,
        ]);
    }

    if ($tipo === 'cadastros') {
        // Resumo de cadastros (totais sempre + crescimento no período)
        $tot_cli       = (int)$db->query("SELECT COUNT(*) FROM clientes")->fetchColumn();
        $tot_for       = (int)$db->query("SELECT COUNT(*) FROM fornecedores WHERE ativo=1")->fetchColumn();
        $tot_pro       = (int)$db->query("SELECT COUNT(*) FROM produtos WHERE ativo=1 AND tipo_item='produto'")->fetchColumn();
        $tot_serv      = (int)$db->query("SELECT COUNT(*) FROM produtos WHERE ativo=1 AND tipo_item='servico'")->fetchColumn();
        $tot_func      = (int)$db->query("SELECT COUNT(*) FROM funcionarios WHERE status='Ativo'")->fetchColumn();
        $tot_usu       = (int)$db->query("SELECT COUNT(*) FROM usuarios WHERE ativo=1")->fetchColumn();

        // Novos no período
        $stN = $db->prepare("SELECT COUNT(*) FROM clientes WHERE data_criacao BETWEEN ? AND ?");
        $stN->execute([$d1, $d2]); $novos_cli = (int)$stN->fetchColumn();
        $stN2 = $db->prepare("SELECT COUNT(*) FROM fornecedores WHERE data_criacao BETWEEN ? AND ?");
        $stN2->execute([$d1, $d2]); $novos_for = (int)$stN2->fetchColumn();
        $stN3 = $db->prepare("SELECT COUNT(*) FROM produtos WHERE data_criacao BETWEEN ? AND ?");
        $stN3->execute([$d1, $d2]); $novos_pro = (int)$stN3->fetchColumn();

        // Top clientes (por valor)
        $sql_tc = "SELECT c.id, c.nome,
                          COUNT(v.id) AS qtd_vendas,
                          COALESCE(SUM(v.total),0) AS total_comprado
                   FROM clientes c
                   LEFT JOIN vendas v ON v.cliente_id=c.id AND v.status='Paga'
                                       AND COALESCE(v.data_criacao,v.data_confirmacao) BETWEEN ? AND ?
                   GROUP BY c.id ORDER BY total_comprado DESC LIMIT 20";
        $sttc = $db->prepare($sql_tc); $sttc->execute([$d1, $d2]);
        $top_clientes = $sttc->fetchAll();

        // Lista de clientes recentes
        $stRC = $db->prepare("SELECT id, nome, telefone, email, cpf, data_criacao FROM clientes WHERE data_criacao BETWEEN ? AND ? ORDER BY data_criacao DESC LIMIT 50");
        $stRC->execute([$d1, $d2]);
        $clientes_recentes = $stRC->fetchAll();

        resp(200, [
            'periodo' => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'  => [
                'clientes'     => $tot_cli,
                'fornecedores' => $tot_for,
                'produtos'     => $tot_pro,
                'servicos'     => $tot_serv,
                'funcionarios' => $tot_func,
                'usuarios'     => $tot_usu,
                'novos_clientes'     => $novos_cli,
                'novos_fornecedores' => $novos_for,
                'novos_produtos'     => $novos_pro,
            ],
            'top_clientes'      => $top_clientes,
            'clientes_recentes' => $clientes_recentes,
        ]);
    }

    if ($tipo === 'comissoes') {
        $funcionario_id = isset($_GET['funcionario_id']) && $_GET['funcionario_id'] !== '' ? (int)$_GET['funcionario_id'] : 0;

        $where = "cr.status = 'Recebida'
                  AND cr.origem IN ('venda','nfce','nfe')
                  AND cr.data_recebimento BETWEEN ? AND ?
                  AND f.comissao_venda_ativo = 1";
        $params = [$data_ini, $data_fim];
        if ($funcionario_id > 0) { $where .= " AND f.id = ?"; $params[] = $funcionario_id; }

        // Resolve a venda real cobrindo origem 'venda', 'nfce' e 'nfe'.
        // Para 'venda', cr.venda_id = vendas.id.
        // Para 'nfce'/'nfe', cr.venda_id = nfce_emitidas.id / nfe_emitidas.id, e a venda real está em <doc>.venda_id.
        $sql = "
            SELECT
                f.id   AS funcionario_id,
                f.nome AS funcionario_nome,
                f.comissao_venda_percentual AS percentual,
                v.id   AS venda_id,
                cr.id  AS cr_id,
                cr.descricao,
                cr.origem,
                cr.valor,
                cr.valor_recebido,
                cr.data_emissao,
                cr.data_vencimento,
                cr.data_recebimento,
                COALESCE(c.nome, cr.cliente_nome_manual,'—') AS cliente_nome,
                ROUND(cr.valor_recebido * f.comissao_venda_percentual / 100.0, 2) AS comissao
            FROM contas_receber cr
            LEFT JOIN vendas         vd   ON cr.origem='venda' AND vd.id   = cr.venda_id
            LEFT JOIN nfce_emitidas  nfce ON cr.origem='nfce'  AND nfce.id = cr.venda_id
            LEFT JOIN nfe_emitidas   nfe  ON cr.origem='nfe'   AND nfe.id  = cr.venda_id
            LEFT JOIN vendas v ON v.id = COALESCE(vd.id, nfce.venda_id, nfe.venda_id)
            INNER JOIN funcionarios f ON f.id = v.vendedor_id
            LEFT JOIN clientes c ON c.id = cr.cliente_id
            WHERE $where
            ORDER BY f.nome, cr.data_recebimento DESC, cr.id DESC
        ";
        $st = $db->prepare($sql);
        $st->execute($params);
        $rows = $st->fetchAll();

        // Agregados por funcionário
        $funcs = [];
        foreach ($rows as $r) {
            $fid = (int)$r['funcionario_id'];
            if (!isset($funcs[$fid])) {
                $funcs[$fid] = [
                    'funcionario_id'   => $fid,
                    'funcionario_nome' => $r['funcionario_nome'],
                    'percentual'       => (float)$r['percentual'],
                    'qtd_recebimentos' => 0,
                    'base_calculo'     => 0,
                    'total_comissao'   => 0,
                ];
            }
            $funcs[$fid]['qtd_recebimentos']++;
            $funcs[$fid]['base_calculo']   += (float)$r['valor_recebido'];
            $funcs[$fid]['total_comissao'] += (float)$r['comissao'];
        }
        $por_funcionario = array_values(array_map(function($f){
            $f['base_calculo']   = round($f['base_calculo'], 2);
            $f['total_comissao'] = round($f['total_comissao'], 2);
            return $f;
        }, $funcs));
        usort($por_funcionario, fn($a,$b) => $b['total_comissao'] <=> $a['total_comissao']);

        // Funcionários elegíveis (para popular o filtro, mesmo sem recebimentos)
        $stE = $db->query("SELECT id, nome, comissao_venda_percentual FROM funcionarios WHERE status='Ativo' AND comissao_venda_ativo=1 ORDER BY nome");
        $funcionarios_elegiveis = $stE->fetchAll();

        $totais = [
            'qtd_recebimentos' => count($rows),
            'qtd_funcionarios' => count($por_funcionario),
            'base_calculo'     => round(array_sum(array_map(fn($r) => (float)$r['valor_recebido'], $rows)), 2),
            'total_comissao'   => round(array_sum(array_map(fn($r) => (float)$r['comissao'], $rows)), 2),
        ];

        resp(200, [
            'periodo'                 => ['inicio' => $data_ini, 'fim' => $data_fim],
            'totais'                  => $totais,
            'por_funcionario'         => $por_funcionario,
            'rows'                    => $rows,
            'funcionarios_elegiveis'  => $funcionarios_elegiveis,
        ]);
    }

    resp(400, ['error' => 'Tipo de relatório inválido']);
}