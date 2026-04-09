<?php
// =============================================================
// api.php — Backend único do consertaOS
// =============================================================

set_exception_handler(function($e) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $e->getMessage(), 'file' => basename($e->getFile()), 'line' => $e->getLine()], JSON_UNESCAPED_UNICODE);
    exit;
});
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    throw new \ErrorException($errstr, $errno, 0, $errfile, $errline);
});

session_start();
date_default_timezone_set('America/Sao_Paulo');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ─── HELPERS ─────────────────────────────────────────────────
function resp(int $code, $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
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

// ─── BANCO DE DADOS ──────────────────────────────────────────
$db_path = __DIR__ . '/agtech.db3';
if (!is_writable(__DIR__)) {
    resp(500, ['error' => 'Sem permissão de escrita no diretório: ' . __DIR__]);
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
"CREATE TABLE IF NOT EXISTS orcamentos (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, observacoes TEXT DEFAULT '', valor REAL DEFAULT 0, status_orcamento TEXT DEFAULT 'Pendente')",
"CREATE TABLE IF NOT EXISTS midias_os (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, caminho TEXT NOT NULL, tipo TEXT DEFAULT '', comentario TEXT DEFAULT '', data_upload DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS ordem_observacoes (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER NOT NULL, usuario_id INTEGER, observacao TEXT NOT NULL, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS notificacoes (id INTEGER PRIMARY KEY AUTOINCREMENT, ordem_id INTEGER, novo_status TEXT DEFAULT '', lida INTEGER DEFAULT 0, data_notificacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_bancarias (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, banco TEXT DEFAULT '', agencia TEXT DEFAULT '', conta TEXT DEFAULT '', tipo TEXT DEFAULT 'corrente', ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS operadoras_cartao (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'credito', taxa_padrao REAL DEFAULT 0, prazo_repasse INTEGER DEFAULT 30, ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS formas_pagamento (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'dinheiro', modalidade TEXT DEFAULT 'a_vista', parcelas_padrao INTEGER DEFAULT 1, intervalo_dias INTEGER DEFAULT 30, juros_am REAL DEFAULT 0, taxa_fixa REAL DEFAULT 0, tipo_repeticao TEXT DEFAULT 'mensal', lancar_financeiro INTEGER DEFAULT 1, confirmar_auto INTEGER DEFAULT 0, conta_bancaria TEXT DEFAULT '', operadora TEXT DEFAULT '', taxa_operadora REAL DEFAULT 0, ativo INTEGER DEFAULT 1)",
"CREATE TABLE IF NOT EXISTS vendas (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER, vendedor_id INTEGER, os_id INTEGER, cpf_cnpj TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_confirmacao DATETIME, status TEXT DEFAULT 'Paga', total REAL DEFAULT 0, desconto_valor REAL DEFAULT 0, desconto_percentual REAL DEFAULT 0, desconto_tipo TEXT DEFAULT 'valor', acrescimo_valor REAL DEFAULT 0, acrescimo_percentual REAL DEFAULT 0, acrescimo_tipo TEXT DEFAULT 'valor', valor_frete REAL DEFAULT 0, observacoes TEXT DEFAULT '')",
"CREATE TABLE IF NOT EXISTS venda_faturamentos (id INTEGER PRIMARY KEY AUTOINCREMENT, venda_id INTEGER NOT NULL, forma_pagamento_id INTEGER, forma_pagamento_nome TEXT DEFAULT '', valor_total REAL DEFAULT 0, valor_pago REAL DEFAULT 0, num_parcelas INTEGER DEFAULT 1, data_primeira_parcela DATE, intervalo_dias INTEGER DEFAULT 30, juros_am REAL DEFAULT 0, taxa_fixa REAL DEFAULT 0, tipo_repeticao TEXT DEFAULT 'mensal', observacoes TEXT DEFAULT '')",
"CREATE TABLE IF NOT EXISTS venda_parcelas (id INTEGER PRIMARY KEY AUTOINCREMENT, faturamento_id INTEGER NOT NULL, venda_id INTEGER, numero INTEGER DEFAULT 1, valor REAL DEFAULT 0, valor_juros REAL DEFAULT 0, valor_taxa REAL DEFAULT 0, data_vencimento DATE, data_pagamento DATE, status TEXT DEFAULT 'Aberta')",
"CREATE TABLE IF NOT EXISTS venda_items (id INTEGER PRIMARY KEY AUTOINCREMENT, venda_id INTEGER, produto_id INTEGER, quantidade REAL DEFAULT 1, valor_unitario REAL DEFAULT 0, desconto_valor REAL DEFAULT 0, desconto_percentual REAL DEFAULT 0, acrescimo_valor REAL DEFAULT 0, subtotal REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS fornecedores (id INTEGER PRIMARY KEY AUTOINCREMENT, razao_social TEXT NOT NULL, nome_fantasia TEXT DEFAULT '', cpf_cnpj TEXT DEFAULT '', telefone TEXT DEFAULT '', email TEXT DEFAULT '', endereco TEXT DEFAULT '', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS tabelas_preco (id INTEGER PRIMARY KEY AUTOINCREMENT, produto_id INTEGER NOT NULL, nome TEXT NOT NULL, margem_lucro REAL DEFAULT 0, preco_venda REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS ncm_tabela (id INTEGER PRIMARY KEY AUTOINCREMENT, codigo TEXT NOT NULL UNIQUE, descricao TEXT NOT NULL, aliq_ii REAL DEFAULT 0, aliq_ipi REAL DEFAULT 0, aliq_pis REAL DEFAULT 0, aliq_cofins REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS cest_tabela (id INTEGER PRIMARY KEY AUTOINCREMENT, cest TEXT NOT NULL, ncm TEXT NOT NULL, descricao TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS tabelas_servico (id INTEGER PRIMARY KEY AUTOINCREMENT, codigo TEXT NOT NULL, descricao TEXT NOT NULL, cnae TEXT DEFAULT '', cod_trib_municipio TEXT DEFAULT '', aliq_iss REAL DEFAULT 0, cst_pis TEXT DEFAULT '01', aliq_pis REAL DEFAULT 0, cst_cofins TEXT DEFAULT '01', aliq_cofins REAL DEFAULT 0, ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS notas_fiscais_entrada (id INTEGER PRIMARY KEY AUTOINCREMENT, numero TEXT DEFAULT '', serie TEXT DEFAULT '', chave_acesso TEXT NOT NULL DEFAULT '', fornecedor_id INTEGER, fornecedor_nome TEXT DEFAULT '', fornecedor_cnpj TEXT DEFAULT '', data_emissao DATE, data_entrada DATE, valor_total REAL DEFAULT 0, valor_bc_icms REAL DEFAULT 0, valor_icms REAL DEFAULT 0, valor_bc_icms_st REAL DEFAULT 0, valor_icms_st REAL DEFAULT 0, valor_ii REAL DEFAULT 0, valor_pis_st REAL DEFAULT 0, valor_cofins_st REAL DEFAULT 0, comple_icms REAL DEFAULT 0, valor_liquido REAL DEFAULT 0, valor_servico REAL DEFAULT 0, valor_ipi REAL DEFAULT 0, valor_pis REAL DEFAULT 0, valor_cofins REAL DEFAULT 0, valor_frete REAL DEFAULT 0, valor_desconto REAL DEFAULT 0, status TEXT DEFAULT 'Recebida', observacoes TEXT DEFAULT '', xml_conteudo TEXT DEFAULT '', data_importacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS nfe_items (id INTEGER PRIMARY KEY AUTOINCREMENT, nfe_id INTEGER NOT NULL, codigo_produto TEXT DEFAULT '', descricao TEXT NOT NULL, ncm TEXT DEFAULT '', cfop TEXT DEFAULT '', unidade TEXT DEFAULT 'UN', quantidade REAL DEFAULT 1, valor_unitario REAL DEFAULT 0, valor_total REAL DEFAULT 0, valor_icms REAL DEFAULT 0, valor_ipi REAL DEFAULT 0, valor_pis REAL DEFAULT 0, valor_cofins REAL DEFAULT 0)",
"CREATE TABLE IF NOT EXISTS nfce_emitidas (id INTEGER PRIMARY KEY AUTOINCREMENT, os_id INTEGER, venda_id INTEGER, n_prot TEXT DEFAULT '', status TEXT DEFAULT 'Aguardando', numero TEXT DEFAULT '', serie TEXT DEFAULT '', chave_acesso TEXT DEFAULT '', valor_total REAL DEFAULT 0, danfe_url TEXT DEFAULT '', xml_url TEXT DEFAULT '', motivo_rejeicao TEXT DEFAULT '', ambiente TEXT DEFAULT 'Homologacao', payload_json TEXT DEFAULT '', data_emissao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS uploads_temporarios (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, os_id INTEGER, status TEXT DEFAULT 'pendente', data_expiracao DATETIME)",
// ── FINANCEIRO ──────────────────────────────────────────────────────────────
"CREATE TABLE IF NOT EXISTS categorias_financeiras (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, tipo TEXT DEFAULT 'ambos', cor TEXT DEFAULT '#7d8590', ativo INTEGER DEFAULT 1, data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_receber (id INTEGER PRIMARY KEY AUTOINCREMENT, origem TEXT DEFAULT 'manual', venda_id INTEGER, parcela_id INTEGER, cliente_id INTEGER, categoria_id INTEGER, conta_bancaria_id INTEGER, descricao TEXT NOT NULL, valor REAL DEFAULT 0, valor_recebido REAL DEFAULT 0, data_emissao DATE, data_vencimento DATE, data_recebimento DATE, status TEXT DEFAULT 'Aberta', documento_ref TEXT DEFAULT '', observacoes TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
"CREATE TABLE IF NOT EXISTS contas_pagar (id INTEGER PRIMARY KEY AUTOINCREMENT, origem TEXT DEFAULT 'manual', nfe_id INTEGER, fornecedor_id INTEGER, cliente_id INTEGER, categoria_id INTEGER, conta_bancaria_id INTEGER, descricao TEXT NOT NULL, valor REAL DEFAULT 0, valor_pago REAL DEFAULT 0, data_emissao DATE, data_vencimento DATE, data_pagamento DATE, status TEXT DEFAULT 'Aberta', documento_ref TEXT DEFAULT '', observacoes TEXT DEFAULT '', data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP, data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP)",
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
    ['empresa_dados',        'nfce_cuf',       "TEXT DEFAULT '42'"],
    ['empresa_dados',        'nfce_cert_senha',"TEXT DEFAULT ''"],
    ['empresa_dados',        'nfce_csc_id',    "TEXT DEFAULT '01'"],
    ['empresa_dados',        'nfce_ambiente',  "TEXT DEFAULT 'homologacao'"],
    ['empresa_dados',        'nfce_serie',     "TEXT DEFAULT '1'"],
    ['empresa_dados',        'nfce_proximo_numero', "INTEGER DEFAULT 1"],
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
    ['contas_pagar',    'valor_pago',       'REAL DEFAULT 0'],
    ['contas_pagar',    'conta_bancaria_id','INTEGER'],
    ['contas_pagar',    'documento_ref',    "TEXT DEFAULT ''"],
    ['contas_pagar',    'cliente_id',       'INTEGER'],
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
    ['midias_os',        'data_upload',     'DATETIME'],
    ['clientes',         'data_criacao',    'DATETIME'],
    ['clientes',         'ativo',           'INTEGER DEFAULT 1'],
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

// ─── USUÁRIO ADMIN GARANTIDO ─────────────────────────────────
// Cria o usuário admin@consertaos.com.br apenas se não existir.
// NÃO atualiza a senha a cada requisição para não sobrescrever alterações.
$admin_nome = 'admin@consertaos.com.br';
$existe = $db->prepare("SELECT id FROM usuarios WHERE nome = ?");
$existe->execute([$admin_nome]);
if (!$existe->fetch()) {
    $admin_senha = password_hash('admin123', PASSWORD_DEFAULT);
    $db->prepare("INSERT INTO usuarios (nome, email, senha, nivel_acesso, ativo) VALUES (?, ?, ?, 'admin', 1)")
       ->execute([$admin_nome, $admin_nome, $admin_senha]);
}

$count = (int)$db->query("SELECT COUNT(*) FROM usuarios")->fetchColumn();
if ($count === 0) {
    $hash = password_hash('admin123', PASSWORD_DEFAULT);
    $db->prepare("INSERT INTO usuarios (nome, email, senha, nivel_acesso, ativo) VALUES (?, ?, ?, ?, 1)")
       ->execute(['Administrador', 'admin@sistema.com', $hash, 'admin']);
}

// ─── ROTEAMENTO ──────────────────────────────────────────────
$method   = $_SERVER['REQUEST_METHOD'];
$resource = $_GET['resource'] ?? '';
$action   = $_GET['action']   ?? '';
$id       = (isset($_GET['id']) && is_numeric($_GET['id'])) ? (int)$_GET['id'] : null;
$data     = get_input();

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
                resp(200, ['success' => true, 'usuario' => $user]);
            }
        }
        // Retorna mensagem genérica — não revela se o usuário existe
        resp(401, ['error' => 'Usuário ou senha inválidos']);
    }
    if ($action === 'logout' && $method === 'POST') {
        session_destroy();
        resp(200, ['success' => true]);
    }
    if ($action === 'me' && $method === 'GET') {
        if (!isset($_SESSION['usuario']) || !is_array($_SESSION['usuario'])) resp(401, ['error' => 'Não autenticado']);
        resp(200, $_SESSION['usuario']);
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
        $db->prepare("UPDATE empresa_dados SET nome=?, razao_social=?, telefone=?, endereco=?, logo_principal=?, cnpj=?, ie=?, cep=?, logradouro=?, numero=?, complemento=?, bairro=?, cidade=?, uf=?, certificado_pfx=?, certificado_nome=?, certificado_validade=? WHERE id=1")
           ->execute([$nome, $razao_social, $telefone, $endereco, $logo_principal, $cnpj, $ie, $cep, $logradouro, $numero, $complemento, $bairro, $cidade, $uf, $cert_pfx, $cert_nome, $cert_val]);
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
        $db->prepare("INSERT INTO clientes (nome,email,telefone,cpf,endereco,ativo) VALUES (?,?,?,?,?,?)")
           ->execute([$nome_upper, $data['email']??'', $data['telefone']??'', $data['cpf']??'', $data['endereco']??'', (int)($data['ativo']??1)]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $nome_upper_u = mb_strtoupper(trim($data['nome']??''), 'UTF-8');
        $db->prepare("UPDATE clientes SET nome=?,email=?,telefone=?,cpf=?,endereco=?,ativo=? WHERE id=?")
           ->execute([$nome_upper_u, $data['email']??'', $data['telefone']??'', $data['cpf']??'', $data['endereco']??'', (int)($data['ativo']??1), $id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM clientes WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
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
        $q = '%' . normalizar_busca($q_raw_p) . '%';
        $tipo_p = $_GET['tipo'] ?? '';
        // Usar parâmetro preparado para tipo_item (evita SQL injection e quote duplo)
        if ($tipo_p !== '') {
            $s = $db->prepare("SELECT * FROM produtos WHERE (LOWER(descricao) LIKE ? OR LOWER(codigo_interno) LIKE ?) AND ativo=1 AND tipo_item=? ORDER BY descricao LIMIT 200");
            $s->execute([$q, $q, $tipo_p]);
        } else {
            $s = $db->prepare("SELECT * FROM produtos WHERE (LOWER(descricao) LIKE ? OR LOWER(codigo_interno) LIKE ?) AND ativo=1 ORDER BY descricao LIMIT 200");
            $s->execute([$q, $q]);
        }
        resp(200, $s->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT * FROM produtos WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        if (empty($data['descricao'])) resp(400, ['error' => 'Descrição obrigatória']);
        $now = date('Y-m-d H:i:s');
        $db->prepare("INSERT INTO produtos (tipo_item,ativo,codigo_interno,codigo_barras,descricao,descricao_complementar,unidade_medida,unidade_compra,unidade_saida,fator_conversao,preco_custo,despesas_acessorias,outras_despesas,custo_final,preco_venda,margem_lucro,percentual_desconto_max,percentual_comissao,estoque_atual,estoque_minimo,estoque_maximo,estoque_imobilizado,estoque_uso_consumo,estoque_revenda,localizacao,peso_liquido,peso_bruto,largura,altura,profundidade,ncm,ncm_descricao,cfop,cest,origem,cst_icms,aliq_icms,cst_pis,aliq_pis,cst_cofins,aliq_cofins,cst_ipi,aliq_ipi,nfse_movimenta,nfse_codigo_servico,nfse_municipio,nfse_cnae,nfse_descricao_servico,nfse_deducoes,nfse_cofins,nfse_ir,nfse_outras_deducoes,nfse_pis,nfse_inss,nfse_csll,nfse_iss,nfse_id_municipal_evento,nfse_descricao_evento,nfse_data_ini_evento,nfse_data_fim_evento,nfse_logradouro,nfse_numero,tabela_servico_id,codigo_nbs,iss_percentual,nfse_natureza,nfse_incentivo_fiscal,observacoes,data_criacao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
           ->execute([$data['tipo_item']??'produto',$data['ativo']??1,$data['codigo_interno']??'',(!empty($data['codigo_barras']) ? $data['codigo_barras'] : null),$data['descricao'],$data['descricao_complementar']??'',$data['unidade_medida']??'UN',$data['unidade_compra']??'',$data['unidade_saida']??'',(float)($data['fator_conversao']??1),(float)($data['preco_custo']??0),(float)($data['despesas_acessorias']??0),(float)($data['outras_despesas']??0),(float)($data['custo_final']??0),(float)($data['preco_venda']??0),(float)($data['margem_lucro']??0),(float)($data['percentual_desconto_max']??0),(float)($data['percentual_comissao']??0),(float)($data['estoque_atual']??0),(float)($data['estoque_minimo']??0),(float)($data['estoque_maximo']??0),(float)($data['estoque_imobilizado']??0),(float)($data['estoque_uso_consumo']??0),(float)($data['estoque_revenda']??0),$data['localizacao']??'',(float)($data['peso_liquido']??0),(float)($data['peso_bruto']??0),(float)($data['largura']??0),(float)($data['altura']??0),(float)($data['profundidade']??0),$data['ncm']??'',$data['ncm_descricao']??'',$data['cfop']??'',$data['cest']??'',$data['origem']??'0',$data['cst_icms']??'',(float)($data['aliq_icms']??0),$data['cst_pis']??'',(float)($data['aliq_pis']??0),$data['cst_cofins']??'',(float)($data['aliq_cofins']??0),$data['cst_ipi']??'',(float)($data['aliq_ipi']??0),(int)($data['nfse_movimenta']??0),$data['nfse_codigo_servico']??'',$data['nfse_municipio']??'',$data['nfse_cnae']??'',$data['nfse_descricao_servico']??'',(float)($data['nfse_deducoes']??0),(float)($data['nfse_cofins']??0),(float)($data['nfse_ir']??0),(float)($data['nfse_outras_deducoes']??0),(float)($data['nfse_pis']??0),(float)($data['nfse_inss']??0),(float)($data['nfse_csll']??0),(float)($data['nfse_iss']??0),$data['nfse_id_municipal_evento']??'',$data['nfse_descricao_evento']??'',$data['nfse_data_ini_evento']??'',$data['nfse_data_fim_evento']??'',$data['nfse_logradouro']??'',$data['nfse_numero']??'',$data['tabela_servico_id']??null,$data['codigo_nbs']??'',(float)($data['iss_percentual']??0),$data['nfse_natureza']??'tributacao_municipio',$data['nfse_incentivo_fiscal']??'nao',$data['observacoes']??'',$now,$now]);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE produtos SET tipo_item=?,ativo=?,codigo_interno=?,codigo_barras=?,descricao=?,descricao_complementar=?,unidade_medida=?,unidade_compra=?,unidade_saida=?,fator_conversao=?,preco_custo=?,despesas_acessorias=?,outras_despesas=?,custo_final=?,preco_venda=?,margem_lucro=?,percentual_desconto_max=?,percentual_comissao=?,estoque_atual=?,estoque_minimo=?,estoque_maximo=?,estoque_imobilizado=?,estoque_uso_consumo=?,estoque_revenda=?,localizacao=?,peso_liquido=?,peso_bruto=?,largura=?,altura=?,profundidade=?,ncm=?,ncm_descricao=?,cfop=?,cest=?,origem=?,cst_icms=?,aliq_icms=?,cst_pis=?,aliq_pis=?,cst_cofins=?,aliq_cofins=?,cst_ipi=?,aliq_ipi=?,nfse_movimenta=?,nfse_codigo_servico=?,nfse_municipio=?,nfse_cnae=?,nfse_descricao_servico=?,nfse_deducoes=?,nfse_cofins=?,nfse_ir=?,nfse_outras_deducoes=?,nfse_pis=?,nfse_inss=?,nfse_csll=?,nfse_iss=?,nfse_id_municipal_evento=?,nfse_descricao_evento=?,nfse_data_ini_evento=?,nfse_data_fim_evento=?,nfse_logradouro=?,nfse_numero=?,tabela_servico_id=?,codigo_nbs=?,iss_percentual=?,nfse_natureza=?,nfse_incentivo_fiscal=?,observacoes=?,data_atualizacao=? WHERE id=?")
           ->execute([$data['tipo_item']??'produto',$data['ativo']??1,$data['codigo_interno']??'',(!empty($data['codigo_barras']) ? $data['codigo_barras'] : null),$data['descricao'],$data['descricao_complementar']??'',$data['unidade_medida']??'UN',$data['unidade_compra']??'',$data['unidade_saida']??'',(float)($data['fator_conversao']??1),(float)($data['preco_custo']??0),(float)($data['despesas_acessorias']??0),(float)($data['outras_despesas']??0),(float)($data['custo_final']??0),(float)($data['preco_venda']??0),(float)($data['margem_lucro']??0),(float)($data['percentual_desconto_max']??0),(float)($data['percentual_comissao']??0),(float)($data['estoque_atual']??0),(float)($data['estoque_minimo']??0),(float)($data['estoque_maximo']??0),(float)($data['estoque_imobilizado']??0),(float)($data['estoque_uso_consumo']??0),(float)($data['estoque_revenda']??0),$data['localizacao']??'',(float)($data['peso_liquido']??0),(float)($data['peso_bruto']??0),(float)($data['largura']??0),(float)($data['altura']??0),(float)($data['profundidade']??0),$data['ncm']??'',$data['ncm_descricao']??'',$data['cfop']??'',$data['cest']??'',$data['origem']??'0',$data['cst_icms']??'',(float)($data['aliq_icms']??0),$data['cst_pis']??'',(float)($data['aliq_pis']??0),$data['cst_cofins']??'',(float)($data['aliq_cofins']??0),$data['cst_ipi']??'',(float)($data['aliq_ipi']??0),(int)($data['nfse_movimenta']??0),$data['nfse_codigo_servico']??'',$data['nfse_municipio']??'',$data['nfse_cnae']??'',$data['nfse_descricao_servico']??'',(float)($data['nfse_deducoes']??0),(float)($data['nfse_cofins']??0),(float)($data['nfse_ir']??0),(float)($data['nfse_outras_deducoes']??0),(float)($data['nfse_pis']??0),(float)($data['nfse_inss']??0),(float)($data['nfse_csll']??0),(float)($data['nfse_iss']??0),$data['nfse_id_municipal_evento']??'',$data['nfse_descricao_evento']??'',$data['nfse_data_ini_evento']??'',$data['nfse_data_fim_evento']??'',$data['nfse_logradouro']??'',$data['nfse_numero']??'',$data['tabela_servico_id']??null,$data['codigo_nbs']??'',(float)($data['iss_percentual']??0),$data['nfse_natureza']??'tributacao_municipio',$data['nfse_incentivo_fiscal']??'nao',$data['observacoes']??'',date('Y-m-d H:i:s'),$id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM produtos WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
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
        $page   = max(1, (int)($_GET['page'] ?? 1));
        $limit  = 20; $offset = ($page - 1) * $limit;
        $where = ['1=1']; $params = [];
        if ($status !== '') { $where[] = 'os.status = ?'; $params[] = $status; }
        if ($q_raw !== '') { $where[] = '(LOWER(c.nome) LIKE ? OR CAST(os.id AS TEXT) LIKE ? OR c.telefone LIKE ?)'; $params = array_merge($params, [$q, $q, $q]); }
        $w = implode(' AND ', $where);
        $tc = $db->prepare("SELECT COUNT(*) FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();
        $s = $db->prepare("SELECT os.*, c.nome AS cliente_nome, c.telefone AS cliente_telefone, ta.nome AS tipo_nome, m.nome AS marca_nome, mo.nome AS modelo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id LEFT JOIN marcas m ON os.marca_id=m.id LEFT JOIN modelos mo ON os.modelo_id=mo.id WHERE $w ORDER BY os.id DESC LIMIT ? OFFSET ?");
        $s->execute(array_merge($params, [$limit, $offset]));
        resp(200, ['data' => $s->fetchAll(), 'total' => $total, 'page' => $page, 'pages' => (int)ceil($total / $limit)]);
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT os.*, c.nome AS cliente_nome, c.telefone AS cliente_telefone, c.cpf AS cliente_cpf, ta.nome AS tipo_nome, m.nome AS marca_nome, mo.nome AS modelo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id LEFT JOIN marcas m ON os.marca_id=m.id LEFT JOIN modelos mo ON os.modelo_id=mo.id WHERE os.id=?");
        $s->execute([$id]); $os = $s->fetch();
        if (!$os) resp(404, ['error' => 'Não encontrado']);
        $s2 = $db->prepare("SELECT * FROM orcamentos WHERE ordem_id=? ORDER BY id"); $s2->execute([$id]); $os['orcamentos'] = $s2->fetchAll();
        $s3 = $db->prepare("SELECT * FROM midias_os WHERE ordem_id=? ORDER BY id DESC"); $s3->execute([$id]); $os['midias'] = $s3->fetchAll();
        $s4 = $db->prepare("SELECT o.*, u.nome AS usuario_nome FROM ordem_observacoes o LEFT JOIN usuarios u ON o.usuario_id=u.id WHERE o.ordem_id=? ORDER BY o.id DESC"); $s4->execute([$id]); $os['observacoes'] = $s4->fetchAll();
        resp(200, $os);
    }
    if ($method === 'POST') {
        if (empty($data['cliente_id'])) resp(400, ['error' => 'cliente_id obrigatório']);
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO ordens_servico (cliente_id,tipo_aparelho_id,marca_id,modelo_id,descricao,informacoes_adicionais,senha_aparelho,status,data_abertura) VALUES (?,?,?,?,?,?,?,?,?)")
               ->execute([$data['cliente_id'],$data['tipo_aparelho_id']??null,$data['marca_id']??null,$data['modelo_id']??null,$data['descricao']??'',$data['informacoes_adicionais']??'',$data['senha_aparelho']??'',$data['status']??'Aberta',date('Y-m-d H:i:s')]);
            $lid = (int)$db->lastInsertId(); $db->commit();
            resp(201, ['success' => true, 'id' => $lid]);
        } catch (Exception $e) { $db->rollBack(); resp(500, ['error' => $e->getMessage()]); }
    }
    if ($method === 'PUT' && $id !== null) {
        $db->beginTransaction();
        try {
            $old = $db->prepare("SELECT status FROM ordens_servico WHERE id=?"); $old->execute([$id]); $old_s = $old->fetchColumn();
            $new_s = $data['status'] ?? 'Aberta';
            $db->prepare("UPDATE ordens_servico SET cliente_id=?,tipo_aparelho_id=?,marca_id=?,modelo_id=?,descricao=?,informacoes_adicionais=?,senha_aparelho=?,status=?,previsao_conclusao=?,data_atualizacao=? WHERE id=?")
               ->execute([$data['cliente_id'],$data['tipo_aparelho_id']??null,$data['marca_id']??null,$data['modelo_id']??null,$data['descricao']??'',$data['informacoes_adicionais']??'',$data['senha_aparelho']??'',$new_s,$data['previsao_conclusao']??null,date('Y-m-d H:i:s'),$id]);
            if ($old_s && $old_s !== $new_s) $db->prepare("INSERT INTO notificacoes (ordem_id,novo_status) VALUES (?,?)")->execute([$id,$new_s]);
            $db->commit(); resp(200, ['success' => true]);
        } catch (Exception $e) { $db->rollBack(); resp(500, ['error' => $e->getMessage()]); }
    }
    if ($method === 'DELETE' && $id !== null) {
        $s = $db->prepare("SELECT caminho FROM midias_os WHERE ordem_id=?"); $s->execute([$id]);
        foreach ($s->fetchAll() as $m) { $p = __DIR__ . '/' . ltrim($m['caminho'],'/'); if (file_exists($p)) unlink($p); }
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
        $db->prepare("INSERT INTO orcamentos (ordem_id,observacoes,valor,status_orcamento) VALUES (?,?,?,?)")
           ->execute([$data['ordem_id'],$data['observacoes']??'',$data['valor']??0,$data['status_orcamento']??'Pendente']);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE orcamentos SET observacoes=?,valor=?,status_orcamento=? WHERE id=?")
           ->execute([$data['observacoes']??'',$data['valor']??0,$data['status_orcamento']??'Pendente',$id]);
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM orcamentos WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
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
        resp(200, $db->query("SELECT id,nome,email,nivel_acesso,COALESCE(ativo,1) as ativo FROM usuarios ORDER BY nome")->fetchAll());
    }
    if ($method === 'GET' && $id !== null) {
        $s = $db->prepare("SELECT id,nome,email,nivel_acesso,COALESCE(ativo,1) as ativo FROM usuarios WHERE id=?"); $s->execute([$id]);
        $r = $s->fetch(); resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }
    if ($method === 'POST') {
        if (empty($data['nome']) || empty($data['senha'])) resp(400, ['error' => 'Nome e senha obrigatórios']);
        $h = password_hash($data['senha'], PASSWORD_DEFAULT);
        $db->prepare("INSERT INTO usuarios (nome,email,senha,nivel_acesso) VALUES (?,?,?,?)")
           ->execute([$data['nome'],$data['email']??'',$h,$data['nivel_acesso']??'tecnico']);
        resp(201, ['success' => true, 'id' => (int)$db->lastInsertId()]);
    }
    if ($method === 'PUT' && $id !== null) {
        if (!empty($data['senha'])) {
            $h = password_hash($data['senha'], PASSWORD_DEFAULT);
            $db->prepare("UPDATE usuarios SET nome=?,email=?,senha=?,nivel_acesso=? WHERE id=?")->execute([$data['nome'],$data['email']??'',$h,$data['nivel_acesso']??'tecnico',$id]);
        } else {
            $db->prepare("UPDATE usuarios SET nome=?,email=?,nivel_acesso=? WHERE id=?")->execute([$data['nome'],$data['email']??'',$data['nivel_acesso']??'tecnico',$id]);
        }
        resp(200, ['success' => true]);
    }
    if ($method === 'DELETE' && $id !== null) {
        $db->prepare("DELETE FROM usuarios WHERE id=?")->execute([$id]); resp(200, ['success' => true]);
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
        $uploads_dir = __DIR__ . '/uploads/';
        if (!is_dir($uploads_dir)) mkdir($uploads_dir, 0755, true);
        $arquivos = $_FILES['midia'] ?? [];
        if (empty($arquivos['name'])) resp(400, ['error' => 'Nenhum arquivo enviado']);
        // Normaliza estrutura (múltiplos arquivos vs único)
        $nomes    = is_array($arquivos['name'])    ? $arquivos['name']    : [$arquivos['name']];
        $tmps     = is_array($arquivos['tmp_name']) ? $arquivos['tmp_name'] : [$arquivos['tmp_name']];
        $erros    = is_array($arquivos['error'])   ? $arquivos['error']   : [$arquivos['error']];
        $comments = isset($_POST['midia_comment']) ? (is_array($_POST['midia_comment']) ? $_POST['midia_comment'] : [$_POST['midia_comment']]) : [];
        $salvos = [];
        foreach ($nomes as $i => $nome_original) {
            if ($erros[$i] !== UPLOAD_ERR_OK) continue;
            $ext  = strtolower(pathinfo($nome_original, PATHINFO_EXTENSION));
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
        if ($row) { $p = __DIR__ . '/' . ltrim($row['caminho'],'/'); if (file_exists($p)) unlink($p); }
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
    $uploads_dir = __DIR__ . '/uploads/';
    if (!is_dir($uploads_dir)) mkdir($uploads_dir, 0755, true);
    $arquivos = $_FILES['imagens'] ?? [];
    if (empty($arquivos['name'])) resp(400, ['error' => 'Nenhum arquivo recebido']);
    $nomes = is_array($arquivos['name']) ? $arquivos['name'] : [$arquivos['name']];
    $tmps  = is_array($arquivos['tmp_name']) ? $arquivos['tmp_name'] : [$arquivos['tmp_name']];
    $erros = is_array($arquivos['error']) ? $arquivos['error'] : [$arquivos['error']];
    $salvos = [];
    foreach ($nomes as $i => $nome_original) {
        if ($erros[$i] !== UPLOAD_ERR_OK) continue;
        $ext  = strtolower(pathinfo($nome_original, PATHINFO_EXTENSION));
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
    $s['ordens_em_andamento'] = (int)$db->query("SELECT COUNT(*) FROM ordens_servico WHERE status NOT IN ('Aberta','Entregue','Retirada','Cancelada') AND status NOT LIKE 'Conclu%' AND status NOT LIKE 'N_o Aprovada' AND status NOT LIKE 'Sem Con%'")->fetchColumn();
    $s['total_clientes']      = (int)$db->query("SELECT COUNT(*) FROM clientes")->fetchColumn();
    $s['total_produtos']      = (int)$db->query("SELECT COUNT(*) FROM produtos WHERE ativo=1")->fetchColumn();
    $s['notificacoes']        = (int)$db->query("SELECT COUNT(*) FROM notificacoes WHERE lida=0")->fetchColumn();
    $s['por_status']          = $db->query("SELECT status, COUNT(*) as total FROM ordens_servico GROUP BY status ORDER BY total DESC")->fetchAll();
    $s['recentes']            = $db->query("SELECT os.id, os.status, os.data_abertura, c.nome AS cliente_nome, ta.nome AS tipo_nome FROM ordens_servico os JOIN clientes c ON os.cliente_id=c.id LEFT JOIN tipos_aparelho ta ON os.tipo_aparelho_id=ta.id ORDER BY os.id DESC LIMIT 5")->fetchAll();
    resp(200, $s);
}

// ─── CONSULTA PÚBLICA ─────────────────────────────────────────
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
            $subtotal_bruto = array_sum(array_map(fn($i)=>(+$i['quantidade'])*(+$i['valor_unitario']), $items));
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
            if (!$d_conf) $d_conf = date('Y-m-d H:i:s');
            $db->prepare("INSERT INTO vendas (cliente_id,vendedor_id,os_id,cpf_cnpj,data_criacao,data_confirmacao,status,total,desconto_valor,desconto_percentual,desconto_tipo,acrescimo_valor,acrescimo_percentual,acrescimo_tipo,valor_frete,observacoes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([$data['cliente_id']??null,null,$os_id,$cpf,$d_cri,$d_conf,$data['status']??'Paga',$total,$desc_val,$desc_pct,$desc_tipo,$acres_val,$acres_pct,$acres_tipo,$frete,$data['observacoes']??'']);
            $vid = (int)$db->lastInsertId();
            foreach ($items as $item) {
                $qty = (float)($item['quantidade']??1);
                $vu  = (float)($item['valor_unitario']??0);
                $db->prepare("INSERT INTO venda_items (venda_id,produto_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)")
                   ->execute([$vid,$item['produto_id']??null,$qty,$vu,round($qty*$vu,2)]);
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

            // ── Gerar contas a receber automaticamente ────────────────────
            // Uma conta por parcela de cada faturamento
            $sf2 = $db->prepare("SELECT f.*, p.id as parc_id, p.numero as parc_num, p.valor as parc_val, p.data_vencimento as parc_venc FROM venda_faturamentos f JOIN venda_parcelas p ON p.faturamento_id=f.id WHERE f.venda_id=?");
            $sf2->execute([$vid]);
            $parcelas_geradas = $sf2->fetchAll();
            $now_cr = date('Y-m-d H:i:s');
            $cli_id_cr = $data['cliente_id'] ?? null;
            foreach ($parcelas_geradas as $parc) {
                $nparcelas_fat = (int)$parc['num_parcelas'];
                $desc_cr = $nparcelas_fat > 1
                    ? "Venda #{$vid} — Parcela {$parc['parc_num']}/{$nparcelas_fat} ({$parc['forma_pagamento_nome']})"
                    : "Venda #{$vid} — {$parc['forma_pagamento_nome']}";
                $status_cr = ($data['status'] ?? 'Paga') === 'Paga' ? 'Recebida' : 'Aberta';
                $val_rec   = $status_cr === 'Recebida' ? (float)$parc['parc_val'] : 0;
                $dt_rec    = $status_cr === 'Recebida' ? date('Y-m-d') : null;
                $db->prepare("INSERT INTO contas_receber (origem,venda_id,parcela_id,cliente_id,descricao,valor,valor_recebido,data_emissao,data_vencimento,data_recebimento,status,data_criacao,data_atualizacao) VALUES ('venda',?,?,?,?,?,?,?,?,?,?,?,?)")
                   ->execute([$vid, $parc['parc_id'], $cli_id_cr, $desc_cr, (float)$parc['parc_val'], $val_rec, date('Y-m-d'), $parc['parc_venc'], $dt_rec, $status_cr, $now_cr, $now_cr]);
            }

            $db->commit();
            resp(201,['success'=>true,'id'=>$vid,'total'=>$total]);
        } catch(Exception $e){$db->rollBack();resp(500,['error'=>$e->getMessage()]);}
    }
    if ($method === 'PUT' && $id !== null) {
        $db->prepare("UPDATE vendas SET status=?,observacoes=? WHERE id=?")
           ->execute([$data['status']??'Paga',$data['observacoes']??'',$id]);
        resp(200,['success'=>true]);
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

// ─── TABELAS DE SERVIÇO ───────────────────────────────────────
// ─── NOTAS FISCAIS DE ENTRADA ────────────────────────────────
if ($resource === 'nfe') {
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
            // codigo_barras do XML: usar NULL se vazio (evita UNIQUE constraint)
            $cod_barras_xml = !empty($cod) ? $cod : null;
            $db->prepare("INSERT INTO produtos (tipo_item,codigo_interno,codigo_barras,descricao,unidade_medida,preco_custo,preco_venda,ncm,estoque_atual,ativo,data_criacao,data_atualizacao) VALUES ('produto',?,?,?,?,?,?,?,0,1,?,?)")
               ->execute([$newCod,$cod_barras_xml,$desc,$un,$vUnit,$vUnit,$ncm,$now2,$now2]);
            $prodId=(int)$db->lastInsertId();
            $avisos[]="✅ Produto cadastrado automaticamente: {$desc} (Cód: {$newCod})";
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
        if ($q_raw)    { $where[] = '(cr.descricao LIKE ? OR c.nome LIKE ? OR cr.documento_ref LIKE ?)'; $q = '%'.$q_raw.'%'; $params[] = $q; $params[] = $q; $params[] = $q; }
        if ($data_ini) { $where[] = 'cr.data_vencimento >= ?'; $params[] = $data_ini; }
        if ($data_fim) { $where[] = 'cr.data_vencimento <= ?'; $params[] = $data_fim; }
        if ($vencidas === '1') { $where[] = "cr.data_vencimento < DATE('now') AND cr.status='Aberta'"; }
        $w = implode(' AND ', $where);

        $tc = $db->prepare("SELECT COUNT(*) FROM contas_receber cr LEFT JOIN clientes c ON cr.cliente_id=c.id WHERE $w");
        $tc->execute($params); $total = (int)$tc->fetchColumn();

        $s = $db->prepare("
            SELECT cr.*,
                   c.nome  AS cliente_nome,
                   cf.nome AS categoria_nome, cf.cor AS categoria_cor,
                   cb.nome AS conta_bancaria_nome
            FROM contas_receber cr
            LEFT JOIN clientes c          ON cr.cliente_id=c.id
            LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id
            LEFT JOIN contas_bancarias cb  ON cr.conta_bancaria_id=cb.id
            WHERE $w
            ORDER BY cr.data_vencimento ASC, cr.id DESC
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
        $s = $db->prepare("SELECT cr.*, c.nome AS cliente_nome, cf.nome AS categoria_nome FROM contas_receber cr LEFT JOIN clientes c ON cr.cliente_id=c.id LEFT JOIN categorias_financeiras cf ON cr.categoria_id=cf.id WHERE cr.id=?");
        $s->execute([$id]); $r = $s->fetch();
        resp($r ? 200 : 404, $r ?: ['error' => 'Não encontrado']);
    }

    // ── POST criar manual ─────────────────────────────────────────────────
    if ($method === 'POST' && $action !== 'receber' && $action !== 'cancelar') {
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
        $w = implode(' AND ', $where);

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
            ORDER BY cp.data_vencimento ASC, cp.id DESC
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
    if ($method === 'POST' && $action !== 'pagar' && $action !== 'cancelar') {
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

    if ($method === 'POST') {
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
            'storage_dir'       => __DIR__ . '/storage/nfce',
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
            $db->prepare("INSERT INTO nfce_emitidas (os_id,venda_id,status,numero,serie,chave_acesso,valor_total,motivo_rejeicao,n_prot,ambiente,cliente_nome,cfop,payload_json,data_emissao,data_atualizacao) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
               ->execute([$data['os_id']??null,$data['venda_id']??null,$status,$numero,$serie_ins,$resultado['chave']??'',$data['valor_total']??0,$resultado['xMotivo']??'',$n_prot_ins,$config['ambiente'],$cliente_nome_ins,$cfop_ins,json_encode($data),$now,$now]);
            $local_id=(int)$db->lastInsertId();
            if(!$resultado['autorizada'])
                $db->exec("UPDATE empresa_dados SET nfce_proximo_numero=nfce_proximo_numero-1 WHERE id=1");
            // Sempre retorna 200 para que o frontend leia xMotivo/cStat mesmo em rejeição
            resp(200, array_merge($resultado, ['id'=>$local_id,'numero'=>$numero]));
        } catch(\Exception $e) {
            $db->exec("UPDATE empresa_dados SET nfce_proximo_numero=nfce_proximo_numero-1 WHERE id=1");
            resp(500,['error'=>$e->getMessage()]);
        }
    }

    if ($method === 'DELETE' && $id !== null) {
        if(!$nfephp_ok) resp(400,['error'=>'NFePHP não instalado']);
        $s=$db->prepare("SELECT * FROM nfce_emitidas WHERE id=?"); $s->execute([$id]); $nf=$s->fetch();
        if(!$nf) resp(404,['error'=>'NFC-e não encontrada']);
        $just=$data['justificativa']??'';
        if(strlen($just)<15) resp(400,['error'=>'Justificativa mínimo 15 caracteres']);
        try {
            require_once $autoload;
            require_once __DIR__.'/src/NfceService.php';
            $emp2=$db->query("SELECT * FROM empresa_dados WHERE id=1")->fetch();
            $cfg2=['ambiente'=>$emp2['nfce_ambiente']??'homologacao','csc'=>$emp2['nfce_csc'],'csc_id'=>$emp2['nfce_csc_id'],'certificado_pfx'=>$emp2['certificado_pfx'],'certificado_senha'=>$data['cert_senha']??$emp2['nfce_cert_senha']??'','storage_dir'=>__DIR__.'/storage/nfce','empresa'=>['cnpj'=>$emp2['cnpj'],'razao_social'=>$emp2['razao_social'],'nome_fantasia'=>$emp2['nome'],'ie'=>$emp2['ie'],'cMun'=>$emp2['nfce_cmun']??'','cUF'=>(int)($emp2['nfce_cuf']??42),'uf'=>$emp2['uf'],'logradouro'=>$emp2['logradouro'],'numero'=>$emp2['numero'],'bairro'=>$emp2['bairro'],'cidade'=>$emp2['cidade'],'cep'=>$emp2['cep'],'telefone'=>$emp2['telefone']]];
            $svc=new \ConsertaOS\NfcE\NfceService($cfg2);
            $svc->cancelar($nf['chave_acesso'],$just,$nf['n_prot']??'');
            $db->prepare("UPDATE nfce_emitidas SET status='Cancelada',data_atualizacao=? WHERE id=?")->execute([date('Y-m-d H:i:s'),$id]);
            resp(200,['success'=>true]);
        } catch(\Exception $e){ resp(500,['error'=>$e->getMessage()]); }
    }
    resp(405,['error'=>'Método não permitido']);
}

;