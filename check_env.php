<?php
/**
 * ConsertaOS — Diagnóstico de ambiente para NFePHP
 * Coloque este arquivo na raiz do site e acesse via navegador UMA VEZ.
 * APAGUE depois de verificar (contém informações sensíveis do servidor).
 */

// Segurança mínima: só exibir para o próprio IP ou com senha
// $senha = $_GET['key'] ?? ''; if($senha !== 'minha_senha_aqui') die('Acesso negado.');

header('Content-Type: text/plain; charset=utf-8');

echo "============================================\n";
echo " ConsertaOS — Diagnóstico NFePHP\n";
echo " Data: " . date('d/m/Y H:i:s') . "\n";
echo "============================================\n\n";

// PHP
echo "=== PHP ===\n";
echo "Versão: " . PHP_VERSION . "\n";
echo "Mínimo necessário: 8.0 — " . (version_compare(PHP_VERSION, '8.0.0', '>=') ? "OK ✓" : "FALHOU ✗ (atualize o PHP)") . "\n\n";

// Extensões obrigatórias
echo "=== Extensões obrigatórias ===\n";
$required = [
    'openssl'   => 'Assinatura digital do XML',
    'curl'      => 'Comunicação com SEFAZ',
    'dom'       => 'Geração de XML',
    'zip'       => 'Compactação',
    'zlib'      => 'Compressão',
    'json'      => 'Serialização',
    'mbstring'  => 'Strings multibyte',
    'fileinfo'  => 'Detecção de tipos',
    'libxml'    => 'Parser XML',
    'soap'      => 'Webservice SEFAZ',
];
$allOk = true;
foreach ($required as $ext => $desc) {
    $ok = extension_loaded($ext);
    if (!$ok) $allOk = false;
    echo sprintf("%-12s %-38s %s\n", $ext, "($desc)", $ok ? "OK ✓" : "AUSENTE ✗");
}

// Funções críticas
echo "\n=== Funções OpenSSL ===\n";
$funcs = ['openssl_pkcs12_read', 'openssl_x509_parse', 'openssl_sign', 'openssl_pkcs7_sign'];
foreach ($funcs as $f) {
    echo sprintf("%-30s %s\n", $f, function_exists($f) ? "OK ✓" : "AUSENTE ✗");
}

// SoapClient
echo "\n=== SOAP ===\n";
echo "SoapClient: " . (class_exists('SoapClient') ? "OK ✓" : "AUSENTE ✗") . "\n";

// Composer
echo "\n=== Composer ===\n";
$composer = shell_exec('composer --version 2>&1');
if ($composer && strpos($composer, 'Composer') !== false) {
    echo "Composer: " . trim($composer) . "\n";
} else {
    $composer2 = shell_exec('php composer.phar --version 2>&1');
    if ($composer2 && strpos($composer2, 'Composer') !== false) {
        echo "Composer (phar): " . trim($composer2) . "\n";
    } else {
        echo "Composer: AUSENTE ✗\n";
        echo "  → Baixe em https://getcomposer.org/download/\n";
    }
}

// Permissões de escrita
echo "\n=== Permissões de escrita ===\n";
$dirs = [
    __DIR__ . '/storage'       => 'storage/ (XMLs e logs)',
    __DIR__ . '/storage/nfce'  => 'storage/nfce/',
    sys_get_temp_dir()         => 'Temp do sistema (' . sys_get_temp_dir() . ')',
];
foreach ($dirs as $dir => $label) {
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    echo sprintf("%-45s %s\n", $label, is_writable($dir) ? "OK ✓" : "SEM PERMISSÃO ✗");
}

// Conectividade SEFAZ (SC — adapte para seu estado)
echo "\n=== Conectividade externa (SEFAZ) ===\n";
$urls = [
    'https://nfce.fazenda.sc.gov.br/nfce/consulta' => 'SEFAZ-SC NFC-e',
    'https://www.google.com'                         => 'Internet geral',
];
foreach ($urls as $url => $label) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_NOBODY         => true,
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    $ok = ($code >= 200 && $code < 500);
    echo sprintf("%-45s %s\n", $label, $ok ? "OK ✓ (HTTP $code)" : "FALHOU ✗ ($err)");
}

// shell_exec disponível?
echo "\n=== Shell ===\n";
echo "shell_exec: " . (function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', ini_get('disable_functions')))) ? "OK ✓" : "BLOQUEADO ✗") . "\n";

// Resumo
echo "\n============================================\n";
echo $allOk ? "✓ AMBIENTE OK — pode prosseguir com NFePHP\n" : "✗ PROBLEMAS ENCONTRADOS — veja itens com ✗\n";
echo "============================================\n";
echo "\nAPAGUE ESTE ARQUIVO APÓS O DIAGNÓSTICO!\n";
