<?php
/**
 * diagnostico_nfephp.php
 * Coloque este arquivo em: consertav2/diagnostico_nfephp.php
 * Acesse via navegador: https://consertaos.iltda.net.br/consertav2/diagnostico_nfephp.php
 * APAGUE o arquivo do servidor após usar.
 */

$autoload = __DIR__ . '/nfephp/vendor/autoload.php';
if (!file_exists($autoload)) {
    die(json_encode(['erro' => 'autoload não encontrado em ' . $autoload]));
}
require_once $autoload;

header('Content-Type: application/json; charset=utf-8');

$resultado = [];

// Versão do sped-nfe
$composerLock = __DIR__ . '/nfephp/composer.lock';
if (file_exists($composerLock)) {
    $lock = json_decode(file_get_contents($composerLock), true);
    foreach ($lock['packages'] ?? [] as $pkg) {
        if (in_array($pkg['name'], ['nfephp-org/sped-nfe', 'nfephp-org/sped-common', 'nfephp-org/sped-da'])) {
            $resultado['versoes'][$pkg['name']] = $pkg['version'];
        }
    }
}

// Todos os métodos tag* da classe Make
$ref = new ReflectionClass('NFePHP\NFe\Make');
$metodos = [];
foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
    if (str_starts_with($m->getName(), 'tag')) {
        $metodos[] = $m->getName();
    }
}
sort($metodos);
$resultado['metodos_tag'] = $metodos;
$resultado['total_metodos_tag'] = count($metodos);

// Filtra especificamente PIS e COFINS
$resultado['metodos_pis_cofins'] = array_values(array_filter($metodos, function($m) {
    return str_contains(strtoupper($m), 'PIS') || str_contains(strtoupper($m), 'COFINS');
}));

echo json_encode($resultado, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
