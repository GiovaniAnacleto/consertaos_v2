<?php
/**
 * ConsertaOS — Instalador NFePHP via navegador
 * 
 * INSTRUÇÕES:
 * 1. Suba este arquivo para a raiz do site
 * 2. Acesse: https://seusite.com.br/instalar_nfephp.php
 * 3. Clique em "Instalar NFePHP"
 * 4. APAGUE este arquivo imediatamente após a instalação!
 * 
 * SEGURANÇA: protegido por senha para evitar acesso não autorizado
 */

define('SENHA_INSTALADOR', 'consertaos2025'); // Troque antes de subir!
define('BASE_DIR', __DIR__);
define('NFEPHP_DIR', BASE_DIR . '/nfephp');

session_start();

// ── Verificar senha ──────────────────────────────────────────────
$autenticado = ($_SESSION['instalador_ok'] ?? false);
if (!$autenticado) {
    if ($_POST['senha'] ?? '' === SENHA_INSTALADOR) {
        $_SESSION['instalador_ok'] = true;
        $autenticado = true;
    }
}

// ── Ação de instalação (POST) ────────────────────────────────────
$log = [];
$erro = null;
$concluido = false;

if ($autenticado && ($_POST['acao'] ?? '') === 'instalar') {
    set_time_limit(300); // 5 minutos
    ini_set('memory_limit', '256M');
    
    function log_add(&$log, $msg) {
        $log[] = date('[H:i:s] ') . $msg;
        ob_flush(); flush();
    }

    try {
        // 1. Criar pasta nfephp
        log_add($log, 'Criando pasta nfephp/...');
        if (!is_dir(NFEPHP_DIR)) mkdir(NFEPHP_DIR, 0755, true);

        // 2. Criar .user.ini para permitir phar (necessário Locaweb)
        $userIni = BASE_DIR . '/.user.ini';
        if (!file_exists($userIni) || strpos(file_get_contents($userIni), 'phar') === false) {
            log_add($log, 'Configurando .user.ini para suporte a phar...');
            $iniContent = file_exists($userIni) ? file_get_contents($userIni) : '';
            file_put_contents($userIni, $iniContent . "\nsuhosin.executor.include.whitelist = phar\n");
        }

        // 3. Baixar Composer
        $composerPhar = NFEPHP_DIR . '/composer.phar';
        if (!file_exists($composerPhar)) {
            log_add($log, 'Baixando Composer...');
            $composerSetup = file_get_contents('https://getcomposer.org/installer');
            if (!$composerSetup) throw new Exception('Não foi possível baixar o Composer. Verifique a conexão do servidor.');
            file_put_contents(NFEPHP_DIR . '/composer-setup.php', $composerSetup);
            
            // Executar instalador do Composer
            $output = shell_exec('cd ' . NFEPHP_DIR . ' && php composer-setup.php --quiet 2>&1');
            @unlink(NFEPHP_DIR . '/composer-setup.php');
            
            if (!file_exists($composerPhar)) {
                // Tentar baixar o phar diretamente
                log_add($log, 'Tentando download direto do composer.phar...');
                $phar = file_get_contents('https://getcomposer.org/composer-stable.phar');
                if (!$phar) throw new Exception('Falha ao baixar composer.phar');
                file_put_contents($composerPhar, $phar);
            }
            log_add($log, 'Composer instalado.');
        } else {
            log_add($log, 'Composer já existe, pulando download.');
        }

        // 4. Criar composer.json na pasta nfephp
        $composerJson = NFEPHP_DIR . '/composer.json';
        log_add($log, 'Criando composer.json...');
        file_put_contents($composerJson, json_encode([
            'name'    => 'consertaos/nfce',
            'require' => [
                'php'                       => '>=8.0',
                'nfephp-org/sped-nfe'       => '^5.1',
                'nfephp-org/sped-da'        => '^5.1',
                'nfephp-org/sped-common'    => '^5.2',
            ],
            'config' => [
                'optimize-autoloader' => true,
                'sort-packages'       => true,
                'vendor-dir'          => 'vendor',
            ],
            'minimum-stability' => 'stable',
            'prefer-stable'     => true,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        // 5. Rodar composer install
        log_add($log, 'Instalando NFePHP via Composer (pode demorar 2-5 min)...');
        $phpBin = PHP_BINARY ?: 'php';
        $cmd = 'cd ' . escapeshellarg(NFEPHP_DIR) . ' && '
             . escapeshellarg($phpBin) . ' composer.phar install --no-dev --optimize-autoloader --no-interaction 2>&1';
        $output = shell_exec($cmd);
        $log[] = '<pre style="font-size:11px;background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:4px;max-height:200px;overflow-y:auto">' . htmlspecialchars($output ?? '') . '</pre>';

        if (!file_exists(NFEPHP_DIR . '/vendor/autoload.php')) {
            throw new Exception("vendor/autoload.php não encontrado após instalação.\nOutput: " . ($output ?? 'vazio'));
        }
        log_add($log, '✅ NFePHP instalado com sucesso!');

        // 6. Criar pastas de storage
        log_add($log, 'Criando pastas de storage...');
        foreach (['storage/nfce/autorizada','storage/nfce/cancelada','storage/nfce/rejeitada','storage/nfce/pendente','storage/logs'] as $dir) {
            $path = BASE_DIR . '/' . $dir;
            if (!is_dir($path)) mkdir($path, 0755, true);
        }

        // 7. Criar pasta src/ se não existir
        if (!is_dir(BASE_DIR . '/src')) mkdir(BASE_DIR . '/src', 0755, true);
        log_add($log, 'Pasta src/ verificada.');

        // 8. Verificar NfceService.php
        if (file_exists(BASE_DIR . '/src/NfceService.php')) {
            log_add($log, '✅ src/NfceService.php encontrado.');
        } else {
            log_add($log, '⚠️  src/NfceService.php NÃO encontrado — suba o arquivo via FTP.');
        }

        $concluido = true;
        log_add($log, '🎉 Instalação concluída! APAGUE ESTE ARQUIVO AGORA.');

    } catch (Exception $e) {
        $erro = $e->getMessage();
        $log[] = '❌ ERRO: ' . htmlspecialchars($erro);
    }
}

// ── Verificar status atual ───────────────────────────────────────
$status = [
    'nfephp'    => file_exists(NFEPHP_DIR . '/vendor/autoload.php'),
    'composer'  => file_exists(NFEPHP_DIR . '/composer.phar'),
    'service'   => file_exists(BASE_DIR . '/src/NfceService.php'),
    'storage'   => is_dir(BASE_DIR . '/storage/nfce/autorizada'),
    'shell_exec'=> function_exists('shell_exec') && !in_array('shell_exec', array_map('trim', explode(',', ini_get('disable_functions')))),
    'curl'      => function_exists('curl_init'),
    'php'       => PHP_VERSION,
];
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ConsertaOS — Instalador NFePHP</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, sans-serif; background: #f5f5f5; color: #333; }
.wrap { max-width: 680px; margin: 40px auto; padding: 0 20px; }
h1 { font-size: 22px; margin-bottom: 6px; }
.sub { color: #666; font-size: 13px; margin-bottom: 24px; }
.card { background: #fff; border-radius: 8px; border: 1px solid #e0e0e0; padding: 20px; margin-bottom: 16px; }
.card h2 { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: #555; margin-bottom: 14px; }
.row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
.row:last-child { border-bottom: none; }
.ok  { color: #10b981; font-weight: 600; }
.err { color: #ef4444; font-weight: 600; }
.warn { color: #f59e0b; font-weight: 600; }
.btn { display: inline-block; padding: 10px 24px; background: #e85d26; color: #fff; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none; }
.btn:hover { background: #c94e1e; }
.btn-sec { background: #6b7280; }
.btn-sec:hover { background: #4b5563; }
.log-area { background: #1e1e1e; color: #d4d4d4; border-radius: 6px; padding: 14px; font-family: monospace; font-size: 12px; max-height: 320px; overflow-y: auto; }
.log-area p { margin: 2px 0; }
.alert { padding: 12px 16px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; }
.alert-warn { background: rgba(251,191,36,.1); border: 1px solid #f59e0b; }
.alert-err  { background: rgba(239,68,68,.1);  border: 1px solid #ef4444; }
.alert-ok   { background: rgba(16,185,129,.1); border: 1px solid #10b981; }
input[type=password], input[type=text] { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; margin-bottom: 10px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>🔧 ConsertaOS — Instalador NFePHP</h1>
  <p class="sub">Instala o NFePHP (sped-nfe) para emissão de NFC-e diretamente no servidor.</p>

  <?php if (!$autenticado): ?>
  <!-- Tela de login -->
  <div class="card">
    <h2>Acesso restrito</h2>
    <form method="POST">
      <input type="password" name="senha" placeholder="Senha do instalador" autofocus/>
      <button type="submit" class="btn">Entrar</button>
    </form>
    <?php if (isset($_POST['senha'])): ?>
      <p style="color:#ef4444;margin-top:8px;font-size:13px">Senha incorreta.</p>
    <?php endif; ?>
  </div>

  <?php else: ?>

  <!-- Status atual -->
  <div class="card">
    <h2>Status atual</h2>
    <div class="row"><span>PHP <?= $status['php'] ?></span><span class="ok">OK ✓</span></div>
    <div class="row"><span>NFePHP (vendor/autoload.php)</span><span class="<?= $status['nfephp'] ? 'ok' : 'err' ?>"><?= $status['nfephp'] ? 'Instalado ✓' : 'Não instalado ✗' ?></span></div>
    <div class="row"><span>Composer.phar</span><span class="<?= $status['composer'] ? 'ok' : 'warn' ?>"><?= $status['composer'] ? 'Presente ✓' : 'Ausente (será baixado)' ?></span></div>
    <div class="row"><span>src/NfceService.php</span><span class="<?= $status['service'] ? 'ok' : 'warn' ?>"><?= $status['service'] ? 'Presente ✓' : 'Ausente — suba via FTP' ?></span></div>
    <div class="row"><span>Pastas storage/</span><span class="<?= $status['storage'] ? 'ok' : 'warn' ?>"><?= $status['storage'] ? 'Criadas ✓' : 'Serão criadas' ?></span></div>
    <div class="row"><span>shell_exec (necessário)</span><span class="<?= $status['shell_exec'] ? 'ok' : 'err' ?>"><?= $status['shell_exec'] ? 'Disponível ✓' : 'BLOQUEADO ✗' ?></span></div>
    <div class="row"><span>cURL</span><span class="<?= $status['curl'] ? 'ok' : 'err' ?>"><?= $status['curl'] ? 'OK ✓' : 'AUSENTE ✗' ?></span></div>
  </div>

  <?php if (!$status['shell_exec']): ?>
  <div class="alert alert-err">
    <strong>❌ shell_exec bloqueado</strong> — O seu plano não permite executar comandos no servidor. 
    O Composer precisa de <code>shell_exec</code> para rodar. 
    Entre em contato com a Locaweb e peça para <strong>liberar shell_exec</strong> ou 
    <strong>habilitar SSH completo</strong> na sua hospedagem.
  </div>
  <?php endif; ?>

  <?php if ($status['shell_exec']): ?>
  <div class="alert alert-warn">
    ⚠️ <strong>Apague este arquivo imediatamente após a instalação!</strong> 
    Deixá-lo no servidor é um risco de segurança.
  </div>
  <?php endif; ?>

  <?php if ($concluido): ?>
  <div class="alert alert-ok">
    🎉 <strong>NFePHP instalado com sucesso!</strong> 
    Volte ao ConsertaOS e vá em <strong>Administração → Configurações → NFC-e</strong> para configurar o CSC.
    <br><strong style="color:#ef4444">APAGUE ESTE ARQUIVO AGORA!</strong>
  </div>
  <?php endif; ?>

  <!-- Log de execução -->
  <?php if (!empty($log)): ?>
  <div class="card">
    <h2>Log da instalação</h2>
    <div class="log-area">
      <?php foreach ($log as $linha): ?>
        <p><?= $linha ?></p>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

  <!-- Botão instalar -->
  <?php if (!$concluido && $status['shell_exec']): ?>
  <form method="POST">
    <input type="hidden" name="acao" value="instalar"/>
    <div class="card">
      <h2>Instalar NFePHP</h2>
      <p style="font-size:13px;color:#555;margin-bottom:14px">
        O processo vai baixar o Composer e instalar as bibliotecas 
        <code>sped-nfe</code>, <code>sped-da</code> e <code>sped-common</code> 
        na pasta <code>nfephp/vendor/</code> do seu site. Pode demorar 2-5 minutos.
      </p>
      <button type="submit" class="btn">▶ Instalar NFePHP</button>
    </div>
  </form>
  <?php endif; ?>

  <?php if ($concluido): ?>
  <a href="javascript:void(0)" onclick="if(confirm('Confirma apagar o instalador?')) fetch('?apagar=1').then(()=>location.href='/')" class="btn" style="background:#ef4444">🗑️ Apagar este arquivo agora</a>
  <?php endif; ?>

  <?php endif; ?>
</div>

<?php
// Apagar o próprio arquivo
if (isset($_GET['apagar']) && $autenticado) {
    @unlink(__FILE__);
    echo '<script>location.href="/"</script>';
    exit;
}
?>
</body>
</html>
