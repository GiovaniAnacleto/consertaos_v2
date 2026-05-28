<?php
return [
    'provisionar_secret' => '787220b48625f1331c382c0b94e2d302e679613ee1cd9687fc4671185d8cce99',

    // ─── SMTP — envio de emails (ex.: redefinição de senha) ─────
    'smtp_host'  => 'pop.consertaos.com.br',
    'smtp_porta' => 587,
    'smtp_user'  => 'atendimento@consertaos.com.br',
    'smtp_pass'  => 'Anacleto22@',
    'email_from' => 'ConsertaOS <atendimento@consertaos.com.br>',

    // ─── Fallback de email via landing (caso SMTP direto falhe) ──
    'email_api_url' => 'https://consertaos.com.br/admin/email_api.php',

    // ─── Central de Suporte ───────────────────────────────────
    'centralsuporte_url' => 'https://consertaos.com.br/centralsuporte/api.php',

    // ─── Backup API URL (usado pelo painel admin da landing) ──
    // Este valor é lido pelo admin/backup.php na landing, não aqui.
    // Inserido aqui apenas para documentação — configure em admin/config.php.
];