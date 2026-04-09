#!/bin/bash
# ConsertaOS — Instalação NFePHP
# Execute na pasta do site via SSH: bash instalar.sh

echo "=== ConsertaOS — Instalação NFePHP ==="

# ── Detectar PHP ────────────────────────────────────────────────────
PHP=""
for bin in php8.3 php8.2 php8.1 php8.0 php8 php; do
    if command -v "$bin" &>/dev/null; then PHP="$bin"; break; fi
done
if [ -z "$PHP" ]; then
    for path in /usr/local/php83/bin/php /usr/local/php82/bin/php /usr/bin/php8.3 /usr/bin/php8.2 /usr/bin/php; do
        if [ -x "$path" ]; then PHP="$path"; break; fi
    done
fi
[ -z "$PHP" ] && { echo "❌ PHP não encontrado."; exit 1; }
echo "✓ PHP: $PHP ($($PHP -r 'echo PHP_VERSION;'))"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NFEPHP_DIR="$SCRIPT_DIR/nfephp"
COMPOSER="$NFEPHP_DIR/composer.phar"
mkdir -p "$NFEPHP_DIR"
echo "✓ Pasta: $SCRIPT_DIR"

# ── Composer ────────────────────────────────────────────────────────
if [ ! -f "$COMPOSER" ]; then
    echo "Baixando Composer..."
    curl -sS https://getcomposer.org/installer -o /tmp/cs.php 2>/dev/null \
        || wget -q https://getcomposer.org/installer -O /tmp/cs.php
    $PHP /tmp/cs.php --install-dir="$NFEPHP_DIR" --filename=composer.phar --quiet
    rm -f /tmp/cs.php
    [ -f "$COMPOSER" ] && echo "✓ Composer instalado." || { echo "❌ Falha no Composer."; exit 1; }
else
    echo "✓ Composer já existe."
fi

# ── composer.json ───────────────────────────────────────────────────
cat > "$NFEPHP_DIR/composer.json" << 'JSON'
{
    "name": "consertaos/nfce",
    "require": {
        "php": ">=8.0",
        "nfephp-org/sped-nfe":    "^5.1",
        "nfephp-org/sped-da":     "^1.1",
        "nfephp-org/sped-common": "^5.1"
    },
    "config": {
        "vendor-dir": "vendor"
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
JSON

# ── Instalar SEM autoloader otimizado (Locaweb bloqueia php_strip_whitespace) ──
echo ""
echo "Instalando NFePHP (aguarde 2-5 minutos)..."
cd "$NFEPHP_DIR"

# --no-autoloader primeiro para baixar os pacotes
$PHP composer.phar install --no-dev --no-autoloader --no-interaction

# Depois gerar o autoloader padrão (sem otimização, sem classmap)
echo "Gerando autoloader..."
$PHP composer.phar dump-autoload --no-interaction

# ── Verificar ───────────────────────────────────────────────────────
if [ -f "$NFEPHP_DIR/vendor/autoload.php" ]; then
    echo ""
    echo "✅ NFePHP instalado com sucesso!"
    echo "   Pacotes instalados:"
    ls "$NFEPHP_DIR/vendor/nfephp-org/" 2>/dev/null | sed 's/^/   - /'
else
    echo ""
    echo "❌ vendor/autoload.php não encontrado."
    echo "   Tentando abordagem alternativa..."

    # Última tentativa: install sem nenhuma opção de autoload
    $PHP composer.phar install --no-dev --no-interaction 2>&1 | tail -5

    if [ -f "$NFEPHP_DIR/vendor/autoload.php" ]; then
        echo "✅ Instalado na segunda tentativa!"
    else
        echo "❌ Falha. Entre em contato com suporte."
        exit 1
    fi
fi

# ── Pastas de storage ───────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/storage/nfce/autorizada" \
         "$SCRIPT_DIR/storage/nfce/cancelada" \
         "$SCRIPT_DIR/storage/nfce/rejeitada" \
         "$SCRIPT_DIR/storage/nfce/pendente" \
         "$SCRIPT_DIR/storage/logs"
chmod -R 755 "$SCRIPT_DIR/storage" 2>/dev/null
echo "✓ Pastas de storage criadas."

[ -f "$SCRIPT_DIR/src/NfceService.php" ] \
    && echo "✅ src/NfceService.php encontrado." \
    || echo "⚠️  Suba src/NfceService.php via FTP para: $SCRIPT_DIR/src/"

echo ""
echo "=== Instalação concluída ==="
echo "Configure em: Administração → Configurações → NFC-e"