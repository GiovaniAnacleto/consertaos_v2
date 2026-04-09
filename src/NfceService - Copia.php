<?php
namespace ConsertaOS\NfcE;

use NFePHP\NFe\Make;
use NFePHP\NFe\Tools;
use NFePHP\DA\NFe\Danfce;
use NFePHP\Common\Certificate;

/**
 * ConsertaOS — Serviço de emissão de NFC-e usando NFePHP
 * 
 * Uso:
 *   $svc = new NfceService($config);
 *   $resultado = $svc->emitir($dados);
 */
class NfceService
{
    private array $config;
    private Tools $tools;
    private string $storageDir;

    public function __construct(array $config)
    {
        $this->config     = $config;
        $this->storageDir = $config['storage_dir'] ?? __DIR__ . '/../storage/nfce';
        $this->tools      = $this->buildTools();
    }

    // ─────────────────────────────────────────────────────────────
    // EMITIR NFC-e
    // ─────────────────────────────────────────────────────────────
    public function emitir(array $dados): array
    {
        try {
            // 1. Montar XML
            $xml = $this->montarXml($dados);

            // 2. Assinar
            $xmlAssinado = $this->tools->signNFe($xml);

            // 3. Enviar para SEFAZ
            $resposta = $this->tools->sefazEnvia(
                $dados['serie'],
                $xmlAssinado
            );

            // 4. Processar resposta
            return $this->processarResposta($resposta, $xmlAssinado, $dados);

        } catch (\Exception $e) {
            $this->log('ERRO emitir: ' . $e->getMessage());
            throw $e;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // CANCELAR NFC-e
    // ─────────────────────────────────────────────────────────────
    public function cancelar(string $chave, string $justificativa, string $nProt): array
    {
        if (strlen($justificativa) < 15) {
            throw new \InvalidArgumentException('Justificativa deve ter mínimo 15 caracteres');
        }
        $resposta = $this->tools->sefazCancela($chave, $justificativa, $nProt);
        $this->log("CANCELAMENTO chave=$chave");
        return ['xml_resposta' => $resposta, 'sucesso' => true];
    }

    // ─────────────────────────────────────────────────────────────
    // CONSULTAR STATUS NA SEFAZ
    // ─────────────────────────────────────────────────────────────
    public function consultar(string $chave): array
    {
        $resposta = $this->tools->sefazConsultaChave($chave);
        return $this->parsearRetorno($resposta);
    }

    // ─────────────────────────────────────────────────────────────
    // GERAR DANFE NFC-e (HTML/PDF)
    // ─────────────────────────────────────────────────────────────
    public function gerarDanfe(string $xmlAutorizado): string
    {
        $danfe = new Danfce($xmlAutorizado);
        return $danfe->render(); // retorna HTML
    }

    // ─────────────────────────────────────────────────────────────
    // MONTAR XML DA NFC-e
    // ─────────────────────────────────────────────────────────────
    private function montarXml(array $d): string
    {
        $make = new Make();
        $emp  = $this->config['empresa'];

        // ── infNFe ───────────────────────────────────────────────
        $infNFe = new \stdClass();
        $infNFe->versao = '4.00';
        $make->taginfNFe($infNFe);

        // ── ide ──────────────────────────────────────────────────
        $ide = new \stdClass();
        $ide->cUF       = $emp['cUF'];            // 42 = SC
        $ide->cNF       = str_pad(rand(1,99999999), 8, '0', STR_PAD_LEFT);
        $ide->natOp      = 'VENDA AO CONSUMIDOR';
        $ide->mod        = 65;                     // 65 = NFC-e
        $ide->serie      = $d['serie'] ?? 1;
        $ide->nNF        = $d['numero'];
        $ide->dhEmi      = date('Y-m-d\TH:i:sP');
        $ide->tpNF       = 1;                     // saída
        $ide->idDest     = 1;                     // operação interna
        $ide->cMunFG     = $emp['cMun'];
        $ide->tpImp      = 4;                     // DANFE NFC-e
        $ide->tpEmis     = 1;                     // normal
        $ide->cDV        = 0;                     // calculado automaticamente
        $ide->tpAmb      = $this->config['ambiente'] === 'producao' ? 1 : 2;
        $ide->finNFe     = 1;                     // normal
        $ide->indFinal   = 1;                     // consumidor final
        $ide->indPres    = 1;                     // presencial
        $ide->procEmi    = 0;
        $ide->verProc    = '1.0';
        $make->tagide($ide);

        // ── emit (emitente) ──────────────────────────────────────
        $emit = new \stdClass();
        $emit->CNPJ     = preg_replace('/\D/', '', $emp['cnpj']);
        $emit->xNome    = $emp['razao_social'];
        $emit->xFant    = $emp['nome_fantasia'] ?? $emp['razao_social'];
        $emit->IE       = preg_replace('/\D/', '', $emp['ie']);
        $emit->CRT      = 1; // 1=Simples Nacional
        $make->tagemit($emit);

        // Endereço emitente
        $end = new \stdClass();
        $end->xLgr    = $emp['logradouro'];
        $end->nro     = $emp['numero'];
        $end->xBairro = $emp['bairro'];
        $end->cMun    = $emp['cMun'];
        $end->xMun    = $emp['cidade'];
        $end->UF      = $emp['uf'];
        $end->CEP     = preg_replace('/\D/', '', $emp['cep']);
        $end->cPais   = '1058';
        $end->xPais   = 'BRASIL';
        $end->fone    = preg_replace('/\D/', '', $emp['telefone'] ?? '');
        $make->tagenderEmit($end);

        // ── dest (destinatário — opcional NFC-e) ─────────────────
        if (!empty($d['cliente_cpf'])) {
            $dest = new \stdClass();
            $dest->CPF   = preg_replace('/\D/', '', $d['cliente_cpf']);
            $dest->xNome = $d['cliente_nome'] ?? 'CONSUMIDOR';
            $dest->indIEDest = 9; // não contribuinte
            $make->tagdest($dest);
        }

        // ── det (itens) ──────────────────────────────────────────
        $totalProd = 0;
        foreach ($d['itens'] as $idx => $item) {
            $nItem = $idx + 1;

            $det = new \stdClass();
            $det->item = $nItem;
            $make->tagdet($det);

            // prod
            $prod = new \stdClass();
            $prod->item       = $nItem;
            $prod->cProd      = $item['codigo'] ?? str_pad($nItem, 4, '0', STR_PAD_LEFT);
            $prod->cEAN       = 'SEM GTIN';
            $prod->xProd      = mb_strtoupper(substr($item['descricao'], 0, 120));
            $prod->NCM        = preg_replace('/\D/', '', $item['ncm']);
            $prod->CFOP       = $item['cfop'] ?? '5102';
            $prod->uCom       = $item['unidade'] ?? 'UN';
            $prod->qCom       = number_format((float)$item['quantidade'], 4, '.', '');
            $prod->vUnCom     = number_format((float)$item['valor_unitario'], 10, '.', '');
            $prod->vProd      = number_format((float)$item['valor_total'], 2, '.', '');
            $prod->cEANTrib   = 'SEM GTIN';
            $prod->uTrib      = $item['unidade'] ?? 'UN';
            $prod->qTrib      = $prod->qCom;
            $prod->vUnTrib    = $prod->vUnCom;
            $prod->indTot     = 1;
            $make->tagprod($prod);
            $totalProd += (float)$item['valor_total'];

            // imposto — ICMS Simples Nacional CSOSN 400
            $imposto = new \stdClass();
            $imposto->item = $nItem;
            $make->tagimposto($imposto);

            $icms = new \stdClass();
            $icms->item  = $nItem;
            $icms->orig  = $item['origem'] ?? 0;
            $icms->CSOSN = $item['csosn'] ?? '400'; // mais comum no SN sem ST
            $make->tagICMSSN($icms);

            // PIS — CST 07 isento (Simples Nacional não destaca PIS)
            $pis = new \stdClass();
            $pis->item = $nItem;
            $pis->CST  = '07';
            $make->tagPISNT($pis);

            // COFINS — CST 07 isento
            $cof = new \stdClass();
            $cof->item = $nItem;
            $cof->CST  = '07';
            $make->tagCOFINSNT($cof);
        }

        // ── total ────────────────────────────────────────────────
        $ICMSTot = new \stdClass();
        $ICMSTot->vBC    = '0.00';
        $ICMSTot->vICMS  = '0.00';
        $ICMSTot->vICMSDeson = '0.00';
        $ICMSTot->vFCP   = '0.00';
        $ICMSTot->vBCST  = '0.00';
        $ICMSTot->vST    = '0.00';
        $ICMSTot->vFCPST = '0.00';
        $ICMSTot->vFCPSTRet = '0.00';
        $ICMSTot->vProd  = number_format($totalProd, 2, '.', '');
        $ICMSTot->vFrete = '0.00';
        $ICMSTot->vSeg   = '0.00';
        $ICMSTot->vDesc  = number_format((float)($d['desconto'] ?? 0), 2, '.', '');
        $ICMSTot->vII    = '0.00';
        $ICMSTot->vIPI   = '0.00';
        $ICMSTot->vIPIDevol = '0.00';
        $ICMSTot->vPIS   = '0.00';
        $ICMSTot->vCOFINS = '0.00';
        $ICMSTot->vOutro = '0.00';
        $ICMSTot->vNF    = number_format($totalProd - (float)($d['desconto'] ?? 0), 2, '.', '');
        $make->tagICMSTot($ICMSTot);

        // ── transp ───────────────────────────────────────────────
        $transp = new \stdClass();
        $transp->modFrete = 9; // sem frete
        $make->tagtransp($transp);

        // ── pag (pagamentos) ─────────────────────────────────────
        $detPag = new \stdClass();
        $detPag->indPag = 0; // à vista
        $detPag->tPag   = $this->mapearFormaPagamento($d['formas_pagamento'][0]['tipo'] ?? 'Dinheiro');
        $detPag->vPag   = number_format((float)($d['formas_pagamento'][0]['valor'] ?? $totalProd), 2, '.', '');
        $make->tagdetPag($detPag);

        // pagamentos adicionais
        for ($i = 1; $i < count($d['formas_pagamento'] ?? []); $i++) {
            $fp = $d['formas_pagamento'][$i];
            $dp2 = new \stdClass();
            $dp2->indPag = 0;
            $dp2->tPag   = $this->mapearFormaPagamento($fp['tipo']);
            $dp2->vPag   = number_format((float)$fp['valor'], 2, '.', '');
            $make->tagdetPag($dp2);
        }

        // ── infAdFisco (QR Code NFC-e) ────────────────────────────
        $infNFeSupl = new \stdClass();
        $infNFeSupl->qrCode = ''; // preenchido automaticamente pelo sped-nfe
        $infNFeSupl->urlFrag = '';
        $make->taginfNFeSupl($infNFeSupl);

        // ── Gerar XML ─────────────────────────────────────────────
        if (!$make->montaNFe()) {
            throw new \RuntimeException('Erro ao montar XML: ' . implode('; ', $make->getErrors()));
        }

        return $make->getXML();
    }

    // ─────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────
    private function buildTools(): Tools
    {
        $emp = $this->config['empresa'];

        // Configuração para o sped-nfe
        $configJson = json_encode([
            'atualizacao' => date('Y-m-d H:i:s'),
            'tpAmb'       => $this->config['ambiente'] === 'producao' ? 1 : 2,
            'razaosocial' => $emp['razao_social'],
            'siglaUF'     => $emp['uf'],
            'cnpj'        => preg_replace('/\D/', '', $emp['cnpj']),
            'schemes'     => 'PL_009_V4',
            'versao'      => '4.00',
            'tokenIBPT'   => '',
            'CSC'         => $this->config['csc'],
            'CSCid'       => $this->config['csc_id'],
            'aProxyConf'  => [
                'proxyIp'   => '',
                'proxyPort' => '',
                'proxyUser' => '',
                'proxyPass' => '',
            ],
            'aMailConf'   => [
                'mailAuth'      => false,
                'mailFrom'      => '',
                'mailSmtp'      => '',
                'mailUser'      => '',
                'mailPass'      => '',
                'mailPort'      => 587,
                'mailFromMail'  => '',
                'mailFromName'  => '',
            ],
        ]);

        // Certificado A1
        $pfxContent = base64_decode($this->config['certificado_pfx']);
        $certificate = Certificate::readPfx($pfxContent, $this->config['certificado_senha']);

        $tools = new Tools($configJson, $certificate);
        $tools->model(65); // 65 = NFC-e

        return $tools;
    }

    private function processarResposta(string $resposta, string $xmlAssinado, array $dados): array
    {
        // Extrair dados do retorno da SEFAZ via XML
        $dom = new \DOMDocument();
        $dom->loadXML($resposta);

        $cStat = $dom->getElementsByTagName('cStat')->item(0)?->nodeValue ?? '';
        $xMotivo = $dom->getElementsByTagName('xMotivo')->item(0)?->nodeValue ?? '';
        $nProt   = $dom->getElementsByTagName('nProt')->item(0)?->nodeValue ?? '';
        $chNFe   = $dom->getElementsByTagName('chNFe')->item(0)?->nodeValue ?? '';

        $autorizada = ($cStat === '100');

        if ($autorizada) {
            // Salvar XML autorizado
            $nomeArq = $this->storageDir . '/autorizada/' . $chNFe . '-nfce.xml';
            file_put_contents($nomeArq, $resposta);
            $this->log("AUTORIZADA chave=$chNFe nProt=$nProt");
        } else {
            $this->log("REJEITADA cStat=$cStat motivo=$xMotivo");
        }

        return [
            'autorizada'  => $autorizada,
            'cStat'       => $cStat,
            'xMotivo'     => $xMotivo,
            'nProt'       => $nProt,
            'chave'       => $chNFe,
            'xml_retorno' => $resposta,
        ];
    }

    private function parsearRetorno(string $xml): array
    {
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
        return [
            'cStat'   => $dom->getElementsByTagName('cStat')->item(0)?->nodeValue ?? '',
            'xMotivo' => $dom->getElementsByTagName('xMotivo')->item(0)?->nodeValue ?? '',
            'nProt'   => $dom->getElementsByTagName('nProt')->item(0)?->nodeValue ?? '',
        ];
    }

    private function mapearFormaPagamento(string $tipo): string
    {
        return match($tipo) {
            'Dinheiro'      => '01',
            'Cheque'        => '02',
            'CartaoCredito' => '03',
            'CartaoDebito'  => '04',
            'CreditoLoja'   => '05',
            'Pix'           => '17',
            'Boleto'        => '15',
            default         => '99', // outros
        };
    }

    private function log(string $msg): void
    {
        $dir = $this->storageDir . '/../logs';
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        file_put_contents(
            $dir . '/nfce_' . date('Y-m') . '.log',
            date('[Y-m-d H:i:s] ') . $msg . "\n",
            FILE_APPEND
        );
    }
}
