<?php
/**
 * NfceService.php — Emissão de NFC-e via NFePHP (sped-nfe v5.x)
 * Compatível com: sped-nfe ^5.1, sped-common ^5.1, sped-da ^1.1
 *
 * Estrutura de $config esperada:
 * [
 *   'ambiente'          => 'homologacao' | 'producao',
 *   'csc'               => '...',
 *   'csc_id'            => '01',
 *   'certificado_pfx'   => '<base64 do .pfx>',
 *   'certificado_senha' => '...',
 *   'storage_dir'       => '/caminho/para/storage/nfce',
 *   'empresa' => [
 *       'cnpj', 'razao_social', 'nome_fantasia', 'ie',
 *       'cMun', 'cUF', 'uf', 'logradouro', 'numero',
 *       'bairro', 'cidade', 'cep', 'telefone',
 *   ],
 * ]
 *
 * Estrutura de $dados esperada (enviada pelo frontend):
 * [
 *   'numero'            => 1,
 *   'serie'             => 1,
 *   'ambiente'          => 'homologacao',
 *   'natop'             => 'VENDA AO CONSUMIDOR',
 *   'desconto'          => 0.00,
 *   'valor_total'       => 100.00,
 *   'cliente_nome'      => 'CONSUMIDOR',
 *   'cliente_cpf'       => '',          // 11 dígitos ou vazio
 *   'formas_pagamento'  => [['tipo'=>'01','valor'=>100.00]],
 *   'itens' => [[
 *       'descricao'     => 'Produto X',
 *       'codigo'        => '001',
 *       'ncm'           => '85171800',
 *       'cfop'          => '5102',
 *       'csosn'         => '400',
 *       'origem'        => 0,
 *       'unidade'       => 'UN',
 *       'quantidade'    => 1,
 *       'valor_unitario'=> 100.00,
 *       'valor_total'   => 100.00,
 *   ]],
 * ]
 */

namespace ConsertaOS\NfcE;

use NFePHP\NFe\Make;
use NFePHP\NFe\Tools;
use NFePHP\Common\Certificate;

class NfceService
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $storageDir = $config['storage_dir'] ?? __DIR__ . '/../storage/nfce';
        foreach (['autorizada', 'cancelada', 'rejeitada', 'logs'] as $sub) {
            $path = "$storageDir/$sub";
            if (!is_dir($path)) {
                mkdir($path, 0755, true);
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // EMITIR
    // ──────────────────────────────────────────────────────────────────
    public function emitir(array $dados): array
    {
        $ambiente   = $this->config['ambiente'] === 'producao' ? 1 : 2;
        $empresa    = $this->config['empresa'];
        $numero     = (int) ($dados['numero'] ?? 1);
        $serie      = (int) ($dados['serie']  ?? 1);
        $natop      = $dados['natop']  ?? 'VENDA AO CONSUMIDOR';
        $itens      = $dados['itens']  ?? [];
        $storageDir = $this->config['storage_dir'];

        // ── Calcula totais ─────────────────────────────────────────────
        $vProd    = 0.0;
        foreach ($itens as $it) {
            $vProd += round((float)($it['quantidade'] ?? 1) * (float)($it['valor_unitario'] ?? 0), 2);
        }
        $desconto   = round((float)($dados['desconto'] ?? 0), 2);
        $valorTotal = round($vProd - $desconto, 2);

        // ── Chave de acesso ────────────────────────────────────────────
        $cUF   = str_pad((string)($empresa['cUF'] ?? 42), 2, '0', STR_PAD_LEFT);
        $cMun  = $empresa['cMun'] ?? '4204194';
        $cnpj  = preg_replace('/\D/', '', $empresa['cnpj'] ?? '');
        $dhEmi = date('Y-m-d\TH:i:sP');
        $cNF   = str_pad((string)rand(10000000, 99999999), 8, '0', STR_PAD_LEFT);
        $mod   = '65'; // NFC-e

        // ── Monta XML via sped-nfe Make ────────────────────────────────
        $make = new Make();

        // taginfNFe — versão do layout
        $std = new \stdClass();
        $std->versao = '4.00';
        $make->taginfNFe($std);

        // tagide — identificação
        $ide = new \stdClass();
        $ide->cUF       = (int)$cUF;
        $ide->cNF       = $cNF;
        $ide->natOp     = $natop;
        $ide->mod       = (int)$mod;
        $ide->serie     = $serie;
        $ide->nNF       = $numero;
        $ide->dhEmi     = $dhEmi;
        $ide->tpNF      = 1;           // saída
        $ide->idDest    = 1;           // operação interna
        $ide->cMunFG    = (int)$cMun;
        $ide->tpImp     = 4;           // DANFE NFC-e
        $ide->tpEmis    = 1;           // emissão normal
        $ide->tpAmb     = $ambiente;
        $ide->finNFe    = 1;           // NF-e normal
        $ide->indFinal  = 1;           // consumidor final
        $ide->indPres   = 1;           // presencial
        $ide->procEmi   = 0;           // emissão por app próprio
        $ide->verProc   = '1.0';
        $make->tagide($ide);

        // tagEmit — emitente (apenas identificação)
        $emit = new \stdClass();
        $emit->CNPJ  = $cnpj;
        $emit->xNome = mb_strtoupper(substr($empresa['razao_social'] ?? 'EMPRESA', 0, 60));
        $emit->xFant = mb_strtoupper(substr($empresa['nome_fantasia'] ?? $empresa['razao_social'] ?? '', 0, 60));
        $emit->IE    = preg_replace('/\D/', '', $empresa['ie'] ?? '') ?: 'ISENTO';
        $emit->CRT   = 1; // Simples Nacional
        $make->tagEmit($emit);

        // tagenderEmit — endereço do emitente (separado na v5)
        $enderEmit = new \stdClass();
        $enderEmit->xLgr   = mb_strtoupper(substr($empresa['logradouro'] ?? '', 0, 60));
        $enderEmit->nro    = mb_strtoupper(substr($empresa['numero'] ?? 'S/N', 0, 60));
        $enderEmit->xBairro= mb_strtoupper(substr($empresa['bairro'] ?? '', 0, 60));
        $enderEmit->cMun   = (int)$cMun;
        $enderEmit->xMun   = mb_strtoupper(substr($empresa['cidade'] ?? '', 0, 60));
        $enderEmit->UF     = strtoupper($empresa['uf'] ?? 'SC');
        $enderEmit->CEP    = preg_replace('/\D/', '', $empresa['cep'] ?? '');
        $enderEmit->cPais  = 1058;
        $enderEmit->xPais  = 'BRASIL';
        $enderEmit->fone   = preg_replace('/\D/', '', $empresa['telefone'] ?? '');
        $make->tagenderEmit($enderEmit);

        // tagdest + tagenderDest — destinatário (opcional)
        $cpfDest = preg_replace('/\D/', '', $dados['cliente_cpf'] ?? '');
        if (strlen($cpfDest) === 11) {
            $dest = new \stdClass();
            $dest->xNome     = mb_strtoupper(substr($dados['cliente_nome'] ?? 'CONSUMIDOR', 0, 60));
            $dest->CPF       = $cpfDest;
            $dest->indIEDest = 9; // não contribuinte
            $make->tagdest($dest);
        }

        // ── Itens ──────────────────────────────────────────────────────
        foreach ($itens as $nItem => $it) {
            $nItem++;   // 1-based
            $qtd   = round((float)($it['quantidade']    ?? 1), 4);
            $vUnit = round((float)($it['valor_unitario'] ?? 0), 10);
            $vTot  = round($qtd * (float)($it['valor_unitario'] ?? 0), 2);
            $csosn = (string)($it['csosn'] ?? '400');
            $orig  = (int)($it['origem'] ?? 0);
            $ncm   = preg_replace('/\D/', '', $it['ncm'] ?? '00000000');
            $ncm   = str_pad($ncm, 8, '0', STR_PAD_LEFT);

            // tagprod
            $prod = new \stdClass();
            $prod->item         = $nItem;
            $prod->cProd        = substr(preg_replace('/[^a-zA-Z0-9\-]/', '', $it['codigo'] ?? str_pad((string)$nItem, 3, '0', STR_PAD_LEFT)), 0, 60);
            $prod->cEAN         = 'SEM GTIN';
            $prod->xProd        = mb_strtoupper(substr(trim($it['descricao'] ?? 'PRODUTO'), 0, 120));
            $prod->NCM          = $ncm;
            $prod->CFOP         = (string)($it['cfop'] ?? '5102');
            $prod->uCom         = strtoupper($it['unidade'] ?? 'UN');
            $prod->qCom         = $qtd;
            $prod->vUnCom       = $vUnit;
            $prod->vProd        = $vTot;
            $prod->cEANTrib     = 'SEM GTIN';
            $prod->uTrib        = strtoupper($it['unidade'] ?? 'UN');
            $prod->qTrib        = $qtd;
            $prod->vUnTrib      = $vUnit;
            $prod->indTot       = 1;
            $make->tagprod($prod);

            // tagimposto
            $imp = new \stdClass();
            $imp->item = $nItem;
            $make->tagimposto($imp);

            // tagICMSSN — Simples Nacional
            // Determina a tag correta conforme CSOSN
            $icms = new \stdClass();
            $icms->item  = $nItem;
            $icms->orig  = $orig;
            $icms->CSOSN = $csosn;

            // CSOSN que têm base de cálculo para crédito (101, 201)
            if (in_array($csosn, ['101', '201'])) {
                $icms->pCredSN    = 0.00;
                $icms->vCredICMSSN = 0.00;
            }
            // CSOSN com ST (201, 202, 203) — base e valor ST zerados
            if (in_array($csosn, ['201', '202', '203'])) {
                $icms->modBCST    = 3;
                $icms->vBCST      = 0.00;
                $icms->pICMSST    = 0.00;
                $icms->vICMSST    = 0.00;
            }
            // CSOSN 500 — ICMS cobrado por ST: informar vBCSTRet e vICMSSTRet zerados
            if ($csosn === '500') {
                $icms->vBCSTRet   = 0.00;
                $icms->vICMSSTRet = 0.00;
            }

            $make->tagICMSSN($icms);

            // tagPIS — Simples Nacional (CST 07 = isento, sem base de cálculo)
            $pis = new \stdClass();
            $pis->item = $nItem;
            $pis->CST  = '07';
            $make->tagPIS($pis);

            // tagCOFINS — Simples Nacional (CST 07 = isento, sem base de cálculo)
            $cof = new \stdClass();
            $cof->item = $nItem;
            $cof->CST  = '07';
            $make->tagCOFINS($cof);

            // tagIBSCBS — Reforma Tributária (obrigatório a partir de 2026)
            // Para Simples Nacional: IBS e CBS com alíquotas sobre o valor do item
            // Alíquotas provisórias 2026: CBS=0.9%, IBS estadual=0.1%, IBS municipal=0%
            $ibscbs = new \stdClass();
            $ibscbs->item         = $nItem;
            $ibscbs->cst          = '01'; // tributado
            $ibscbs->vBC          = $vTot;
            // CBS (federal)
            $ibscbs->pCBS         = 0.9;
            $ibscbs->vCBS         = round($vTot * 0.009, 2);
            // IBS Estadual
            $ibscbs->pIBSUF       = 0.1;
            $ibscbs->vIBSUF       = round($vTot * 0.001, 2);
            // IBS Municipal
            $ibscbs->pIBSMun      = 0.0;
            $ibscbs->vIBSMun      = 0.00;
            $make->tagIBSCBS($ibscbs);
        }

        // tagtotal
        $total = new \stdClass();
        $total->vBC      = 0.00;
        $total->vICMS    = 0.00;
        $total->vICMSDeson = 0.00;
        $total->vFCP     = 0.00;
        $total->vBCST    = 0.00;
        $total->vST      = 0.00;
        $total->vFCPST   = 0.00;
        $total->vFCPSTRet = 0.00;
        $total->vProd    = $vProd;
        $total->vFrete   = 0.00;
        $total->vSeg     = 0.00;
        $total->vDesc    = $desconto;
        $total->vII      = 0.00;
        $total->vIPI     = 0.00;
        $total->vIPIDevol = 0.00;
        $total->vPIS     = 0.00;
        $total->vCOFINS  = 0.00;
        $total->vOutro   = 0.00;
        $total->vNF      = $valorTotal;
        $total->vTotTrib = 0.00;
        $make->tagTotal($total);

        // tagIBSCBSTot — totalizador da Reforma Tributária
        $ibsTot = new \stdClass();
        $ibsTot->vBCIBSCBS  = $vProd;
        $ibsTot->vCBS        = round(array_sum(array_map(
            fn($it) => round((float)($it['quantidade']??1) * (float)($it['valor_unitario']??0) * 0.009, 2),
            $itens
        )), 2);
        $ibsTot->vIBSUF      = round(array_sum(array_map(
            fn($it) => round((float)($it['quantidade']??1) * (float)($it['valor_unitario']??0) * 0.001, 2),
            $itens
        )), 2);
        $ibsTot->vIBSMun     = 0.00;
        $make->tagIBSCBSTot($ibsTot);

        // tagtransp — sem transportador (NFC-e)
        $transp = new \stdClass();
        $transp->modFrete = 9; // sem frete
        $make->tagtransp($transp);

        // tagpag — container (deve vir antes dos tagdetPag na v5)
        $pagContainer = new \stdClass();
        $pagContainer->vTroco = 0.00;
        $make->tagpag($pagContainer);

        // tagdetPag — formas de pagamento (dentro do tagpag)
        $formasPag = $dados['formas_pagamento'] ?? [['tipo' => '01', 'valor' => $valorTotal]];
        foreach ($formasPag as $fp) {
            $pag = new \stdClass();
            $pag->indPag = 0; // 0=à vista, 1=a prazo
            $pag->tPag   = str_pad((string)($fp['tipo'] ?? '01'), 2, '0', STR_PAD_LEFT);
            $pag->vPag   = round((float)($fp['valor'] ?? $valorTotal), 2);
            $make->tagdetPag($pag);
        }

        // taginfAdic — informações adicionais (obrigatório para NFC-e)
        $infAdic = new \stdClass();
        $infAdic->infCpl = 'Emitido por ConsertaOS';
        $make->taginfAdic($infAdic);

        // taginfRespTec — responsável técnico pelo software (obrigatório desde 2020)
        $respTec = new \stdClass();
        $respTec->CNPJ    = '38060284000179'; // CNPJ do desenvolvedor ConsertaOS
        $respTec->xContato= 'ConsertaOS';
        $respTec->email   = 'suporte@consertaos.com.br';
        $respTec->fone    = '4799999999';
        $make->taginfRespTec($respTec);

        // taginfNFeSupl — QR Code (obrigatório para NFC-e)
        // O sped-nfe gera o QR Code automaticamente ao assinar, mas a tag precisa existir
        $supl = new \stdClass();
        $supl->qrCode  = ''; // será preenchido automaticamente pelo Tools após assinatura
        $supl->urlChave= $ambiente === 1
            ? 'https://nfe.sefaz.virtual.go.gov.br/nfce/consultanfce'   // produção
            : 'https://www.sefaz.sc.gov.br/servicos/nfce/nfce.aspx';    // homologação SC
        $make->taginfNFeSupl($supl);

        // ── Gera XML, assina e transmite ───────────────────────────────
        $xml = $make->getXML();

        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );

        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('65'); // NFC-e

        // Assina
        $xmlAssinado = $tools->signNFe($xml);

        // Salva XML assinado antes de transmitir (para debug)
        $xmlDir = $storageDir . '/enviados';
        if (!is_dir($xmlDir)) mkdir($xmlDir, 0755, true);
        file_put_contents("$xmlDir/{$numero}.xml", $xmlAssinado);

        // Transmite em modo SÍNCRONO (indSinc=1) — obrigatório para NFC-e
        // sefazEnviaLote($xmls, $idLote, $indSinc, $compactado, $tags)
        $idLote  = str_pad((string)$numero, 15, '0', STR_PAD_LEFT);
        $resposta = $tools->sefazEnviaLote([$xmlAssinado], $idLote, 1);

        // Processa retorno
        return $this->_processarRetorno($resposta, $xmlAssinado, $storageDir, $numero);

        // Processa retorno
        return $this->_processarRetorno($resposta, $xmlAssinado, $storageDir, $numero);
    }

    // ──────────────────────────────────────────────────────────────────
    // CANCELAR
    // ──────────────────────────────────────────────────────────────────
    public function cancelar(string $chave, string $justificativa, string $nProt): array
    {
        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('65');

        $resp = $tools->sefazCancela($chave, $justificativa, $nProt);

        $st = new \NFePHP\NFe\Common\Standardize();
        $obj = $st->toStd($resp);

        $autorizada = isset($obj->retEvento->infEvento->cStat) &&
                      in_array((string)$obj->retEvento->infEvento->cStat, ['135', '155']);

        return [
            'autorizada' => $autorizada,
            'xMotivo'    => (string)($obj->retEvento->infEvento->xMotivo ?? 'Sem retorno'),
            'nProt'      => (string)($obj->retEvento->infEvento->nProt   ?? ''),
        ];
    }

    // ──────────────────────────────────────────────────────────────────
    // PRIVADOS
    // ──────────────────────────────────────────────────────────────────
    private function _buildToolsConfig(): array
    {
        $empresa = $this->config['empresa'];
        $cnpj    = preg_replace('/\D/', '', $empresa['cnpj'] ?? '');
        return [
            'atualizacao' => date('Y-m-d H:i:s'),
            'tpAmb'       => $this->config['ambiente'] === 'producao' ? 1 : 2,
            'razaosocial' => $empresa['razao_social'] ?? '',
            'siglaUF'     => strtoupper($empresa['uf'] ?? 'SC'),
            'cnpj'        => $cnpj,
            'schemes'     => 'PL_009_V4',
            'versao'      => '4.00',
            'tokenIBPT'   => '',
            'CSC'         => $this->config['csc'] ?? '',
            'CSCid'       => $this->config['csc_id'] ?? '01',
        ];
    }

    private function _processarRetorno(string $resposta, string $xmlAssinado, string $storageDir, int $numero): array
    {
        // Salva resposta bruta para diagnóstico
        $logDir = $storageDir . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);
        file_put_contents("$logDir/retorno_{$numero}.xml", $resposta);

        $cStat   = '';
        $xMotivo = '';
        $nProt   = '';
        $chave   = '';

        try {
            $st  = new \NFePHP\NFe\Common\Standardize();
            $obj = $st->toStd($resposta);

            // Estrutura 1: retEnviNFe > protNFe > infProt  (retorno síncrono)
            if (isset($obj->retEnviNFe)) {
                $ret = $obj->retEnviNFe;
                // cStat do envelope
                $cStat   = (string)($ret->cStat   ?? '');
                $xMotivo = (string)($ret->xMotivo ?? '');
                // Dentro do envelope pode ter protNFe
                if (isset($ret->protNFe->infProt)) {
                    $inf     = $ret->protNFe->infProt;
                    $cStat   = (string)($inf->cStat   ?? $cStat);
                    $xMotivo = (string)($inf->xMotivo ?? $xMotivo);
                    $nProt   = (string)($inf->nProt   ?? '');
                    $chave   = (string)($inf->chNFe   ?? '');
                }
            }

            // Estrutura 2: protNFe direto (algumas versões)
            if ($cStat === '' && isset($obj->protNFe->infProt)) {
                $inf     = $obj->protNFe->infProt;
                $cStat   = (string)($inf->cStat   ?? '');
                $xMotivo = (string)($inf->xMotivo ?? '');
                $nProt   = (string)($inf->nProt   ?? '');
                $chave   = (string)($inf->chNFe   ?? '');
            }

            // Estrutura 3: retorno lote assíncrono (infRec) — não deveria ocorrer com indSinc=1
            if ($cStat === '' && isset($obj->infRec)) {
                $cStat   = (string)($obj->cStat   ?? '');
                $xMotivo = (string)($obj->xMotivo ?? '') . ' [lote assíncrono - use consulta]';
            }

            // Estrutura 4: objeto raiz direto (cStat no nível 0)
            if ($cStat === '' && isset($obj->cStat)) {
                $cStat   = (string)$obj->cStat;
                $xMotivo = (string)($obj->xMotivo ?? '');
            }

        } catch (\Exception $e) {
            // Se não conseguiu parsear, loga e retorna com XML bruto truncado para diagnóstico
            return [
                'autorizada' => false,
                'chave'      => '',
                'nProt'      => '',
                'cStat'      => 'PARSE_ERROR',
                'xMotivo'    => 'Erro ao processar retorno: ' . $e->getMessage() .
                                ' | Resposta bruta: ' . substr($resposta, 0, 300),
            ];
        }

        $autorizada = ($cStat === '100');

        // Salva XML assinado na pasta correta
        $subDir  = $autorizada ? 'autorizada' : 'rejeitada';
        $arquivo = "$storageDir/$subDir/{$numero}.xml";
        @file_put_contents($arquivo, $xmlAssinado);

        return [
            'autorizada' => $autorizada,
            'chave'      => $chave,
            'nProt'      => $nProt,
            'cStat'      => $cStat,
            'xMotivo'    => $xMotivo ?: ('Sem retorno da SEFAZ [cStat vazio] | Resposta: ' . substr($resposta, 0, 200)),
        ];
    }
}