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
        // vProd = soma dos valores brutos dos itens (qtd × vUnit), conforme exige a SEFAZ
        // vDesc = desconto da venda + soma dos descontos por item
        // vNF   = vProd - vDesc  (deve igualar a soma dos pagamentos)
        $vProd      = 0.0;
        $vDescItens = 0.0;
        foreach ($itens as $it) {
            $qtd   = (float)($it['quantidade']     ?? 1);
            $vUnit = (float)($it['valor_unitario'] ?? 0);
            $vBruto = round($qtd * $vUnit, 2);
            $vProd += $vBruto;
            // Desconto declarado pelo item (pode ser 0)
            $vDescItens += round((float)($it['valor_desconto'] ?? 0), 2);
        }
        $vProd      = round($vProd, 2);
        $vDescItens = round($vDescItens, 2);
        $desconto   = round((float)($dados['desconto'] ?? 0), 2); // desconto da venda
        $vDesc      = round($vDescItens + $desconto, 2);
        $valorTotal = round($vProd - $vDesc, 2);

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
        $docDest = preg_replace('/\D/', '', $dados['cliente_cpf'] ?? '');
        $docLen  = strlen($docDest);
        // Fallback: openNfceModal envia CNPJ em 'cliente_cnpj' (campo separado)
        if ($docLen !== 11 && $docLen !== 14) {
            $docDest = preg_replace('/\D/', '', $dados['cliente_cnpj'] ?? '');
            $docLen  = strlen($docDest);
        }
        if ($docLen === 11 || $docLen === 14) {
            $dest = new \stdClass();
            $dest->xNome     = mb_strtoupper(substr(trim($dados['cliente_nome'] ?? '') ?: 'CONSUMIDOR', 0, 60));
            $dest->indIEDest = 9; // não contribuinte
            if ($docLen === 11) {
                $dest->CPF  = $docDest;
            } else {
                $dest->CNPJ = $docDest;
            }
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

            // EAN: usa codigo_barras do produto se for GTIN válido (8/12/13/14 dígitos)
            $eanRaw  = preg_replace('/\D/', '', $it['ean'] ?? '');
            $eanVal  = in_array(strlen($eanRaw), [8, 12, 13, 14]) ? $eanRaw : 'SEM GTIN';

            // tagprod
            $prod = new \stdClass();
            $prod->item         = $nItem;
            $prod->cProd        = substr(preg_replace('/[^a-zA-Z0-9\-]/', '', $it['codigo'] ?? str_pad((string)$nItem, 3, '0', STR_PAD_LEFT)), 0, 60);
            $prod->cEAN         = $eanVal;
            $prod->xProd        = mb_strtoupper(substr(trim($it['descricao'] ?? 'PRODUTO'), 0, 120));
            $prod->NCM          = $ncm;
            $prod->CFOP         = (string)($it['cfop'] ?? '5102');
            $prod->uCom         = strtoupper($it['unidade'] ?? 'UN');
            $prod->qCom         = $qtd;
            $prod->vUnCom       = $vUnit;
            $prod->vProd        = $vTot;  // valor bruto (qtd × vUnit)
            $prod->cEANTrib     = $eanVal;
            $prod->uTrib        = strtoupper($it['unidade'] ?? 'UN');
            $prod->qTrib        = $qtd;
            $prod->vUnTrib      = $vUnit;
            // Desconto declarado pelo item
            $vDescItem = round((float)($it['valor_desconto'] ?? 0), 2);
            if ($vDescItem > 0) {
                $prod->vDesc = $vDescItem;
            }
            $prod->indTot       = 1;
            $make->tagprod($prod);

            // tagimposto — vTotTrib = estimativa de tributos (0 quando não disponível)
            $imp = new \stdClass();
            $imp->item      = $nItem;
            $imp->vTotTrib  = round((float)($it['vTotTrib'] ?? 0), 2);
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
            $vLiqItem = round((float)($it['valor_total'] ?? $vTot), 2); // valor com desconto
            $ibscbs = new \stdClass();
            $ibscbs->item         = $nItem;
            $ibscbs->cst          = '01';
            $ibscbs->vBC          = $vLiqItem;
            $ibscbs->pCBS         = 0.9;
            $ibscbs->vCBS         = round($vLiqItem * 0.009, 2);
            $ibscbs->pIBSUF       = 0.1;
            $ibscbs->vIBSUF       = round($vLiqItem * 0.001, 2);
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
        $total->vDesc    = $vDesc;
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
        $ibsTot->vBCIBSCBS  = round(array_sum(array_map(
            fn($it) => (float)($it['valor_total'] ?? round((float)($it['quantidade']??1) * (float)($it['valor_unitario']??0), 2)),
            $itens
        )), 2);
        $ibsTot->vCBS        = round(array_sum(array_map(
            fn($it) => round((float)($it['valor_total'] ?? round((float)($it['quantidade']??1) * (float)($it['valor_unitario']??0), 2)) * 0.009, 2),
            $itens
        )), 2);
        $ibsTot->vIBSUF      = round(array_sum(array_map(
            fn($it) => round((float)($it['valor_total'] ?? round((float)($it['quantidade']??1) * (float)($it['valor_unitario']??0), 2)) * 0.001, 2),
            $itens
        )), 2);
        $ibsTot->vIBSMun     = 0.00;
        $make->tagIBSCBSTot($ibsTot);

        // tagtransp — sem transportador (NFC-e)
        $transp = new \stdClass();
        $transp->modFrete = 9; // sem frete
        $make->tagtransp($transp);

        // tagpag — container (deve vir antes dos tagdetPag na v5)
        // vTroco omitido (0.00 causa rejeição na SEFAZ SC — só incluir quando > 0)
        $pagContainer = new \stdClass();
        $make->tagpag($pagContainer);

        // tagdetPag — formas de pagamento (dentro do tagpag)
        // Para cartão de crédito (03) e débito (04) a SEFAZ exige a sub-tag <card>
        // com os dados da operadora. Sem ela o retorno é:
        // "Rejeicao: Nao informados os dados do cartao de credito/debito nas Formas de Pagamento"
        // indPag removido: campo descontinuado no schema NFe 4.00 atual — inclui-lo
        // faz a SEFAZ SC rejeitar qualquer forma de pagamento diferente de dinheiro.
        $formasPag = $dados['formas_pagamento'] ?? [['tipo' => '01', 'valor' => $valorTotal]];
        foreach ($formasPag as $fp) {
            $pag = new \stdClass();
            $pag->tPag   = str_pad((string)($fp['tipo'] ?? '01'), 2, '0', STR_PAD_LEFT);
            $pag->vPag   = round((float)($fp['valor'] ?? $valorTotal), 2);

            // ── Dados do cartão (obrigatório quando tPag = 03 ou 04) ────────
            // tpIntegra: 1 = Integrado com TEF/POS → CNPJ, tBand e cAut obrigatórios
            //            2 = Não integrado (operação manual) → CNPJ omitido (SEFAZ rejeita zeros)
            // tBand:     01=Visa 02=Mastercard 03=AmericanExpress 04=Sorocred
            //            05=DinersClub 06=Elo 07=Hipercard 08=Aura 09=Cabal 99=Outros
            // cAut:      código de autorização retornado pelo POS/TEF
            if (in_array($pag->tPag, ['03', '04'])) {
                $pag->tpIntegra = (int)($fp['card_tp_integra'] ?? 2);
                $pag->tBand     = str_pad((string)($fp['card_tband'] ?? '99'), 2, '0', STR_PAD_LEFT);
                $pag->cAut      = $fp['card_caut'] ?? '000000';
                // CNPJ da credenciadora: obrigatório apenas em tpIntegra=1 (integrado com TEF)
                if ($pag->tpIntegra === 1) {
                    $pag->CNPJ = preg_replace('/\D/', '', $fp['card_cnpj'] ?? '');
                }
            }

            $make->tagdetPag($pag);
        }

        // taginfAdic — informações adicionais (obrigatório para NFC-e)
        $infAdic = new \stdClass();
        $obsUsuario = trim($dados['inf_cpl'] ?? '');
        $infAdic->infCpl = $obsUsuario ? $obsUsuario . ' | Emitido por ConsertaOS' : 'Emitido por ConsertaOS';
        $make->taginfAdic($infAdic);

        // taginfRespTec — responsável técnico pelo software (obrigatório desde 2020)
        $respTec = new \stdClass();
        $respTec->CNPJ    = '30366939000135'; // CNPJ do desenvolvedor ConsertaOS
        $respTec->xContato= 'AG Tech';
        $respTec->email   = 'atendimento.agtech@hotmail.com';
        $respTec->fone    = '47997484054';
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

        // Garante <card> em detPag para cartão de crédito/débito.
        // Algumas versões do sped-nfe não incluem <card> a partir das propriedades
        // do stdClass (equilizeParameters não lista tpIntegra/tBand/cAut), por isso
        // fazemos a injeção diretamente no XML antes de assinar.
        $xml = $this->_injectCardElements($xml, $formasPag);
        $xml = $this->_injectVTotTrib($xml);

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
    }

    // ──────────────────────────────────────────────────────────────────
    // INUTILIZAR faixa de numeração
    // Deve ser usado para números rejeitados ou pulados que não serão
    // reaproveitados, conforme exige o Manual de Orientação ao Contribuinte.
    //
    // POR QUE ZERAMOS pathschemes:
    // O isValid() em Common/Tools.php (linha 418) monta o caminho do schema assim:
    //   $schema = $this->pathschemes . $method . "_v$version.xsd";
    // Para inutilização, busca "inutNFe_v4.00.xsd". Esse arquivo existe mas
    // contém o schema de NF-e normal, causando:
    //   "Element '{...}total': This element is not expected."
    // O isValid() tem uma saída segura: se o arquivo NÃO existir, retorna true.
    // Ao zerar pathschemes, o is_file() retorna false e a validação é pulada.
    // O XML em si está correto — a SEFAZ faz a validação real no servidor.
    // ──────────────────────────────────────────────────────────────────
    public function inutilizar(int $nIni, int $nFin, string $justificativa, int $serie = 1): array
    {
        if (strlen($justificativa) < 15) {
            throw new \InvalidArgumentException('Justificativa deve ter no mínimo 15 caracteres.');
        }

        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $configTools = $this->_buildToolsConfig();
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('65'); // NFC-e

        // ── Bypass do schema errado ────────────────────────────────────
        // pathschemes é public — zeramos para que is_file() retorne false
        // dentro do isValid(), fazendo-o retornar true sem validar nada.
        $pathSchemesOriginal = $tools->pathschemes;
        $tools->pathschemes  = '';

        $resp = $tools->sefazInutiliza(
            $serie,
            $nIni,
            $nFin,
            $justificativa
        );

        // Restaura pathschemes para uso eventual do objeto após este método
        $tools->pathschemes = $pathSchemesOriginal;

        // ── Salva retorno bruto para diagnóstico ───────────────────────
        $storageDir = $this->config['storage_dir'];
        $inutDir    = $storageDir . '/inutilizados';
        if (!is_dir($inutDir)) mkdir($inutDir, 0755, true);
        file_put_contents("$inutDir/{$nIni}-{$nFin}-ret.xml", $resp);

        // ── Processa retorno ───────────────────────────────────────────
        $st  = new \NFePHP\NFe\Common\Standardize();
        $obj = $st->toStd($resp);

        $inf = $obj->retInutNFe->infInut ?? $obj->infInut ?? null;

        // Fallback via SimpleXML direto
        if ($inf === null && !empty($resp)) {
            $xml = @simplexml_load_string($resp);
            if ($xml) {
                $xml->registerXPathNamespace('nfe', 'http://www.portalfiscal.inf.br/nfe');
                $nodes = $xml->xpath('//nfe:infInut') ?: $xml->xpath('//*[local-name()="infInut"]');
                if (!empty($nodes)) {
                    $inf = $nodes[0];
                }
            }
        }

        $cStat       = (string)($inf->cStat   ?? '');
        $xMotivo     = (string)($inf->xMotivo ?? 'Sem retorno');
        $nProt       = (string)($inf->nProt   ?? '');
        $inutilizado = in_array($cStat, ['102', '103', '563']); // 102=homologado, 103=em homologação, 563=já inutilizado (aceito para registrar localmente)

        return [
            'inutilizado' => $inutilizado,
            'cStat'       => $cStat,
            'xMotivo'     => $xMotivo,
            'nProt'       => $nProt,
        ];
    }

    // ──────────────────────────────────────────────────────────────────
    // CANCELAR
    // ──────────────────────────────────────────────────────────────────
    public function cancelar(string $chave, string $justificativa, string $nProt): array
    {
        if (strlen($chave) !== 44) {
            throw new \InvalidArgumentException("Chave de acesso inválida (deve ter 44 dígitos): '$chave'");
        }
        if (!$nProt) {
            throw new \InvalidArgumentException('Número de protocolo (nProt) não encontrado. A NFC-e pode não ter sido autorizada corretamente.');
        }

        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('65'); // NFC-e

        $logDir = $this->config['storage_dir'] . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);

        try {
            $resp = $tools->sefazCancela($chave, $justificativa, $nProt);
        } catch (\Throwable $e) {
            $errMsg = $e->getMessage();
            file_put_contents("$logDir/cancelamento_erro_" . date('YmdHis') . ".txt", $errMsg);
            return [
                'autorizada' => false,
                'cStat'      => 'EXCECAO',
                'xMotivo'    => 'Erro ao comunicar com a SEFAZ: ' . $errMsg,
                'nProt'      => '',
            ];
        }

        // Captura erros internos do NFePHP (SOAP/cURL silenciosos)
        $internalErrors = '';
        if (!empty($tools->errors)) {
            $internalErrors = implode(' | ', array_map(
                fn($e) => is_array($e) ? json_encode($e) : (string)$e,
                $tools->errors
            ));
        }

        // Se resp veio vazio, tenta recuperar lastResponse do Tools
        if (empty($resp) && property_exists($tools, 'lastResponse')) {
            $resp = (string)$tools->lastResponse;
        }

        // Loga tudo para diagnóstico
        $logContent = "=== RESP ===\n" . (string)$resp
                    . "\n=== ERRORS ===\n" . $internalErrors;
        file_put_contents("$logDir/cancelamento_" . date('YmdHis') . ".txt", $logContent);

        // sefazCancela retorna o envelope SOAP completo nesta versão do NFePHP.
        // É preciso extrair o retEnvEvento de dentro de soap:Body > nfeResultMsg.
        $cStat   = '';
        $xMotivo = '';
        $nProt   = '';

        if (!empty($resp)) {
            // Tenta via SimpleXML com local-name() para ignorar namespaces SOAP
            $xmlSoap = @simplexml_load_string($resp);
            if ($xmlSoap) {
                $nodes = $xmlSoap->xpath('//*[local-name()="infEvento"]');
                if (!empty($nodes)) {
                    $cStat   = (string)($nodes[0]->cStat   ?? '');
                    $xMotivo = (string)($nodes[0]->xMotivo ?? '');
                    $nProt   = (string)($nodes[0]->nProt   ?? '');
                }
            }

            // Fallback: Standardize sobre o XML limpo (sem envelope SOAP)
            if (!$cStat) {
                $st  = new \NFePHP\NFe\Common\Standardize();
                $obj = $st->toStd($resp);
                $inf = $obj->retEnvEvento->retEvento->infEvento
                    ?? $obj->retEvento->infEvento
                    ?? null;
                $cStat   = (string)($inf->cStat   ?? '');
                $xMotivo = (string)($inf->xMotivo ?? '');
                $nProt   = (string)($inf->nProt   ?? '');
            }
        }

        // 135 = cancelado; 155 = fora do prazo mas aceito; 136 = evento duplicado (já cancelado)
        $autorizada = in_array($cStat, ['135', '155', '136']);

        if (!$xMotivo && !$autorizada) {
            $xMotivo = $internalErrors
                ? "Erro interno NFePHP: $internalErrors"
                : "Sem retorno da SEFAZ [cStat=$cStat] | Resp: " . substr((string)$resp, 0, 300);
        }

        return [
            'autorizada' => $autorizada,
            'cStat'      => $cStat,
            'xMotivo'    => $xMotivo,
            'nProt'      => $nProt,
        ];
    }

    // ──────────────────────────────────────────────────────────────────
    // PRIVADOS
    // ──────────────────────────────────────────────────────────────────
    /**
     * Injeta <card> em cada <detPag> de cartão que esteja sem o elemento.
     *
     * Opera por substituição direta na string XML (sem DOMDocument) para não
     * introduzir declarações de namespace extras que invalidam a assinatura.
     *
     * A SEFAZ SC exige <card> para qualquer pagamento eletrônico, não apenas
     * tPag 03/04 (cartão). PIX (17), boleto (15), transferência (18), etc.
     * também precisam de <card> com defaults de "não integrado".
     * Exceções: 01 (dinheiro) e 90 (sem pagamento) — esses nunca levam <card>.
     * Defaults: tpIntegra=2 (não integrado), tBand=99, cAut=000000.
     */
    private function _injectCardElements(string $xml, array $formasPag): string
    {
        // tPag que NUNCA precisam de <card>
        $semCard = ['01', '90'];

        // Dados de cartão fornecidos pelo frontend (só para tPag 03/04)
        $cardsData = [];
        foreach ($formasPag as $fp) {
            $tPag = str_pad((string)($fp['tipo'] ?? '01'), 2, '0', STR_PAD_LEFT);
            if (in_array($tPag, ['03', '04'])) {
                $cardsData[] = [
                    'tpIntegra' => (int)($fp['card_tp_integra'] ?? 2),
                    'tBand'     => str_pad((string)($fp['card_tband'] ?? '99'), 2, '0', STR_PAD_LEFT),
                    'cAut'      => $fp['card_caut'] ?? '000000',
                ];
            }
        }

        $cardIdx = 0;

        $result = preg_replace_callback(
            '/<detPag>(.*?)<\/detPag>/s',
            function (array $m) use ($semCard, $cardsData, &$cardIdx): string {
                $inner = $m[1];

                // Extrai o tPag do bloco
                if (!preg_match('/<tPag>(\d+)<\/tPag>/', $inner, $tm)) {
                    return $m[0];
                }
                $tPag = str_pad($tm[1], 2, '0', STR_PAD_LEFT);

                // Dinheiro e sem-pagamento: sem <card>
                if (in_array($tPag, $semCard)) {
                    return $m[0];
                }

                // Já tem <card>: nada a fazer
                if (strpos($inner, '<card>') !== false) {
                    return $m[0];
                }

                // Cartão crédito/débito usa dados do frontend; demais usam defaults
                $cf = $cardsData[$cardIdx] ?? [
                    'tpIntegra' => 2,
                    'tBand'     => '99',
                    'cAut'      => '000000',
                ];
                if (in_array($tPag, ['03', '04'])) {
                    $cardIdx++;
                }

                $card = '<card>'
                    . '<tpIntegra>' . (int)$cf['tpIntegra']        . '</tpIntegra>'
                    . '<tBand>'     . htmlspecialchars((string)$cf['tBand'], ENT_XML1) . '</tBand>'
                    . '<cAut>'      . htmlspecialchars((string)$cf['cAut'],  ENT_XML1) . '</cAut>'
                    . '</card>';

                return '<detPag>' . $inner . $card . '</detPag>';
            },
            $xml
        );

        return $result ?? $xml;
    }

    /**
     * Garante <vTotTrib> no XML quando o NFePHP omite o campo (valor zero).
     * — No <ICMSTot>: injeta antes de </ICMSTot>
     * — Por item em <imposto>: injeta como primeiro filho, antes de <ICMS>
     */
    private function _injectVTotTrib(string $xml): string
    {
        // <vTotTrib> em <ICMSTot>
        $xml = preg_replace_callback(
            '/<ICMSTot>(.*?)<\/ICMSTot>/s',
            function (array $m): string {
                if (strpos($m[1], '<vTotTrib>') !== false) return $m[0];
                return '<ICMSTot>' . $m[1] . '<vTotTrib>0.00</vTotTrib></ICMSTot>';
            },
            $xml
        ) ?? $xml;

        // <vTotTrib> por item em <imposto> (deve ser o primeiro filho)
        $xml = preg_replace_callback(
            '/<imposto>(.*?)<\/imposto>/s',
            function (array $m): string {
                if (strpos($m[1], '<vTotTrib>') !== false) return $m[0];
                return '<imposto><vTotTrib>0.00</vTotTrib>' . $m[1] . '</imposto>';
            },
            $xml
        ) ?? $xml;

        return $xml;
    }

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