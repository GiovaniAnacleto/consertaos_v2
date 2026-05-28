<?php
/**
 * NfeService.php — Emissão de NF-e (modelo 55) via NFePHP (sped-nfe v5.x)
 * Compatível com: sped-nfe ^5.1, sped-common ^5.2
 *
 * Diferenças em relação à NFC-e (modelo 65):
 *   - mod=55, tpImp=1 (DANFE A4 retrato)
 *   - Sem QR Code / CSC
 *   - Destinatário obrigatório com endereço completo
 *   - Suporte a transportadora e volumes
 *   - finNFe, indFinal, idDest configuráveis por emissão
 *
 * Estrutura de $config esperada:
 * [
 *   'ambiente'          => 'homologacao' | 'producao',
 *   'certificado_pfx'   => '<base64 do .pfx>',
 *   'certificado_senha' => '...',
 *   'storage_dir'       => '/caminho/para/storage/nfe',
 *   'empresa' => [
 *       'cnpj', 'razao_social', 'nome_fantasia', 'ie',
 *       'cMun', 'cUF', 'uf', 'logradouro', 'numero',
 *       'bairro', 'cidade', 'cep', 'telefone',
 *   ],
 * ]
 *
 * Estrutura de $dados esperada:
 * [
 *   'numero'            => 1,
 *   'serie'             => 1,
 *   'natop'             => 'VENDA DE MERCADORIA',
 *   'fin_nfe'           => 1,   // 1=normal 2=complementar 3=ajuste 4=devolução
 *   'ind_final'         => 1,   // 0=não consumidor final 1=consumidor final
 *   'ind_pres'          => 1,   // 1=presencial 2=internet 9=outros
 *   'tp_nf'             => 1,   // 0=entrada 1=saída
 *   'id_dest'           => 1,   // 1=interno 2=interestadual 3=exterior
 *   'desconto'          => 0.00,
 *   'valor_frete'       => 0.00,
 *   'valor_seguro'      => 0.00,
 *   'valor_outro'       => 0.00,
 *   'info_adicional'    => '',
 *   // Destinatário
 *   'dest_cpf'          => '',  // 11 dígitos ou vazio
 *   'dest_cnpj'         => '',  // 14 dígitos ou vazio
 *   'dest_nome'         => '',
 *   'dest_ind_ie'       => 9,   // 1=contribuinte ICMS 2=isento 9=não contribuinte
 *   'dest_ie'           => '',
 *   'dest_email'        => '',
 *   'dest_logradouro'   => '',
 *   'dest_numero'       => '',
 *   'dest_complemento'  => '',
 *   'dest_bairro'       => '',
 *   'dest_cep'          => '',
 *   'dest_cidade'       => '',
 *   'dest_cMun'         => '',  // código IBGE
 *   'dest_uf'           => '',
 *   // Transporte
 *   'mod_frete'         => 9,   // 9=sem frete 0=emitente 1=dest 2=terceiro
 *   'transp_cnpj'       => '',
 *   'transp_cpf'        => '',
 *   'transp_nome'       => '',
 *   'transp_ie'         => '',
 *   'transp_uf'         => '',
 *   'vol_qtd'           => 0,
 *   'vol_esp'           => '',
 *   'vol_peso_l'        => 0.00,
 *   'vol_peso_b'        => 0.00,
 *   // Pagamento
 *   'formas_pagamento'  => [['tipo'=>'01','valor'=>100.00]],
 *   // Itens
 *   'itens' => [[
 *       'descricao'      => 'Produto X',
 *       'codigo'         => '001',
 *       'ncm'            => '85171800',
 *       'cfop'           => '5102',
 *       'csosn'          => '400',
 *       'origem'         => 0,
 *       'unidade'        => 'UN',
 *       'quantidade'     => 1,
 *       'valor_unitario' => 100.00,
 *       'valor_total'    => 100.00,
 *       'valor_desconto' => 0.00,
 *   ]],
 * ]
 */

namespace ConsertaOS\NFe;

use NFePHP\NFe\Make;
use NFePHP\NFe\Tools;
use NFePHP\Common\Certificate;

class NfeService
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $storageDir = $config['storage_dir'] ?? __DIR__ . '/../storage/nfe';
        foreach (['autorizada', 'cancelada', 'rejeitada', 'inutilizados', 'enviados', 'logs'] as $sub) {
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
        $numero     = (int)($dados['numero'] ?? 1);
        $serie      = (int)($dados['serie']  ?? 1);
        $natop      = trim($dados['natop'] ?? '') ?: 'VENDA DE MERCADORIA';
        $itens      = $dados['itens'] ?? [];
        $storageDir = $this->config['storage_dir'];

        // ── Totais ─────────────────────────────────────────────────────
        $vProd = $vDescItens = 0.0;
        foreach ($itens as $it) {
            $qtd   = (float)($it['quantidade']     ?? 1);
            $vUnit = (float)($it['valor_unitario'] ?? 0);
            $vProd     += round($qtd * $vUnit, 2);
            $vDescItens += round((float)($it['valor_desconto'] ?? 0), 2);
        }
        $vProd   = round($vProd, 2);
        $vFrete  = round((float)($dados['valor_frete']  ?? 0), 2);
        $vSeg    = round((float)($dados['valor_seguro'] ?? 0), 2);
        $vOutro  = round((float)($dados['valor_outro']  ?? 0), 2);
        $vDesc   = round($vDescItens + (float)($dados['desconto'] ?? 0), 2);
        $vNF     = round($vProd - $vDesc + $vFrete + $vSeg + $vOutro, 2);

        $cUF   = str_pad((string)($empresa['cUF'] ?? 42), 2, '0', STR_PAD_LEFT);
        $cMun  = $empresa['cMun'] ?? '4204194';
        $cnpj  = preg_replace('/\D/', '', $empresa['cnpj'] ?? '');
        $dhEmi = date('Y-m-d\TH:i:sP');
        $cNF   = str_pad((string)rand(10000000, 99999999), 8, '0', STR_PAD_LEFT);

        $make = new Make();

        // taginfNFe
        $std = new \stdClass();
        $std->versao = '4.00';
        $make->taginfNFe($std);

        // tagide
        $ide = new \stdClass();
        $ide->cUF      = (int)$cUF;
        $ide->cNF      = $cNF;
        $ide->natOp    = $natop;
        $ide->mod      = 55; // NF-e modelo 55
        $ide->serie    = $serie;
        $ide->nNF      = $numero;
        $ide->dhEmi    = $dhEmi;
        $ide->dhSaiEnt = $dados['dh_sai_ent'] ?? $dhEmi; // data/hora saída
        $ide->tpNF     = (int)($dados['tp_nf']    ?? 1); // 1=saída
        $ide->idDest   = (int)($dados['id_dest']  ?? 1); // 1=interno 2=interestadual 3=exterior
        $ide->cMunFG   = (int)$cMun;
        $ide->tpImp    = 1;   // DANFE retrato A4
        $ide->tpEmis   = 1;   // emissão normal
        $ide->tpAmb    = $ambiente;
        $ide->finNFe   = (int)($dados['fin_nfe']   ?? 1); // 1=normal 2=complementar 3=ajuste 4=devolução
        $ide->indFinal = (int)($dados['ind_final'] ?? 1); // 1=consumidor final
        $ide->indPres  = (int)($dados['ind_pres']  ?? 1); // 1=presencial
        $ide->procEmi  = 0;
        $ide->verProc  = '1.0';
        $make->tagide($ide);

        // tagEmit
        $emit = new \stdClass();
        $emit->CNPJ  = $cnpj;
        $emit->xNome = mb_strtoupper(substr($empresa['razao_social'] ?? 'EMPRESA', 0, 60));
        $emit->xFant = mb_strtoupper(substr($empresa['nome_fantasia'] ?? $empresa['razao_social'] ?? '', 0, 60));
        $emit->IE    = preg_replace('/\D/', '', $empresa['ie'] ?? '') ?: 'ISENTO';
        $emit->CRT   = 1; // Simples Nacional
        $make->tagEmit($emit);

        // tagenderEmit
        $enderEmit = new \stdClass();
        $enderEmit->xLgr    = mb_strtoupper(substr($empresa['logradouro'] ?? '', 0, 60));
        $enderEmit->nro     = mb_strtoupper(substr($empresa['numero']     ?? 'S/N', 0, 60));
        $enderEmit->xBairro = mb_strtoupper(substr($empresa['bairro']     ?? '', 0, 60));
        $enderEmit->cMun    = (int)$cMun;
        $enderEmit->xMun    = mb_strtoupper(substr($empresa['cidade'] ?? '', 0, 60));
        $enderEmit->UF      = strtoupper($empresa['uf'] ?? 'SC');
        $enderEmit->CEP     = preg_replace('/\D/', '', $empresa['cep'] ?? '');
        $enderEmit->cPais   = 1058;
        $enderEmit->xPais   = 'BRASIL';
        $enderEmit->fone    = preg_replace('/\D/', '', $empresa['telefone'] ?? '');
        $make->tagenderEmit($enderEmit);

        // tagdest — obrigatório para NF-e modelo 55
        $destCpf  = preg_replace('/\D/', '', $dados['dest_cpf']  ?? '');
        $destCnpj = preg_replace('/\D/', '', $dados['dest_cnpj'] ?? '');
        $idDest   = (int)($dados['id_dest'] ?? 1);
        // O schema da NF-e exige: CNPJ|CPF|idEstrangeiro → xNome → indIEDest → IE → email
        $dest = new \stdClass();
        if (strlen($destCnpj) === 14) {
            $dest->CNPJ = $destCnpj;
        } elseif (strlen($destCpf) === 11) {
            $dest->CPF = $destCpf;
        } elseif ($idDest === 3) {
            // Exterior: idEstrangeiro deve ter 5–20 chars ou ser omitido
            $idEstr = trim($dados['dest_id_estrangeiro'] ?? '');
            if (strlen($idEstr) >= 5 && strlen($idEstr) <= 20) {
                $dest->idEstrangeiro = $idEstr;
            }
        }
        $dest->xNome     = mb_strtoupper(substr(trim($dados['dest_nome'] ?? '') ?: 'CONSUMIDOR', 0, 60));
        $dest->indIEDest = (int)($dados['dest_ind_ie'] ?? 9); // 9=não contribuinte
        $destIe = preg_replace('/\D/', '', $dados['dest_ie'] ?? '');
        if ($destIe && (int)($dados['dest_ind_ie'] ?? 9) === 1) {
            $dest->IE = $destIe;
        }
        if (!empty($dados['dest_email'])) {
            $dest->email = trim($dados['dest_email']);
        }
        $make->tagdest($dest);

        // tagenderDest — obrigatório para NF-e modelo 55
        $destCMun  = preg_replace('/\D/', '', $dados['dest_cMun'] ?? '');
        $enderDest = new \stdClass();
        $enderDest->xLgr    = mb_strtoupper(substr(trim($dados['dest_logradouro'] ?? '') ?: 'NAO INFORMADO', 0, 60));
        $enderDest->nro     = mb_strtoupper(substr(trim($dados['dest_numero']     ?? '') ?: 'S/N', 0, 60));
        if (!empty($dados['dest_complemento'])) {
            $enderDest->xCpl = mb_strtoupper(substr($dados['dest_complemento'], 0, 60));
        }
        $enderDest->xBairro = mb_strtoupper(substr(trim($dados['dest_bairro'] ?? '') ?: 'NAO INFORMADO', 0, 60));
        $enderDest->cMun    = $destCMun ? (int)$destCMun : (int)$cMun;
        $enderDest->xMun    = mb_strtoupper(substr(trim($dados['dest_cidade'] ?? '') ?: ($empresa['cidade'] ?? 'NAO INFORMADO'), 0, 60));
        $enderDest->UF      = strtoupper(trim($dados['dest_uf'] ?? '') ?: ($empresa['uf'] ?? 'SC'));
        $enderDest->CEP     = preg_replace('/\D/', '', $dados['dest_cep'] ?? '');
        $enderDest->cPais   = 1058;
        $enderDest->xPais   = 'BRASIL';
        $make->tagenderDest($enderDest);

        // ── Itens ──────────────────────────────────────────────────────
        foreach ($itens as $nItem => $it) {
            $nItem++;
            $qtd   = round((float)($it['quantidade']     ?? 1), 4);
            $vUnit = round((float)($it['valor_unitario'] ?? 0), 10);
            $vTot  = round($qtd * (float)($it['valor_unitario'] ?? 0), 2);
            $csosn = (string)($it['csosn'] ?? '102');
            $orig  = (int)($it['origem'] ?? 0);
            $ncm   = str_pad(preg_replace('/\D/', '', $it['ncm'] ?? '00000000'), 8, '0', STR_PAD_LEFT);

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
            $vDescItem = round((float)($it['valor_desconto'] ?? 0), 2);
            if ($vDescItem > 0) {
                $prod->vDesc = $vDescItem;
            }
            $prod->indTot = 1;
            $make->tagprod($prod);

            // tagimposto
            $imp = new \stdClass();
            $imp->item = $nItem;
            $make->tagimposto($imp);

            // tagICMSSN — Simples Nacional (CRT=1)
            $icms = new \stdClass();
            $icms->item  = $nItem;
            $icms->orig  = $orig;
            $icms->CSOSN = $csosn;
            if (in_array($csosn, ['101', '201'])) {
                $icms->pCredSN     = 0.00;
                $icms->vCredICMSSN = 0.00;
            }
            if (in_array($csosn, ['201', '202', '203'])) {
                $icms->modBCST = 3;
                $icms->vBCST   = 0.00;
                $icms->pICMSST = 0.00;
                $icms->vICMSST = 0.00;
            }
            if ($csosn === '500') {
                $icms->vBCSTRet   = 0.00;
                $icms->vICMSSTRet = 0.00;
            }
            $make->tagICMSSN($icms);

            // tagPIS — CST 49 = Outras Operações de Saída (PISOutr exige vBC+pPIS+vPIS)
            $pis = new \stdClass();
            $pis->item = $nItem;
            $pis->CST  = '49';
            $pis->vBC  = 0.00;
            $pis->pPIS = 0.00;
            $pis->vPIS = 0.00;
            $make->tagPIS($pis);

            // tagCOFINS — CST 49 = Outras Operações de Saída (COFINSOutr exige vBC+pCOFINS+vCOFINS)
            $cof = new \stdClass();
            $cof->item    = $nItem;
            $cof->CST     = '49';
            $cof->vBC     = 0.00;
            $cof->pCOFINS = 0.00;
            $cof->vCOFINS = 0.00;
            $make->tagCOFINS($cof);

            // tagIBSCBS — Reforma Tributária
            $vLiqItem = round((float)($it['valor_total'] ?? $vTot), 2);
            $ibscbs = new \stdClass();
            $ibscbs->item    = $nItem;
            $ibscbs->cst     = '01';
            $ibscbs->vBC     = $vLiqItem;
            $ibscbs->pCBS    = 0.9;
            $ibscbs->vCBS    = round($vLiqItem * 0.009, 2);
            $ibscbs->pIBSUF  = 0.1;
            $ibscbs->vIBSUF  = round($vLiqItem * 0.001, 2);
            $ibscbs->pIBSMun = 0.0;
            $ibscbs->vIBSMun = 0.00;
            $make->tagIBSCBS($ibscbs);
        }

        // tagTotal
        $total = new \stdClass();
        $total->vBC        = 0.00;
        $total->vICMS      = 0.00;
        $total->vICMSDeson = 0.00;
        $total->vFCP       = 0.00;
        $total->vBCST      = 0.00;
        $total->vST        = 0.00;
        $total->vFCPST     = 0.00;
        $total->vFCPSTRet  = 0.00;
        $total->vProd      = $vProd;
        $total->vFrete     = $vFrete;
        $total->vSeg       = $vSeg;
        $total->vDesc      = $vDesc;
        $total->vII        = 0.00;
        $total->vIPI       = 0.00;
        $total->vIPIDevol  = 0.00;
        $total->vPIS       = 0.00;
        $total->vCOFINS    = 0.00;
        $total->vOutro     = $vOutro;
        $total->vNF        = $vNF;
        $total->vTotTrib   = 0.00;
        $make->tagTotal($total);

        // tagIBSCBSTot
        $calcBC = fn($it) => (float)($it['valor_total'] ?? round((float)($it['quantidade']??1)*(float)($it['valor_unitario']??0),2));
        $ibsTot = new \stdClass();
        $ibsTot->vBCIBSCBS = round(array_sum(array_map($calcBC, $itens)), 2);
        $ibsTot->vCBS      = round(array_sum(array_map(fn($it)=>round($calcBC($it)*0.009,2), $itens)), 2);
        $ibsTot->vIBSUF    = round(array_sum(array_map(fn($it)=>round($calcBC($it)*0.001,2), $itens)), 2);
        $ibsTot->vIBSMun   = 0.00;
        $make->tagIBSCBSTot($ibsTot);

        // tagtransp
        $modFrete = (int)($dados['mod_frete'] ?? 9);
        $transp = new \stdClass();
        $transp->modFrete = $modFrete;
        $make->tagtransp($transp);

        // tagtransporta — quando há transportadora
        if ($modFrete !== 9 && !empty($dados['transp_nome'])) {
            $transporta = new \stdClass();
            $transpCnpj = preg_replace('/\D/', '', $dados['transp_cnpj'] ?? '');
            $transpCpf  = preg_replace('/\D/', '', $dados['transp_cpf']  ?? '');
            if (strlen($transpCnpj) === 14) {
                $transporta->CNPJ = $transpCnpj;
            } elseif (strlen($transpCpf) === 11) {
                $transporta->CPF = $transpCpf;
            }
            $transporta->xNome = mb_strtoupper(substr($dados['transp_nome'], 0, 60));
            $transpIe = preg_replace('/\D/', '', $dados['transp_ie'] ?? '');
            if ($transpIe) {
                $transporta->IE = $transpIe;
            }
            if (!empty($dados['transp_uf'])) {
                $transporta->UF = strtoupper($dados['transp_uf']);
            }
            $make->tagtransporta($transporta);
        }

        // tagvol — volumes
        if (!empty($dados['vol_qtd']) && (int)$dados['vol_qtd'] > 0) {
            $vol = new \stdClass();
            $vol->item = 1;
            $vol->qVol = (int)$dados['vol_qtd'];
            if (!empty($dados['vol_esp']))    $vol->esp   = strtoupper($dados['vol_esp']);
            if (!empty($dados['vol_peso_l'])) $vol->pesoL = round((float)$dados['vol_peso_l'], 3);
            if (!empty($dados['vol_peso_b'])) $vol->pesoB = round((float)$dados['vol_peso_b'], 3);
            $make->tagvol($vol);
        }

        // tagpag
        $pagContainer = new \stdClass();
        $pagContainer->vTroco = 0.00;
        $make->tagpag($pagContainer);

        // tagdetPag
        $formasPag = $dados['formas_pagamento'] ?? [['tipo' => '01', 'valor' => $vNF]];
        foreach ($formasPag as $fp) {
            $pag = new \stdClass();
            $pag->indPag = 0; // à vista
            $pag->tPag   = str_pad((string)($fp['tipo'] ?? '01'), 2, '0', STR_PAD_LEFT);
            $pag->vPag   = round((float)($fp['valor'] ?? $vNF), 2);
            if (in_array($pag->tPag, ['03', '04'])) {
                $pag->tpIntegra = (int)($fp['card_tp_integra'] ?? 2);
                $pag->tBand     = str_pad((string)($fp['card_tband'] ?? '99'), 2, '0', STR_PAD_LEFT);
                $pag->cAut      = $fp['card_caut'] ?? '000000';
                if ($pag->tpIntegra === 1) {
                    $pag->CNPJ = preg_replace('/\D/', '', $fp['card_cnpj'] ?? '');
                }
            }
            $make->tagdetPag($pag);
        }

        // taginfAdic
        $infCpl = trim($dados['info_adicional'] ?? '');
        $infAdic = new \stdClass();
        $infAdic->infCpl = $infCpl ?: 'Emitido por ConsertaOS';
        $make->taginfAdic($infAdic);

        // taginfRespTec — responsável técnico (obrigatório desde 2020)
        $respTec = new \stdClass();
        $respTec->CNPJ     = '30366939000135';
        $respTec->xContato = 'AG Tech';
        $respTec->email    = 'atendimento.agtech@hotmail.com';
        $respTec->fone     = '47997484054';
        $make->taginfRespTec($respTec);

        // NF-e modelo 55 NÃO tem infNFeSupl (QR Code — exclusivo da NFC-e)

        // ── Gera, assina e transmite ───────────────────────────────────
        $xml = $make->getXML();

        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('55'); // NF-e modelo 55

        $xmlAssinado = $tools->signNFe($xml);

        $xmlDir = $storageDir . '/enviados';
        if (!is_dir($xmlDir)) mkdir($xmlDir, 0755, true);
        file_put_contents("$xmlDir/{$numero}.xml", $xmlAssinado);

        $idLote  = str_pad((string)$numero, 15, '0', STR_PAD_LEFT);
        $resposta = $tools->sefazEnviaLote([$xmlAssinado], $idLote, 1); // indSinc=1

        return $this->_processarRetorno($resposta, $xmlAssinado, $storageDir, $numero);
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
            throw new \InvalidArgumentException('nProt não encontrado. A NF-e pode não ter sido autorizada corretamente.');
        }

        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('55');

        $logDir = $this->config['storage_dir'] . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);

        try {
            $resp = $tools->sefazCancela($chave, $justificativa, $nProt);
        } catch (\Throwable $e) {
            $errMsg = $e->getMessage();
            file_put_contents("$logDir/cancelamento_erro_" . date('YmdHis') . ".txt", $errMsg);
            return ['autorizada' => false, 'cStat' => 'EXCECAO', 'xMotivo' => 'Erro ao comunicar com a SEFAZ: ' . $errMsg, 'nProt' => ''];
        }

        $logContent = "=== RESP ===\n" . (string)$resp;
        if (!empty($tools->errors)) {
            $logContent .= "\n=== ERRORS ===\n" . implode(' | ', array_map(
                fn($e) => is_array($e) ? json_encode($e) : (string)$e,
                $tools->errors
            ));
        }
        file_put_contents("$logDir/cancelamento_" . date('YmdHis') . ".txt", $logContent);

        $cStat = $xMotivo = $nProtRet = '';
        if (!empty($resp)) {
            $xmlSoap = @simplexml_load_string($resp);
            if ($xmlSoap) {
                $nodes = $xmlSoap->xpath('//*[local-name()="infEvento"]');
                if (!empty($nodes)) {
                    $cStat    = (string)($nodes[0]->cStat   ?? '');
                    $xMotivo  = (string)($nodes[0]->xMotivo ?? '');
                    $nProtRet = (string)($nodes[0]->nProt   ?? '');
                }
            }
            if (!$cStat) {
                $st  = new \NFePHP\NFe\Common\Standardize();
                $obj = $st->toStd($resp);
                $inf = $obj->retEnvEvento->retEvento->infEvento ?? $obj->retEvento->infEvento ?? null;
                $cStat    = (string)($inf->cStat   ?? '');
                $xMotivo  = (string)($inf->xMotivo ?? '');
                $nProtRet = (string)($inf->nProt   ?? '');
            }
        }

        // 135=cancelada 155=fora do prazo aceito 136=evento duplicado (já cancelada)
        $autorizada = in_array($cStat, ['135', '155', '136']);
        return ['autorizada' => $autorizada, 'cStat' => $cStat, 'xMotivo' => $xMotivo, 'nProt' => $nProtRet];
    }

    // ──────────────────────────────────────────────────────────────────
    // CONSULTAR situação da NF-e na SEFAZ
    // ──────────────────────────────────────────────────────────────────
    public function consultar(string $chave): array
    {
        if (strlen($chave) !== 44) {
            throw new \InvalidArgumentException("Chave de acesso inválida (deve ter 44 dígitos).");
        }

        $configTools = $this->_buildToolsConfig();
        $certificate = Certificate::readPfx(
            base64_decode($this->config['certificado_pfx']),
            $this->config['certificado_senha']
        );
        $tools = new Tools(json_encode($configTools), $certificate);
        $tools->model('55');

        $logDir = $this->config['storage_dir'] . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);

        try {
            $resp = $tools->sefazConsultaChave($chave);
        } catch (\Throwable $e) {
            $errMsg = $e->getMessage();
            file_put_contents("$logDir/consulta_erro_" . date('YmdHis') . ".txt", $errMsg);
            return ['autorizada' => false, 'cStat' => 'EXCECAO', 'xMotivo' => 'Erro ao consultar SEFAZ: ' . $errMsg, 'nProt' => ''];
        }

        file_put_contents("$logDir/consulta_" . date('YmdHis') . ".txt", "=== RESP ===\n" . (string)$resp);

        $cStat = $xMotivo = $nProtRet = '';
        if (!empty($resp)) {
            try {
                $st  = new \NFePHP\NFe\Common\Standardize();
                $obj = $st->toStd($resp);
                $prot = $obj->retConsSitNFe->protNFe->infProt ?? $obj->protNFe->infProt ?? null;
                if ($prot) {
                    $cStat    = (string)($prot->cStat   ?? '');
                    $xMotivo  = (string)($prot->xMotivo ?? '');
                    $nProtRet = (string)($prot->nProt   ?? '');
                }
                if (!$cStat) {
                    $ret = $obj->retConsSitNFe ?? $obj ?? null;
                    $cStat   = (string)($ret->cStat   ?? '');
                    $xMotivo = (string)($ret->xMotivo ?? '');
                }
            } catch (\Throwable $e) {
                $xMotivo = 'Erro ao interpretar resposta da SEFAZ.';
            }
        }

        // 100 = autorizada, 101 = cancelada, 110 = denegada, 150 = autorizada fora do prazo
        $autorizada = in_array($cStat, ['100', '150']);
        return ['autorizada' => $autorizada, 'cStat' => $cStat, 'xMotivo' => $xMotivo, 'nProt' => $nProtRet];
    }

    // ──────────────────────────────────────────────────────────────────
    // INUTILIZAR faixa de numeração
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
        $tools->model('55');

        // Bypass do schema errado (mesmo comportamento do NfceService)
        $pathSchemesOriginal = $tools->pathschemes;
        $tools->pathschemes  = '';
        $resp = $tools->sefazInutiliza($serie, $nIni, $nFin, $justificativa);
        $tools->pathschemes  = $pathSchemesOriginal;

        $storageDir = $this->config['storage_dir'];
        $inutDir    = $storageDir . '/inutilizados';
        if (!is_dir($inutDir)) mkdir($inutDir, 0755, true);
        file_put_contents("$inutDir/{$nIni}-{$nFin}-ret.xml", $resp);

        $st  = new \NFePHP\NFe\Common\Standardize();
        $obj = $st->toStd($resp);
        $inf = $obj->retInutNFe->infInut ?? $obj->infInut ?? null;

        if ($inf === null && !empty($resp)) {
            $xml = @simplexml_load_string($resp);
            if ($xml) {
                $xml->registerXPathNamespace('nfe', 'http://www.portalfiscal.inf.br/nfe');
                $nodes = $xml->xpath('//nfe:infInut') ?: $xml->xpath('//*[local-name()="infInut"]');
                if (!empty($nodes)) $inf = $nodes[0];
            }
        }

        $cStat   = (string)($inf->cStat   ?? '');
        $xMotivo = (string)($inf->xMotivo ?? 'Sem retorno');
        $nProt   = (string)($inf->nProt   ?? '');

        return [
            'inutilizado' => in_array($cStat, ['102', '103', '563']),
            'cStat'       => $cStat,
            'xMotivo'     => $xMotivo,
            'nProt'       => $nProt,
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
            'CSC'         => '', // NF-e modelo 55 não usa CSC
            'CSCid'       => '',
        ];
    }

    private function _processarRetorno(string $resposta, string $xmlAssinado, string $storageDir, int $numero): array
    {
        $logDir = $storageDir . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);
        file_put_contents("$logDir/retorno_{$numero}.xml", $resposta);

        $cStat = $xMotivo = $nProt = $chave = '';

        try {
            $st  = new \NFePHP\NFe\Common\Standardize();
            $obj = $st->toStd($resposta);

            // Estrutura 1: retEnviNFe > protNFe > infProt (síncrono)
            if (isset($obj->retEnviNFe)) {
                $ret     = $obj->retEnviNFe;
                $cStat   = (string)($ret->cStat   ?? '');
                $xMotivo = (string)($ret->xMotivo ?? '');
                if (isset($ret->protNFe->infProt)) {
                    $inf     = $ret->protNFe->infProt;
                    $cStat   = (string)($inf->cStat   ?? $cStat);
                    $xMotivo = (string)($inf->xMotivo ?? $xMotivo);
                    $nProt   = (string)($inf->nProt   ?? '');
                    $chave   = (string)($inf->chNFe   ?? '');
                }
            }

            // Estrutura 2: protNFe direto
            if ($cStat === '' && isset($obj->protNFe->infProt)) {
                $inf     = $obj->protNFe->infProt;
                $cStat   = (string)($inf->cStat   ?? '');
                $xMotivo = (string)($inf->xMotivo ?? '');
                $nProt   = (string)($inf->nProt   ?? '');
                $chave   = (string)($inf->chNFe   ?? '');
            }

            // Estrutura 3: infRec — retorno assíncrono (lote recebido, aguardando processamento)
            if ($cStat === '' && isset($obj->infRec)) {
                $cStat   = (string)($obj->cStat   ?? '');
                $xMotivo = (string)($obj->xMotivo ?? '') . ' [lote assíncrono — use consulta de recibo]';
            }

            // Estrutura 4: cStat no nível raiz
            if ($cStat === '' && isset($obj->cStat)) {
                $cStat   = (string)$obj->cStat;
                $xMotivo = (string)($obj->xMotivo ?? '');
            }

        } catch (\Exception $e) {
            return [
                'autorizada' => false,
                'chave'      => '',
                'nProt'      => '',
                'cStat'      => 'PARSE_ERROR',
                'xMotivo'    => 'Erro ao processar retorno: ' . $e->getMessage() . ' | Resp: ' . substr($resposta, 0, 300),
            ];
        }

        $autorizada = ($cStat === '100');
        $subDir     = $autorizada ? 'autorizada' : 'rejeitada';
        @file_put_contents("$storageDir/$subDir/{$numero}.xml", $xmlAssinado);

        return [
            'autorizada' => $autorizada,
            'chave'      => $chave,
            'nProt'      => $nProt,
            'cStat'      => $cStat,
            'xMotivo'    => $xMotivo ?: 'Sem retorno da SEFAZ | Resp: ' . substr($resposta, 0, 200),
        ];
    }

    // ──────────────────────────────────────────────────────────────────
    // LISTA DE CFOPs
    // ──────────────────────────────────────────────────────────────────
    public static function listaCfops(): array
    {
        return [
            // ── ENTRADAS DENTRO DO ESTADO (1xxx) ─────────────────────────
            ['cfop'=>'1101','desc'=>'Compra para industrialização ou produção rural'],
            ['cfop'=>'1102','desc'=>'Compra para comercialização'],
            ['cfop'=>'1111','desc'=>'Compra para industrialização de mercadoria recebida anteriormente em consignação industrial'],
            ['cfop'=>'1113','desc'=>'Compra para industrialização, de mercadoria recebida anteriormente em consignação mercantil'],
            ['cfop'=>'1116','desc'=>'Compra para industrialização originada de encomenda para recebimento futuro'],
            ['cfop'=>'1117','desc'=>'Compra para comercialização, originada de encomenda para recebimento futuro'],
            ['cfop'=>'1118','desc'=>'Compra de mercadoria para comercialização pelo adquirente originário'],
            ['cfop'=>'1120','desc'=>'Compra para industrialização, em venda à ordem, já recebida do vendedor remetente'],
            ['cfop'=>'1121','desc'=>'Compra para comercialização, em venda à ordem, já recebida do vendedor remetente'],
            ['cfop'=>'1122','desc'=>'Compra para industrialização em que a mercadoria foi remetida pelo fornecedor para industrialização'],
            ['cfop'=>'1124','desc'=>'Industrialização efetuada por outra empresa'],
            ['cfop'=>'1125','desc'=>'Industrialização efetuada por outra empresa quando a mercadoria remetida não transitou pelo estabelecimento'],
            ['cfop'=>'1151','desc'=>'Transferência para industrialização ou produção rural'],
            ['cfop'=>'1152','desc'=>'Transferência para comercialização'],
            ['cfop'=>'1201','desc'=>'Devolução de venda de produção do estabelecimento'],
            ['cfop'=>'1202','desc'=>'Devolução de venda de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'1208','desc'=>'Devolução de venda de mercadoria recebida em transferência'],
            ['cfop'=>'1209','desc'=>'Devolução de venda de mercadoria recebida em transferência para comercialização'],
            ['cfop'=>'1251','desc'=>'Compra de energia elétrica para distribuição ou comercialização'],
            ['cfop'=>'1301','desc'=>'Aquisição de serviço de comunicação para execução de serviço da mesma natureza'],
            ['cfop'=>'1351','desc'=>'Aquisição de serviço de transporte para execução de serviço da mesma natureza'],
            ['cfop'=>'1352','desc'=>'Aquisição de serviço de transporte de estabelecimento industrial'],
            ['cfop'=>'1353','desc'=>'Aquisição de serviço de transporte de estabelecimento comercial'],
            ['cfop'=>'1401','desc'=>'Compra para industrialização em operação com ST (substituto)'],
            ['cfop'=>'1403','desc'=>'Compra para comercialização em operação com ST (substituto)'],
            ['cfop'=>'1406','desc'=>'Compra de mercadoria para uso ou consumo em operação com ST'],
            ['cfop'=>'1407','desc'=>'Aquisição de serviço de transporte em operação com ST'],
            ['cfop'=>'1408','desc'=>'Transferência para industrialização em operação com ST'],
            ['cfop'=>'1409','desc'=>'Transferência para comercialização em operação com ST'],
            ['cfop'=>'1410','desc'=>'Devolução de venda de produção em operação com ST'],
            ['cfop'=>'1411','desc'=>'Devolução de venda de mercadoria adquirida de terceiros em operação com ST'],
            ['cfop'=>'1501','desc'=>'Entrada de mercadoria recebida com fim específico de exportação'],
            ['cfop'=>'1503','desc'=>'Entrada decorrente de devolução de produto remetido com fim específico de exportação'],
            ['cfop'=>'1551','desc'=>'Compra de bem para o ativo imobilizado'],
            ['cfop'=>'1552','desc'=>'Transferência de bem do ativo imobilizado'],
            ['cfop'=>'1553','desc'=>'Devolução de venda de bem do ativo imobilizado'],
            ['cfop'=>'1554','desc'=>'Retorno de bem do ativo imobilizado remetido para uso fora do estabelecimento'],
            ['cfop'=>'1555','desc'=>'Entrada de bem do ativo imobilizado de terceiro, remetido para uso no estabelecimento'],
            ['cfop'=>'1556','desc'=>'Retorno de bem do ativo imobilizado remetido para conserto ou reparo'],
            ['cfop'=>'1557','desc'=>'Transferência de bem do ativo imobilizado para o ativo imobilizado de outro estabelecimento'],
            ['cfop'=>'1601','desc'=>'Recebimento, por transferência, de crédito de ICMS'],
            ['cfop'=>'1651','desc'=>'Compra de combustível ou lubrificante para industrialização subseqüente'],
            ['cfop'=>'1652','desc'=>'Compra de combustível ou lubrificante para comercialização'],
            ['cfop'=>'1653','desc'=>'Compra de combustível ou lubrificante para consumo'],
            ['cfop'=>'1658','desc'=>'Transferência de combustível ou lubrificante de produção do estabelecimento'],
            ['cfop'=>'1659','desc'=>'Transferência de combustível ou lubrificante adquirido ou recebido de terceiros'],
            ['cfop'=>'1660','desc'=>'Devolução de venda de combustível ou lubrificante para industrialização subseqüente'],
            ['cfop'=>'1661','desc'=>'Devolução de venda de combustível ou lubrificante para comercialização'],
            ['cfop'=>'1662','desc'=>'Devolução de venda de combustível ou lubrificante para consumo'],
            ['cfop'=>'1801','desc'=>'Recebimento de vasilhames, recipientes e embalagens'],
            ['cfop'=>'1802','desc'=>'Entradas de vasilhames, recipientes e embalagens'],
            ['cfop'=>'1901','desc'=>'Entrada para industrialização por encomenda'],
            ['cfop'=>'1902','desc'=>'Retorno de mercadoria remetida para industrialização por encomenda'],
            ['cfop'=>'1903','desc'=>'Entrada de mercadoria remetida para industrialização e não aplicada'],
            ['cfop'=>'1904','desc'=>'Retorno de remessa para venda fora do estabelecimento'],
            ['cfop'=>'1905','desc'=>'Entrada de mercadoria recebida para depósito em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'1906','desc'=>'Retorno de mercadoria remetida para depósito em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'1907','desc'=>'Retorno simbólico de mercadoria remetida para depósito em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'1908','desc'=>'Entrada de bem por conta de contrato de comodato'],
            ['cfop'=>'1909','desc'=>'Retorno de bem remetido por conta de contrato de comodato'],
            ['cfop'=>'1910','desc'=>'Entrada de bonificação, doação ou brinde'],
            ['cfop'=>'1911','desc'=>'Entrada de amostra grátis'],
            ['cfop'=>'1912','desc'=>'Entrada de mercadoria ou bem recebido para demonstração'],
            ['cfop'=>'1913','desc'=>'Retorno de mercadoria ou bem remetido para demonstração'],
            ['cfop'=>'1914','desc'=>'Retorno de mercadoria ou bem remetido para exposição ou feira'],
            ['cfop'=>'1915','desc'=>'Entrada de mercadoria ou bem recebido para conserto ou reparo'],
            ['cfop'=>'1916','desc'=>'Retorno de mercadoria ou bem remetido para conserto ou reparo'],
            ['cfop'=>'1917','desc'=>'Entrada de mercadoria recebida em consignação mercantil ou industrial'],
            ['cfop'=>'1918','desc'=>'Devolução de mercadoria remetida em consignação mercantil ou industrial'],
            ['cfop'=>'1919','desc'=>'Devolução simbólica de mercadoria vendida ou utilizada em processo industrial, remetida anteriormente em consignação mercantil ou industrial'],
            ['cfop'=>'1920','desc'=>'Entrada de vasilhame, embalagem ou acondicionamento'],
            ['cfop'=>'1921','desc'=>'Retorno de vasilhame, embalagem ou acondicionamento'],
            ['cfop'=>'1922','desc'=>'Lançamento efetuado a título de simples faturamento decorrente de compra para recebimento futuro'],
            ['cfop'=>'1923','desc'=>'Entrada de mercadoria recebida do vendedor remetente, em venda à ordem'],
            ['cfop'=>'1924','desc'=>'Entrada para industrialização por conta e ordem do adquirente da mercadoria'],
            ['cfop'=>'1925','desc'=>'Retorno de mercadoria remetida para industrialização por conta e ordem do adquirente'],
            ['cfop'=>'1932','desc'=>'Aquisição de serviço de transporte iniciado em unidade da Federação diversa daquela onde inscrito o prestador'],
            ['cfop'=>'1933','desc'=>'Aquisição de serviço tributado pelo ISSQN'],
            ['cfop'=>'1949','desc'=>'Outra entrada de mercadoria ou prestação de serviço não especificado'],
            // ── ENTRADAS INTERESTADUAIS (2xxx) ───────────────────────────
            ['cfop'=>'2101','desc'=>'Compra para industrialização ou produção rural (interestadual)'],
            ['cfop'=>'2102','desc'=>'Compra para comercialização (interestadual)'],
            ['cfop'=>'2111','desc'=>'Compra para industrialização de mercadoria recebida em consignação industrial (interestadual)'],
            ['cfop'=>'2113','desc'=>'Compra para industrialização de mercadoria recebida em consignação mercantil (interestadual)'],
            ['cfop'=>'2116','desc'=>'Compra para industrialização originada de encomenda para recebimento futuro (interestadual)'],
            ['cfop'=>'2117','desc'=>'Compra para comercialização originada de encomenda para recebimento futuro (interestadual)'],
            ['cfop'=>'2118','desc'=>'Compra de mercadoria para comercialização pelo adquirente originário (interestadual)'],
            ['cfop'=>'2120','desc'=>'Compra para industrialização, em venda à ordem, já recebida do vendedor remetente (interestadual)'],
            ['cfop'=>'2121','desc'=>'Compra para comercialização, em venda à ordem, já recebida do vendedor remetente (interestadual)'],
            ['cfop'=>'2122','desc'=>'Compra para industrialização em que a mercadoria foi remetida pelo fornecedor para industrialização (interestadual)'],
            ['cfop'=>'2124','desc'=>'Industrialização efetuada por outra empresa (interestadual)'],
            ['cfop'=>'2125','desc'=>'Industrialização efetuada por outra empresa sem trânsito pelo estabelecimento adquirente (interestadual)'],
            ['cfop'=>'2151','desc'=>'Transferência para industrialização ou produção rural (interestadual)'],
            ['cfop'=>'2152','desc'=>'Transferência para comercialização (interestadual)'],
            ['cfop'=>'2201','desc'=>'Devolução de venda de produção do estabelecimento (interestadual)'],
            ['cfop'=>'2202','desc'=>'Devolução de venda de mercadoria adquirida ou recebida de terceiros (interestadual)'],
            ['cfop'=>'2208','desc'=>'Devolução de venda de mercadoria recebida em transferência para industrialização (interestadual)'],
            ['cfop'=>'2209','desc'=>'Devolução de venda de mercadoria recebida em transferência para comercialização (interestadual)'],
            ['cfop'=>'2251','desc'=>'Compra de energia elétrica para distribuição ou comercialização (interestadual)'],
            ['cfop'=>'2301','desc'=>'Aquisição de serviço de comunicação para execução de serviço da mesma natureza (interestadual)'],
            ['cfop'=>'2351','desc'=>'Aquisição de serviço de transporte para execução de serviço da mesma natureza (interestadual)'],
            ['cfop'=>'2352','desc'=>'Aquisição de serviço de transporte de estabelecimento industrial (interestadual)'],
            ['cfop'=>'2353','desc'=>'Aquisição de serviço de transporte de estabelecimento comercial (interestadual)'],
            ['cfop'=>'2401','desc'=>'Compra para industrialização em operação com ST (interestadual)'],
            ['cfop'=>'2403','desc'=>'Compra para comercialização em operação com ST (interestadual)'],
            ['cfop'=>'2406','desc'=>'Compra de mercadoria para uso ou consumo em operação com ST (interestadual)'],
            ['cfop'=>'2407','desc'=>'Aquisição de serviço de transporte em operação com ST (interestadual)'],
            ['cfop'=>'2551','desc'=>'Compra de bem para o ativo imobilizado (interestadual)'],
            ['cfop'=>'2553','desc'=>'Devolução de venda de bem do ativo imobilizado (interestadual)'],
            ['cfop'=>'2651','desc'=>'Compra de combustível ou lubrificante para industrialização subseqüente (interestadual)'],
            ['cfop'=>'2652','desc'=>'Compra de combustível ou lubrificante para comercialização (interestadual)'],
            ['cfop'=>'2653','desc'=>'Compra de combustível ou lubrificante para consumo (interestadual)'],
            ['cfop'=>'2658','desc'=>'Transferência de combustível ou lubrificante de produção do estabelecimento (interestadual)'],
            ['cfop'=>'2659','desc'=>'Transferência de combustível ou lubrificante adquirido ou recebido de terceiros (interestadual)'],
            ['cfop'=>'2901','desc'=>'Entrada para industrialização por encomenda (interestadual)'],
            ['cfop'=>'2902','desc'=>'Retorno de mercadoria remetida para industrialização por encomenda (interestadual)'],
            ['cfop'=>'2903','desc'=>'Entrada de mercadoria remetida para industrialização e não aplicada no referido processo (interestadual)'],
            ['cfop'=>'2904','desc'=>'Retorno de remessa para venda fora do estabelecimento (interestadual)'],
            ['cfop'=>'2907','desc'=>'Retorno simbólico de mercadoria remetida para depósito em depósito fechado ou armazém alfandegado (interestadual)'],
            ['cfop'=>'2949','desc'=>'Outra entrada de mercadoria ou prestação de serviço não especificado (interestadual)'],
            // ── ENTRADAS DO EXTERIOR (3xxx) ───────────────────────────────
            ['cfop'=>'3101','desc'=>'Compra para industrialização ou produção rural (importação)'],
            ['cfop'=>'3102','desc'=>'Compra para comercialização (importação)'],
            ['cfop'=>'3126','desc'=>'Compra para utilização na prestação de serviço sujeita ao ISSQN (importação)'],
            ['cfop'=>'3127','desc'=>'Compra para industrialização sob o regime aduaneiro especial de drawback'],
            ['cfop'=>'3201','desc'=>'Devolução de exportação'],
            ['cfop'=>'3211','desc'=>'Devolução de venda de produção do estabelecimento com fim específico de exportação'],
            ['cfop'=>'3212','desc'=>'Devolução de venda de mercadoria adquirida ou recebida de terceiros com fim específico de exportação'],
            ['cfop'=>'3251','desc'=>'Compra de energia elétrica (importação)'],
            ['cfop'=>'3301','desc'=>'Aquisição de serviço de comunicação (importação)'],
            ['cfop'=>'3351','desc'=>'Aquisição de serviço de transporte (importação)'],
            ['cfop'=>'3551','desc'=>'Compra de bem para o ativo imobilizado (importação)'],
            ['cfop'=>'3651','desc'=>'Compra de combustível ou lubrificante (importação)'],
            ['cfop'=>'3949','desc'=>'Outra entrada de mercadoria ou prestação de serviço não especificado (importação)'],
            // ── SAÍDAS DENTRO DO ESTADO (5xxx) ───────────────────────────
            ['cfop'=>'5101','desc'=>'Venda de produção do estabelecimento'],
            ['cfop'=>'5102','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'5103','desc'=>'Venda de produção do estabelecimento efetuada fora do estabelecimento'],
            ['cfop'=>'5104','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, realizada fora do estabelecimento'],
            ['cfop'=>'5105','desc'=>'Venda de produção do estabelecimento que não deva transitar pelo estabelecimento remetente'],
            ['cfop'=>'5106','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros que não deva transitar pelo estabelecimento remetente'],
            ['cfop'=>'5109','desc'=>'Venda de produção do estabelecimento, destinada à Zona Franca de Manaus ou Áreas de Livre Comércio'],
            ['cfop'=>'5110','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, destinada à Zona Franca de Manaus ou Áreas de Livre Comércio'],
            ['cfop'=>'5111','desc'=>'Venda de produção do estabelecimento remetida anteriormente em consignação industrial'],
            ['cfop'=>'5112','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida anteriormente em consignação industrial'],
            ['cfop'=>'5113','desc'=>'Venda de produção do estabelecimento remetida anteriormente em consignação mercantil'],
            ['cfop'=>'5114','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida anteriormente em consignação mercantil'],
            ['cfop'=>'5115','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros recebida anteriormente em consignação mercantil'],
            ['cfop'=>'5116','desc'=>'Venda de produção do estabelecimento originada de encomenda para entrega futura'],
            ['cfop'=>'5117','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, originada de encomenda para entrega futura'],
            ['cfop'=>'5118','desc'=>'Venda de produção do estabelecimento entregue ao destinatário por conta e ordem do adquirente originário'],
            ['cfop'=>'5119','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros entregue ao destinatário por conta e ordem do adquirente originário'],
            ['cfop'=>'5120','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros entregue ao destinatário pelo vendedor remetente, em venda à ordem'],
            ['cfop'=>'5122','desc'=>'Venda de produção do estabelecimento remetida para industrialização, por conta e ordem do adquirente'],
            ['cfop'=>'5123','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida para industrialização, por conta e ordem do adquirente'],
            ['cfop'=>'5124','desc'=>'Industrialização efetuada para outra empresa'],
            ['cfop'=>'5125','desc'=>'Industrialização efetuada para outra empresa quando a mercadoria não transitou pelo estabelecimento adquirente'],
            ['cfop'=>'5151','desc'=>'Transferência de produção do estabelecimento'],
            ['cfop'=>'5152','desc'=>'Transferência de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'5153','desc'=>'Transferência de energia elétrica'],
            ['cfop'=>'5155','desc'=>'Transferência de bem do ativo imobilizado'],
            ['cfop'=>'5156','desc'=>'Transferência de sal, a granel'],
            ['cfop'=>'5201','desc'=>'Devolução de compra para industrialização ou produção rural'],
            ['cfop'=>'5202','desc'=>'Devolução de compra para comercialização'],
            ['cfop'=>'5205','desc'=>'Anulação de valor relativo a aquisição de serviço de comunicação'],
            ['cfop'=>'5206','desc'=>'Anulação de valor relativo a aquisição de serviço de transporte'],
            ['cfop'=>'5207','desc'=>'Anulação de valor relativo à compra de energia elétrica'],
            ['cfop'=>'5208','desc'=>'Devolução de mercadoria recebida em transferência para industrialização'],
            ['cfop'=>'5209','desc'=>'Devolução de mercadoria recebida em transferência para comercialização'],
            ['cfop'=>'5210','desc'=>'Devolução de compra para utilização na prestação de serviço'],
            ['cfop'=>'5251','desc'=>'Venda de energia elétrica para distribuição ou comercialização'],
            ['cfop'=>'5252','desc'=>'Venda de energia elétrica para estabelecimentos comerciais'],
            ['cfop'=>'5253','desc'=>'Venda de energia elétrica para estabelecimentos industriais'],
            ['cfop'=>'5254','desc'=>'Venda de energia elétrica para consumo por demanda contratada'],
            ['cfop'=>'5255','desc'=>'Venda de energia elétrica para consumidores rurais'],
            ['cfop'=>'5256','desc'=>'Venda de energia elétrica para órgãos da administração pública'],
            ['cfop'=>'5257','desc'=>'Venda de energia elétrica para consumidores residenciais'],
            ['cfop'=>'5258','desc'=>'Venda de energia elétrica a não contribuintes'],
            ['cfop'=>'5301','desc'=>'Prestação de serviço de comunicação para execução de serviço da mesma natureza'],
            ['cfop'=>'5302','desc'=>'Prestação de serviço de comunicação a estabelecimento industrial'],
            ['cfop'=>'5303','desc'=>'Prestação de serviço de comunicação a estabelecimento comercial'],
            ['cfop'=>'5307','desc'=>'Prestação de serviço de comunicação a não contribuinte'],
            ['cfop'=>'5351','desc'=>'Prestação de serviço de transporte para execução de serviço da mesma natureza'],
            ['cfop'=>'5352','desc'=>'Prestação de serviço de transporte a estabelecimento industrial'],
            ['cfop'=>'5353','desc'=>'Prestação de serviço de transporte a estabelecimento comercial'],
            ['cfop'=>'5354','desc'=>'Prestação de serviço de transporte a estabelecimento de prestador de serviços'],
            ['cfop'=>'5355','desc'=>'Prestação de serviço de transporte a estabelecimento de produtor rural'],
            ['cfop'=>'5357','desc'=>'Prestação de serviço de transporte a não contribuinte'],
            ['cfop'=>'5401','desc'=>'Venda de produção do estabelecimento em operação com ST (substituto)'],
            ['cfop'=>'5402','desc'=>'Venda de produção do estabelecimento em operação com ST entre contribuintes substitutos do mesmo produto'],
            ['cfop'=>'5403','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros em operação com ST (substituto)'],
            ['cfop'=>'5405','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros com ST (substituído)'],
            ['cfop'=>'5408','desc'=>'Transferência de produção do estabelecimento em operação com ST'],
            ['cfop'=>'5409','desc'=>'Transferência de mercadoria adquirida ou recebida de terceiros em operação com ST'],
            ['cfop'=>'5410','desc'=>'Devolução de compra para industrialização em operação com ST'],
            ['cfop'=>'5411','desc'=>'Devolução de compra para comercialização em operação com ST'],
            ['cfop'=>'5412','desc'=>'Devolução de bem do ativo imobilizado em operação com ST'],
            ['cfop'=>'5413','desc'=>'Devolução de mercadoria destinada ao uso ou consumo em operação com ST'],
            ['cfop'=>'5501','desc'=>'Remessa de produção do estabelecimento com fim específico de exportação'],
            ['cfop'=>'5502','desc'=>'Remessa de mercadoria adquirida ou recebida de terceiros com fim específico de exportação'],
            ['cfop'=>'5503','desc'=>'Devolução de mercadoria recebida com fim específico de exportação'],
            ['cfop'=>'5504','desc'=>'Remessa de mercadorias para formação de lote de exportação de produtos industrializados ou produzidos pelo próprio estabelecimento'],
            ['cfop'=>'5505','desc'=>'Remessa de mercadorias adquiridas ou recebidas de terceiros para formação de lote de exportação'],
            ['cfop'=>'5551','desc'=>'Venda de bem do ativo imobilizado'],
            ['cfop'=>'5552','desc'=>'Transferência de bem do ativo imobilizado'],
            ['cfop'=>'5553','desc'=>'Devolução de compra de bem para o ativo imobilizado'],
            ['cfop'=>'5554','desc'=>'Remessa de bem do ativo imobilizado para uso fora do estabelecimento'],
            ['cfop'=>'5555','desc'=>'Remessa de bem do ativo imobilizado para conserto ou reparo'],
            ['cfop'=>'5556','desc'=>'Devolução de bem do ativo imobilizado recebido para conserto ou reparo'],
            ['cfop'=>'5557','desc'=>'Transferência de bem do ativo imobilizado para ativo imobilizado de outro estabelecimento'],
            ['cfop'=>'5601','desc'=>'Transferência de crédito de ICMS acumulado'],
            ['cfop'=>'5651','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento destinados à industrialização subseqüente'],
            ['cfop'=>'5652','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento destinados à comercialização'],
            ['cfop'=>'5653','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento destinados a consumidor ou usuário final'],
            ['cfop'=>'5654','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros destinados à industrialização subseqüente'],
            ['cfop'=>'5655','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros destinados à comercialização'],
            ['cfop'=>'5656','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros destinados a consumidor ou usuário final'],
            ['cfop'=>'5657','desc'=>'Remessa de combustível ou lubrificante adquiridos ou recebidos de terceiros para venda fora do estabelecimento'],
            ['cfop'=>'5658','desc'=>'Transferência de combustível ou lubrificante de produção do estabelecimento'],
            ['cfop'=>'5659','desc'=>'Transferência de combustível ou lubrificante adquiridos ou recebidos de terceiros'],
            ['cfop'=>'5660','desc'=>'Devolução de compra de combustível ou lubrificante adquiridos para industrialização subseqüente'],
            ['cfop'=>'5661','desc'=>'Devolução de compra de combustível ou lubrificante adquiridos para comercialização'],
            ['cfop'=>'5662','desc'=>'Devolução de compra de combustível ou lubrificante adquiridos por consumidor ou usuário final'],
            ['cfop'=>'5751','desc'=>'Venda de exportação para o exterior de mercadoria industrializada ou produzida pelo próprio estabelecimento'],
            ['cfop'=>'5752','desc'=>'Venda de exportação para o exterior de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'5801','desc'=>'Remessa de vasilhames, recipientes e embalagens'],
            ['cfop'=>'5802','desc'=>'Devolução de vasilhames, recipientes e embalagens'],
            ['cfop'=>'5803','desc'=>'Remessa de amostra grátis'],
            ['cfop'=>'5804','desc'=>'Remessa de mercadoria de uso ou consumo'],
            ['cfop'=>'5805','desc'=>'Remessa para industrialização ou produção rural'],
            ['cfop'=>'5806','desc'=>'Devolução de mercadoria recebida para industrialização ou produção rural'],
            ['cfop'=>'5807','desc'=>'Remessa de mercadoria decorrente de prestação de serviço'],
            ['cfop'=>'5809','desc'=>'Remessa de bem por conta de contrato de comodato'],
            ['cfop'=>'5810','desc'=>'Devolução de bem recebido por conta de contrato de comodato'],
            ['cfop'=>'5811','desc'=>'Remessa de bem por conta de arrendamento mercantil'],
            ['cfop'=>'5812','desc'=>'Devolução de bem recebido por conta de arrendamento mercantil'],
            ['cfop'=>'5813','desc'=>'Remessa de aparelho ou equipamento para conserto ou reparo'],
            ['cfop'=>'5814','desc'=>'Retorno de aparelho ou equipamento recebido para conserto ou reparo'],
            ['cfop'=>'5815','desc'=>'Remessa de mercadoria de produção do estabelecimento para depósito em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'5816','desc'=>'Remessa de mercadoria adquirida ou recebida de terceiros para depósito em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'5817','desc'=>'Remessa de mercadoria em depósito fechado ou armazém alfandegado'],
            ['cfop'=>'5818','desc'=>'Reintrodução de mercadoria em estoque'],
            ['cfop'=>'5922','desc'=>'Lançamento efetuado a título de simples faturamento decorrente de venda para entrega futura'],
            ['cfop'=>'5923','desc'=>'Remessa de mercadoria por conta e ordem de terceiros, em venda à ordem ou em operações com armazém geral ou depósito fechado'],
            ['cfop'=>'5924','desc'=>'Remessa para venda fora do estabelecimento'],
            ['cfop'=>'5925','desc'=>'Remessa por conta e ordem de terceiros'],
            ['cfop'=>'5926','desc'=>'Lançamento efetuado a título de reclassificação de mercadoria decorrente de formação de kit ou de sua desagregação'],
            ['cfop'=>'5927','desc'=>'Lançamento efetuado a título de baixa de estoque decorrente de perda, roubo ou deterioração'],
            ['cfop'=>'5928','desc'=>'Lançamento efetuado a título de baixa de estoque decorrente do encerramento da atividade da empresa'],
            ['cfop'=>'5929','desc'=>'Lançamento efetuado em decorrência de emissão de documento fiscal relativo a operação também acobertada por documento fiscal emitido por sistema diferente'],
            ['cfop'=>'5931','desc'=>'Lançamento efetuado em decorrência da responsabilidade de retenção do imposto por substituição tributária atribuída ao remetente pelo serviço de transporte'],
            ['cfop'=>'5932','desc'=>'Prestação de serviço de transporte iniciado em unidade da Federação diversa daquela onde inscrito o prestador'],
            ['cfop'=>'5949','desc'=>'Outra saída de mercadoria ou prestação de serviço não especificado'],
            // ── SAÍDAS INTERESTADUAIS (6xxx) ─────────────────────────────
            ['cfop'=>'6101','desc'=>'Venda de produção do estabelecimento (interestadual)'],
            ['cfop'=>'6102','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros (interestadual)'],
            ['cfop'=>'6103','desc'=>'Venda de produção do estabelecimento efetuada fora do estabelecimento (interestadual)'],
            ['cfop'=>'6104','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, realizada fora do estabelecimento (interestadual)'],
            ['cfop'=>'6105','desc'=>'Venda de produção do estabelecimento que não deva transitar pelo estabelecimento remetente (interestadual)'],
            ['cfop'=>'6106','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros que não deva transitar pelo estabelecimento remetente (interestadual)'],
            ['cfop'=>'6107','desc'=>'Venda de produção do estabelecimento, destinada a não contribuinte (interestadual)'],
            ['cfop'=>'6108','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, destinada a não contribuinte (interestadual)'],
            ['cfop'=>'6109','desc'=>'Venda de produção do estabelecimento destinada ao exterior'],
            ['cfop'=>'6110','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros destinada ao exterior'],
            ['cfop'=>'6111','desc'=>'Venda de produção do estabelecimento remetida anteriormente em consignação industrial (interestadual)'],
            ['cfop'=>'6112','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida anteriormente em consignação industrial (interestadual)'],
            ['cfop'=>'6113','desc'=>'Venda de produção do estabelecimento remetida anteriormente em consignação mercantil (interestadual)'],
            ['cfop'=>'6114','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida anteriormente em consignação mercantil (interestadual)'],
            ['cfop'=>'6115','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros recebida anteriormente em consignação mercantil (interestadual)'],
            ['cfop'=>'6116','desc'=>'Venda de produção do estabelecimento originada de encomenda para entrega futura (interestadual)'],
            ['cfop'=>'6117','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros, originada de encomenda para entrega futura (interestadual)'],
            ['cfop'=>'6118','desc'=>'Venda de produção do estabelecimento entregue ao destinatário por conta e ordem do adquirente originário (interestadual)'],
            ['cfop'=>'6119','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros entregue ao destinatário por conta e ordem do adquirente originário (interestadual)'],
            ['cfop'=>'6120','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros entregue ao destinatário pelo vendedor remetente, em venda à ordem (interestadual)'],
            ['cfop'=>'6122','desc'=>'Venda de produção do estabelecimento remetida para industrialização, por conta e ordem do adquirente (interestadual)'],
            ['cfop'=>'6123','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros remetida para industrialização, por conta e ordem do adquirente (interestadual)'],
            ['cfop'=>'6124','desc'=>'Industrialização efetuada para outra empresa (interestadual)'],
            ['cfop'=>'6125','desc'=>'Industrialização efetuada para outra empresa sem trânsito pelo estabelecimento adquirente (interestadual)'],
            ['cfop'=>'6151','desc'=>'Transferência de produção do estabelecimento (interestadual)'],
            ['cfop'=>'6152','desc'=>'Transferência de mercadoria adquirida ou recebida de terceiros (interestadual)'],
            ['cfop'=>'6201','desc'=>'Devolução de compra para industrialização ou produção rural (interestadual)'],
            ['cfop'=>'6202','desc'=>'Devolução de compra para comercialização (interestadual)'],
            ['cfop'=>'6208','desc'=>'Devolução de mercadoria recebida em transferência para industrialização (interestadual)'],
            ['cfop'=>'6209','desc'=>'Devolução de mercadoria recebida em transferência para comercialização (interestadual)'],
            ['cfop'=>'6210','desc'=>'Devolução de compra para utilização na prestação de serviço (interestadual)'],
            ['cfop'=>'6251','desc'=>'Venda de energia elétrica para distribuição ou comercialização (interestadual)'],
            ['cfop'=>'6252','desc'=>'Venda de energia elétrica para estabelecimentos comerciais (interestadual)'],
            ['cfop'=>'6253','desc'=>'Venda de energia elétrica para estabelecimentos industriais (interestadual)'],
            ['cfop'=>'6258','desc'=>'Venda de energia elétrica a não contribuintes (interestadual)'],
            ['cfop'=>'6301','desc'=>'Prestação de serviço de comunicação (interestadual)'],
            ['cfop'=>'6351','desc'=>'Prestação de serviço de transporte a estabelecimento industrial (interestadual)'],
            ['cfop'=>'6352','desc'=>'Prestação de serviço de transporte a estabelecimento comercial (interestadual)'],
            ['cfop'=>'6353','desc'=>'Prestação de serviço de transporte a estabelecimento de prestador de serviços (interestadual)'],
            ['cfop'=>'6354','desc'=>'Prestação de serviço de transporte a estabelecimento de produtor rural (interestadual)'],
            ['cfop'=>'6357','desc'=>'Prestação de serviço de transporte a não contribuinte (interestadual)'],
            ['cfop'=>'6401','desc'=>'Venda de produção do estabelecimento em operação com ST (interestadual)'],
            ['cfop'=>'6403','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros em operação com ST — substituto (interestadual)'],
            ['cfop'=>'6404','desc'=>'Venda de mercadoria com ST, cujo imposto já tenha sido retido anteriormente (interestadual)'],
            ['cfop'=>'6405','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros com ST — substituído (interestadual)'],
            ['cfop'=>'6408','desc'=>'Transferência de produção do estabelecimento em operação com ST (interestadual)'],
            ['cfop'=>'6409','desc'=>'Transferência de mercadoria adquirida ou recebida de terceiros em operação com ST (interestadual)'],
            ['cfop'=>'6410','desc'=>'Devolução de compra para industrialização em operação com ST (interestadual)'],
            ['cfop'=>'6411','desc'=>'Devolução de compra para comercialização em operação com ST (interestadual)'],
            ['cfop'=>'6501','desc'=>'Remessa de produção do estabelecimento com fim específico de exportação (interestadual)'],
            ['cfop'=>'6502','desc'=>'Remessa de mercadoria adquirida ou recebida de terceiros com fim específico de exportação (interestadual)'],
            ['cfop'=>'6503','desc'=>'Devolução de mercadoria recebida com fim específico de exportação (interestadual)'],
            ['cfop'=>'6551','desc'=>'Venda de bem do ativo imobilizado (interestadual)'],
            ['cfop'=>'6553','desc'=>'Devolução de compra de bem para o ativo imobilizado (interestadual)'],
            ['cfop'=>'6651','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento para industrialização (interestadual)'],
            ['cfop'=>'6652','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento para comercialização (interestadual)'],
            ['cfop'=>'6653','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento para consumo final (interestadual)'],
            ['cfop'=>'6654','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros para industrialização (interestadual)'],
            ['cfop'=>'6655','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros para comercialização (interestadual)'],
            ['cfop'=>'6656','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros para consumo final (interestadual)'],
            ['cfop'=>'6751','desc'=>'Venda para o exterior de mercadoria industrializada ou produzida pelo próprio estabelecimento'],
            ['cfop'=>'6752','desc'=>'Venda para o exterior de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'6801','desc'=>'Remessa de vasilhames, recipientes e embalagens (interestadual)'],
            ['cfop'=>'6802','desc'=>'Devolução de vasilhames, recipientes e embalagens (interestadual)'],
            ['cfop'=>'6803','desc'=>'Remessa de amostra grátis (interestadual)'],
            ['cfop'=>'6804','desc'=>'Remessa de mercadoria de uso ou consumo (interestadual)'],
            ['cfop'=>'6805','desc'=>'Remessa para industrialização ou produção rural (interestadual)'],
            ['cfop'=>'6806','desc'=>'Devolução de mercadoria recebida para industrialização ou produção rural (interestadual)'],
            ['cfop'=>'6807','desc'=>'Remessa de mercadoria decorrente de prestação de serviço (interestadual)'],
            ['cfop'=>'6809','desc'=>'Remessa de bem por conta de contrato de comodato (interestadual)'],
            ['cfop'=>'6810','desc'=>'Devolução de bem recebido por conta de contrato de comodato (interestadual)'],
            ['cfop'=>'6813','desc'=>'Remessa de aparelho ou equipamento para conserto ou reparo (interestadual)'],
            ['cfop'=>'6814','desc'=>'Retorno de aparelho ou equipamento recebido para conserto ou reparo (interestadual)'],
            ['cfop'=>'6905','desc'=>'Remessa de mercadoria para depósito em depósito fechado ou armazém alfandegado (interestadual)'],
            ['cfop'=>'6922','desc'=>'Lançamento a título de simples faturamento decorrente de venda para entrega futura (interestadual)'],
            ['cfop'=>'6923','desc'=>'Remessa de mercadoria por conta e ordem de terceiros (interestadual)'],
            ['cfop'=>'6924','desc'=>'Remessa para venda fora do estabelecimento (interestadual)'],
            ['cfop'=>'6925','desc'=>'Remessa por conta e ordem de terceiros (interestadual)'],
            ['cfop'=>'6929','desc'=>'Lançamento decorrente de emissão de documento fiscal relativo a operação também acobertada por outro documento (interestadual)'],
            ['cfop'=>'6949','desc'=>'Outra saída de mercadoria ou prestação de serviço não especificado (interestadual)'],
            // ── SAÍDAS PARA O EXTERIOR (7xxx) ─────────────────────────────
            ['cfop'=>'7101','desc'=>'Venda de produção do estabelecimento (exportação)'],
            ['cfop'=>'7102','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros (exportação)'],
            ['cfop'=>'7105','desc'=>'Venda de produção do estabelecimento que não deva transitar pelo estabelecimento remetente (exportação)'],
            ['cfop'=>'7106','desc'=>'Venda de mercadoria adquirida ou recebida de terceiros que não deva transitar pelo estabelecimento remetente (exportação)'],
            ['cfop'=>'7127','desc'=>'Venda de produção do estabelecimento sob o regime aduaneiro especial de drawback'],
            ['cfop'=>'7129','desc'=>'Venda de produção do estabelecimento ao invés de operação de exportação indireta'],
            ['cfop'=>'7201','desc'=>'Devolução de compra para industrialização ou produção rural (exportação)'],
            ['cfop'=>'7202','desc'=>'Devolução de compra para comercialização (exportação)'],
            ['cfop'=>'7205','desc'=>'Anulação de valor relativo à exportação de mercadoria que não tenha sido efetivada'],
            ['cfop'=>'7210','desc'=>'Devolução de compra para industrialização e produção rural (importação devolvida ao exterior)'],
            ['cfop'=>'7211','desc'=>'Devolução de compras para comercialização (importação devolvida ao exterior)'],
            ['cfop'=>'7501','desc'=>'Exportação de mercadorias recebidas com fim específico de exportação'],
            ['cfop'=>'7551','desc'=>'Venda de bem do ativo imobilizado (exportação)'],
            ['cfop'=>'7651','desc'=>'Venda de combustível ou lubrificante de produção do estabelecimento (exportação)'],
            ['cfop'=>'7654','desc'=>'Venda de combustível ou lubrificante adquiridos ou recebidos de terceiros (exportação)'],
            ['cfop'=>'7667','desc'=>'Remessa de combustível ou lubrificante adquiridos ou recebidos de terceiros (exportação)'],
            ['cfop'=>'7751','desc'=>'Venda para o exterior de mercadoria industrializada ou produzida pelo próprio estabelecimento'],
            ['cfop'=>'7752','desc'=>'Venda para o exterior de mercadoria adquirida ou recebida de terceiros'],
            ['cfop'=>'7949','desc'=>'Outra saída de mercadoria ou prestação de serviço para o exterior não especificado'],
        ];
    }
}
