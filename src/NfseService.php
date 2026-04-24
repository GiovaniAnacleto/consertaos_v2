<?php
/**
 * NfseService.php — Emissão de NFS-e via WebService IPM/Atende.Net
 *
 * Prefeitura de Chapadão do Lageado/SC usa o sistema Atende.Net (IPM Sistemas).
 * Referência: Nota Técnica IPM nº 35/2021 v2.2 (atualizada em 11/03/2023)
 *
 * Protocolo: HTTP POST multipart/form-data
 * Autenticação: Header Authorization: Basic base64(cnpj:senha_prefeitura)
 * Formato: XML proprietário IPM
 * Resposta: XML com tag raiz <retorno> contendo número, link PDF e código verificador
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Estrutura de $config esperada:
 * [
 *   'nfse_usuario'    => '12345678000199',  // CNPJ do prestador (só números)
 *   'nfse_senha'      => 'senha123',        // Senha de acesso ao portal da prefeitura
 *   'nfse_cidade_tom' => '8137',            // Código TOM (Receita Federal) — DIFERENTE do IBGE
 *   'nfse_ambiente'   => 'homologacao' | 'producao',
 *   'nfse_serie'      => 'E',               // Série da NFS-e
 *   'modo_teste'      => false,             // true = usa <nfse_teste>1</nfse_teste> (NT §4.8)
 *   'storage_dir'     => '/caminho/storage/nfse',
 *   'empresa' => [
 *       'cnpj'        => '12345678000199',
 *       'razao_social'=> 'EMPRESA LTDA',
 *       'im'          => '12345',
 *       'cidade_tom'  => '8137',
 *   ],
 * ]
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Formas de pagamento (NT 35/2021 v2.2, Tabela p.15):
 *   1=À vista  2=A prazo  3=Depósito  4=Na apresentação
 *   5=Cartão débito  6=Cartão crédito  7=Cheque  8=PIX
 *
 * Situações Tributárias (NT 35/2021 v2.2, Tabela 13):
 *   0=TI (tributado integralmente — mais comum para assistência técnica)
 *   1=TIRF  2=TIST  3=TRBC  4=TRBCRF  5=TRBCST
 *   6=ISE  7=IMU  8=NTIFix  9=NTIEs  10=NTICc  14=NTRIB  15=NTAC
 *
 * Código TOM: consulte em https://www.tomweb.receita.fazenda.gov.br
 *   Ou no Atende.Net: Cadastros Únicos >> Cidades >> Aba Detalhes
 * ─────────────────────────────────────────────────────────────────────────────
 */

namespace ConsertaOS\NfsE;

class NfseService
{
    private array $config;

    // URL do webservice para Chapadão do Lageado/SC
    // Padrão IPM: https://{cidade-sem-acento}.atende.net/atende.php?pg=rest&service=WNERestServiceNFSe&cidade=padrao
    private const URL_NFSE = 'https://nfse-chapadaodolageado.atende.net/atende.php?pg=rest&service=WNERestServiceNFSe&cidade=padrao';

    // Código TOM de Chapadão do Lageado/SC = 8416 (confirmado via tela do Atende.Net)
    // Série padrão da prefeitura = 1 (confirmado via tela do Atende.Net)
    public const CIDADE_TOM  = '8416';
    public const SERIE_PADRAO = '1';

    // Cookie PHPSESSID reutilizado entre requisições (NT §3.4: reduz consideravelmente o tempo de emissão)
    private static ?string $sessionCookie = null;

    public function __construct(array $config)
    {
        $this->config = $config;
        $storageDir = $config['storage_dir'] ?? __DIR__ . '/../storage/nfse';
        foreach (['autorizada', 'cancelada', 'rejeitada', 'logs'] as $sub) {
            $path = "$storageDir/$sub";
            if (!is_dir($path)) mkdir($path, 0755, true);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // EMITIR NFS-e
    // ──────────────────────────────────────────────────────────────────────────
    public function emitir(array $dados): array
    {
        $xml = $this->_montarXmlEmissao($dados);
        return $this->_enviar($xml, 'emitir');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // CANCELAR NFS-e
    // NT §4.2: cancelamento direto (dentro do prazo configurado no município)
    // NT §4.3: solicitação de cancelamento (fora do prazo — aprovação da prefeitura)
    // ──────────────────────────────────────────────────────────────────────────
    public function cancelar(string $numero, string $serie, string $motivo, bool $solicitacao = false): array
    {
        $xml = $solicitacao
            ? $this->_montarXmlSolicitacaoCancelamento($numero, $serie, $motivo)
            : $this->_montarXmlCancelamento($numero, $serie, $motivo);

        return $this->_enviar($xml, $solicitacao ? 'solicitacao_cancelamento' : 'cancelar');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // CONSULTAR NFS-e por número e série (NT §4.5.2, Tabela 9)
    // ──────────────────────────────────────────────────────────────────────────
    public function consultar(string $numero, string $serie): array
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<nfse>
  <pesquisa>
    <numero>{$numero}</numero>
    <serie_nfse>{$serie}</serie_nfse>
    <cadastro></cadastro>
  </pesquisa>
</nfse>
XML;
        return $this->_enviar($xml, 'consultar');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Monta XML de emissão (NT §4.1, Tabela 4)
    // ──────────────────────────────────────────────────────────────────────────
    private function _montarXmlEmissao(array $dados): string
    {
        $empresa   = $this->config['empresa'];
        $cnpj      = preg_replace('/\D/', '', $empresa['cnpj'] ?? '');
        $cidadeTom = $empresa['cidade_tom'] ?? $this->config['nfse_cidade_tom'] ?? '';
        $serie     = $this->config['nfse_serie'] ?? '1'; // padrão confirmado: série 1
        $modoTeste = !empty($this->config['modo_teste']);

        // ── Tomador ───────────────────────────────────────────────────────────
        $tomadorCpfCnpj = preg_replace('/\D/', '', $dados['cliente_cpfcnpj'] ?? '');
        $tomadorTipo    = $dados['cliente_tipo']       ?? 'F'; // F=Física J=Jurídica E=Estrangeiro
        $tomadorNome    = $this->_esc($dados['cliente_nome']       ?? '');
        $tomadorEmail   = $this->_esc($dados['cliente_email']      ?? '');
        $tomadorLog     = $this->_esc($dados['cliente_logradouro'] ?? '');
        $tomadorNro     = $this->_esc($dados['cliente_numero']     ?? '');
        $tomadorBairro  = $this->_esc($dados['cliente_bairro']     ?? '');
        $tomadorCidade  = $dados['cliente_cidade_tom'] ?? $cidadeTom;
        $tomadorCep     = preg_replace('/\D/', '', $dados['cliente_cep'] ?? '');

        // ── Totais (NT §4: vírgula como separador decimal obrigatório) ────────
        $valorTotal    = number_format((float)($dados['valor_total']    ?? 0), 2, ',', '');
        $valorDesconto = number_format((float)($dados['valor_desconto'] ?? 0), 2, ',', '');
        $valorIr       = number_format((float)($dados['valor_ir']       ?? 0), 2, ',', '');
        $valorInss     = number_format((float)($dados['valor_inss']     ?? 0), 2, ',', '');
        $valorPis      = number_format((float)($dados['valor_pis']      ?? 0), 2, ',', '');
        $valorCofins   = number_format((float)($dados['valor_cofins']   ?? 0), 2, ',', '');
        $observacao    = $this->_esc($dados['observacao'] ?? '');
        $dataFato      = $dados['data_competencia'] ?? date('d/m/Y');

        // ── Forma de pagamento (v2.2 Tabela p.15) ─────────────────────────────
        // 1=À vista  2=A prazo  3=Depósito  4=Na apresentação
        // 5=Cartão débito  6=Cartão crédito  7=Cheque  8=PIX
        $tipoPag = (string)($dados['forma_pagamento'] ?? '1');

        // ── Identificador de idempotência (NT §4.1) ───────────────────────────
        // Mesmo identificador = nota não será emitida duas vezes
        $identificador = $cnpj . date('YmdHis') . rand(1000, 9999);

        // ── Tag modo teste (NT §4.8) ──────────────────────────────────────────
        // Quando ativada, o WS valida o XML mas não emite a nota.
        // Retorno com "válida para emissão" = XML correto; sem essa msg = tem erros.
        $testeTag = $modoTeste ? "\n  <nfse_teste>1</nfse_teste>" : '';

        // ── Itens de serviço ──────────────────────────────────────────────────
        $itensXml = '';
        foreach ($dados['itens'] ?? [] as $item) {
            $codServico      = $this->_esc($item['codigo_servico']      ?? '');
            $descricao       = $this->_esc($item['descricao']           ?? 'Servico prestado');
            $aliquota        = number_format((float)($item['aliquota_iss']     ?? 0), 4, ',', '');
            // Situação tributária: 0=TI (Tributada Integralmente) — confirmado via tela Atende.Net
            $situacaoTrib    = (string)($item['situacao_tributaria'] ?? '0');
            $valorTributavel = number_format((float)($item['valor_tributavel']  ?? $dados['valor_total'] ?? 0), 2, ',', '');
            $valorDeducao    = number_format((float)($item['valor_deducao']     ?? 0), 2, ',', '');
            $valorIssRf      = number_format((float)($item['valor_issrf']       ?? 0), 2, ',', '');
            // 1=tributa no município do prestador, 0=no local da prestação do serviço
            $tributaMun      = $item['tributa_municipio'] ?? '1';
            $codLocal        = $item['codigo_local']      ?? $cidadeTom;
            $codAtividade    = $this->_esc($item['codigo_atividade'] ?? '');

            // Bloco unidade: só envia se a prefeitura tiver unidades cadastradas (config nfse_usa_unidade=1)
            // Quando desligado, omite os campos de unidade — o IPM aceita sem eles.
            $usaUnidade      = !empty($this->config['nfse_usa_unidade']);
            $unidadeCod      = $usaUnidade ? (string)($item['unidade_codigo']      ?? '') : '';
            $unidadeQtd      = $usaUnidade ? ($item['unidade_quantidade']   ?? null) : null;
            $unidadeVunit    = $usaUnidade ? ($item['unidade_valor_unitario'] ?? null) : null;
            $temUnidade      = ($unidadeCod !== '' && $unidadeQtd !== null && $unidadeVunit !== null);
            $unidadeQtdFmt   = $temUnidade ? number_format((float)$unidadeQtd,   5, ',', '') : '';
            $unidadeVunitFmt = $temUnidade ? number_format((float)$unidadeVunit, 2, ',', '') : '';

            $itensXml .= "
  <lista>
    <tributa_municipio_prestador>{$tributaMun}</tributa_municipio_prestador>
    <codigo_local_prestacao_servico>{$codLocal}</codigo_local_prestacao_servico>
    <codigo_item_lista_servico>{$codServico}</codigo_item_lista_servico>" .
    ($codAtividade ? "\n    <codigo_atividade>{$codAtividade}</codigo_atividade>" : '') . "
    <descritivo>{$descricao}</descritivo>" .
    ($temUnidade ? "
    <unidade_codigo>{$unidadeCod}</unidade_codigo>
    <unidade_quantidade>{$unidadeQtdFmt}</unidade_quantidade>
    <unidade_valor_unitario>{$unidadeVunitFmt}</unidade_valor_unitario>" : "") . "
    <aliquota_item_lista_servico>{$aliquota}</aliquota_item_lista_servico>
    <situacao_tributaria>{$situacaoTrib}</situacao_tributaria>
    <valor_tributavel>{$valorTributavel}</valor_tributavel>
    <valor_deducao>{$valorDeducao}</valor_deducao>
    <valor_issrf>{$valorIssRf}</valor_issrf>
  </lista>";
        }

        // ── Bloco tomador (opcional — só inclui se tiver CPF/CNPJ ou nome) ────
        // endereco_informado=N: município não aceita cadastro alternativo de endereço
        // Enviamos apenas identificação (tipo, cpfcnpj, nome, email) sem campos de endereço
        $tomadorXml = '';
        if ($tomadorCpfCnpj || ($tomadorNome && strtoupper($tomadorNome) !== 'CONSUMIDOR')) {
            $tomadorXml = "
<tomador>
  <endereco_informado>N</endereco_informado>
  <tipo>{$tomadorTipo}</tipo>
  <cpfcnpj>{$tomadorCpfCnpj}</cpfcnpj>
  <nome_razao_social>{$tomadorNome}</nome_razao_social>" .
  ($tomadorEmail ? "\n  <email>{$tomadorEmail}</email>" : '') . "
</tomador>";
        }

        // ── Parcelas (quando a prazo, Tabela p.15 — máximo 24 parcelas) ──────
        $parcelasXml = '';
        if (!empty($dados['parcelas']) && is_array($dados['parcelas'])) {
            $parcelasXml = "\n  <parcelas>";
            foreach ($dados['parcelas'] as $p) {
                $num  = (int)($p['numero'] ?? 1);
                $val  = number_format((float)($p['valor'] ?? 0), 2, ',', '');
                $venc = $p['data_vencimento'] ?? date('d/m/Y');
                $parcelasXml .= "
    <parcela>
      <numero>{$num}</numero>
      <valor>{$val}</valor>
      <data_vencimento>{$venc}</data_vencimento>
    </parcela>";
            }
            $parcelasXml .= "\n  </parcelas>";
        }

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<nfse>{$testeTag}
  <identificador>{$identificador}</identificador>
  <nf>
    <serie_nfse>{$serie}</serie_nfse>
    <data_fato_gerador>{$dataFato}</data_fato_gerador>
    <valor_total>{$valorTotal}</valor_total>
    <valor_desconto>{$valorDesconto}</valor_desconto>
    <valor_ir>{$valorIr}</valor_ir>
    <valor_inss>{$valorInss}</valor_inss>
    <valor_pis>{$valorPis}</valor_pis>
    <valor_cofins>{$valorCofins}</valor_cofins>
    <observacao>{$observacao}</observacao>
  </nf>
  <prestador>
    <cpfcnpj>{$cnpj}</cpfcnpj>
    <cidade>{$cidadeTom}</cidade>
  </prestador>
  {$tomadorXml}
  <itens>
    {$itensXml}
  </itens>
  <forma_pagamento>
    <tipo_pagamento>{$tipoPag}</tipo_pagamento>
    {$parcelasXml}
  </forma_pagamento>
</nfse>
XML;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Cancelamento direto (NT §4.2, Tabela 5)
    // ──────────────────────────────────────────────────────────────────────────
    private function _montarXmlCancelamento(string $numero, string $serie, string $motivo): string
    {
        $cnpj      = preg_replace('/\D/', '', $this->config['empresa']['cnpj'] ?? '');
        $cidadeTom = $this->config['empresa']['cidade_tom'] ?? '';
        $motivoEsc = $this->_esc($motivo);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<nfse>
  <nf>
    <numero>{$numero}</numero>
    <serie_nfse>{$serie}</serie_nfse>
    <situacao>C</situacao>
    <observacao>{$motivoEsc}</observacao>
  </nf>
  <prestador>
    <cpfcnpj>{$cnpj}</cpfcnpj>
    <cidade>{$cidadeTom}</cidade>
  </prestador>
</nfse>
XML;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Solicitação de cancelamento (NT §4.3, Tabela 6)
    // Usado quando o prazo para cancelamento autônomo já expirou
    // ──────────────────────────────────────────────────────────────────────────
    private function _montarXmlSolicitacaoCancelamento(string $numero, string $serie, string $motivo): string
    {
        $cnpj      = preg_replace('/\D/', '', $this->config['empresa']['cnpj'] ?? '');
        $cidadeTom = $this->config['empresa']['cidade_tom'] ?? '';
        $motivoEsc = $this->_esc($motivo);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<solicitacao_cancelamento>
  <prestador>
    <cpfcnpj>{$cnpj}</cpfcnpj>
    <cidade>{$cidadeTom}</cidade>
  </prestador>
  <documentos>
    <nfse>
      <numero>{$numero}</numero>
      <serie>{$serie}</serie>
      <observacao>{$motivoEsc}</observacao>
    </nfse>
  </documentos>
</solicitacao_cancelamento>
XML;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Envia XML ao webservice via cURL (NT §3.4)
    //   - POST multipart/form-data, campo "arquivo" com CURLFile
    //   - Authorization: Basic base64(cnpj:senha)
    //   - Cookie PHPSESSID reutilizado entre requisições (NT §3.4)
    // ──────────────────────────────────────────────────────────────────────────
    private function _enviar(string $xml, string $operacao): array
    {
        $storageDir = $this->config['storage_dir'] ?? __DIR__ . '/../storage/nfse';
        $logDir     = $storageDir . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);

        $usuario = $this->config['nfse_usuario'] ?? preg_replace('/\D/', '', $this->config['empresa']['cnpj'] ?? '');
        $senha   = $this->config['nfse_senha']   ?? '';

        $timestamp = date('YmdHis');
        file_put_contents("$logDir/{$operacao}_{$timestamp}_envio.xml", $xml);

        // O WS IPM exige envio do XML como arquivo via multipart/form-data
        $tmpFile = tempnam(sys_get_temp_dir(), 'nfse_') . '.xml';
        file_put_contents($tmpFile, $xml);

        $authHeader = 'Authorization: Basic ' . base64_encode("{$usuario}:{$senha}");
        $headers    = [$authHeader];

        // Reutiliza cookie de sessão (NT §3.4: "reduz consideravelmente o tempo de emissão")
        if (self::$sessionCookie !== null) {
            $headers[] = 'Cookie: ' . self::$sessionCookie;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => self::URL_NFSE,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => [
                'arquivo' => new \CURLFile($tmpFile, 'text/xml', 'nfse.xml'),
            ],
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_HEADER         => true,  // captura headers para extrair PHPSESSID
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $respostaCompleta = curl_exec($ch);
        $headerSize       = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode         = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError        = curl_error($ch);
        curl_close($ch);

        @unlink($tmpFile);

        // Extrai e armazena PHPSESSID para reutilizar nas próximas requisições
        $headersResposta = substr($respostaCompleta, 0, $headerSize);
        $resposta        = substr($respostaCompleta, $headerSize);
        if (preg_match('/Set-Cookie:\s*(PHPSESSID=[^;]+)/i', $headersResposta, $m)) {
            self::$sessionCookie = $m[1];
        }

        file_put_contents("$logDir/{$operacao}_{$timestamp}_retorno.xml", $resposta ?: $curlError);

        if ($resposta === false || $curlError) {
            return $this->_erro("Erro de conexão com a prefeitura: {$curlError}", 'CURL_ERROR');
        }

        if ($httpCode === 401) {
            return $this->_erro(
                'Credenciais inválidas [401]. Verifique CNPJ e senha em Configurações → NFS-e.',
                'AUTH_ERROR',
                $resposta
            );
        }

        return $this->_processarRetorno($resposta, $storageDir, $operacao);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Processa retorno XML do webservice IPM
    //
    // TODA resposta usa tag raiz <retorno> (NT Figura 2, p.4 e Tabela 10, p.19):
    //
    // SUCESSO emissão:
    //   <retorno>
    //     <mensagem><codigo>00001 - Sucesso</codigo></mensagem>
    //     <numero_nfse>1293</numero_nfse>
    //     <serie_nfse>1</serie_nfse>
    //     <data_nfse>28/10/2021</data_nfse>
    //     <hora_nfse>10:39:12</hora_nfse>
    //     <situacao_codigo_nfse>1</situacao_codigo_nfse>
    //     <situacao_descricao_nfse>Emitida</situacao_descricao_nfse>
    //     <link_nfse>https://...</link_nfse>
    //     <cod_verificador_autenticidade>...</cod_verificador_autenticidade>
    //   </retorno>
    //
    // ERRO qualquer:
    //   <retorno>
    //     <mensagem><codigo>[132] Usuário ou Senha inválidos!</codigo></mensagem>
    //   </retorno>
    //
    // CANCELAMENTO direto OK (§4.2):
    //   <retorno><mensagem><codigo>01 - Sucesso</codigo></mensagem></retorno>
    //
    // SOLICITAÇÃO DE CANCELAMENTO OK (§4.3 Tabela 7):
    //   <retorno>
    //     <documentos><nfse>
    //       <dados><numero>X</numero><serie>E</serie></dados>
    //       <mensagem><codigo>01 - Sucesso</codigo></mensagem>
    //     </nfse></documentos>
    //   </retorno>
    // ──────────────────────────────────────────────────────────────────────────
    private function _processarRetorno(string $resposta, string $storageDir, string $operacao): array
    {
        if (empty(trim($resposta))) {
            return $this->_erro(
                'Webservice não retornou dados. Verifique configurações e tente novamente.',
                'EMPTY_RESPONSE'
            );
        }

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($resposta);
        libxml_clear_errors();

        if ($xml === false) {
            $texto = trim(preg_replace('/\s+/', ' ', strip_tags($resposta)));
            return $this->_erro('Retorno inválido do servidor: ' . mb_substr($texto, 0, 300), 'INVALID_XML', $resposta);
        }

        // Toda resposta do IPM deve ter tag raiz <retorno>
        if ($xml->getName() !== 'retorno') {
            return $this->_erro(
                'Tag raiz inesperada: <' . $xml->getName() . '>. Esperado <retorno>.',
                'UNEXPECTED_TAG',
                $resposta
            );
        }

        // Extrai códigos de mensagem (pode haver múltiplos <codigo> em <mensagem>)
        $codigosMensagem = [];
        if (isset($xml->mensagem)) {
            foreach ($xml->mensagem->codigo as $cod) {
                $c = trim((string)$cod);
                if ($c !== '') $codigosMensagem[] = $c;
            }
            // Fallback para quando simplexml não itera corretamente
            if (empty($codigosMensagem) && isset($xml->mensagem->codigo)) {
                $c = trim((string)$xml->mensagem->codigo);
                if ($c !== '') $codigosMensagem[] = $c;
            }
        }
        $mensagemTexto = implode('; ', $codigosMensagem);

        // ── SOLICITAÇÃO DE CANCELAMENTO (Tabela 7) ─────────────────────────────
        if ($operacao === 'solicitacao_cancelamento') {
            $codSol = isset($xml->documentos->nfse->mensagem->codigo)
                ? trim((string)$xml->documentos->nfse->mensagem->codigo)
                : $mensagemTexto;
            $sucesso = str_starts_with($codSol, '01') || stripos($codSol, 'sucesso') !== false;
            return [
                'autorizada'  => $sucesso,
                'numero'      => '',
                'serie'       => '',
                'link_pdf'    => '',
                'xMotivo'     => $sucesso
                    ? 'Solicitação de cancelamento enviada à prefeitura (sujeita a aprovação)'
                    : $codSol,
                'codigo'      => $sucesso ? '01' : $codSol,
                'xml_retorno' => $resposta,
            ];
        }

        // ── CANCELAMENTO DIRETO (§4.2) ─────────────────────────────────────────
        if ($operacao === 'cancelar') {
            $primeiroCod = $codigosMensagem[0] ?? '';
            $sucesso = str_starts_with($primeiroCod, '01') || stripos($primeiroCod, 'sucesso') !== false;
            if ($sucesso) {
                $dir = $storageDir . '/cancelada';
                if (!is_dir($dir)) mkdir($dir, 0755, true);
                file_put_contents("$dir/cancel_" . date('YmdHis') . '.xml', $resposta);
            }
            return [
                'autorizada'  => $sucesso,
                'numero'      => '',
                'serie'       => '',
                'link_pdf'    => '',
                'xMotivo'     => $sucesso
                    ? 'NFS-e cancelada com sucesso'
                    : ($mensagemTexto ?: 'Cancelamento não aceito pela prefeitura'),
                'codigo'      => $primeiroCod,
                'xml_retorno' => $resposta,
            ];
        }

        // ── EMISSÃO ────────────────────────────────────────────────────────────
        $numero   = trim((string)($xml->numero_nfse   ?? ''));
        $serie    = trim((string)($xml->serie_nfse    ?? ''));
        $linkPdf  = trim((string)($xml->link_nfse     ?? ''));
        $codVerif = trim((string)($xml->cod_verificador_autenticidade ?? ''));
        $dataEmis = trim((string)($xml->data_nfse     ?? ''));
        $horaEmis = trim((string)($xml->hora_nfse     ?? ''));
        $sitCod   = trim((string)($xml->situacao_codigo_nfse    ?? ''));
        $sitDesc  = trim((string)($xml->situacao_descricao_nfse ?? ''));

        $autorizada = !empty($numero);

        if ($autorizada) {
            $dir = $storageDir . '/autorizada';
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            file_put_contents("$dir/nfse_{$numero}.xml", $resposta);
        }

        // ── Modo teste (NT §4.8) ──────────────────────────────────────────────
        // O WS retorna erro propositalmente.
        // "Caso o XML estiver correto, o erro conterá a mensagem de que a nota é válida para emissão."
        if (!empty($this->config['modo_teste']) && !$autorizada) {
            $xmlValido = stripos($mensagemTexto, 'válida para emissão') !== false
                      || stripos($mensagemTexto, 'valida para emissao') !== false;
            return [
                'autorizada'  => false,
                'numero'      => '',
                'serie'       => '',
                'link_pdf'    => '',
                'xMotivo'     => $xmlValido
                    ? '[MODO TESTE] XML válido — remova modo_teste=true para emitir de verdade'
                    : '[MODO TESTE] XML com erros: ' . $mensagemTexto,
                'codigo'      => $xmlValido ? 'XML_VALIDO' : 'XML_INVALIDO',
                'xml_retorno' => $resposta,
            ];
        }

        return [
            'autorizada'         => $autorizada,
            'numero'             => $numero,
            'serie'              => $serie,
            'link_pdf'           => $linkPdf,
            'codigo_verificacao' => $codVerif,
            'data_emissao'       => $dataEmis,
            'hora_emissao'       => $horaEmis,
            'situacao_codigo'    => $sitCod,
            'situacao_descricao' => $sitDesc,
            'xMotivo'            => $autorizada
                ? ($sitDesc ?: 'NFS-e autorizada')
                : ($mensagemTexto ?: 'NFS-e não gerada — sem retorno da prefeitura'),
            'codigo'             => $autorizada ? ($sitCod ?: '1') : ($codigosMensagem[0] ?? 'ERR'),
            'xml_retorno'        => $resposta,
        ];
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Escapa caracteres proibidos no XML IPM (NT Tabela 3, p.6)
    // Proibidos: < > ' " & /  (barra → substituída por espaço)
    // ──────────────────────────────────────────────────────────────────────────
    private function _esc(string $str): string
    {
        $str = str_replace('/', ' ', $str); // barra não é permitida pelo IPM
        return htmlspecialchars($str, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    // ──────────────────────────────────────────────────────────────────────────
    // PRIVADO — Retorno de erro padronizado
    // ──────────────────────────────────────────────────────────────────────────
    private function _erro(string $mensagem, string $codigo, string $xmlRetorno = ''): array
    {
        return [
            'autorizada'  => false,
            'numero'      => '',
            'serie'       => '',
            'link_pdf'    => '',
            'xMotivo'     => $mensagem,
            'codigo'      => $codigo,
            'xml_retorno' => $xmlRetorno,
        ];
    }
}