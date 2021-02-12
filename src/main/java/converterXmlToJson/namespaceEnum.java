package converterXmlToJson;

import java.util.HashMap;
import java.util.Map;

public enum namespaceEnum {
	transmissao("transmissao", "http://www.esocial.gov.br/schema/lote/eventos/envio/v1_1_0",
			"http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/v1_1_0/ServicoEnviarLoteEventos/EnviarLoteEventos"),
	consulta("consulta", "http://www.esocial.gov.br/schema/lote/eventos/envio/consulta/retornoProcessamento/v1_0_0",
			"http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/consulta/retornoProcessamento/v1_1_0/ServicoConsultarLoteEventos/ConsultarLoteEventos");

	private String tpConexao;
	private String namespace;
	private String action;
	private static Map<String, String> mapOperacao;
	private static Map<String, String> mapAction;

	namespaceEnum(String tpConexao, String namespace, String action) {
		this.tpConexao = tpConexao;
		this.namespace = namespace;
		this.action = action;
	}

	public static String getSpaceByOper(String tpConexao) {
		if (mapOperacao == null) {
			initializeMappingSpaceByOper();
		}
		if (mapOperacao.containsKey(tpConexao)) {
			return mapOperacao.get(tpConexao);
		}
		return null;
	}

	public String getNamespace() {
		return this.namespace;
	}

	public String getAction() {
		return this.action;
	}

	public static String getActionByOper(String tpConexao) {
		if (mapAction == null) {
			initializeMappingActionByOper();
		}
		if (mapAction.containsKey(tpConexao)) {
			return mapAction.get(tpConexao);
		}
		return null;
	}

	private static void initializeMappingSpaceByOper() {
		mapOperacao = new HashMap<String, String>();
		for (namespaceEnum s : namespaceEnum.values()) {
			mapOperacao.put(s.tpConexao, s.namespace);
		}
	}

	private static void initializeMappingActionByOper() {
		mapAction = new HashMap<String, String>();
		for (namespaceEnum s : namespaceEnum.values()) {
			mapOperacao.put(s.tpConexao, s.action);
		}
	}
}
