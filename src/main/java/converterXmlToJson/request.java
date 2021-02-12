package converterXmlToJson;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;

import javax.swing.JOptionPane;

import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public class request {
	
	private static final SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");  
	public static final DERObjectIdentifier RESPONSAVEL = new DERObjectIdentifier("2.16.76.1.3.2");  
	public static final DERObjectIdentifier CNPJ = new DERObjectIdentifier("2.16.76.1.3.3");   
	public static final DERObjectIdentifier CPF = new DERObjectIdentifier("2.16.76.1.3.1");
	
	public KeyStore carregarCertificados(){
		try{
			KeyStore ks = KeyStore.getInstance("Windows-MY");
			try {
				ks.load(null, "@Techne".toCharArray());
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
			
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
			
				e.printStackTrace();
			}
			return ks;
		}catch (KeyStoreException e) {
			// TODO Auto-generated catch block

			e.printStackTrace();
		} /**catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		return null;
	}
	
	public X509Certificate getCertificado(String aliasKey) throws KeyStoreException {
		request cm = new request();	
		KeyStore ks = cm.carregarCertificados();
		X509Certificate cert = (X509Certificate) ks.getCertificate(aliasKey);
		
		return cert;
	}
	
	public KeyStore getCertificadoKs(String aliasKey) throws KeyStoreException {
		request cm = new request();	
		KeyStore ks = cm.carregarCertificados();
		
		return ks;
	}	
	
	public Boolean VerificaValidade(String aliasKey) {
		try {
			Boolean valido;
			Date data = new Date(System.currentTimeMillis());
			request cm = new request();	
			KeyStore ks = cm.carregarCertificados();
			X509Certificate cert = (X509Certificate) ks.getCertificate(aliasKey);
			
			if(cert.getNotAfter().after(data)) {
				valido = true;
			} else {
				valido = false;
			}

			return valido;
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	public List<String> listCertificadosNet(){
		try {
			request cm = new request();			
			KeyStore ks = cm.carregarCertificados();
			Vector listaCertificados = new Vector<String>();
			Enumeration<String> aliasEnum;
			try {
				aliasEnum = ks.aliases();
				while (aliasEnum.hasMoreElements()) {
					String aliasKey = (String) aliasEnum.nextElement();
					Certificate c = ks.getCertificate(aliasKey);
					if (ks.isKeyEntry(aliasKey)) {
						listaCertificados.add(aliasKey);
					}
				}
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(!listaCertificados.isEmpty()){
				String[] certs = new String[listaCertificados.size()];
				listaCertificados.toArray(certs);
			}
		
			
//			System.out.println(listaCertificados + "/" + cert.getNotAfter());
			
			return listaCertificados;
		} catch (Exception e) {
			e.getStackTrace();
		}
		return new ArrayList<String>();
	}
	
	public String getCertificateByKeyStore(KeyStore ks){
		try {
			List<String> listaCertificados = new ArrayList<String>();
			Enumeration<String> aliasEnum;
			try {
				aliasEnum = ks.aliases();		
				while (aliasEnum.hasMoreElements()) {
					String aliasKey = (String) aliasEnum.nextElement();
					Certificate c = ks.getCertificate(aliasKey) ;
					if (ks.isKeyEntry(aliasKey)) {
						listaCertificados.add(aliasKey);
					}
				}
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(!listaCertificados.isEmpty()){
				String[] certs = new String[listaCertificados.size()];
				listaCertificados.toArray(certs);
				String response = (String) JOptionPane.showInputDialog(null, "Escolha o certificado para envio", "Opção certificados",
				        JOptionPane.PLAIN_MESSAGE, null, certs, certs[0]);
				
			
				Certificate cert = ks.getCertificate(response);
				if (cert instanceof X509Certificate) {
			      X509Certificate x509=(X509Certificate)cert;
			      String certCnpj = getCnpjCertificado(x509);
			      //KeyStore customKey = (KeyStore) ks.getKey(response, null);
			      return response;
			    }
			}else{
				JOptionPane.showMessageDialog(null, "Nenhum certificidado encontrado");
			}
			return null;
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		return null;
	}
	
	public String getCnpjCertificado(X509Certificate certificate){
		Collection<?> alternativeNames;
		try {
			alternativeNames = X509ExtensionUtil.getSubjectAlternativeNames(certificate);
		 
	        for (Object alternativeName : alternativeNames) {  
	            if (alternativeName instanceof ArrayList) {  
	                ArrayList<?> listOfValues = (ArrayList<?>) alternativeName;  
	                Object value = listOfValues.get(1);  
	                if (value instanceof DERSequence) {  
	                    DERSequence derSequence = (DERSequence) value;  
	                    DERObjectIdentifier derObjectIdentifier = (DERObjectIdentifier) derSequence.getObjectAt(0);  
	                    DERTaggedObject derTaggedObject = (DERTaggedObject) derSequence.getObjectAt(1);  
	                    DERObject derObject = derTaggedObject.getObject();  
	  
	                    String valueOfTag = "";  
	                    if (derObject instanceof DEROctetString) {  
	                        DEROctetString octet = (DEROctetString) derObject;  
	                        valueOfTag = new String(octet.getOctets());  
	                    }   
	                    else if (derObject instanceof DERPrintableString) {  
	                        DERPrintableString octet = (DERPrintableString) derObject;  
	                        valueOfTag = new String(octet.getOctets());  
	                    }   
	                    else if (derObject instanceof DERUTF8String) {  
	                        DERUTF8String str = (DERUTF8String) derObject;  
	                        valueOfTag = str.getString();  
	                    }  
	                      
	                    if ((valueOfTag != null) && (!"".equals(valueOfTag))) {  
	                        if (derObjectIdentifier.equals(CNPJ)) {  
	                        	return valueOfTag; 
	                        }  
	                        if (derObjectIdentifier.equals(CPF)) {  
	                        	return valueOfTag.substring(8, 19); 
	                        }  
	                    }  
	                }  
	            } 
	        }
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
		return null;
	}
	
	
	
	public static void main(String[] args) {
		JavaCall javaCall = new JavaCall();
		Vector listCertif = new Vector<String>();
		request certificadoManager = new request();
		X509Certificate certificadoMaquina = null;
		List<String> resultRetorn = new ArrayList<String>();
		Boolean valido;
		String aliasKey = null;
		request certificadosManager = new request();
		KeyStore ks = certificadosManager.carregarCertificados();
		String Certific = null;
		for (int i = 0; i < certificadoManager.listCertificadosNet().size(); i++) {
			listCertif.add(certificadoManager.listCertificadosNet().get(i).format(
					certificadoManager.listCertificadosNet().get(i) + ".pfx",
					certificadoManager.listCertificadosNet().get(i)));
		}
		
		aliasKey = listCertif.get(1).toString().replaceAll(".pfx", "");
		
		try {
			certificadoMaquina = certificadosManager.getCertificado(aliasKey);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String urlTransmissao = null;

		CustomKeyStore.setKs(ks);
		CustomKeyStore.setX509(certificadoMaquina);
		CustomKeyStore.setAlias(aliasKey);
		
		String xmlAssinado = "<eventos>\r\n"
				+ "	<tpCertificado>A3</tpCertificado>\r\n"
				+ "	<evento Id=\"ID1507377660000002020071510004200006\">\r\n"
				+ "		<eSocial xmlns=\"http://www.esocial.gov.br/schema/evt/evtTabCargo/v02_05_00\">\r\n"
				+ "			<evtTabCargo Id=\"ID1507377660000002020071510004200006\">\r\n"
				+ "				<ideEvento>\r\n"
				+ "					<tpAmb>2</tpAmb>\r\n"
				+ "					<procEmi>1</procEmi>\r\n"
				+ "					<verProc>2.5.00.02.00</verProc>\r\n"
				+ "				</ideEvento>\r\n"
				+ "				<ideEmpregador>\r\n"
				+ "					<tpInsc>1</tpInsc>\r\n"
				+ "					<nrInsc>50737766</nrInsc>\r\n"
				+ "				</ideEmpregador>\r\n"
				+ "				<infoCargo>\r\n"
				+ "					<inclusao>\r\n"
				+ "						<ideCargo>\r\n"
				+ "							<codCargo>1991</codCargo>\r\n"
				+ "							<iniValid>2017-01</iniValid>\r\n"
				+ "						</ideCargo>\r\n"
				+ "						<dadosCargo>\r\n"
				+ "							<nmCargo>ENCARREGADO ADMINISTRATIVO</nmCargo>\r\n"
				+ "							<codCBO>411010</codCBO>\r\n"
				+ "							<cargoPublico>\r\n"
				+ "								<acumCargo>1</acumCargo>\r\n"
				+ "								<contagemEsp>1</contagemEsp>\r\n"
				+ "								<dedicExcl>N</dedicExcl>\r\n"
				+ "								<leiCargo>\r\n"
				+ "									<nrLei>002</nrLei>\r\n"
				+ "									<dtLei>1994-01-01</dtLei>\r\n"
				+ "									<sitCargo>1</sitCargo>\r\n"
				+ "								</leiCargo>\r\n"
				+ "							</cargoPublico>\r\n"
				+ "						</dadosCargo>\r\n"
				+ "					</inclusao>\r\n"
				+ "				</infoCargo>\r\n"
				+ "			</evtTabCargo>\r\n"
				+ "			<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\r\n"
				+ "				<SignedInfo>\r\n"
				+ "					<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\r\n"
				+ "					<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\r\n"
				+ "					<Reference URI=\"\">\r\n"
				+ "						<Transforms>\r\n"
				+ "							<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\r\n"
				+ "							<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\r\n"
				+ "						</Transforms>\r\n"
				+ "						<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\r\n"
				+ "						<DigestValue>PRnQsWsOhTHpiotNgZtDvMtkwxKdRNNVb5vtjvOXsa0=</DigestValue>\r\n"
				+ "					</Reference>\r\n"
				+ "				</SignedInfo>\r\n"
				+ "				<SignatureValue>uYVGh2PJX4sbRmV0QIVgJ2F1llDErtazEXqJlJEKsnUvRFwkBbe48PueqteSCaCb34f0HwnbbU1m&#13;\r\n"
				+ "					Er7ZferZ65x29FlILlwMbzMHQ2BbF1e7MfgdkVJLdC5qTygVEMd+2pCQBcveP0K/089mHfUMkCJJ&#13;\r\n"
				+ "					bWXoZMC1HOs++7TxEMy22To+4vDqPHFVrSDwKddIDy1/ixXO5RPOCIwXxc+22MNnWKN9C1GGjUs0&#13;\r\n"
				+ "					b0Zi3Vm/g1EDc15Qh6a7OUJskOa93SLdHRbbgPmxyiwu4JJLqx8WD4pE9/CKOmzH7u3yh4IvkbCX&#13;\r\n"
				+ "					um0MZTIpIGJ+PWnaBmXdEJWeLphIZxnZpPccbw==</SignatureValue>\r\n"
				+ "				<KeyInfo>\r\n"
				+ "					<X509Data>\r\n"
				+ "						<X509Certificate>MIIH/DCCBeSgAwIBAgIQEC4uqvumhoLxHMCVyvfOsTANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQG&#13;\r\n"
				+ "							EwJCUjETMBEGA1UEChMKSUNQLUJyYXNpbDE2MDQGA1UECxMtU2VjcmV0YXJpYSBkYSBSZWNlaXRh&#13;\r\n"
				+ "							IEZlZGVyYWwgZG8gQnJhc2lsIC0gUkZCMRwwGgYDVQQDExNBQyBDZXJ0aXNpZ24gUkZCIEc1MB4X&#13;\r\n"
				+ "							DTE5MDcxOTE5MjU0M1oXDTIwMDcxODE5MjU0M1owgecxCzAJBgNVBAYTAkJSMRMwEQYDVQQKDApJ&#13;\r\n"
				+ "							Q1AtQnJhc2lsMQswCQYDVQQIDAJTUDESMBAGA1UEBwwJU2FvIFBhdWxvMTYwNAYDVQQLDC1TZWNy&#13;\r\n"
				+ "							ZXRhcmlhIGRhIFJlY2VpdGEgRmVkZXJhbCBkbyBCcmFzaWwgLSBSRkIxFjAUBgNVBAsMDVJGQiBl&#13;\r\n"
				+ "							LUNOUEogQTExFzAVBgNVBAsMDjEwOTA5NjYzMDAzOTUwMTkwNwYDVQQDDDBURUNITkUgRU5HRU5I&#13;\r\n"
				+ "							QVJJQSBFIFNJU1RFTUFTIExUREE6NTA3Mzc3NjYwMDAxMjEwggEiMA0GCSqGSIb3DQEBAQUAA4IB&#13;\r\n"
				+ "							DwAwggEKAoIBAQC9FjHkpYWru4qrvA2ZbsBJld4cM5tPtywlAPCvysHWC0vEARfjSjHQY2Y/Xl/9&#13;\r\n"
				+ "							S+uUO/q6EnGO+azkQVgFy33AxLT34qF+XuifYzk95bjXYdDvlhCHrn3DKhUfVhijdBGsMgKmsVkr&#13;\r\n"
				+ "							qtbx0u6hxBHsuE4UU0CqByzijITapqrtz3V+AoeQ7gQ9RO64u8UxN6i18qSJSg7dW8FFkh0VFFaL&#13;\r\n"
				+ "							jl51tHJlav+T7qy+jJOQIuB5z2FFxWBnrSpZYuFrSo5j4qT1YXcS9+JlSLlpIqq+LBdHC8MwdNNg&#13;\r\n"
				+ "							S3hsUkTS/7X5eBps29jZ+7ao/dNErMV3GVSe4HOZrvsnegB1ACmvAgMBAAGjggMQMIIDDDCBvwYD&#13;\r\n"
				+ "							VR0RBIG3MIG0oD0GBWBMAQMEoDQEMjA0MDUxOTU3MzUwMTIyODU2MjAwMDAwMDAwMDAwMDAwMDAw&#13;\r\n"
				+ "							MDAwOTU1OTYyN1NTUFNQoCEGBWBMAQMCoBgEFk1BVVJJQ0lPIERBIENPU1RBIE1FTE+gGQYFYEwB&#13;\r\n"
				+ "							AwOgEAQONTA3Mzc3NjYwMDAxMjGgFwYFYEwBAwegDgQMMDAwMDAwMDAwMDAwgRxST0JFUlRBLk1P&#13;\r\n"
				+ "							UkFFU0BURUNITkUuQ09NLkJSMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUU31/nb7RYdAgutqf44mn&#13;\r\n"
				+ "							E3NYzUIwfwYDVR0gBHgwdjB0BgZgTAECAQwwajBoBggrBgEFBQcCARZcaHR0cDovL2ljcC1icmFz&#13;\r\n"
				+ "							aWwuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9kcGMvQUNfQ2VydGlzaWduX1JGQi9EUENf&#13;\r\n"
				+ "							QUNfQ2VydGlzaWduX1JGQi5wZGYwgbwGA1UdHwSBtDCBsTBXoFWgU4ZRaHR0cDovL2ljcC1icmFz&#13;\r\n"
				+ "							aWwuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9sY3IvQUNDZXJ0aXNpZ25SRkJHNS9MYXRl&#13;\r\n"
				+ "							c3RDUkwuY3JsMFagVKBShlBodHRwOi8vaWNwLWJyYXNpbC5vdXRyYWxjci5jb20uYnIvcmVwb3Np&#13;\r\n"
				+ "							dG9yaW8vbGNyL0FDQ2VydGlzaWduUkZCRzUvTGF0ZXN0Q1JMLmNybDAOBgNVHQ8BAf8EBAMCBeAw&#13;\r\n"
				+ "							HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMIGsBggrBgEFBQcBAQSBnzCBnDBfBggrBgEF&#13;\r\n"
				+ "							BQcwAoZTaHR0cDovL2ljcC1icmFzaWwuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9jZXJ0&#13;\r\n"
				+ "							aWZpY2Fkb3MvQUNfQ2VydGlzaWduX1JGQl9HNS5wN2MwOQYIKwYBBQUHMAGGLWh0dHA6Ly9vY3Nw&#13;\r\n"
				+ "							LWFjLWNlcnRpc2lnbi1yZmIuY2VydGlzaWduLmNvbS5icjANBgkqhkiG9w0BAQsFAAOCAgEAlY51&#13;\r\n"
				+ "							e+g2roLRVfFmQ63Cd0s+lGINsmN8sZVGm8iQ/8L0eT5IUOvaqWAFQx/sssnFpY6/NBtV3i20h5KL&#13;\r\n"
				+ "							kNiA8+TCKvvi0Qdx2w9eze6YL32pmbb86q6fXNUJJXZS//6H3ctqfVoSmud3Del4KSLqKxYbo2Ab&#13;\r\n"
				+ "							RfoZounz+olv4JGuSZlIvfaQNOfZNIJSyNl39CpaN2nMGrpzjBKDYONeeCe+853xdYODsfz9GrXr&#13;\r\n"
				+ "							0kK6Nl57GvcY0r/ldkGhXqriCPrW49zQBb/PWHxaq/z5ue6HLvXzicN5u/umAOHbk6tk7f3Am2gG&#13;\r\n"
				+ "							FK8tLrv5AffZxfUiDmciCMpDmV0zbkfqlA981J2mFI0u7sMFiZ3Fmdiy9/p53Lreu7TfUVeTtAqZ&#13;\r\n"
				+ "							vlMleKJRrxwOglYs/5fmbuI1GJL6zZevXMdfLd9qqyC+Bfoul+a1cniIkr78859QIZc6WxOTbnxp&#13;\r\n"
				+ "							Wc5Tly05WuBH8yUo1n7PLHyQvnyZDZqzAPNxUvK/J/s81eUP3y05eR4sYDYSST0rB1cA395CnWcj&#13;\r\n"
				+ "							FUbWemJQq8LlDvrM5qNq1G7kbZXawwB4L1ALF4+scS7UZ+of2JThquOFadPScDw7WwwcmiM2wX96&#13;\r\n"
				+ "							rN5s1DxYp6T9PJPxLvav0v42iVLqRxybSrVcNyoUA7E2EU93xeTmYBEUt6srJ7bSqCIehHA=</X509Certificate>\r\n"
				+ "					</X509Data>\r\n"
				+ "				</KeyInfo>\r\n"
				+ "			</Signature>\r\n"
				+ "		</eSocial>\r\n"
				+ "	</evento>"
				+ "</eventos>";
		
		String configNsEnvio = "https://webservices.producaorestrita.esocial.gov.br/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc";
		urlTransmissao = "https://webservices.producaorestrita.esocial.gov.br/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc";
		
		resultRetorn.add(javaCall.javaCall(CustomKeyStore.getKs(), xmlAssinado.trim(), urlTransmissao,
				configNsEnvio, namespaceEnum.transmissao.getAction(), aliasKey));
		
		listCertif.forEach(c -> System.out.println(c.toString()));
	}

}
