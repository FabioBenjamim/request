package converterXmlToJson;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class JavaCall {

	public String javaCall(KeyStore ks, String xmlSemi, String urlTransmissao, String namespace, String SOAPAction, final String alias){
		try{
			
//			urlTransmissao = "https://www.dataaccess.com/webservicesserver/NumberConversion.wso";
//			
//			xmlSemi = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
//					+ "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
//					+ "  <soap:Body>\r\n"
//					+ "    <NumberToWords xmlns=\"http://www.dataaccess.com/webservicesserver/\">\r\n"
//					+ "      <ubiNum>500</ubiNum>\r\n"
//					+ "    </NumberToWords>\r\n"
//					+ "  </soap:Body>\r\n"
//					+ "</soap:Envelope>";
			
			String xml = xmlSemi.replaceAll("<tpCertificado>A3<\\/tpCertificado>", "");
			
			SOAPConnection soapConnection = SOAPConnectionFactory.newInstance().createConnection();
	        HttpsURLConnection httpsConnection = null;
	        
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        
	        InputStream cfv5 = getClass().getClassLoader().getResourceAsStream("certificados/acserproacfv5.crt");
	        X509Certificate acserproacfv5 = (X509Certificate)cf.generateCertificate(cfv5);
	        ks.setCertificateEntry("acserproacfv5", acserproacfv5);
	        
	        InputStream icpsv5 = getClass().getClassLoader().getResourceAsStream("certificados/icpbrasilv5.crt");
	        X509Certificate icpbrasilv5 = (X509Certificate)cf.generateCertificate(icpsv5);
	        ks.setCertificateEntry("icpbrasilv5", icpbrasilv5); 
	        
	        InputStream prov4 =getClass().getClassLoader().getResourceAsStream("certificados/acserprov4.crt");
	        X509Certificate acserprov4 = (X509Certificate)cf.generateCertificate(prov4);
	        ks.setCertificateEntry("acserprov4", acserprov4);  
	        
	        InputStream acr3 =getClass().getClassLoader().getResourceAsStream("certificados/acrfbv3.crt");
	        X509Certificate acrfbv3 = (X509Certificate)cf.generateCertificate(acr3);
	        ks.setCertificateEntry("acrfbv3", acrfbv3);
	        
	        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	        
	        //KeyManagerFactory keyManagerFactory;
	        //keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
	        
	        ks.load(null ,null);
	        ks.store(null, "tECHNE@".toCharArray());
	        
	        KeyStore ksPrivate = KeyStore.getInstance("JKS");
	        
	        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection("tEHCNE@".toCharArray()));
	        
	        ksPrivate.load(null, null);
	        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
	        //keySotre2.setKeyEntry("key1", (Key)keyEntry.getPrivateKey(), "tECHNE@".toCharArray(), certChain);  
	        //keySotre2.setEntry(alias, keyEntry, protParam);
	        
	        HSKeyManager hsKey = new HSKeyManager(cert, keyEntry.getPrivateKey());  
	        ksPrivate.setCertificateEntry(alias, cert);
	        //keyManagerFactory.init(ksPrivate, null);	        
	        
	        
	        tmf.init(ks);
	        SSLContext sslContext = SSLContext.getInstance("TLS");
	        KeyManager[] keysManager = new KeyManager[]{hsKey}; 	        
	        
	        sslContext.init(keysManager, tmf.getTrustManagers(), new SecureRandom());
	        SSLSocketFactory sllPadrão =  HttpsURLConnection.getDefaultSSLSocketFactory();
	        
	        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
	        
	        URL endpoint = new URL(urlTransmissao);
	        
	        httpsConnection = (HttpsURLConnection) endpoint.openConnection();
	        
	        httpsConnection.connect();
	        
	        int result = httpsConnection.getResponseCode();
	        InputStreamReader resultReader;
	        System.out.println(result + " - Result");
	        
	        MimeHeaders headers = new MimeHeaders();
	        headers.addHeader("Content-Type", "text/xml; charset=utf-8");
	        
	        MessageFactory messageFactory = MessageFactory.newInstance();
	        byte[] b = xml.getBytes(StandardCharsets.UTF_8);
	        SOAPMessage soapMessage = messageFactory.createMessage(headers , (new ByteArrayInputStream(b)));
	        SOAPPart soapPart = soapMessage.getSOAPPart();
	        final SOAPElement stringToSOAPElement = stringToSOAPElement(xml);
	        SOAPEnvelope envelope = soapPart.getEnvelope();
	        SOAPBody soapBody = envelope.getBody();
			headers.addHeader("SOAPAction", SOAPAction);
			soapMessage.saveChanges();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			soapMessage.writeTo(out);
			String strMsg = new String(out.toByteArray());
			
	        SOAPMessage soapResponse = soapConnection.call(soapMessage, endpoint);
	        
	        Document xmlRespostaARequisicao= soapResponse.getSOAPBody().getOwnerDocument();
	        
	        StringWriter sw = new StringWriter();
	        TransformerFactory transformerFactory = TransformerFactory.newInstance();
	        Transformer transformer = transformerFactory.newTransformer();
	        Source sourceContent = soapResponse.getSOAPPart().getContent();
//	        StreamResult result = new StreamResult(sw);
//	        transformer.transform(sourceContent, result);  
	        
	        String xmlRetorno = sw.toString();
	        xmlRetorno = xmlRetorno.replaceAll("\r", "");
	        xmlRetorno = xmlRetorno.replaceAll("\t", "");
	        xmlRetorno = xmlRetorno.replaceAll("\n", "");
	        
	        System.out.println(xmlRetorno);
	        
	        httpsConnection.disconnect();
	        
	        soapConnection.close();
	        
//	        sslContext.init(null, null, null);
//	        HttpsURLConnection.setDefaultSSLSocketFactory(sllPadrão);
	        
	        return xmlRetorno;
		}catch(Exception e) {
			JOptionPane.showMessageDialog(null, "Erro ao transmitir arquivo: "+ e.getMessage());
		}
		return null; 
	}
	
	private SOAPElement stringToSOAPElement(String xmlRequestBody) throws SOAPException, SAXException, IOException, ParserConfigurationException {
		
		// Load the XML text into a DOM Document
		final DocumentBuilderFactory builderFactory = DocumentBuilderFactory
				.newInstance();
		builderFactory.setNamespaceAware(true);		
		byte[] b = xmlRequestBody.getBytes(StandardCharsets.UTF_8);
		final InputStream stream = new ByteArrayInputStream(b);
		final Document doc = builderFactory.newDocumentBuilder().parse(stream);
		// Use SAAJ to convert Document to SOAPElement
		// Create SoapMessage
		
		final MessageFactory msgFactory = MessageFactory.newInstance();
		final SOAPMessage message = msgFactory.createMessage();
		final SOAPBody soapBody = message.getSOAPBody();
		// This returns the SOAPBodyElement that contains ONLY the Payload
		return soapBody.addDocument(doc);
	}
	
     
}