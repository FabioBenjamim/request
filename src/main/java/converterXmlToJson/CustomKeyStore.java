package converterXmlToJson;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class CustomKeyStore {
	
	private static KeyStore ks;
	private static X509Certificate x509;
	private static String alias;
	
	
	public static KeyStore getKs() {
		return ks;
	}
	public static void setKs(KeyStore ks) {
		CustomKeyStore.ks = ks;
	}
	public static X509Certificate getX509() {
		return x509;
	}
	public static void setX509(X509Certificate x509) {
		CustomKeyStore.x509 = x509;
	}
	public static String getAlias() {
		return alias;
	}
	public static void setAlias(String alias) {
		CustomKeyStore.alias = alias;
	}
	
}
