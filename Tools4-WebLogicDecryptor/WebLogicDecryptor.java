import java.util.*;
import java.io.*;
import javax.xml.parsers.*;
import javax.xml.xpath.*;
import org.w3c.dom.*;
import weblogic.security.internal.*; // requires weblogic.jar in the class path
import weblogic.security.internal.encryption.*;
 
public class WebLogicDecryptor {
	private static final String PREFIX = "{AES}";
	private static final String XPATH_EXPRESSION = "//node()[starts-with(text(), '"
			+ PREFIX + "')] | //@*[starts-with(., '" + PREFIX + "')]";
	private static ClearOrEncryptedService ces;
 
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			throw new Exception("Usage: [domainDir] [configFile]");
		}
 
		ces = new ClearOrEncryptedService(
				SerializedSystemIni.getEncryptionService(new File(args[0])
						.getAbsolutePath()));
		File file = new File(args[1]);
		if (file.getName().endsWith(".xml")) {
			processXml(file);
		}
 
		else if (file.getName().endsWith(".properties")) {
			processProperties(file);
		}
 
	}
 
	private static void processXml(File file) throws Exception {
		Document doc = DocumentBuilderFactory.newInstance()
				.newDocumentBuilder().parse(file);
		XPathExpression expr = XPathFactory.newInstance().newXPath()
				.compile(XPATH_EXPRESSION);
		NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
		for (int i = 0; i < nodes.getLength(); i++) {
			Node node = nodes.item(i);
			print(node.getNodeName(), node.getTextContent());
		}
 
	}
 
	private static void processProperties(File file) throws Exception {
		Properties properties = new Properties();
		properties.load(new FileInputStream(file));
		for (Map.Entry p : properties.entrySet()) {
			if (p.getValue().toString().startsWith(PREFIX)) {
				print(p.getKey(), p.getValue());
			}
		}
	}
 
	private static void print(Object attributeName, Object encrypted) {
		System.out.println("Node name: " + attributeName);
		System.out.println("Encrypted: " + encrypted);
		System.out.println("Decrypted: " + ces.decrypt((String) encrypted)
				+ "\n");
	}
}