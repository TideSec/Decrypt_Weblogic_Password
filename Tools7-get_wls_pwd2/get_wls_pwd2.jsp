<%@page pageEncoding="utf-8"%>
<%@page import="weblogic.security.internal.*,weblogic.security.internal.encryption.*"%>
<%
   EncryptionService es = null;
   ClearOrEncryptedService ces = null;
    String s = null;
    s="{AES}yvGnizbUS0lga6iPA5LkrQdImFiS/DJ8Lw/yeE7Dt0k=";
    es = SerializedSystemIni.getEncryptionService();
    if (es == null) {
       out.println("Unable to initialize encryption service");
        return;
    }
    ces = new ClearOrEncryptedService(es);
    if (s != null) {
        out.println("\nDecrypted Password is:" + ces.decrypt(s));
    }
%>