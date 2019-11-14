import weblogic.security.internal.*;
import weblogic.security.internal.encryption.*;

import java.io.PrintStream;


public class Decrypt {
    static EncryptionService es = null;
    static ClearOrEncryptedService ces = null;

    public static void main(String[] args) {
        String s = null;

        if (args.length == 0) {
            s = ServerAuthenticate.promptValue("Password: ", false);
        } else if (args.length == 1) {
            s = args[0];
        } else {
            System.err.println("Usage: java Decrypt [ password ]");
        }

        es = SerializedSystemIni.getExistingEncryptionService();

        if (es == null) {
            System.err.println("Unable to initialize encryption service");

            return;
        }

        ces = new ClearOrEncryptedService(es);

        if (s != null) {
            System.out.println("\nDecrypted Password is:" + ces.decrypt(s));
        }
    }
}