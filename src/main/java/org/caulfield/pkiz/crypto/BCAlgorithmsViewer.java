package org.caulfield.pkiz.crypto;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author pbakhtiari
 */
public class BCAlgorithmsViewer {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Provider p = Security.getProvider("BC");
        for (Provider.Service s : p.getServices()) {
            if (s.getType().equals("Cipher")) {
                System.out.println(s.getAlgorithm());
                //System.out.println( "++++++++++++ " + s.toString());     
            }
        }
    }
}
