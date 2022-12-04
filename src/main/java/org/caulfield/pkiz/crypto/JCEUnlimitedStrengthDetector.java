package org.caulfield.pkiz.crypto;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

/**
 * @author pbakhtiari
 */
public class JCEUnlimitedStrengthDetector {

    public static boolean isJCEUnlimited() {
        try {
            int length = Cipher.getMaxAllowedKeyLength("AES");
            boolean unlimited = (length == Integer.MAX_VALUE);
            return unlimited;
        } catch (NoSuchAlgorithmException ex) {

        }
        return false;
    }
}
