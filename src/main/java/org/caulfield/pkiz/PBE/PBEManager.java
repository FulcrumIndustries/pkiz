package org.caulfield.pkiz.PBE;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.caulfield.pkiz.database.definition.CryptoDAO;
import org.caulfield.pkiz.database.definition.HSQLLoader;
import org.openide.util.Exceptions;

/**
 * @author phili
 */
public class PBEManager {

    private static char[] submittedPassword = new char[0];
    private static String decryptedPassword = "";
    private static String encryptedPassword = "";
    private static String salt = "";

    /**
     * @return the encryptedPassword
     */
    public static String getEncryptedPassword() {
        return encryptedPassword;
    }

    /**
     * @return the salt
     */
    public static String getSalt() {
        return salt;
    }

    /**
     * @param aEncryptedPassword the encryptedPassword to set
     */
    public static void setEncryptedPassword(String aEncryptedPassword) {
        encryptedPassword = aEncryptedPassword;
    }

    /**
     * @param aSalt the salt to set
     */
    public static void setSalt(String aSalt) {
        salt = aSalt;
    }

    /**
     * @return the submittedPassword
     */
    public static char[] getSubmittedPassword() {
        return submittedPassword;
    }

    /**
     * @param aSubmittedPassword the submittedPassword to set
     */
    public static void setSubmittedPassword(char[] aSubmittedPassword) {
        submittedPassword = aSubmittedPassword;
    }

    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        byte salt[] = new byte[16];
        SecureRandom saltGen = SecureRandom.getInstance("SHA1PRNG");
        saltGen.nextBytes(salt);
        return salt;
    }

    public static byte[] encrypt(String plainText, char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());

        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, 20);
        if (!decryptedPassword.equals("")) {
            password = decryptedPassword.toCharArray();
        }
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        Cipher encryptionCipher = Cipher.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        return encryptionCipher.doFinal(plainText.getBytes());
    }

    public static byte[] decrypt(byte[] cipher, String password, byte[] salt, final int iterationCount)
            throws Exception {
        PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(new SHA256Digest());
        char[] passwordChars = password.toCharArray();
        if (!decryptedPassword.equals("")) {
            password = decryptedPassword;
        }
        final byte[] pkcs12PasswordBytes = PBEParametersGenerator.PKCS12PasswordToBytes(passwordChars);
        pGen.init(pkcs12PasswordBytes, salt, iterationCount);
        CBCBlockCipher aesCBC = new CBCBlockCipher(new AESEngine());
        ParametersWithIV aesCBCParams = (ParametersWithIV) pGen.generateDerivedParameters(256, 128);
        aesCBC.init(false, aesCBCParams);
        PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(aesCBC, new PKCS7Padding());
        byte[] plainTemp = new byte[aesCipher.getOutputSize(cipher.length)];
        int offset = aesCipher.processBytes(cipher, 0, cipher.length, plainTemp, 0);
        int last = aesCipher.doFinal(plainTemp, offset);
        final byte[] plain = new byte[offset + last];
        System.arraycopy(plainTemp, 0, plain, 0, plain.length);
        return plain;
    }

    public static String tryLogin(String password) {
        // Get Salt and test Cipher from DB
        HSQLLoader sql = new HSQLLoader();
        String[] params = sql.getSaltAndPassword();
        String salt = params[0];
        String encryptedSaltedPassword = params[1];
        submittedPassword = password.toCharArray();
        // Try to decrypt : if = "password is valid" then ok
        try {
            //System.out.println("org.caulfield.pkiz.PBE.PBEManager.tryLogin() ENTERED PASSWORD IS " + password);
            String decypherTest = getSecurePassword(password, salt.getBytes());
            System.out.println("org.caulfield.pkiz.PBE.PBEManager.tryLogin() HASHED TO " + decypherTest);
            if (decypherTest.equals(encryptedSaltedPassword)) {
                return "Login Successful";
            } else {
                return "Login Failed";
            }
        } catch (Exception ex) {
            return "Login Failed";
        }
    }

    public static String getSecurePassword(String password, byte[] salt) {

        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] bytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    public static String createLogin(String password) {
        try {
            System.out.println("org.caulfield.pkiz.PBE.PBEManager.createLogin() TRYING ");
            byte[] salt = generateSalt();
            String encryptedSaltedPassword = getSecurePassword(password, salt);
            // Write Salt and Encrypted password in the database during initialization
            HSQLLoader sql = new HSQLLoader();
            sql.initDatabase(encryptedSaltedPassword, new String(salt));
            System.out.println("org.caulfield.pkiz.PBE.PBEManager.createLogin() STORED " + new String(salt) + " " + encryptedSaltedPassword);
            return "Registering of Master password OK";
        } catch (Exception ex) {
            System.out.println("org.caulfield.pkiz.PBE.PBEManager.createLogin() F " + ex.toString());
            return "Registering of Master password Failed";

        }
    }

    public static void main(String[] args) {
        String password = "qwerty";
        String plainText = "hello world";
        try {
            System.out.println("Specified Password : " + password);
            System.out.println("Specified Plain Text : " + plainText);
            byte[] salt = generateSalt();
            System.out.println("Generated Salt : " + new String(salt));
            byte[] cipherText = encrypt(plainText, password.toCharArray(), salt);
            System.out.println("Generated Cipher : " + new String(cipherText));
            byte[] decryptedText = decrypt(cipherText, password, salt, 20);
            System.out.println("Decrypted message : " + new String(decryptedText));
            String encryp = getSecurePassword(password, salt);
            System.out.println("Other encrypted salted password : " + encryp);

        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException ex) {

        } catch (Exception ex) {
            Exceptions.printStackTrace(ex);
        }
    }

}
