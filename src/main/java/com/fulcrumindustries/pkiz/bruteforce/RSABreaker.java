package com.fulcrumindustries.pkiz.bruteforce;

import org.apache.commons.io.FileUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Paths;

import org.caulfield.pkiz.crypto.CryptoGenerator;
import org.caulfield.pkiz.crypto.EnigmaException;
import org.openide.util.Exceptions;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Bibliography:
 * <p>
 * [1] W. Stallings, D. Vieira, A. Barbosa and M. Ferreira, Criptografia e
 * segurança de redes. São Paulo: Pearson Prentice Hall, 2008. [2] H. Java?,
 * "How to generate a random BigInteger value in Java?", Stackoverflow.com,
 * 2018. [Online]. Available:
 * https://stackoverflow.com/questions/2290057/how-to-generate-a-random-biginteger-value-in-java.
 * [Accessed: 20- Apr- 2018]. [3] w. David Ireland, "RSA Algorithm",
 * Di-mgt.com.au, 2018. [Online]. Available:
 * https://www.di-mgt.com.au/rsa_alg.html. [Accessed: 21- Apr- 2018]. [4] w.
 * David Ireland, "The Euclidean Algorithm and the Extended Euclidean
 * Algorithm", Di-mgt.com.au, 2018. [Online]. Available:
 * https://www.di-mgt.com.au/euclidean.html. [Accessed: 21- Apr- 2018]. [5]
 * "Extended Euclidean Algorithm", Www-math.ucdenver.edu, 2018. [Online].
 * Available:
 * http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html.
 * [Accessed: 22- Apr- 2018]. [6] S. Dasgupta, C. Papadimitriou and U. Vazirani,
 * Algorithms. [7] W. RSA?, "Why do we need Euler's totient function
 * $\varphi(N)$ in RSA?", Crypto.stackexchange.com, 2018. [Online]. Available:
 * https://crypto.stackexchange.com/questions/33676/why-do-we-need-eulers-totient-function-varphin-in-rsa.
 * [Accessed: 22- Apr- 2018]. [8] "A Quick Tutorial on Pollard's Rho Algorithm",
 * Cs.colorado.edu, 2018. [Online]. Available:
 * https://www.cs.colorado.edu/~srirams/courses/csci2824-spr14/pollardsRho.html.
 * [Accessed: 26- Apr- 2018]. [9] T. Cormen and C. Leiserson, Introduction to
 * algorithms, 3rd edition.
 */
public class RSABreaker {

    public static void main(String[] args) throws Exception {
        String publicKey = "D:/TEST/smallkey.key";
        String inputFile = "C:/Users/phili/OneDrive/Documents/GitHub/pkiz/smalltest.txt.enc";
        String solved = PollardForce(inputFile, publicKey, inputFile + ".out");
        System.out.print("Solution : " + solved);
    }

    private static void generateKeyFiles(int keySize) throws Exception {
        RSA rsa = new RSA(keySize);
        rsa.generateKeys();
        FileUtils.writeByteArrayToFile(Paths.get("public_key.rsa").toFile(), serialize(rsa.getPublicKey()));
        FileUtils.writeByteArrayToFile(Paths.get("private_key.rsa").toFile(), serialize(rsa.getPrivateKey()));
    }

    private static void encrypt(String inputFile, String publicKey, String outputFile) throws Exception {
        PublicKey pubK = (PublicKey) deserialize(FileUtils.readFileToByteArray(Paths.get(publicKey).toFile()));
        String message = FileUtils.readFileToString(Paths.get(inputFile).toFile(), "UTF-8");
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.crypto = pubK.encrypt(message);
        FileUtils.writeByteArrayToFile(Paths.get(outputFile).toFile(), serialize(encryptedMessage));
    }

    private static void decrypt(String inputFile, String decryptKey, String outputFile) throws Exception {
        PrivateKey priK = (PrivateKey) deserialize(FileUtils.readFileToByteArray(Paths.get(decryptKey).toFile()));
        EncryptedMessage encryptedMessage = (EncryptedMessage) deserialize(FileUtils.readFileToByteArray(Paths.get(inputFile).toFile()));
        FileUtils.write(Paths.get(outputFile).toFile(), priK.decrypt(encryptedMessage.crypto), "UTF-8");
    }

    private static void bruteForce(String inputFile, String publicKey, String outputFile) throws Exception {
        PublicKey pubK = (PublicKey) deserialize(FileUtils.readFileToByteArray(Paths.get(publicKey).toFile()));
        EncryptedMessage encryptedMessage = (EncryptedMessage) deserialize(FileUtils.readFileToByteArray(Paths.get(inputFile).toFile()));
        String solution = BruteForce.solve(pubK, encryptedMessage.crypto);
        FileUtils.write(Paths.get(outputFile).toFile(), solution, "UTF-8");
    }

    private static void pollardForce(String inputFile, String publicKey, String outputFile) throws Exception {
        PublicKey pubK = (PublicKey) deserialize(FileUtils.readFileToByteArray(Paths.get(publicKey).toFile()));
        EncryptedMessage encryptedMessage = (EncryptedMessage) deserialize(FileUtils.readFileToByteArray(Paths.get(inputFile).toFile()));
        String solution = PollardForce.solve(pubK, encryptedMessage.crypto);
        FileUtils.write(Paths.get(outputFile).toFile(), solution, "UTF-8");
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }

    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }

    public static void showPubKeyspecs(String publicKey) {

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Base64.getDecoder().decode(publicKey.getBytes("UTF-8"));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            java.security.PublicKey fileGeneratedPublicKey = keyFactory.generatePublic(spec);
            RSAPublicKey rsaPub = (RSAPublicKey) (fileGeneratedPublicKey);
            BigInteger publicKeyModulus = rsaPub.getModulus();
            BigInteger publicKeyExponent = rsaPub.getPublicExponent();
            System.out.println("publicKeyModulus: " + publicKeyModulus);
            System.out.println("publicKeyExponent: " + publicKeyExponent);
            String nModulus = Base64.getUrlEncoder().encodeToString(publicKeyModulus.toByteArray());
            String eExponent = Base64.getUrlEncoder().encodeToString(publicKeyExponent.toByteArray());
            System.out.println("n Modulus for RSA Algorithm: " + nModulus);
            System.out.println("e Exponent for RSA Algorithm: " + eExponent);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeySpecException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }

    }

    public static BigInteger estimatePollard(String publicKey) {
        BigInteger eval = BigInteger.ONE;
        try {
            CryptoGenerator cg = new CryptoGenerator();
            java.security.PublicKey pub = cg.getPublicKeyV2(publicKey);
            RSAPublicKey rsaPub = (RSAPublicKey) (pub);
            System.out.println("KEYSIZE:" + rsaPub.getModulus().bitLength());
            BigInteger bigE = BigInteger.TWO;
            BigInteger computationRequired = bigE.pow(rsaPub.getModulus().bitLength());
            Runtime rtr = Runtime.getRuntime();
            int procs = rtr.availableProcessors();
            BigInteger cpuStrength = BigInteger.valueOf(procs * 3 * 1000 * 1000 * 1000);
            System.out.println("CPU STR:" + cpuStrength);
            eval = computationRequired.divide(cpuStrength).divide(BigInteger.valueOf(3600));
            System.out.println("EVAL:" + eval);
        } catch (EnigmaException ex) {
            Exceptions.printStackTrace(ex);
        }
        return eval;
    }

    public static String PollardForce(String publicKey, String inputFile, String outputFile) {

        String solution = "";
        try {
            CryptoGenerator cg = new CryptoGenerator();
            java.security.PublicKey pub = cg.getPublicKeyV2(publicKey);
            RSAPublicKey rsaPub = (RSAPublicKey) (pub);
            System.out.print(rsaPub.getPublicExponent());
            System.out.print(rsaPub.getModulus());
            PublicKey brutePub = new PublicKey();
            brutePub.e = rsaPub.getPublicExponent();
            brutePub.n = rsaPub.getModulus();
            brutePub.keySize = rsaPub.getModulus().bitLength();

            EncryptedMessage encryptedMessage = new EncryptedMessage();
            FileInputStream fis = null;
            File f = new File(inputFile);
            encryptedMessage.crypto = FileUtils.readFileToString(f, "UTF-8");
            solution = PollardForce.solve(brutePub, encryptedMessage.crypto);
            FileUtils.writeStringToFile(new File(outputFile), solution, "UTF-8");
        } catch (EnigmaException | IOException ex) {
            Exceptions.printStackTrace(ex);
        }
        return solution;
    }

}
