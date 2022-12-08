package org.caulfield.pkiz.init;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Date;
import java.util.stream.IntStream;
import org.caulfield.pkiz.crypto.CryptoGenerator;
import java.util.stream.Collectors;
import org.openide.util.Exceptions;

/**
 * @author pbakhtiari
 */
public class ObjectsInitializer {

    public static String generateRandomPassword(int len) {
        // ASCII range – alphanumeric (0-9, a-z, A-Z)
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        SecureRandom random = new SecureRandom();

        // each iteration of the loop randomly chooses a character from the given
        // ASCII range and appends it to the `StringBuilder` instance
        return IntStream.range(0, len)
                .map(i -> random.nextInt(chars.length()))
                .mapToObj(randomIndex -> String.valueOf(chars.charAt(randomIndex)))
                .collect(Collectors.joining());
    }

    public static String[] createLocalObjects() {
        String[] outs = new String[3];
        CryptoGenerator cg = new CryptoGenerator();
        String user = System.getProperty("user.name").toUpperCase();
        String generationDir = System.getProperty("user.dir") + "\\generated\\";
        String password = generateRandomPassword(8);
        // GENERATE ROOT PRIVATE KEY
        outs[0] = cg.buildPrivateKey(generationDir, password, user + "_private.key", 2048, "65537", 8, "RSA", user + "_private");
        // GENERATE ROOT PUBLIC KEY
        outs[1] = cg.generatePublicKeyFromPrivateKey("1. " + user + "_private", password, generationDir, user + "_public.key", user + "_public");
        // GENERATE ROOT CERTIFICATE USING PRIVATE & PUBLIC KEY
        outs[2] = cg.generateCertificateFromPublicKeyAndPrivateKey("CN=AC LOCALE DE " + user + ",O=LOCAL", "2. " + user + "_public", "1. " + user + "_private", password, generationDir, user + "_certificate.crt", new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), "SHA256withRSA", "V3", System.getProperty("user.name").toUpperCase());

        for (String out : outs) {
            System.out.println(out);
        }
        return outs;
    }

    public static void createGeneratedDir() {
        Path path = Paths.get(System.getProperty("user.dir") + "\\generated\\");
        try {
            Files.createDirectory(path);
            System.out.println("Directory /generated created.");
        } catch (IOException ex) {
            // Exceptions.printStackTrace(ex);
            System.out.println("Directory /generated cannot be created.");
        }
    }

    public static void main(String[] args) {
        createGeneratedDir();
        createLocalObjects();
    }
}
