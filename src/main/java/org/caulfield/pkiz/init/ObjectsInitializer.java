/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.pkiz.init;

import java.security.SecureRandom;
import java.util.Date;
import java.util.stream.IntStream;
import org.caulfield.pkiz.crypto.CryptoGenerator;
import java.util.stream.Collectors;

/**
 * GET
 *
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
        String[] out = new String[3];
        CryptoGenerator cg = new CryptoGenerator();
        String user = System.getProperty("user.name").toUpperCase();
        String password = generateRandomPassword(8);
        // GENERATE ROOT PRIVATE KEY
        out[0] = cg.buildPrivateKey("", password, user + "_private.key", 2048, "65537", 8, "RSA", user + "_private");
        // GENERATE ROOT PUBLIC KEY
        out[1] = cg.generatePublicKeyFromPrivateKey("1. " + user + "_private", password, "", user + "_public.key", user + "_public");
        // GENERATE ROOT CERTIFICATE USING PRIVATE & PUBLIC KEY
        out[2] = cg.generateCertificateFromPublicKeyAndPrivateKey("CN=AC LOCALE DE " + user + ",O=LOCAL", "2. " + user + "_public", "1. " + user + "_private", password, "", user + "_certificate.crt", new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), "SHA256withRSA", "V3", System.getProperty("user.name").toUpperCase());
        return out;
    }

    public static void main(String[] args) {
        createLocalObjects();
    }
}
