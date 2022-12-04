package org.caulfield.pkiz.database.algo;

/**
 * @author pbakhtiari
 */
public enum AlgoEnum {
    ALIAS("Alg.Alias."),
    CIPHER("Cipher."),
    KEYAGREEMENT("KeyAgreement."),
    MAC("Mac."),
    MESSAGEDIGEST("MessageDigest."),
    SIGNATURE("Signature."),
    KEYPAIRGENERATOR("KeyPairGenerator."),
    KEYFACTORY("KeyFactory."),
    KEYGENERATOR("KeyGenerator.");

    private String name = "";

    AlgoEnum(String name) {
        this.name = name;
    }

    public String toString() {
        return name;
    }

}
