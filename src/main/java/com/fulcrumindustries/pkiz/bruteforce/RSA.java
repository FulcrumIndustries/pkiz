package com.fulcrumindustries.pkiz.bruteforce;

import java.math.BigInteger;
import java.util.Random;

/**
 * @author pbakhtiari
 */
public class RSA {

    private int keySize = 1024;

    private BigInteger lowBound = new BigInteger("200");

    private BigInteger p = null;

    private BigInteger q = null;

    private BigInteger n = null;

    private BigInteger phi = null;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    public RSA() {
        super();
    }

    public RSA(int keySize) {
        super();
        this.keySize = keySize;
    }

    public void generateKeys() { // O(n^4)
        generatePrimeNumbers(); // O(n^4)
        n = p.multiply(q); // O(n^2)
        phi = getTotientEuler(); // O(n^2)
        createPublicKey(); // O(n^3)
        createPrivateKey(); // O(n^3)
    }

    private void generatePrimeNumbers() { // O(n^4)
        int half = keySize / 2; // O(n) considerando operação de shift e O(n^2) divisão normal da escola
        while (p == null) {
            BigInteger temp = getRandomNumber(half); // O(1), necessita de mais buscas para entender como analisar essa complexidade
            if (temp.compareTo(lowBound) > 0 && isPrime(temp)) { // O(n^4)
                p = temp;
            }
        }
        while (q == null) {
            BigInteger temp = getRandomNumber(half); // O(1)
            if (temp.compareTo(lowBound) > 0 && !temp.equals(p) && isPrime(temp)) { // O(n^4)
                q = temp;
            }
        }
    }

    private BigInteger getTotientEuler() { // O(n^2)
        BigInteger p1 = p.subtract(new BigInteger("1")); // O(n)
        BigInteger q1 = q.subtract(new BigInteger("1")); // O(n)
        return p1.multiply(q1); // O(n^2)
    }

    private void createPublicKey() {
        BigInteger[] tries = new BigInteger[5];
        tries[0] = new BigInteger("65537");
        tries[1] = new BigInteger("257");
        tries[2] = new BigInteger("17");
        tries[3] = new BigInteger("5");
        tries[4] = new BigInteger("3");
        publicKey = new PublicKey();
        publicKey.n = n;
        publicKey.keySize = keySize;
        for (BigInteger e : tries) {
            if (e.compareTo(phi) > 0) {
                continue; // O(n)
            }
            if (Euclid.getMDC(e, phi).equals(new BigInteger("1"))) { // O(n^3)
                publicKey.e = e;
                break;
            }
        }
        if (publicKey.e == null) {
            throw new RuntimeException("Not found public key");
        }
    }

    private void createPrivateKey() { // O(n^3)
        privateKey = new PrivateKey();
        privateKey.n = n;
        privateKey.keySize = keySize;
        privateKey.d = Euclid.getModInv(publicKey.e, phi); // O(n^3)
    }

    private BigInteger getRandomNumber(int bits) {
        Random random = new Random();
        BigInteger n = new BigInteger("2").pow(bits);
        BigInteger result = new BigInteger(bits, random);
        while (result.compareTo(n) >= 0 || result.compareTo(new BigInteger("1")) < 0) {
            result = new BigInteger(bits, random);
        }
        return result;
    }

    public BigInteger getRandomNumber(BigInteger n) {
        Random random = new Random();
        BigInteger result = new BigInteger(n.bitLength(), random);
        while (result.compareTo(n) >= 0 || result.compareTo(new BigInteger("1")) < 0) {
            result = new BigInteger(n.bitLength(), random);
        }
        return result;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
    
    public boolean isPrime(BigInteger n) {
        if (isMod2(n)) { 
            return false;
        } else {
            BigInteger n1 = n.subtract(new BigInteger("1")); 
            int k = 0;
            BigInteger q = n1;
            while (isMod2(q)) { 
                if (q.equals(new BigInteger("0"))) {
                    return false; 
                }
                q = q.divide(new BigInteger("2")); 
                k++; // O(n)
            }
            double times = ln(n) / 2; // O(1)
            for (long j = 0; j < times; j++) { 
                if (!isPrimeMillerRabin(n, k, q)) {
                    return false; // O(n^3)
                }
            }
            return true;
        }
    }

    private boolean isMod2(BigInteger n) {
        return n.mod(new BigInteger("2")).compareTo(new BigInteger("0")) == 0;
    }

    private boolean isPrimeMillerRabin(BigInteger n, int k, BigInteger q) {
        BigInteger a = getRandomNumber(n); 
        // a^q mod n == 1
        if (a.modPow(q, n).compareTo(new BigInteger("1")) == 0) {
            return true; 
        }
        for (int j = 0; j < k; j++) {
            BigInteger mod = a.modPow(new BigInteger("2").pow(j).multiply(q), n);
            if (mod.compareTo(n.subtract(new BigInteger("1"))) == 0) {
                return true; 
            }
        }
        return false;
    }

    public static double ln(BigInteger val) {
        int blex = val.bitLength() - 1022;
        if (blex > 0) {
            val = val.shiftRight(blex);
        }
        double res = Math.log(val.doubleValue());
        return blex > 0 ? res + blex * Math.log(2.0) : res;
    }
}
