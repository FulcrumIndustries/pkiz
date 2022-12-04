package com.fulcrumindustries.pkiz.bruteforce;

import java.math.BigInteger;

/**
 * @author pbakhtiari
 */
public class PollardForce {

    public static String solve(PublicKey publicKey, String crypt) {
        BigInteger p = factorize(publicKey.n);
        BigInteger q = publicKey.n.divide(p);
        BigInteger phi = getTotientEuler(p, q);
        PrivateKey privateKey = new PrivateKey();
        privateKey.n = publicKey.n;
        privateKey.d = Euclid.getModInv(publicKey.e, phi);
        return privateKey.decrypt(crypt);
    }

    private static BigInteger getTotientEuler(BigInteger p, BigInteger q) {
        return p.subtract(new BigInteger("1")).multiply(q.subtract(new BigInteger("1")));
    }

    /**
     * Pollard factorization 
     */
    public static BigInteger factorize(BigInteger n) { // O(sqrt(p)), p sendo o fator primo de n [9]

        // From Cormen
        BigInteger i = BigInteger.ONE;
        BigInteger xi = new RSA().getRandomNumber(n.subtract(i));
        BigInteger y = xi; 
        BigInteger k = new BigInteger("2");
        BigInteger d = null;
        boolean cont = true;
        while (cont) { 
            i = i.add(BigInteger.ONE);
            xi = xi.pow(2).subtract(BigInteger.ONE).mod(n);
            d = gcd(y.subtract(xi), n);
            if (d.compareTo(BigInteger.ONE) != 0 && d.compareTo(n) != 0) {
                cont = false;
            }
            if (i.compareTo(k) == 0) {
                y = xi;
                k = k.multiply(new BigInteger("2"));
            }
        }
        return d;
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        BigInteger remainder;
        while (b.compareTo(new BigInteger("0")) != 0) {
            remainder = a.mod(b);
            a = b;
            b = remainder;
        }
        return a;
    }

}
