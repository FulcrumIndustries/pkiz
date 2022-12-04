package com.fulcrumindustries.pkiz.bruteforce;

import java.math.BigInteger;

/**
 * @author pbakhtiari
 */
public class Euclid {

    /**
     * Algorithm: (Euclidean algorithm) Computing the greatest common divisor of
     * two integers. [4]
     */
    public static BigInteger getMDC(BigInteger a, BigInteger b) { // O(n^3) [6]
        if (a.compareTo(b) < 0) {
            BigInteger aux = b;
            b = a;
            a = aux;
        }
        while (b.compareTo(new BigInteger("0")) > 0) {
            BigInteger r = a.mod(b);
            a = b;
            b = r;
        }
        return a;
    }

    /**
     * Modular inverse [5].
     */
    public static BigInteger getModInv(BigInteger x, BigInteger N) {
        if (x.compareTo(N) > 0) {
            BigInteger aux = N;
            N = x;
            x = aux;
        }
        BigInteger a = N;
        BigInteger b = x;
        BigInteger p2 = new BigInteger("0");
        BigInteger p1 = new BigInteger("1");
        BigInteger q;
        BigInteger p;
        while (b.compareTo(new BigInteger("0")) > 0) { // O(n^3) [6]
            BigInteger r = a.mod(b);
            if (r.compareTo(new BigInteger("0")) > 0) {
                q = a.divide(b);
                p = p2.subtract(p1.multiply(q)).mod(N);
                p2 = p1;
                p1 = p;
            }
            a = b;
            b = r;
        }
        return p1;
    }

}
