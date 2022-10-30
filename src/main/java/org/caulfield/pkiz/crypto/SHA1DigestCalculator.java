/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.pkiz.crypto;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.operator.DigestCalculator;

/**
 *
 * @author Ender
 */
public class SHA1DigestCalculator
        implements DigestCalculator {

    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
    }

    public OutputStream getOutputStream() {
        return bOut;
    }

    public byte[] getDigest() {
        byte[] bytes = bOut.toByteArray();

        bOut.reset();

        Digest sha1 = new SHA1Digest();

        sha1.update(bytes, 0, bytes.length);

        byte[] digest = new byte[sha1.getDigestSize()];

        sha1.doFinal(digest, 0);

        return digest;
    }
}