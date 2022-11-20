package org.caulfield.pkiz.crypto.x509;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.caulfield.pkiz.crypto.SHA1DigestCalculator;
import org.caulfield.pkiz.crypto.hash.HashCalculator;
import org.caulfield.pkiz.database.definition.CryptoDAO;
import org.caulfield.pkiz.database.definition.EnigmaCertificate;

/**
 * Example of how to set up a certificiate chain and a PKCS 12 store for a
 * private individual - obviously you'll need to generate your own keys, and you
 * may need to add a NetscapeCertType extension or add a key usage extension
 * depending on your application, but you should get the idea! As always this is
 * just an example...
 */
public class PKCS12Builder {

    static char[] passwd = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

//    public static KeyStore createKeyStore()
//            throws Exception {
//        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
//
//        // initialize
//        store.load(null, null);
//
//        X500PrivateCredential rootCredential = Utils.createRootCredential();
//        X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
//        X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
//
//        Certificate[] chain = new Certificate[3];
//
//        chain[0] = endCredential.getCertificate();
//        chain[1] = interCredential.getCertificate();
//        chain[2] = rootCredential.getCertificate();
//
//        // set the entries
//        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
//        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), null, chain);
//
//        return store;
//    }
//    public static KeyStore makeKeystore(String password)
//            throws Exception {
//        KeyStore store = createKeyStore();
//        char[] passwrd = password.toCharArray();
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//        store.store(bOut, passwrd);
//        store = KeyStore.getInstance("PKCS12", "BC");
//        store.load(new ByteArrayInputStream(bOut.toByteArray()), passwrd);
//        return store;
////        Enumeration en = store.aliases();
////        while (en.hasMoreElements())
////        {
////            String alias = (String)en.nextElement();
////            System.out.println("found " + alias + ", isCertificate? " + store.isCertificateEntry(alias));
////        }
//    }
    /**
     * we generate the CA's certificate
     */
    public static X509CertificateHolder createMasterCert(PublicKey pubKey, PrivateKey privKey, String subject, String alias, String algo) throws Exception {
        String issuer = subject;
        //
        // create the certificate - version 1
        //
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), new X500Name(subject), subPubKeyInfo);

        AsymmetricKeyParameter pa = PrivateKeyFactory.createKey(privKey.getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algo);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(pa);

        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, subPubKeyInfo);
        v3CertGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign); //| KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment 
        v3CertGen.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        v3CertGen.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

        //
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        //
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("ROOT"));

        return certificateHolder;
    }

    /**
     * we generate an intermediate certificate signed by our CA
     */
    public static X509CertificateHolder createIntermediateCert(PublicKey pubKey, PrivateKey caPrivKey, X509CertificateHolder caCert, String subject, String algo) throws Exception {
        //
        // subject name table.
        //
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

        // GET ACSERIALCURSOR for this caCert in Database (start at 0)
        HashCalculator hc = new HashCalculator();
        String thumbPrint = hc.getThumbprint(caCert.getEncoded());
        EnigmaCertificate caEnigCert = CryptoDAO.getEnigmaCertFromDB(thumbPrint);
        BigInteger nextSerial = caEnigCert.getAcserialcursor();
        // INCREMENT ACSERIALCURSOR for this caCert in Database
//        CryptoDAO.updateACSerialCursorAndDate(thumbPrint,nextSerial);
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(caCert.getSubject(), nextSerial, new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), new X500Name(subject), subPubKeyInfo);

        AsymmetricKeyParameter pa = PrivateKeyFactory.createKey(caPrivKey.getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algo);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(pa);

        //
        // extensions
        // https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.cert.X509v3CertificateBuilder
        //
        X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

        v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPubKeyInfo))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        X509Certificate caccert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caCert);
        cert.checkValidity(new Date());
        cert.verify(caccert.getPublicKey());
//
//        final JcaPEMWriter publicPemWriter = new JcaPEMWriter(new FileWriter(new File("test.crt")));
//        publicPemWriter.writeObject(certificateHolder);
//        publicPemWriter.flush();
//        publicPemWriter.close();

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

        //
        // this is actually optional - but if you want to have control
        // over setting the friendly name this is the way to do it...
        //
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("SUB"));

        return certificateHolder;
    }

    /**
     * we generate a certificate signed by our CA's intermediate certficate
     */
    public static X509CertificateHolder createCert(PublicKey pubKey, PrivateKey caPrivKey, PublicKey caPubKey, X509CertificateHolder caCert, String subject, String algo) throws Exception {

        //
        // create the certificate - version 3
        //
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

        // GET ACSERIALCURSOR for this caCert in Database (start at 0)
        HashCalculator hc = new HashCalculator();
        String thumbPrint = hc.getThumbprint(caCert.getEncoded());
        EnigmaCertificate caEnigCert = CryptoDAO.getEnigmaCertFromDB(thumbPrint);
        BigInteger nextSerial = caEnigCert.getAcserialcursor();
        // INCREMENT ACSERIALCURSOR for this caCert in Database
//        CryptoDAO.updateACSerialCursorAndDate(thumbPrint,nextSerial);
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(caCert.getSubject(), nextSerial, new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)), new X500Name(subject), subPubKeyInfo);

        //
        // add the extensions
        //
        X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

        v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subPubKeyInfo))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation | KeyUsage.dataEncipherment | KeyUsage.keyAgreement))
                .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, subject)));
//                v3Bldr.addExtension(
//                Extension.authorityKeyIdentifier,
//                false,
//                extUtils.createAuthorityKeyIdentifier(caPubKey));
        AsymmetricKeyParameter pa = PrivateKeyFactory.createKey(caPrivKey.getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algo);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(pa);

        X509CertificateHolder certificateHolder = v3CertGen.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        cert.checkValidity(new Date());
        cert.verify(caPubKey);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

        //
        // this is also optional - in the sense that if you leave this
        // out the keystore will add it automatically, note though that
        // for the browser to recognise the associated private key this
        // you should at least use the pkcs_9_localKeyId OID and set it
        // to the same as you do for the private key's localKeyId.
        //
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Master Key"));
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new SubjectKeyIdentifier(pubKey.getEncoded()));

        return certificateHolder;
    }
}
