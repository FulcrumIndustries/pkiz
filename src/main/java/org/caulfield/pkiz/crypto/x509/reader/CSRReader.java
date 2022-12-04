package org.caulfield.pkiz.crypto.x509.reader;

import org.caulfield.pkiz.crypto.x509.reader.PublicKeyReader;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;
import jakarta.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * @author pbakhtiari
 */
public class CSRReader {

    // Private key file using PKCS #8 encoding
    public static final String P10_BEGIN_MARKER
            = "-----BEGIN CERTIFICATE REQUEST"; //$NON-NLS-1$
    public static final String P10_END_MARKER
            = "-----END CERTIFICATE REQUEST"; //$NON-NLS-1$
    public static final String P10_BEGIN_ALTERNATE_MARKER
            = "-----BEGIN X509 CRL"; //$NON-NLS-1$
    public static final String P10_END_ALTERNATE_MARKER
            = "-----END X509 CRL"; //$NON-NLS-1$
    protected final String fileName;

    /**
     * Create a PEM private key file reader.
     *
     * @param fileName The name of the PEM file
     */
    public CSRReader(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Get a Private Key for the file.
     *
     * @return Private key
     * @throws IOException
     */
    public String getCSR() {
//        String output = null;
//        PKCS10CertificationRequest csr = null;
        FileInputStream fis = null;

        File f = new File(fileName);
        try {
            fis = new FileInputStream(f);

            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith(P10_BEGIN_MARKER) || line.startsWith(P10_BEGIN_ALTERNATE_MARKER)) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith(P10_END_MARKER) || line.startsWith(P10_END_ALTERNATE_MARKER)) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }

            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            JcaPKCS10CertificationRequest p10Object = new JcaPKCS10CertificationRequest(encoded);

            System.out.println("org.caulfield.pkiz.crypto.x509.CSRReader.getCSR()" + p10Object.getSubject());
            return "Certificate signing request detected.";

        } catch (IOException | NullPointerException ex) {

            // Try the binary route ?
            Logger.getLogger(PublicKeyReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a certificate signing request";
        }
    }

    private String convertPemToPKCS10CertificationRequest() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String s = "";
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Files.readAllBytes(Paths.get(fileName)));
            s = csr.getSubject().toString();
//            ByteArrayInputStream pemStream = null;
            //          pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
            //        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
            //      PEMParser pemParser = new PEMParser(pemReader);
            //    Object parsedObj = pemParser.readObject();
            //  System.out.println("PemParser returned: " + parsedObj);
            //if (parsedObj instanceof PKCS10CertificationRequest) {
            //  csr = (PKCS10CertificationRequest) parsedObj;
            // }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CSRReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a certificate signing request";
        } catch (IOException ex) {
            Logger.getLogger(CSRReader.class.getName()).log(Level.SEVERE, null, ex);
            return "Not a certificate signing request";
        }

        return "Certificate signing request detected " + s;
    }
    private static final String COUNTRY = "2.5.4.6";
    private static final String STATE = "2.5.4.8";
    private static final String LOCALE = "2.5.4.7";
    private static final String ORGANIZATION = "2.5.4.10";
    private static final String ORGANIZATION_UNIT = "2.5.4.11";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final String EMAIL = "2.5.4.9";

    public String readCertificateSigningRequest(X500Name x500Name) {

        StringBuilder compname = new StringBuilder();
        System.out.println("x500Name is: " + x500Name + "\n");

        RDN cn = x500Name.getRDNs(BCStyle.EmailAddress)[0];
        compname.append(cn.getFirst().getValue().toString()).append("\n");
        if (x500Name.getRDNs(BCStyle.EmailAddress).length > 0) {
            compname.append(x500Name.getRDNs(BCStyle.EmailAddress)[0]).append("\n");
        }
        compname.append("COUNTRY: ").append(getX500Field(COUNTRY, x500Name)).append("\n");
        compname.append("STATE: " + getX500Field(STATE, x500Name)).append("\n");
        compname.append("LOCALE: " + getX500Field(LOCALE, x500Name)).append("\n");
        compname.append("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name)).append("\n");
        compname.append("ORGANIZATION_UNIT: " + getX500Field(ORGANIZATION_UNIT, x500Name)).append("\n");
        compname.append("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name)).append("\n");
        compname.append("EMAIL: " + getX500Field(EMAIL, x500Name)).append("\n");

        return compname.toString();
    }

    private String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));

        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;
    }

}
