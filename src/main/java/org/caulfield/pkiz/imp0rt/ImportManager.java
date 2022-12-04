package org.caulfield.pkiz.imp0rt;

import java.io.File;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.pkiz.crypto.CryptoGenerator;
import org.caulfield.pkiz.crypto.hash.HashCalculator;
import org.caulfield.pkiz.database.definition.CryptoDAO;

/**
 * @author pbakhtiari
 */
public class ImportManager {

    public String importCertificate(File cert) {
        try {
            CryptoGenerator cg = new CryptoGenerator();

            X509Certificate certX = cg.getCertificate(cert);
            byte[] cc = certX.getEncoded();
            String algo = certX.getSigAlgName();
            HashCalculator hashc = new HashCalculator();
            String realHash = hashc.getStringChecksum(cert, HashCalculator.SHA256);
            String thumbPrint = hashc.getThumbprint(certX);
            String CN = certX.getSubjectX500Principal().getName();
            String certName = CN.replace("CN=", "");
            if (CN.contains(",")) {
                certName = certName.substring(0, certName.indexOf(","));
            }

            // DAO Write it
            CryptoDAO.insertCertInDB(cert, certName, CN, realHash, algo, 0, thumbPrint, 1, certX.getNotAfter(), certX.getSerialNumber(), BigInteger.ZERO, null);
            return "Certificate imported successfully as " + certName;

        } catch (CertificateEncodingException | NoSuchAlgorithmException ex) {
            Logger.getLogger(ImportManager.class.getName()).log(Level.SEVERE, null, ex);
            return "Certificate export failed.";
        }
    }

//    public String importKey(File key) {
//        try {
//
//            byte[] buffer = new byte[is.available()];
//            is.read(buffer);
//
//            OutputStream outStream = new FileOutputStream(targetFile);
//            outStream.write(buffer);
//            outStream.flush();
//            outStream.close();
//            return "Key exported successfully as " + targetFile;
//        } catch (IOException ex) {
//            Logger.getLogger(ImportManager.class.getName()).log(Level.SEVERE, null, ex);
//            return "Key export failed.";
//        }
//    }
}
