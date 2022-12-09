package org.caulfield.pkiz.analyzer.ascii;

import com.google.common.base.CharMatcher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author pbakhtiari
 */
public class ASCIIScanner {

    public static boolean isFileASCII(File file) {
        byte[] encoded = null;
        try {
            encoded = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
            String datas = new String(encoded, Charset.defaultCharset());
            return CharMatcher.ascii().matchesAllOf(datas);
        } catch (IOException ex) {
            Logger.getLogger(ASCIIScanner.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }
}
