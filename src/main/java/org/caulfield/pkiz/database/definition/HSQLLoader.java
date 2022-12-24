package org.caulfield.pkiz.database.definition;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.pkiz.PBE.PBEManager;
import org.caulfield.pkiz.crypto.CryptoGenerator;
import static org.caulfield.pkiz.database.definition.CryptoDAO.sql;
import org.caulfield.pkiz.init.ObjectsInitializer;
import org.hsqldb.cmdline.SqlFile;
import org.hsqldb.cmdline.SqlToolError;
import org.openide.util.Exceptions;

/**
 * @author pbakhtiari
 */
public class HSQLLoader {

    private Connection connexion;
    private final String databaseName = "pkiz-database";

    public HSQLLoader() {
        loadConnection();
    }

    public Connection getConnection() {
        return connexion;
    }

    public void closeConnexion() {
        try {
            connexion.close();
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public int runUpdate(String update) throws SQLException {
        if (connexion == null) {
            loadConnection();
        }
        Statement statement = connexion.createStatement();
        int set = statement.executeUpdate(update);
        statement.close();
        return set;
    }

    public ResultSet runQuery(String query) throws SQLException {
        if (connexion == null) {
            loadConnection();
        }
        ResultSet set;
        try ( Statement statement = connexion.createStatement()) {
            set = statement.executeQuery(query);
        }
        return set;
    }

    public boolean baseInitializedAndPasswordDefined() {
        if (connexion == null) {
            loadConnection();
        }
        boolean exists = false;
        try {
            ResultSet f = runQuery("select PASSWORD,SALT from MASTER_PASSWORD");
            if (f.next()) {
                exists = true;
                PBEManager.setEncryptedPassword(f.getString("PASSWORD"));
                PBEManager.setSalt(f.getString("SALT"));
            }
        } catch (SQLException ex) {

        }
        return exists;
    }

    private void loadConnection() {
        try {
            Class.forName("org.hsqldb.jdbcDriver").getDeclaredConstructor().newInstance();
            connexion = DriverManager.getConnection("jdbc:hsqldb:file:" + databaseName, "sa", "");
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | SQLException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private long insertTestPassword(String password, String salt) {
        try {
            PreparedStatement pst = getConnection().prepareStatement("INSERT INTO MASTER_PASSWORD (ID,PASSWORD,SALT,CREATION_DATE) VALUES (NEXT VALUE FOR MASTER_PASSWORD_SEQ,?,?,?)", new String[]{"ID"});
            pst.setString(1, password);
            pst.setString(2, salt);
            pst.setDate(3, new java.sql.Date(new Date().getTime()));
            pst.executeUpdate();
            ResultSet rs = pst.getGeneratedKeys();
            if (rs.next()) {
                return rs.getLong(1);
            }
            pst.close();
            return 0;
        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return 0;
        }
    }

    public String[] getSaltAndPassword() {
        String[] in = new String[2];
        try {
            //System.out.println("SELECT SALT,PASSWORD FROM MASTER_PASSWORD");
            ResultSet ff = runQuery("SELECT SALT,PASSWORD FROM MASTER_PASSWORD");
            if (ff.next()) {
                in[0] = ff.getString("SALT");
                PBEManager.setSalt(in[0]);
                in[1] = ff.getString("PASSWORD");
                PBEManager.setEncryptedPassword(in[1]);
            }
            //  System.out.println("org.caulfield.pkiz.crypto.CryptoGenerator.getKeyPasswordFromDB() RETRIEVED " + in[0] + " " + in[1]);

        } catch (SQLException ex) {
            Logger.getLogger(CryptoGenerator.class.getName()).log(Level.SEVERE, null, ex);

        }
        return in;
    }

    public void initDatabase(String password, String salt) {
        try {
            Class.forName("org.hsqldb.jdbcDriver").getDeclaredConstructor().newInstance();
            connexion = DriverManager.getConnection("jdbc:hsqldb:file:" + databaseName, "sa", "");
            InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("pkiz.sql");
            if (inputStream == null) {
                System.out.println("org.caulfield.pkiz.database.HSQLLoader.initDatabase() reinstall PKIZ - base corrupted");
            }
            SqlFile sqlFile = new SqlFile(new InputStreamReader(inputStream), "init", System.out, "UTF-8", false, new File("build"));
            sqlFile.setConnection(connexion);
            sqlFile.execute();
            sqlFile.closeReader();
            // Add the master password
            PBEManager.setSalt(salt);
            PBEManager.setEncryptedPassword(password);
            insertTestPassword(password, salt);
        } catch (IOException | SqlToolError | SQLException | NoSuchMethodException | SecurityException | ClassNotFoundException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Base already exists !");
        }
        // Create ROOT objects
        ObjectsInitializer.createGeneratedDir();
        ObjectsInitializer.createLocalObjects();
        System.out.println("Build successful !");
    }
}
