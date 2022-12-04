package org.caulfield.pkiz.database.definition;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.caulfield.pkiz.init.ObjectsInitializer;
import org.hsqldb.cmdline.SqlFile;
import org.hsqldb.cmdline.SqlToolError;

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
        try (Statement statement = connexion.createStatement()) {
            set = set = statement.executeQuery(query);
        }
        return set;
    }
    
    private boolean baseDoesNotExist() {
        boolean exists = true;
        try {
            ResultSet f = runQuery("select * from ALGO where ID_ALGO = 1");
            if (f.next()) {
                exists = false;
            }
        } catch (SQLException ex) {
            System.out.println("Base " + databaseName + " does not exist : building a fresh one ...");
        }
        return exists;
    }

    private void loadConnection() {
        try {
            Class.forName("org.hsqldb.jdbcDriver").newInstance();
            connexion = DriverManager.getConnection("jdbc:hsqldb:file:" + databaseName, "sa", "");
            if (baseDoesNotExist()) {
                initDatabase();
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void initDatabase() {
        try {
            InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("pkiz.sql");
            if (inputStream == null) {
                System.out.println("org.caulfield.pkiz.database.HSQLLoader.initDatabase() reinstall PKIZ - base corrupted");
            }
            SqlFile sqlFile = new SqlFile(new InputStreamReader(inputStream), "init", System.out, "UTF-8", false, new File("build"));
            sqlFile.setConnection(connexion);
            sqlFile.execute();
            sqlFile.closeReader();
        } catch (IOException | SqlToolError ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(HSQLLoader.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Base already exists !");
        }
        // Create ROOT objects
        ObjectsInitializer.createLocalObjects();
        System.out.println("Build successful !");

    }

}
