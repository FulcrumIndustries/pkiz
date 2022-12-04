package org.caulfield.pkiz.database.definition;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * @author pbakhtiari
 */
public class EnigmaKey {
    //CREATE TABLE X509KEYS (ID_KEY INTEGER PRIMARY KEY,	KEYNAME VARCHAR(200), KEYTYPE INTEGER,KEYFILE BLOB, ALGO VARCHAR(64), SHA256  VARCHAR(256),ID_ASSOCIATED_KEY INTEGER, PASSWORD  VARCHAR(64));

    private int id;
    private PrivateKey pk;
    private PublicKey pubk;
    private String password;
    private String name;
    private int type;
    private String algo;
    private String sha256;
    private int id_associated_key;
    private InputStream keyStream;
    private PemObject pemObject;

    public EnigmaKey() {

    }

    public EnigmaKey(PrivateKey pk, PublicKey pubk, String password) {
        this.password = password;
        this.pubk = pubk;
        this.pk = pk;
    }

    /**
     * @return the pk
     */
    public PrivateKey getPk() {
        return pk;
    }

    /**
     * @param pk the pk to set
     */
    public void setPk(PrivateKey pk) {
        this.pk = pk;
    }

    /**
     * @return the pubk
     */
    public PublicKey getPubk() {
        return pubk;
    }

    /**
     * @param pubk the pubk to set
     */
    public void setPubk(PublicKey pubk) {
        this.pubk = pubk;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the type
     */
    public int getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(int type) {
        this.type = type;
    }

    /**
     * @return the algo
     */
    public String getAlgo() {
        return algo;
    }

    /**
     * @param algo the algo to set
     */
    public void setAlgo(String algo) {
        this.algo = algo;
    }

    /**
     * @return the sha256
     */
    public String getSha256() {
        return sha256;
    }

    /**
     * @param sha256 the sha256 to set
     */
    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    /**
     * @return the id_associated_key
     */
    public int getId_associated_key() {
        return id_associated_key;
    }

    /**
     * @param id_associated_key the id_associated_key to set
     */
    public void setId_associated_key(int id_associated_key) {
        this.id_associated_key = id_associated_key;
    }

    /**
     * @return the keyStream
     */
    public InputStream getKeyStream() {
        return keyStream;
    }

    /**
     * @param keyStream the keyStream to set
     */
    public void setKeyStream(InputStream keyStream) {
        this.keyStream = keyStream;
    }

    /**
     * @return the id
     */
    public int getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(int id) {
        this.id = id;
    }

    /**
     * @return the pemObject
     */
    public PemObject getPemObject() {
        return pemObject;
    }

    /**
     * @param pemObject the pemObject to set
     */
    public void setPemObject(PemObject pemObject) {
        this.pemObject = pemObject;
    }

}
