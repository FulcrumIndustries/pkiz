package org.caulfield.pkiz.crypto;

/**
 * @author pbakhtiari
 */
public class EnigmaException extends Exception {

    private String msg;

    public EnigmaException(String msg) {
        this.msg = msg;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

}
