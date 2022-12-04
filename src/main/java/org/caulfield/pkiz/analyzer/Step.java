package org.caulfield.pkiz.analyzer;

import java.io.File;

/**
 * @author pbakhtiari
 */
class Step<T> {

    private Class clazz;
    private Object obj;
    private File param;
    private String method;

    public Step(Class clazz, Object obj, File param, String method) {
        this.clazz = clazz;
        this.obj = obj;
        this.param = param;
        this.method = method;
    }

    public File getParam() {
        return param;
    }

    public Object getObj() {
        return obj;
    }

    public String getMethod() {
        return method;
    }

    public Class getClazz() {
        return clazz;
    }

}
