package org.caulfield.pkiz.database.definition;

import java.util.Date;

/**
 * @author pbakhtiari
 */
public class EnigmaCRL {

    private Date startdate;
    private Date enddate;
    private Integer idcrl;
    private Integer dayCycle;
    private Integer idcacert;

    /**
     * @return the startdate
     */
    public Date getStartdate() {
        return startdate;
    }

    /**
     * @param startdate the startdate to set
     */
    public void setStartdate(Date startdate) {
        this.startdate = startdate;
    }

    /**
     * @return the enddate
     */
    public Date getEnddate() {
        return enddate;
    }

    /**
     * @param enddate the enddate to set
     */
    public void setEnddate(Date enddate) {
        this.enddate = enddate;
    }

    /**
     * @return the idcrl
     */
    public Integer getIdcrl() {
        return idcrl;
    }

    /**
     * @param idcrl the idcrl to set
     */
    public void setIdcrl(Integer idcrl) {
        this.idcrl = idcrl;
    }

    /**
     * @return the dayCycle
     */
    public Integer getDayCycle() {
        return dayCycle;
    }

    /**
     * @param dayCycle the dayCycle to set
     */
    public void setDayCycle(Integer dayCycle) {
        this.dayCycle = dayCycle;
    }

    /**
     * @return the idcacert
     */
    public Integer getIdcacert() {
        return idcacert;
    }

    /**
     * @param idcacert the idcacert to set
     */
    public void setIdcacert(Integer idcacert) {
        this.idcacert = idcacert;
    }

}
