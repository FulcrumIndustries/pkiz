package org.caulfield.pkiz;

import com.formdev.flatlaf.FlatLightLaf;
import com.fulcrumindustries.pkiz.bruteforce.RSABreaker;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.Point;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.tree.AbstractLayoutCache;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.caulfield.pkiz.analyzer.FileAnalyzer;
import org.caulfield.pkiz.crypto.CertType;
import org.caulfield.pkiz.crypto.CryptoGenerator;
import org.caulfield.pkiz.crypto.EnigmaException;
import org.caulfield.pkiz.crypto.x509.CRLManager;
import org.caulfield.pkiz.crypto.x509.CertificateChainBuilder;
import org.caulfield.pkiz.crypto.x509.CertificateChainManager;
import org.caulfield.pkiz.database.definition.CryptoDAO;
import org.caulfield.pkiz.database.definition.EnigmaCRL;
import org.caulfield.pkiz.database.definition.EnigmaCertificate;
import org.caulfield.pkiz.database.definition.HSQLLoader;
import org.caulfield.pkiz.export.ExportManager;
import org.caulfield.pkiz.imp0rt.ImportManager;
import org.netbeans.swing.outline.DefaultOutlineModel;
import org.netbeans.swing.outline.Outline;
import org.netbeans.swing.outline.OutlineModel;

/**
 * @author pbakhtiari
 */
public class PKIZ extends javax.swing.JFrame {

    String propFile = "PKIZ.properties";
    Properties props = new Properties();
    int posX = 0, posY = 0;

    /**
     * Creates new form AAAA
     */
    public PKIZ() {
        this.getRootPane().setBorder(BorderFactory.createMatteBorder(4, 4, 4, 4, Color.LIGHT_GRAY));

        addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                posX = e.getX();
                posY = e.getY();
            }
        });
        addMouseMotionListener(new MouseAdapter() {
            public void mouseDragged(MouseEvent evt) {
                //sets frame position when mouse dragged			
                setLocation(evt.getXOnScreen() - posX, evt.getYOnScreen() - posY);

            }
        });
        initComponents();
        Security.addProvider(new BouncyCastleProvider());
        jTextFieldCountry.setDocument(new JTextFieldLimit(2));
        jLabelLoading.setVisible(false);
        this.setTitle("PKIZ - 1.00a");
        try ( InputStream resourceStream = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(propFile)) {
            props.load(resourceStream);
        } catch (IOException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
        jSpinnerKeySize.setValue(Integer.valueOf(props.getProperty("defaultKeySize")));
        jTextAreaDrop.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable()
                            .getTransferData(DataFlavor.javaFileListFlavor);
                    for (File file : droppedFiles) {
                        jTextFieldDrop.setText(file.getAbsolutePath());
                        jTextAreaDrop.setText(file.getAbsolutePath() + " loaded.");
                        FileAnalyzer analyzer = new FileAnalyzer(jTextFieldDrop.getText());
                        for (String dd : analyzer.getResults()) {
                            jEditorPaneIdentifierResults.setText(jEditorPaneIdentifierResults.getText() + dd + "\n");
                        }
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                }

            }
        });
        CertificateChainManager acm = new CertificateChainManager();
        for (String AC : acm.getFullCertList()) {
            jComboBoxSignSignerCert.addItem(AC);
        }

        jTextFieldGlobalOutput.setText(System.getProperty("user.dir") + "\\generated\\");

        jComboBoxAC.addItem("None");
        for (String AC : acm.getFullACList()) {
            jComboBoxAC.addItem(AC);
        }
        jTextFieldSignFile.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
            }

        });

        jTextFieldCipherFile.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
            }

        });

        jTextFieldDecryptFile.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldDecryptOutputFilename.setText(getFileName(jTextFieldDecryptFile.getText()) + ".dec");
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldDecryptOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".dec");
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent de) {
                jTextFieldDecryptOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".dec");
            }

        });
        ButtonGroup bG = new ButtonGroup();
        bG.add(jRadioButtonDER);
        bG.add(jRadioButtonPEM);
        bG.add(jRadioButtonPEMorDER);
        jRadioButtonPEM.setSelected(true);
        jButtonConvertPEM.setEnabled(false);
        refreshCertificateCombos();
        fillCertificateVersionObjects();
        fillAlgoObjects();
        refreshX509KeyTable();
        refreshPKObjects();
        refreshPubKObjects();
        refreshX509CertOutline();
        buildPopupMenuX509();

        outline.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

    }

    private void fillCertificateVersionObjects() {
        jComboBoxCertVersion.addItem("V1");
        jComboBoxCertVersion.addItem("V3");
        jComboBoxCertVersion.setSelectedIndex(1);
    }

    private void refreshCertificateCombos() {
        // Fill SIGNATURE Algo combobox
        try {
            jComboBoxSignSignerCert.removeAllItems();
            jComboBoxCipherCert.removeAllItems();
            jComboBoxWParents.removeAllItems();
            jComboBoxPKCS12MakerCert.removeAllItems();
            HSQLLoader database = new HSQLLoader();
            ResultSet f = database.runQuery("select ID_CERT, CERTNAME from CERTIFICATES");
            while (f.next()) {
                jComboBoxSignSignerCert.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
                jComboBoxCipherCert.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
                jComboBoxWParents.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
                jComboBoxPKCS12MakerCert.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
            }
        } catch (SQLException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void fillAlgoObjects() {
        // Fill SIGNATURE Algo combobox
        try {
            HSQLLoader database = new HSQLLoader();
            ResultSet f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='SIGNATURE'");
            while (f.next()) {
                jComboBoxAlgoSign.addItem(f.getString("ALGONAME"));
                jComboBoxCertAlgo.addItem(f.getString("ALGONAME"));
                jComboBoxAlgoP12.addItem(f.getString("ALGONAME"));
            }
            jComboBoxAlgoSign.setSelectedIndex(5);
            jComboBoxCertAlgo.setSelectedIndex(5);
            jComboBoxAlgoP12.setSelectedIndex(5);

            f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='PKCS8'");
            while (f.next()) {
                jComboBoxAlgoPk.addItem(f.getString("ALGONAME"));
            }
            jComboBoxAlgoPk.setSelectedIndex(0);

            f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='CIPHER'");
            while (f.next()) {
                jComboBoxAlgoCipher.addItem(f.getString("ALGONAME"));
            }
            jComboBoxAlgoCipher.setSelectedIndex(0);
        } catch (SQLException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private void buildPopupMenuX509Keys() {
        final JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem exportKeyPEM = new JMenuItem("> Export Key as PEM");
        exportKeyPEM.addActionListener((ActionEvent e) -> {
            Integer idKey = (Integer) jTablePK.getModel().getValueAt(jTablePK.getSelectedRow(), 1);
            FileFilter ft = new FileNameExtensionFilter("Key file (.key)", "key");
            jFileChooserExportCert.resetChoosableFileFilters();
            jFileChooserExportCert.setFileFilter(ft);
            int ret = jFileChooserExportCert.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File targetCert = jFileChooserExportCert.getSelectedFile();
                String targetFull = targetCert.getAbsolutePath();
                ExportManager xm = new ExportManager();
                if (!targetFull.endsWith(".key")) {
                    targetFull = targetFull + ".key";
                }
                String outRet = xm.exportKey(idKey, targetFull);
                ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            }
        });
        popupMenu.add(exportKeyPEM);
        jTablePK.setComponentPopupMenu(popupMenu);
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = jTablePK
                            .rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), jTablePK));
                    if (rowAtPoint > -1) {
                        jTablePK.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }
        });
    }

    private void buildPopupMenuX509() {
        final JPopupMenu popupMenu = new JPopupMenu();
//        JMenuItem rootCert = new JMenuItem("+ Create New Root Certificate");
//        rootCert.addActionListener((ActionEvent e) -> {
//            System.out.println(".actionPerformed() CREATE ROOT");
//                    jTabbedPaneGenerate.setSelectedIndex(0);
//        jTabbedPaneScreens.setSelectedIndex(1);
//        
//        });
//        popupMenu.add(rootCert);
        JMenuItem subCert = new JMenuItem("+ Create New Sub Certificate");
        subCert.addActionListener((ActionEvent e) -> {
            Integer idCert = (int) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            CertificateChainManager cm = new CertificateChainManager();
            long idGeneratedCert = cm.buildIntermediateCertificate(idCert, "CN=SUBTEST,O=SUB", "");
            Integer fff = (int) (long) idGeneratedCert;
            EnigmaCertificate ddd = CryptoDAO.getEnigmaCertFromDB(fff,
                    ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)));
            ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)).getChilds().add(ddd);
            ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
                    .setAcserialcursor(((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
                            .getAcserialcursor().add(BigInteger.ONE));
            final AbstractLayoutCache layout = outline.getOutlineModel().getLayout();
            TreePath path = layout.getPathForRow(outline.getSelectedRow());

//  outline.collapsePath(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))));
//  outline.getOutlineModel().getLayout().setExpandedState(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))), false);
//  outline.getOutlineModel().getLayout().setExpandedState(path, false);
//  outline.getOutlineModel().getTreePathSupport().collapsePath(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))));
//   outline.getOutlineModel().getTreePathSupport().clear();
            outline.collapsePath(path);
            outline.expandPath(path);
//  outline.getOutlineModel().getTreePathSupport().collapsePath(path);
//  outline.getOutlineModel().getLayout().setExpandedState(path, true);
            refreshX509KeyTable();
            refreshPKObjects();
            refreshPubKObjects();
            ((DefaultListModel) jListEvents.getModel())
                    .addElement("Certificate " + idGeneratedCert + " successfully generated.");
        });
        popupMenu.add(subCert);
        JMenuItem userCert = new JMenuItem("+ Create New User Certificate");
        userCert.addActionListener((ActionEvent e) -> {
            Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            CertificateChainManager cm = new CertificateChainManager();
            long idGeneratedCert = cm.buildUserCertificate(idCert, "CN=USERTEST,O=USER", "");
            Integer fff = (int) (long) idGeneratedCert;
            EnigmaCertificate ddd = CryptoDAO.getEnigmaCertFromDB(fff,
                    ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)));
            ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)).getChilds().add(ddd);
            ((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
                    .setAcserialcursor(((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
                            .getAcserialcursor().add(BigInteger.ONE));
            final AbstractLayoutCache layout = outline.getOutlineModel().getLayout();
            TreePath path = layout.getPathForRow(outline.getSelectedRow());
            outline.collapsePath(path);
            outline.expandPath(path);
            refreshX509KeyTable();
            refreshPKObjects();
            refreshPubKObjects();
            refreshCertificateCombos();
            ((DefaultListModel) jListEvents.getModel())
                    .addElement("Certificate " + idGeneratedCert + " successfully generated.");
        });
        popupMenu.add(userCert);
        JMenuItem importCert = new JMenuItem("+ Import Certificate");
        importCert.addActionListener((ActionEvent e) -> {
            FileFilter ft = new FileNameExtensionFilter("Certificate file (.crt, .p7b, .cer, .der)", "crt", "p7b",
                    "cert", "der");
            jFileChooserExportCert.resetChoosableFileFilters();
            jFileChooserExportCert.setFileFilter(ft);
            int ret = jFileChooserExportCert.showOpenDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File targetCert = jFileChooserExportCert.getSelectedFile();
                ImportManager xm = new ImportManager();
                String outRet = xm.importCertificate(targetCert);
                // TODO : ADD A FIND PARENT AND PRIVATE KEY AUTOMATICALLY ROUTINE
                refreshX509CertOutline();
                refreshCertificateCombos();
                ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            }
        });
        popupMenu.add(importCert);
        JMenuItem exportCertPEM = new JMenuItem("> Export PEM");
        exportCertPEM.addActionListener((ActionEvent e) -> {
            Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            FileFilter ft = new FileNameExtensionFilter("Certificate file (.crt, .cer)", "crt", "cer");
            jFileChooserExportCert.resetChoosableFileFilters();
            jFileChooserExportCert.setFileFilter(ft);
            int ret = jFileChooserExportCert.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File targetCert = jFileChooserExportCert.getSelectedFile();
                String targetFull = targetCert.getAbsolutePath();
                ExportManager xm = new ExportManager();
                if (!targetFull.endsWith(".crt")) {
                    targetFull = targetFull + ".crt";
                }
                String outRet = xm.exportCertificate(idCert, targetFull);
                ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            }
        });
        popupMenu.add(exportCertPEM);
        JMenuItem exportCertDER = new JMenuItem("> Export DER");
        exportCertDER.addActionListener((ActionEvent e) -> {
            Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            FileFilter ft = new FileNameExtensionFilter("Certificate file (.cer, .der, .crt)", "cer", "der", "crt");
            jFileChooserExportCert.resetChoosableFileFilters();
            jFileChooserExportCert.setFileFilter(ft);
            int ret = jFileChooserExportCert.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File targetCert = jFileChooserExportCert.getSelectedFile();
                String targetFull = targetCert.getAbsolutePath();
                ExportManager xm = new ExportManager();
                if (!targetFull.endsWith(".cer")) {
                    targetFull = targetFull + ".cer";
                }
                String outRet = xm.exportCertificateAsDER(idCert, targetFull);
                ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            }
        });
        popupMenu.add(exportCertDER);
        JMenuItem revokeItem = new JMenuItem("/!\\ Revoke in parent CRL");
        revokeItem.addActionListener((ActionEvent e) -> {
            Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            CRLManager crlm = new CRLManager();
            String outRet = crlm.revokeCert(idCert, "");
            ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            refreshX509CertOutline();
        });
        popupMenu.add(revokeItem);
        JMenuItem deleteItem = new JMenuItem("- Delete");
        deleteItem.addActionListener((ActionEvent e) -> {
            Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
            String outRet = CryptoDAO.deleteCertFromDB(idCert);
            ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            refreshX509CertOutline();
        });
        popupMenu.add(deleteItem);
        outline.setComponentPopupMenu(popupMenu);
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = outline
                            .rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), outline));
                    if (rowAtPoint > -1) {
                        outline.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }
        });
    }

    private void buildPopupMenuX509CRL() {
        final JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem exportCRL = new JMenuItem("> Export CRL");
        exportCRL.addActionListener((ActionEvent e) -> {
            Integer idCrl = (int) jTableCRL.getModel().getValueAt(jTableCRL.getSelectedRow(), 0);
            FileFilter ft = new FileNameExtensionFilter("CRL file (.crl)", "crl");
            jFileChooserExportCRL.resetChoosableFileFilters();
            jFileChooserExportCRL.setFileFilter(ft);
            int ret = jFileChooserExportCRL.showSaveDialog(this);
            if (ret == JFileChooser.APPROVE_OPTION) {
                File targetCRL = jFileChooserExportCRL.getSelectedFile();
                String targetFull = targetCRL.getAbsolutePath();
                ExportManager xm = new ExportManager();
                if (!targetFull.endsWith(".crl")) {
                    targetFull = targetFull + ".crl";
                }
                String outRet = xm.exportCRL(idCrl, targetFull);
                ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
            }
        });
        popupMenu.add(exportCRL);

        jTableCRL.setComponentPopupMenu(popupMenu);
        popupMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                SwingUtilities.invokeLater(() -> {
                    int rowAtPoint = jTableCRL
                            .rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), jTableCRL));
                    if (rowAtPoint > -1) {
                        jTableCRL.setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }
                });
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // TODO Auto-generated method stub
            }
        });
    }

    private void refreshX509KeyTable() {
        // Fill X509 Keys Table
        try {
            DefaultTableModel model = (DefaultTableModel) jTablePK.getModel();
            model.getDataVector().removeAllElements();
            model.fireTableDataChanged();
            HSQLLoader database = new HSQLLoader();
            ResultSet f = database
                    .runQuery("select ID_KEY,KEYNAME,KEYTYPE,ALGO, SHA256,ID_ASSOCIATED_KEY from X509KEYS");
            jTablePK.getColumnModel().getColumn(0).setCellRenderer(jTablePK.getDefaultRenderer(ImageIcon.class));
            jTablePK.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
            centerRenderer.setHorizontalAlignment(JLabel.CENTER);
            jTablePK.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
            jTablePK.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
            jTablePK.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
            jTablePK.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
            jTablePK.getColumnModel().getColumn(0).setPreferredWidth(30);
            jTablePK.getColumnModel().getColumn(1).setPreferredWidth(40);
            jTablePK.getColumnModel().getColumn(2).setPreferredWidth(140);
            jTablePK.getColumnModel().getColumn(3).setPreferredWidth(100);
            jTablePK.getColumnModel().getColumn(4).setPreferredWidth(100);
            jTablePK.getColumnModel().getColumn(5).setPreferredWidth(460);
            jTablePK.getColumnModel().getColumn(6).setPreferredWidth(100);
            while (f.next()) {
                ImageIcon icon = null;
                if (1 == f.getInt("KEYTYPE")) {
                    icon = new ImageIcon(getClass().getResource("/key.png"));
                } else {
                    icon = new ImageIcon(getClass().getResource("/keypub.png"));
                }
                model.addRow(new Object[]{icon, f.getInt("ID_KEY"), f.getString("KEYNAME"),
                    f.getInt("KEYTYPE") == 1 ? "Private" : "Public", f.getString("ALGO"), f.getString("SHA256"),
                    f.getInt("ID_ASSOCIATED_KEY")});
            }
        } catch (SQLException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void refreshX509CertOutline() {
        // Fill X509 Certificates Outline
        TreeModel treeMdl = new CertificateTreeModel(CryptoDAO.getEnigmaCertTreeFromDB());
        OutlineModel mdl = DefaultOutlineModel.createOutlineModel(treeMdl, new CertificateRowModel(), true,
                "Certificates");
        outline.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        outline = new Outline();
        outline.setRenderDataProvider(new CertificateDataProvider());
        outline.setRootVisible(false);
        outline.setModel(mdl);
        jScrollPane1.setViewportView(outline);

        outline.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
//        DefaultTableCellRenderer redRenderer = new DefaultTableCellRenderer();
//        redRenderer.setForeground(new Color(230, 76, 76));
//        redRenderer.setHorizontalAlignment(JLabel.CENTER);
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        outline.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(7).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(8).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(9).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(10).setCellRenderer(centerRenderer);
        outline.getColumnModel().getColumn(0).setPreferredWidth(220);
        outline.getColumnModel().getColumn(1).setPreferredWidth(30);
        outline.getColumnModel().getColumn(2).setPreferredWidth(240);
        outline.getColumnModel().getColumn(3).setPreferredWidth(260);
        outline.getColumnModel().getColumn(4).setPreferredWidth(140);
        outline.getColumnModel().getColumn(5).setPreferredWidth(100);
        outline.getColumnModel().getColumn(6).setPreferredWidth(90);
        outline.getColumnModel().getColumn(7).setPreferredWidth(60);
        outline.getColumnModel().getColumn(8).setPreferredWidth(75);
        outline.getColumnModel().getColumn(9).setPreferredWidth(100);
        outline.getColumnModel().getColumn(10).setPreferredWidth(100);
        buildPopupMenuX509();
        outline.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int row = outline.getSelectedRow();
                EnigmaCertificate f = (EnigmaCertificate) outline.getValueAt(row, 0);
                if (!e.getValueIsAdjusting()) {
                    refreshCRLTable(f.getId_cert());
                }
            }
        });
    }

    private void refreshCRLTable(Integer id_cert) {
        System.out.println("org.caulfield.pkiz.EnigmaIHM.refreshCRLTable()" + id_cert);
        ArrayList<EnigmaCRL> crlList = CryptoDAO.getCRLforCertFromDB(id_cert);
        DefaultTableModel model = (DefaultTableModel) jTableCRL.getModel();
        model.getDataVector().removeAllElements();
        model.fireTableDataChanged();
        TableCellRenderer tableCellRenderer = new DefaultTableCellRenderer() {
            SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy");

            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                if (value instanceof Date) {
                    value = f.format(value);
                }
                JLabel parent = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                        column);
                //System.out.println(".getTableCellRendererComponent()" + row + "-" + parent.getFont());
                //System.out.println(".getTableCellRendererComponent()" + jTableCRL.getRowCount());

                if (row == jTableCRL.getRowCount() - 1) {
                    //System.out.println(".getTableCellRendererComponent() update font");
                    parent.setFont(parent.getFont().deriveFont(Font.BOLD));
                }
                return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            }
        };
        ((DefaultTableCellRenderer) tableCellRenderer).setHorizontalAlignment(JLabel.CENTER);
        jTableCRL.getColumnModel().getColumn(0).setCellRenderer(tableCellRenderer);
        jTableCRL.getColumnModel().getColumn(1).setCellRenderer(tableCellRenderer);
        jTableCRL.getColumnModel().getColumn(2).setCellRenderer(tableCellRenderer);
        jTableCRL.getColumnModel().getColumn(0).setPreferredWidth(30);
        jTableCRL.getColumnModel().getColumn(1).setPreferredWidth(60);
        jTableCRL.getColumnModel().getColumn(2).setPreferredWidth(60);

        for (EnigmaCRL crl : crlList) {
            model.addRow(new Object[]{crl.getIdcrl(), crl.getStartdate(), crl.getEnddate()});
        }
        buildPopupMenuX509CRL();
    }

    private void refreshPKObjects() {

        // Fill PK Keys combobox
        try {
            jComboBoxPubPK.removeAllItems();
            jComboBoxCSRPk.removeAllItems();
            jComboBoxSignPK.removeAllItems();
            jComboBoxCertPk.removeAllItems();
            jComboBoxDecryptPK.removeAllItems();
            jComboBoxPKCS12MakerPK.removeAllItems();
            HSQLLoader database = new HSQLLoader();
            ResultSet f = database.runQuery("select ID_KEY,KEYNAME,ALGO from X509KEYS WHERE KEYTYPE=1");
            while (f.next()) {
                jComboBoxPubPK.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxCSRPk.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxSignPK.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxCertPk.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxDecryptPK.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxPKCS12MakerPK.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
            }
            buildPopupMenuX509Keys();
        } catch (SQLException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void refreshPubKObjects() {
        // Fill PK Keys combobox
        try {
            jComboBoxCertPubK.removeAllItems();
            jComboBoxCSRPubK.removeAllItems();
            HSQLLoader database = new HSQLLoader();
            ResultSet f = database.runQuery("select ID_KEY,KEYNAME,ALGO from X509KEYS WHERE KEYTYPE=2");
            while (f.next()) {
                jComboBoxCertPubK
                        .addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
                jComboBoxCSRPubK
                        .addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
            }
            buildPopupMenuX509Keys();
        } catch (SQLException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private String getFileName(String str) {
        String base = str.substring(str.lastIndexOf('\\') + 1);

        return base;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jFileChooserDirectoriesOnly = new javax.swing.JFileChooser();
        jFileChooserFileOnly = new javax.swing.JFileChooser();
        jFrameAbout = new javax.swing.JFrame();
        jButton1 = new javax.swing.JButton();
        jLabel49 = new javax.swing.JLabel();
        jLabel48 = new javax.swing.JLabel();
        jLabel50 = new javax.swing.JLabel();
        jLabel77 = new javax.swing.JLabel();
        jLabel78 = new javax.swing.JLabel();
        jFrameCertWizard = new javax.swing.JFrame();
        jPanelCertWizard = new javax.swing.JPanel();
        jComboBoxWParents = new javax.swing.JComboBox<>();
        jComboBoxWType = new javax.swing.JComboBox<>();
        jTextFieldWAlias = new javax.swing.JTextField();
        jTextFieldWCN = new javax.swing.JTextField();
        jTextFieldWOrg = new javax.swing.JTextField();
        jTextFieldWOU = new javax.swing.JTextField();
        jTextFieldCountry = new javax.swing.JTextField();
        jDateChooserWExpiry = new com.toedter.calendar.JDateChooser();
        jCheckBoxWexport = new javax.swing.JCheckBox();
        jButtonWCertGenerate = new javax.swing.JButton();
        jLabel25 = new javax.swing.JLabel();
        jLabel29 = new javax.swing.JLabel();
        jLabel38 = new javax.swing.JLabel();
        jLabel39 = new javax.swing.JLabel();
        jLabel57 = new javax.swing.JLabel();
        jLabel76 = new javax.swing.JLabel();
        jLabel80 = new javax.swing.JLabel();
        jLabel81 = new javax.swing.JLabel();
        jLabel82 = new javax.swing.JLabel();
        jLabel83 = new javax.swing.JLabel();
        jLabel84 = new javax.swing.JLabel();
        jLabel85 = new javax.swing.JLabel();
        jLabel86 = new javax.swing.JLabel();
        jPasswordFieldW1 = new javax.swing.JPasswordField();
        jPasswordFieldW2 = new javax.swing.JPasswordField();
        jLabel87 = new javax.swing.JLabel();
        jLabel88 = new javax.swing.JLabel();
        jLabelWConsole = new javax.swing.JLabel();
        jLabel89 = new javax.swing.JLabel();
        jDialogFileImport = new javax.swing.JDialog();
        jLabel62 = new javax.swing.JLabel();
        jTextFieldImportKeyName = new javax.swing.JTextField();
        jButtonKeyName = new javax.swing.JButton();
        jLabel63 = new javax.swing.JLabel();
        jTextFieldImportKeyFile = new javax.swing.JTextField();
        jButtonImportKey = new javax.swing.JButton();
        jDialogFileImportPublic = new javax.swing.JDialog();
        jLabel64 = new javax.swing.JLabel();
        jTextFieldImportKeyName1 = new javax.swing.JTextField();
        jButtonKeyName1 = new javax.swing.JButton();
        jLabel65 = new javax.swing.JLabel();
        jTextFieldImportKeyFile1 = new javax.swing.JTextField();
        jButtonImportKey1 = new javax.swing.JButton();
        jFileChooserExportCert = new javax.swing.JFileChooser();
        jFileChooserExportCRL = new javax.swing.JFileChooser();
        jPanelPGPKeyring = new javax.swing.JPanel();
        jLabel56 = new javax.swing.JLabel();
        jTabbedPaneScreens = new javax.swing.JTabbedPane();
        jPanelDashboard = new javax.swing.JPanel();
        jPanel23 = new javax.swing.JPanel();
        jButtonDashX517 = new javax.swing.JButton();
        jButtonDashX518 = new javax.swing.JButton();
        jButtonDashX519 = new javax.swing.JButton();
        jButtonDashX520 = new javax.swing.JButton();
        jButtonDashGenerate = new javax.swing.JButton();
        jButtonDashTransform = new javax.swing.JButton();
        jButtonDashAnalyze = new javax.swing.JButton();
        jButtonDashConvert = new javax.swing.JButton();
        jButtonDashAbout = new javax.swing.JButton();
        jPanel8 = new javax.swing.JPanel();
        jButtonDashX509 = new javax.swing.JButton();
        jButtonDashX510 = new javax.swing.JButton();
        jButtonDashX512 = new javax.swing.JButton();
        jPanel22 = new javax.swing.JPanel();
        jButtonDashX513 = new javax.swing.JButton();
        jButtonDashX514 = new javax.swing.JButton();
        jLabel13 = new javax.swing.JLabel();
        jPanel24 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        jPanel25 = new javax.swing.JPanel();
        jButtonDashX521 = new javax.swing.JButton();
        jButtonDashX522 = new javax.swing.JButton();
        jButtonDashX523 = new javax.swing.JButton();
        jButtonDashX524 = new javax.swing.JButton();
        jPanel26 = new javax.swing.JPanel();
        jButtonDashX525 = new javax.swing.JButton();
        jButtonDashX526 = new javax.swing.JButton();
        jPanelACManagement = new javax.swing.JPanel();
        jPanel19 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        outline = new org.netbeans.swing.outline.Outline();
        jPanel20 = new javax.swing.JPanel();
        jScrollPane9 = new javax.swing.JScrollPane();
        jTablePK = new javax.swing.JTable();
        jPanel21 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTableCRL = new javax.swing.JTable();
        jTabbedPaneGenerate = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        jPanel1 = new javax.swing.JPanel();
        jTextFieldKeystorePW = new javax.swing.JTextField();
        jTextFieldPKCS8PW = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jTextFieldCN = new javax.swing.JTextField();
        jSpinnerKeySize = new javax.swing.JSpinner();
        jLabel4 = new javax.swing.JLabel();
        jComboBoxAC = new javax.swing.JComboBox<>();
        jLabel6 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jComboBoxAlgoP12 = new javax.swing.JComboBox<>();
        jLabel10 = new javax.swing.JLabel();
        jSpinnerP12Expo = new javax.swing.JSpinner();
        jLabel11 = new javax.swing.JLabel();
        jSliderP12Certainty = new javax.swing.JSlider();
        jCheckBoxP12Expo = new javax.swing.JCheckBox();
        jCheckBoxP12Certainty = new javax.swing.JCheckBox();
        jButtonPKCS12Generate = new javax.swing.JButton();
        jDateChooserP12Expiry = new com.toedter.calendar.JDateChooser();
        jLabel31 = new javax.swing.JLabel();
        jLabel40 = new javax.swing.JLabel();
        jTextFieldP12TargetFilename = new javax.swing.JTextField();
        jCheckBoxP12Write = new javax.swing.JCheckBox();
        jLabelCertaintyValue = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        jButtonPkGenerate = new javax.swing.JButton();
        jLabel12 = new javax.swing.JLabel();
        jSpinnerKeySizePkSize = new javax.swing.JSpinner();
        jTextFieldPkTargetFilename = new javax.swing.JTextField();
        jSliderPkCertainty = new javax.swing.JSlider();
        jLabel14 = new javax.swing.JLabel();
        jCheckBoxPkCertainty = new javax.swing.JCheckBox();
        jLabel15 = new javax.swing.JLabel();
        jSpinnerPkExpo = new javax.swing.JSpinner();
        jCheckBoxPkExpo = new javax.swing.JCheckBox();
        jComboBoxAlgoPk = new javax.swing.JComboBox<>();
        jLabel16 = new javax.swing.JLabel();
        jTextFieldPkPw = new javax.swing.JTextField();
        jLabel17 = new javax.swing.JLabel();
        jLabel27 = new javax.swing.JLabel();
        jLabel59 = new javax.swing.JLabel();
        jTextFieldPkTargetKeyName = new javax.swing.JTextField();
        jLabelCertaintyValuePk = new java.awt.Label();
        jPanel4 = new javax.swing.JPanel();
        jLabel19 = new javax.swing.JLabel();
        jTextFieldCertCN = new javax.swing.JTextField();
        jLabel20 = new javax.swing.JLabel();
        jTextFieldCertPkPw = new javax.swing.JTextField();
        jLabel21 = new javax.swing.JLabel();
        jLabel22 = new javax.swing.JLabel();
        jButtonBrowseCertPub = new javax.swing.JButton();
        jButtonBrowseCertPk = new javax.swing.JButton();
        jLabel28 = new javax.swing.JLabel();
        jTextFieldCertTargetFilename = new javax.swing.JTextField();
        jDateChooserExpiry = new com.toedter.calendar.JDateChooser();
        jLabel30 = new javax.swing.JLabel();
        jComboBoxCertPk = new javax.swing.JComboBox<>();
        jComboBoxCertPubK = new javax.swing.JComboBox<>();
        jComboBoxCertAlgo = new javax.swing.JComboBox<>();
        jLabel61 = new javax.swing.JLabel();
        jLabel66 = new javax.swing.JLabel();
        jComboBoxCertVersion = new javax.swing.JComboBox<>();
        jLabel67 = new javax.swing.JLabel();
        jTextFieldPubTargetCertName = new javax.swing.JTextField();
        jButtonCertGenerate = new javax.swing.JButton();
        jPanel5 = new javax.swing.JPanel();
        jButtonPubGenerate = new javax.swing.JButton();
        jLabel23 = new javax.swing.JLabel();
        jLabel24 = new javax.swing.JLabel();
        jTextFieldPubPrivkeyPW = new javax.swing.JTextField();
        jLabel26 = new javax.swing.JLabel();
        jTextFieldPubTargetFilename = new javax.swing.JTextField();
        jComboBoxPubPK = new javax.swing.JComboBox<>();
        jLabel60 = new javax.swing.JLabel();
        jTextFieldPubTargetKeyName = new javax.swing.JTextField();
        jButtonBrowsePubPk = new javax.swing.JButton();
        jPanel6 = new javax.swing.JPanel();
        jButtonCSRGenerate = new javax.swing.JButton();
        jLabel32 = new javax.swing.JLabel();
        jButtonBrowseP10Pk = new javax.swing.JButton();
        jLabel34 = new javax.swing.JLabel();
        jTextFieldP10PkPw = new javax.swing.JTextField();
        jLabel36 = new javax.swing.JLabel();
        jTextFieldP10CN = new javax.swing.JTextField();
        jLabel37 = new javax.swing.JLabel();
        jTextFieldP10TargetFilename = new javax.swing.JTextField();
        jCheckBoxP10PubKey = new javax.swing.JCheckBox();
        jComboBoxCSRPk = new javax.swing.JComboBox<>();
        jComboBoxCSRPubK = new javax.swing.JComboBox<>();
        jButtonBrowseP10PubK = new javax.swing.JButton();
        jPanelTransform = new javax.swing.JPanel();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel9 = new javax.swing.JPanel();
        jPanel11 = new javax.swing.JPanel();
        jLabel41 = new javax.swing.JLabel();
        jLabel42 = new javax.swing.JLabel();
        jTextFieldSignFile = new javax.swing.JTextField();
        jButtonBrowseSignFile = new javax.swing.JButton();
        jComboBoxSignPK = new javax.swing.JComboBox<>();
        jLabel43 = new javax.swing.JLabel();
        jComboBoxAlgoSign = new javax.swing.JComboBox<>();
        jButtonSign = new javax.swing.JButton();
        jLabel46 = new javax.swing.JLabel();
        jTextFieldSignPkPassword = new javax.swing.JTextField();
        jCheckBox2 = new javax.swing.JCheckBox();
        jLabel52 = new javax.swing.JLabel();
        jComboBoxSignSignerCert = new javax.swing.JComboBox<>();
        jLabel44 = new javax.swing.JLabel();
        jTextFieldSignOutputFilename = new javax.swing.JTextField();
        jPanel13 = new javax.swing.JPanel();
        jLabel47 = new javax.swing.JLabel();
        jTextFieldCipherFile = new javax.swing.JTextField();
        jButtonBrowseCipherFile = new javax.swing.JButton();
        jButtonCipher = new javax.swing.JButton();
        jComboBoxAlgoCipher = new javax.swing.JComboBox<>();
        jLabel51 = new javax.swing.JLabel();
        jLabel69 = new javax.swing.JLabel();
        jTextFieldCipherOutputFilename = new javax.swing.JTextField();
        jCheckBoxCustomCipher = new javax.swing.JCheckBox();
        jLabel70 = new javax.swing.JLabel();
        jComboBoxCipherCert = new javax.swing.JComboBox<>();
        jPanel15 = new javax.swing.JPanel();
        jLabel45 = new javax.swing.JLabel();
        jTextFieldDecryptFile = new javax.swing.JTextField();
        jButtonBrowseEncrypt = new javax.swing.JButton();
        jLabel73 = new javax.swing.JLabel();
        jComboBoxDecryptPK = new javax.swing.JComboBox<>();
        jLabel74 = new javax.swing.JLabel();
        jTextFieldDecryptPW = new javax.swing.JTextField();
        jLabel75 = new javax.swing.JLabel();
        jTextFieldDecryptOutputFilename = new javax.swing.JTextField();
        jCheckBoxCustomDecrypt = new javax.swing.JCheckBox();
        jButtonDecrypt = new javax.swing.JButton();
        jCheckBoxCustomDecryptTryAll = new javax.swing.JCheckBox();
        jPanel16 = new javax.swing.JPanel();
        jCheckBoxCustomVerify = new javax.swing.JCheckBox();
        jTextFieldVerifyOutputFilename = new javax.swing.JTextField();
        jLabel71 = new javax.swing.JLabel();
        jComboBoxVerifyCert = new javax.swing.JComboBox<>();
        jLabel72 = new javax.swing.JLabel();
        jLabel68 = new javax.swing.JLabel();
        jTextFieldVerifyFile = new javax.swing.JTextField();
        jButtonBrowseVerifyFile = new javax.swing.JButton();
        jButtonValidate = new javax.swing.JButton();
        jCheckBoxCustomVerifyTryAll = new javax.swing.JCheckBox();
        jButtonVerify = new javax.swing.JButton();
        jPanelAnalyze = new javax.swing.JPanel();
        jLabel7 = new javax.swing.JLabel();
        jTextFieldDrop = new javax.swing.JTextField();
        jButton7 = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        jEditorPaneIdentifierResults = new javax.swing.JEditorPane();
        jLabel8 = new javax.swing.JLabel();
        jPanel12 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        jTextAreaDrop = new javax.swing.JTextArea();
        jButton8 = new javax.swing.JButton();
        jPanelConvert = new javax.swing.JPanel();
        jPanel18 = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
        jTextAreaOriginalData = new javax.swing.JTextArea();
        jScrollPane8 = new javax.swing.JScrollPane();
        jTextAreaBase64Data = new javax.swing.JTextArea();
        jLabel54 = new javax.swing.JLabel();
        jLabel55 = new javax.swing.JLabel();
        jButtonEncodeBase64 = new javax.swing.JButton();
        jButtonDecodeBase64 = new javax.swing.JButton();
        jPanel7 = new javax.swing.JPanel();
        jRadioButtonDER = new javax.swing.JRadioButton();
        jLabel33 = new javax.swing.JLabel();
        jTextFieldConvertSourceFile = new javax.swing.JTextField();
        jButtonConvertSourceFile = new javax.swing.JButton();
        jRadioButtonPEM = new javax.swing.JRadioButton();
        jRadioButtonPEMorDER = new javax.swing.JRadioButton();
        jButtonConvertPEM = new javax.swing.JButton();
        jButtonConvertDER = new javax.swing.JButton();
        jPanel10 = new javax.swing.JPanel();
        jLabel35 = new javax.swing.JLabel();
        jButtonBuildPKCS12Maker = new javax.swing.JButton();
        jLabel90 = new javax.swing.JLabel();
        jComboBoxPKCS12MakerPK = new javax.swing.JComboBox<>();
        jComboBoxPKCS12MakerCert = new javax.swing.JComboBox<>();
        jLabel91 = new javax.swing.JLabel();
        jPasswordFieldPKCS12Maker = new javax.swing.JPasswordField();
        jPanelBruteForce = new javax.swing.JPanel();
        jPanel27 = new javax.swing.JPanel();
        jLabel58 = new javax.swing.JLabel();
        jTextFieldBrutePubKey = new javax.swing.JTextField();
        jButtonBrowseBrutePublicKey = new javax.swing.JButton();
        jLabel79 = new javax.swing.JLabel();
        jTextFieldBruteFile = new javax.swing.JTextField();
        jButtonBrowseBruteFile = new javax.swing.JButton();
        jButtonBruteForce = new javax.swing.JButton();
        jButtonBruteForceCancel = new javax.swing.JButton();
        jScrollPane10 = new javax.swing.JScrollPane();
        jEditorPaneIBruteForceResult = new javax.swing.JEditorPane();
        jLabel18 = new javax.swing.JLabel();
        jLabelLoading = new javax.swing.JLabel();
        jPanelEvents = new javax.swing.JPanel();
        jProgressBarEnigma = new javax.swing.JProgressBar();
        jScrollPaneForEvents = new javax.swing.JScrollPane();
        jListEvents = new javax.swing.JList<>();
        jTextFieldGlobalOutput = new javax.swing.JTextField();
        jLabelGlobalDir = new javax.swing.JLabel();
        jButtonBrowseGlobalOutput = new javax.swing.JButton();
        jButtonBrowseGlobalOutput1 = new javax.swing.JButton();
        menuBar = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        openMenuItem = new javax.swing.JMenuItem();
        saveMenuItem = new javax.swing.JMenuItem();
        exitMenuItem = new javax.swing.JMenuItem();
        editMenu = new javax.swing.JMenu();
        cutMenuItem = new javax.swing.JMenuItem();
        copyMenuItem = new javax.swing.JMenuItem();
        pasteMenuItem = new javax.swing.JMenuItem();
        deleteMenuItem = new javax.swing.JMenuItem();
        jMenuItem1 = new javax.swing.JMenuItem();
        helpMenu = new javax.swing.JMenu();
        aboutMenuItem = new javax.swing.JMenuItem();

        jFileChooserDirectoriesOnly.setDialogTitle("");
        jFileChooserDirectoriesOnly.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);

        jFileChooserFileOnly.setDialogTitle("");

        jFrameAbout.setTitle("About PKIZ");
        jFrameAbout.setAlwaysOnTop(true);
        jFrameAbout.setResizable(false);
        jFrameAbout.setSize(new java.awt.Dimension(256, 356));

        jButton1.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButton1.setFont(new java.awt.Font("Malgun Gothic", 1, 18)); // NOI18N
        jButton1.setForeground(new java.awt.Color(255, 255, 255));
        jButton1.setText("Okay");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel49.setIcon(new javax.swing.ImageIcon(getClass().getResource("/pkiz3.png"))); // NOI18N

        jLabel48.setFont(new java.awt.Font("Malgun Gothic", 1, 16)); // NOI18N
        jLabel48.setText("Author");

        jLabel50.setFont(new java.awt.Font("DM Serif Display", 0, 22)); // NOI18N
        jLabel50.setForeground(new java.awt.Color(21, 107, 158));
        jLabel50.setText("PKIZ version 1.00a");

        jLabel77.setFont(new java.awt.Font("Corbel", 0, 14)); // NOI18N
        jLabel77.setText("Philippe BAKHTIARI");

        jLabel78.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jLabel78.setText("Copyright 2015-2022");

        javax.swing.GroupLayout jFrameAboutLayout = new javax.swing.GroupLayout(jFrameAbout.getContentPane());
        jFrameAbout.getContentPane().setLayout(jFrameAboutLayout);
        jFrameAboutLayout.setHorizontalGroup(
            jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jFrameAboutLayout.createSequentialGroup()
                .addGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jFrameAboutLayout.createSequentialGroup()
                        .addGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(jFrameAboutLayout.createSequentialGroup()
                                    .addGap(94, 94, 94)
                                    .addComponent(jLabel48))
                                .addGroup(jFrameAboutLayout.createSequentialGroup()
                                    .addGap(63, 63, 63)
                                    .addComponent(jLabel77)))
                            .addGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(jFrameAboutLayout.createSequentialGroup()
                                    .addGap(55, 55, 55)
                                    .addComponent(jLabel49))
                                .addGroup(jFrameAboutLayout.createSequentialGroup()
                                    .addGap(32, 32, 32)
                                    .addGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jLabel50, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
                        .addGap(0, 38, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jFrameAboutLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jLabel78)))
                .addContainerGap())
        );
        jFrameAboutLayout.setVerticalGroup(
            jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jFrameAboutLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel50)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel49)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel48)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel77)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 35, Short.MAX_VALUE)
                .addComponent(jLabel78)
                .addContainerGap())
        );

        jFrameCertWizard.setTitle("Certificate Wizard");
        jFrameCertWizard.setAlwaysOnTop(true);
        jFrameCertWizard.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jFrameCertWizard.setLocation(new java.awt.Point(200, 200));
        jFrameCertWizard.setMinimumSize(new java.awt.Dimension(490, 430));
        jFrameCertWizard.getContentPane().setLayout(new java.awt.GridLayout(1, 0));

        jPanelCertWizard.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificate Properties"));

        jComboBoxWParents.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "None" }));
        jComboBoxWParents.setEnabled(false);

        jComboBoxWType.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "CA Certificate", "Intermediate Certificate", "End User Client Certificate", "End User Server Certificate" }));
        jComboBoxWType.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxWTypeActionPerformed(evt);
            }
        });

        jTextFieldWAlias.setText("MyCertificateName");

        jTextFieldWCN.setText("Common Name");

        jTextFieldWOrg.setText("Company");

        jTextFieldWOU.setText("IT");

        jTextFieldCountry.setText("US");

        jDateChooserWExpiry.setName("JDateChooserExpiry"); // NOI18N

        jCheckBoxWexport.setSelected(true);
        jCheckBoxWexport.setText("Export the certificate on disk");
        jCheckBoxWexport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxWexportActionPerformed(evt);
            }
        });

        jButtonWCertGenerate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButtonWCertGenerate.setFont(new java.awt.Font("Lato", 1, 18)); // NOI18N
        jButtonWCertGenerate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonWCertGenerate.setText("Create Certificate");
        jButtonWCertGenerate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonWCertGenerate.setMinimumSize(new java.awt.Dimension(120, 26));
        jButtonWCertGenerate.setPreferredSize(new java.awt.Dimension(120, 26));
        jButtonWCertGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonWCertGenerateActionPerformed(evt);
            }
        });

        jLabel25.setText("Common Name : ");

        jLabel29.setText("Type : ");

        jLabel38.setText("Certificate Alias : ");

        jLabel39.setText("Organization : ");

        jLabel57.setText("(optional)");

        jLabel76.setText("(optional)");

        jLabel80.setText("Organizational Unit : ");

        jLabel81.setText("Country : ");

        jLabel82.setText("(optional)");

        jLabel83.setText("Expiration Date : ");

        jLabel84.setText("Parent Certificate :");

        jLabel85.setText("(optional)");

        jLabel86.setText("Private Key Password : ");

        jPasswordFieldW1.setText("jPasswordField1");

        jPasswordFieldW2.setText("jPasswordField1");
        jPasswordFieldW2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jPasswordFieldW2ActionPerformed(evt);
            }
        });

        jLabel87.setText("Repeat : ");

        jLabel88.setFont(new java.awt.Font("Segoe UI", 2, 12)); // NOI18N
        jLabel88.setText("its name in PKIZ");

        jLabelWConsole.setForeground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jLabelWConsole.setText("Ready to Generate");
        jLabelWConsole.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jLabel89.setText("Export file : ");

        javax.swing.GroupLayout jPanelCertWizardLayout = new javax.swing.GroupLayout(jPanelCertWizard);
        jPanelCertWizard.setLayout(jPanelCertWizardLayout);
        jPanelCertWizardLayout.setHorizontalGroup(
            jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jButtonWCertGenerate, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                        .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel84)
                            .addComponent(jLabel38)
                            .addComponent(jLabel29))
                        .addGap(29, 29, 29)
                        .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(jComboBoxWType, javax.swing.GroupLayout.Alignment.LEADING, 0, 200, Short.MAX_VALUE)
                                    .addComponent(jComboBoxWParents, javax.swing.GroupLayout.Alignment.LEADING, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel85)
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                                .addComponent(jTextFieldWAlias, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel88)
                                .addGap(0, 0, Short.MAX_VALUE))))
                    .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                        .addComponent(jLabel89)
                        .addGap(0, 0, Short.MAX_VALUE))))
            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel86)
                            .addComponent(jLabel25)
                            .addComponent(jLabel39)
                            .addComponent(jLabel80)
                            .addComponent(jLabel81)
                            .addComponent(jLabel83))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                                .addComponent(jPasswordFieldW1, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel87)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jPasswordFieldW2, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(jTextFieldWOrg, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jTextFieldWCN, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel57))
                            .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(jDateChooserWExpiry, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE)
                                    .addComponent(jTextFieldCountry, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jTextFieldWOU, javax.swing.GroupLayout.Alignment.LEADING))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel76)
                                    .addComponent(jLabel82)))
                            .addComponent(jCheckBoxWexport)))
                    .addGroup(jPanelCertWizardLayout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addComponent(jLabelWConsole, javax.swing.GroupLayout.PREFERRED_SIZE, 420, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(12, Short.MAX_VALUE))
        );
        jPanelCertWizardLayout.setVerticalGroup(
            jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelCertWizardLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel29)
                    .addComponent(jComboBoxWType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jComboBoxWParents, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel85)
                    .addComponent(jLabel84))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextFieldWAlias, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel38)
                    .addComponent(jLabel88))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel86)
                    .addComponent(jPasswordFieldW1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPasswordFieldW2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel87))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel25)
                    .addComponent(jTextFieldWCN, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextFieldWOrg, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel57)
                    .addComponent(jLabel39))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel80)
                    .addComponent(jTextFieldWOU, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel76))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel81)
                    .addComponent(jTextFieldCountry, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel82))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jDateChooserWExpiry, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel83, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelCertWizardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel89, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jCheckBoxWexport))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonWCertGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabelWConsole, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(1, 1, 1))
        );

        jFrameCertWizard.getContentPane().add(jPanelCertWizard);

        jDialogFileImport.setTitle("Import Key");
        jDialogFileImport.setAlwaysOnTop(true);
        jDialogFileImport.setMinimumSize(new java.awt.Dimension(352, 125));
        jDialogFileImport.setModalityType(java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        jDialogFileImport.setSize(new java.awt.Dimension(352, 125));

        jLabel62.setText("Key Name :");

        jTextFieldImportKeyName.setText("imported_key");

        jButtonKeyName.setText("Validate");
        jButtonKeyName.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonKeyNameActionPerformed(evt);
            }
        });

        jLabel63.setText("Key File :");

        jButtonImportKey.setText("Browse..");
        jButtonImportKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonImportKeyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jDialogFileImportLayout = new javax.swing.GroupLayout(jDialogFileImport.getContentPane());
        jDialogFileImport.getContentPane().setLayout(jDialogFileImportLayout);
        jDialogFileImportLayout.setHorizontalGroup(
            jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogFileImportLayout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel62)
                    .addComponent(jLabel63))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldImportKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jDialogFileImportLayout.createSequentialGroup()
                        .addComponent(jTextFieldImportKeyFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(6, 6, 6)
                        .addComponent(jButtonImportKey))
                    .addComponent(jButtonKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(44, Short.MAX_VALUE))
        );
        jDialogFileImportLayout.setVerticalGroup(
            jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogFileImportLayout.createSequentialGroup()
                .addGap(11, 11, 11)
                .addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jDialogFileImportLayout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jDialogFileImportLayout.createSequentialGroup()
                                .addGap(1, 1, 1)
                                .addComponent(jTextFieldImportKeyFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jButtonImportKey))
                        .addGap(6, 6, 6)
                        .addComponent(jButtonKeyName))
                    .addGroup(jDialogFileImportLayout.createSequentialGroup()
                        .addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel62)
                            .addComponent(jTextFieldImportKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(15, 15, 15)
                        .addComponent(jLabel63)))
                .addContainerGap(23, Short.MAX_VALUE))
        );

        jDialogFileImportPublic.setTitle("Import Key");
        jDialogFileImportPublic.setAlwaysOnTop(true);
        jDialogFileImportPublic.setMinimumSize(new java.awt.Dimension(352, 125));
        jDialogFileImportPublic.setModalityType(java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        jDialogFileImportPublic.setSize(new java.awt.Dimension(352, 125));

        jLabel64.setText("Key Name :");

        jTextFieldImportKeyName1.setText("imported_key");

        jButtonKeyName1.setText("Validate");
        jButtonKeyName1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonKeyName1ActionPerformed(evt);
            }
        });

        jLabel65.setText("Key File :");

        jButtonImportKey1.setText("Browse..");
        jButtonImportKey1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonImportKey1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jDialogFileImportPublicLayout = new javax.swing.GroupLayout(jDialogFileImportPublic.getContentPane());
        jDialogFileImportPublic.getContentPane().setLayout(jDialogFileImportPublicLayout);
        jDialogFileImportPublicLayout.setHorizontalGroup(
            jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel64)
                    .addComponent(jLabel65))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldImportKeyName1, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                        .addComponent(jTextFieldImportKeyFile1, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(6, 6, 6)
                        .addComponent(jButtonImportKey1))
                    .addComponent(jButtonKeyName1, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(44, Short.MAX_VALUE))
        );
        jDialogFileImportPublicLayout.setVerticalGroup(
            jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                .addGap(11, 11, 11)
                .addGroup(jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addGroup(jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                                .addGap(1, 1, 1)
                                .addComponent(jTextFieldImportKeyFile1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jButtonImportKey1))
                        .addGap(6, 6, 6)
                        .addComponent(jButtonKeyName1))
                    .addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
                        .addGroup(jDialogFileImportPublicLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel64)
                            .addComponent(jTextFieldImportKeyName1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(15, 15, 15)
                        .addComponent(jLabel65)))
                .addContainerGap(31, Short.MAX_VALUE))
        );

        jFileChooserExportCert.setFileFilter(null);

        jFileChooserExportCRL.setDialogTitle("");

        jPanelPGPKeyring.setEnabled(false);

        jLabel56.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel56.setText("Coming soon ... ");

        javax.swing.GroupLayout jPanelPGPKeyringLayout = new javax.swing.GroupLayout(jPanelPGPKeyring);
        jPanelPGPKeyring.setLayout(jPanelPGPKeyringLayout);
        jPanelPGPKeyringLayout.setHorizontalGroup(
            jPanelPGPKeyringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelPGPKeyringLayout.createSequentialGroup()
                .addGap(586, 586, 586)
                .addComponent(jLabel56)
                .addContainerGap(702, Short.MAX_VALUE))
        );
        jPanelPGPKeyringLayout.setVerticalGroup(
            jPanelPGPKeyringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelPGPKeyringLayout.createSequentialGroup()
                .addGap(293, 293, 293)
                .addComponent(jLabel56)
                .addContainerGap(353, Short.MAX_VALUE))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setResizable(false);
        setSize(new java.awt.Dimension(1427, 846));

        jTabbedPaneScreens.setFont(new java.awt.Font("Segoe UI Symbol", 0, 14)); // NOI18N
        jTabbedPaneScreens.setMaximumSize(new java.awt.Dimension(1437, 693));
        jTabbedPaneScreens.setMinimumSize(new java.awt.Dimension(1437, 693));
        jTabbedPaneScreens.setPreferredSize(new java.awt.Dimension(1437, 693));

        jPanelDashboard.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Welcome to PKIZ - Choose an activity", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N

        jPanel23.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Opérations :", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N
        jPanel23.setToolTipText("");

        jButtonDashX517.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX517.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX517.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10454_key_red_icon.png"))); // NOI18N
        jButtonDashX517.setText("Signer un fichier                          ");
        jButtonDashX517.setActionCommand("Signer un fichier ");
        jButtonDashX517.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX517.setIconTextGap(5);
        jButtonDashX517.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX517ActionPerformed(evt);
            }
        });

        jButtonDashX518.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX518.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX518.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10393_calculator_green_icon.png"))); // NOI18N
        jButtonDashX518.setText("Chiffrer un fichier                        ");
        jButtonDashX518.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX518.setIconTextGap(5);
        jButtonDashX518.setMargin(new java.awt.Insets(20, 40, 3, 14));
        jButtonDashX518.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX518ActionPerformed(evt);
            }
        });

        jButtonDashX519.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX519.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX519.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10382_blue_bookmark_icon.png"))); // NOI18N
        jButtonDashX519.setText("Vérifier la signature d'un fichier");
        jButtonDashX519.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX519.setIconTextGap(5);
        jButtonDashX519.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX519ActionPerformed(evt);
            }
        });

        jButtonDashX520.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX520.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX520.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10565_lock_yellow_icon.png"))); // NOI18N
        jButtonDashX520.setText("Déchiffrer un fichier                    ");
        jButtonDashX520.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX520.setIconTextGap(5);
        jButtonDashX520.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX520ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel23Layout = new javax.swing.GroupLayout(jPanel23);
        jPanel23.setLayout(jPanel23Layout);
        jPanel23Layout.setHorizontalGroup(
            jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel23Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonDashX519, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX518, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX520, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX517, javax.swing.GroupLayout.DEFAULT_SIZE, 379, Short.MAX_VALUE))
                .addContainerGap(21, Short.MAX_VALUE))
        );
        jPanel23Layout.setVerticalGroup(
            jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel23Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButtonDashX517)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX518)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX519)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX520)
                .addContainerGap(385, Short.MAX_VALUE))
        );

        jButtonDashGenerate.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashGenerate.setText("Générer");
        jButtonDashGenerate.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
        jButtonDashGenerate.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        jButtonDashGenerate.setIconTextGap(10);
        jButtonDashGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashGenerateActionPerformed(evt);
            }
        });

        jButtonDashTransform.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashTransform.setText("Transformer");
        jButtonDashTransform.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
        jButtonDashTransform.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
        jButtonDashTransform.setIconTextGap(10);
        jButtonDashTransform.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashTransformActionPerformed(evt);
            }
        });

        jButtonDashAnalyze.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashAnalyze.setText("Analyser");
        jButtonDashAnalyze.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
        jButtonDashAnalyze.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        jButtonDashAnalyze.setIconTextGap(10);
        jButtonDashAnalyze.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashAnalyzeActionPerformed(evt);
            }
        });

        jButtonDashConvert.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashConvert.setText("Convertir");
        jButtonDashConvert.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
        jButtonDashConvert.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        jButtonDashConvert.setIconTextGap(10);
        jButtonDashConvert.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashConvertActionPerformed(evt);
            }
        });

        jButtonDashAbout.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashAbout.setText("A propos");
        jButtonDashAbout.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
        jButtonDashAbout.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
        jButtonDashAbout.setIconTextGap(10);
        jButtonDashAbout.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashAboutActionPerformed(evt);
            }
        });

        jPanel8.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Certificate", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N
        jPanel8.setToolTipText("");

        jButtonDashX509.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX509.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX509.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10439_gear_icon.png"))); // NOI18N
        jButtonDashX509.setText("Create a certificate (Wizard) ");
        jButtonDashX509.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX509.setIconTextGap(5);
        jButtonDashX509.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX509ActionPerformed(evt);
            }
        });

        jButtonDashX510.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX510.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX510.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10438_gear_green_icon.png"))); // NOI18N
        jButtonDashX510.setText("Create a certificate (Advanced)");
        jButtonDashX510.setActionCommand("Générer un certificat serveur  ");
        jButtonDashX510.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX510.setIconTextGap(5);
        jButtonDashX510.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX510ActionPerformed(evt);
            }
        });

        jButtonDashX512.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX512.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX512.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10520_security_yellow_icon.png"))); // NOI18N
        jButtonDashX512.setText("View my certificates                 ");
        jButtonDashX512.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX512.setIconTextGap(5);
        jButtonDashX512.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX512ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
        jPanel8.setLayout(jPanel8Layout);
        jPanel8Layout.setHorizontalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButtonDashX509, javax.swing.GroupLayout.PREFERRED_SIZE, 379, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonDashX510, javax.swing.GroupLayout.PREFERRED_SIZE, 379, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonDashX512, javax.swing.GroupLayout.PREFERRED_SIZE, 379, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel8Layout.setVerticalGroup(
            jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel8Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButtonDashX509)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX510)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX512)
                .addContainerGap(70, Short.MAX_VALUE))
        );

        jPanel22.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Analysis", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N
        jPanel22.setToolTipText("");

        jButtonDashX513.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX513.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX513.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10504_puzzle_red_icon.png"))); // NOI18N
        jButtonDashX513.setText("Analyze a file                          ");
        jButtonDashX513.setActionCommand("Analyze a file         ");
        jButtonDashX513.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX513.setIconTextGap(5);
        jButtonDashX513.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX513ActionPerformed(evt);
            }
        });

        jButtonDashX514.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX514.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX514.setIcon(new javax.swing.ImageIcon(getClass().getResource("/1790663_eye_human eye_search_view_icon.png"))); // NOI18N
        jButtonDashX514.setText("Break RSA Key                        ");
        jButtonDashX514.setToolTipText("");
        jButtonDashX514.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX514.setIconTextGap(5);
        jButtonDashX514.setMargin(new java.awt.Insets(20, 40, 3, 14));
        jButtonDashX514.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX514ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel22Layout = new javax.swing.GroupLayout(jPanel22);
        jPanel22.setLayout(jPanel22Layout);
        jPanel22Layout.setHorizontalGroup(
            jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel22Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonDashX514, javax.swing.GroupLayout.DEFAULT_SIZE, 379, Short.MAX_VALUE)
                    .addComponent(jButtonDashX513, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel22Layout.setVerticalGroup(
            jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel22Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButtonDashX513)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX514)
                .addContainerGap(134, Short.MAX_VALUE))
        );

        jLabel13.setFont(new java.awt.Font("Trebuchet MS", 1, 48)); // NOI18N
        jLabel13.setForeground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jLabel13.setText("PKIZ");
        jLabel13.setToolTipText("");

        jPanel24.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));

        jLabel5.setBackground(new java.awt.Color(51, 51, 51));
        jLabel5.setFont(new java.awt.Font("Lato", 1, 48)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(36, 122, 199));
        jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/pkiz3.png"))); // NOI18N
        jLabel5.setText("PKIZ");

        javax.swing.GroupLayout jPanel24Layout = new javax.swing.GroupLayout(jPanel24);
        jPanel24.setLayout(jPanel24Layout);
        jPanel24Layout.setHorizontalGroup(
            jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel24Layout.createSequentialGroup()
                .addContainerGap(37, Short.MAX_VALUE)
                .addComponent(jLabel5)
                .addGap(50, 50, 50))
        );
        jPanel24Layout.setVerticalGroup(
            jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel24Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel25.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Operations", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N
        jPanel25.setToolTipText("");

        jButtonDashX521.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX521.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX521.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10454_key_red_icon.png"))); // NOI18N
        jButtonDashX521.setText("Sign a file                                    ");
        jButtonDashX521.setActionCommand("Signer un fichier ");
        jButtonDashX521.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX521.setIconTextGap(5);
        jButtonDashX521.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX521ActionPerformed(evt);
            }
        });

        jButtonDashX522.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX522.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX522.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10393_calculator_green_icon.png"))); // NOI18N
        jButtonDashX522.setText("Encrypt a file                               ");
        jButtonDashX522.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX522.setIconTextGap(5);
        jButtonDashX522.setMargin(new java.awt.Insets(20, 40, 3, 14));
        jButtonDashX522.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX522ActionPerformed(evt);
            }
        });

        jButtonDashX523.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX523.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX523.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10382_blue_bookmark_icon.png"))); // NOI18N
        jButtonDashX523.setText("Verifiy a signature                      ");
        jButtonDashX523.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX523.setIconTextGap(5);
        jButtonDashX523.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX523ActionPerformed(evt);
            }
        });

        jButtonDashX524.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX524.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX524.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10565_lock_yellow_icon.png"))); // NOI18N
        jButtonDashX524.setText("Decrypt a file                               ");
        jButtonDashX524.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX524.setIconTextGap(5);
        jButtonDashX524.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX524ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel25Layout = new javax.swing.GroupLayout(jPanel25);
        jPanel25.setLayout(jPanel25Layout);
        jPanel25Layout.setHorizontalGroup(
            jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel25Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonDashX523, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX522, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX524, javax.swing.GroupLayout.DEFAULT_SIZE, 379, Short.MAX_VALUE)
                    .addComponent(jButtonDashX521, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel25Layout.setVerticalGroup(
            jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel25Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButtonDashX521)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX522)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX523)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX524)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel26.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Convert formats", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N
        jPanel26.setToolTipText("");

        jButtonDashX525.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX525.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX525.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10514_red_refresh_icon.png"))); // NOI18N
        jButtonDashX525.setText("Convert to Base64                          ");
        jButtonDashX525.setActionCommand("Convert to Base64");
        jButtonDashX525.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX525.setIconTextGap(5);
        jButtonDashX525.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX525ActionPerformed(evt);
            }
        });

        jButtonDashX526.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jButtonDashX526.setForeground(new java.awt.Color(102, 102, 102));
        jButtonDashX526.setIcon(new javax.swing.ImageIcon(getClass().getResource("/10513_green_refresh_icon.png"))); // NOI18N
        jButtonDashX526.setText("Convert PEM / DER                        ");
        jButtonDashX526.setToolTipText("");
        jButtonDashX526.setActionCommand("Convert PEM <-> DER                        ");
        jButtonDashX526.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonDashX526.setIconTextGap(5);
        jButtonDashX526.setMargin(new java.awt.Insets(20, 40, 3, 14));
        jButtonDashX526.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDashX526ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel26Layout = new javax.swing.GroupLayout(jPanel26);
        jPanel26.setLayout(jPanel26Layout);
        jPanel26Layout.setHorizontalGroup(
            jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel26Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonDashX526, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonDashX525, javax.swing.GroupLayout.DEFAULT_SIZE, 379, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel26Layout.setVerticalGroup(
            jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel26Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jButtonDashX525)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jButtonDashX526)
                .addContainerGap(134, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanelDashboardLayout = new javax.swing.GroupLayout(jPanelDashboard);
        jPanelDashboard.setLayout(jPanelDashboardLayout);
        jPanelDashboardLayout.setHorizontalGroup(
            jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelDashboardLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addComponent(jPanel23, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(531, 531, 531))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelDashboardLayout.createSequentialGroup()
                        .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jPanel25, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jPanel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(86, 86, 86)
                        .addComponent(jPanel24, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(77, 77, 77)))
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jPanel26, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel22, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(1657, 1657, 1657)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel13)
                    .addComponent(jButtonDashConvert, javax.swing.GroupLayout.PREFERRED_SIZE, 307, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButtonDashTransform, javax.swing.GroupLayout.PREFERRED_SIZE, 307, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonDashGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 307, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(159, 159, 159)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jButtonDashAbout, javax.swing.GroupLayout.PREFERRED_SIZE, 307, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonDashAnalyze, javax.swing.GroupLayout.PREFERRED_SIZE, 307, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanelDashboardLayout.setVerticalGroup(
            jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelDashboardLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButtonDashTransform)
                .addGap(37, 37, 37)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelDashboardLayout.createSequentialGroup()
                        .addComponent(jButtonDashGenerate)
                        .addGap(717, 717, 717))
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addGap(200, 200, 200)
                        .addComponent(jButtonDashConvert)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
            .addGroup(jPanelDashboardLayout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel8, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPanel22, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(8, 8, 8)
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addComponent(jButtonDashAnalyze)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButtonDashAbout)
                        .addGap(65, 65, 65))
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jPanel26, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel25, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(27, 27, 27)
                        .addComponent(jPanel23, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
            .addGroup(jPanelDashboardLayout.createSequentialGroup()
                .addGroup(jPanelDashboardLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addGap(132, 132, 132)
                        .addComponent(jLabel13))
                    .addGroup(jPanelDashboardLayout.createSequentialGroup()
                        .addGap(250, 250, 250)
                        .addComponent(jPanel24, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTabbedPaneScreens.addTab("Dashboard", jPanelDashboard);

        jPanel19.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Certificates", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N
        jPanel19.setPreferredSize(new java.awt.Dimension(468, 372));

        outline.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        outline.getTableHeader().setResizingAllowed(false);
        jScrollPane1.setViewportView(outline);

        javax.swing.GroupLayout jPanel19Layout = new javax.swing.GroupLayout(jPanel19);
        jPanel19.setLayout(jPanel19Layout);
        jPanel19Layout.setHorizontalGroup(
            jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel19Layout.createSequentialGroup()
                .addComponent(jScrollPane1)
                .addContainerGap())
        );
        jPanel19Layout.setVerticalGroup(
            jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 348, Short.MAX_VALUE)
        );

        jPanel20.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Keys", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N

        jTablePK.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null, null, null}
            },
            new String [] {
                "", "ID", "Key Name", "Type", "Algo", "SHA256", "Related to"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTablePK.getTableHeader().setReorderingAllowed(false);
        jScrollPane9.setViewportView(jTablePK);
        jTablePK.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        if (jTablePK.getColumnModel().getColumnCount() > 0) {
            jTablePK.getColumnModel().getColumn(0).setResizable(false);
            jTablePK.getColumnModel().getColumn(0).setPreferredWidth(5);
        }

        javax.swing.GroupLayout jPanel20Layout = new javax.swing.GroupLayout(jPanel20);
        jPanel20.setLayout(jPanel20Layout);
        jPanel20Layout.setHorizontalGroup(
            jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, 986, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        jPanel20Layout.setVerticalGroup(
            jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel20Layout.createSequentialGroup()
                .addComponent(jScrollPane9, javax.swing.GroupLayout.PREFERRED_SIZE, 260, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 1, Short.MAX_VALUE))
        );

        jPanel21.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Associated CRLs", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N

        jTableCRL.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null}
            },
            new String [] {
                "ID", "Start Date", "End Date"
            }
        ));
        jScrollPane2.setViewportView(jTableCRL);

        javax.swing.GroupLayout jPanel21Layout = new javax.swing.GroupLayout(jPanel21);
        jPanel21.setLayout(jPanel21Layout);
        jPanel21Layout.setHorizontalGroup(
            jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 425, Short.MAX_VALUE)
            .addGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel21Layout.createSequentialGroup()
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 406, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        jPanel21Layout.setVerticalGroup(
            jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 0, Short.MAX_VALUE)
            .addGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel21Layout.createSequentialGroup()
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 261, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );

        javax.swing.GroupLayout jPanelACManagementLayout = new javax.swing.GroupLayout(jPanelACManagement);
        jPanelACManagement.setLayout(jPanelACManagementLayout);
        jPanelACManagementLayout.setHorizontalGroup(
            jPanelACManagementLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel19, javax.swing.GroupLayout.DEFAULT_SIZE, 1437, Short.MAX_VALUE)
            .addGroup(jPanelACManagementLayout.createSequentialGroup()
                .addComponent(jPanel20, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel21, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanelACManagementLayout.setVerticalGroup(
            jPanelACManagementLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelACManagementLayout.createSequentialGroup()
                .addComponent(jPanel19, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelACManagementLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jPanel21, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel20, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTabbedPaneScreens.addTab("My X509 Certificates", jPanelACManagement);

        jTabbedPaneGenerate.setMaximumSize(new java.awt.Dimension(1393, 662));

        jPanel2.setMaximumSize(new java.awt.Dimension(1388, 637));
        jPanel2.setMinimumSize(new java.awt.Dimension(1388, 637));
        jPanel2.setName(""); // NOI18N

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "PKCS#12 - Keystore", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jTextFieldKeystorePW.setToolTipText("");
        jTextFieldKeystorePW.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldKeystorePWActionPerformed(evt);
            }
        });

        jLabel1.setText("Keystore Password : ");

        jLabel2.setText("CN :");

        jLabel3.setText("Private Key Password : ");

        jSpinnerKeySize.setValue(new Integer(2048));

        jLabel4.setText("Key Size : ");

        jComboBoxAC.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxACActionPerformed(evt);
            }
        });

        jLabel6.setText("Target Issuer : ");

        jLabel9.setText("Algorithm :");

        jComboBoxAlgoP12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxAlgoP12ActionPerformed(evt);
            }
        });

        jLabel10.setText("Public Exponent :");
        jLabel10.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel10MouseEntered(evt);
            }
        });

        jSpinnerP12Expo.setEnabled(false);
        jSpinnerP12Expo.setValue(new Integer(65537));

        jLabel11.setText("Certainty : ");

        jSliderP12Certainty.setToolTipText("");
        jSliderP12Certainty.setValue(5);
        jSliderP12Certainty.setEnabled(false);
        jSliderP12Certainty.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jSliderP12CertaintyStateChanged(evt);
            }
        });

        jCheckBoxP12Expo.setSelected(true);
        jCheckBoxP12Expo.setText("auto");
        jCheckBoxP12Expo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxP12ExpoActionPerformed(evt);
            }
        });

        jCheckBoxP12Certainty.setSelected(true);
        jCheckBoxP12Certainty.setText("auto");
        jCheckBoxP12Certainty.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxP12CertaintyActionPerformed(evt);
            }
        });

        jButtonPKCS12Generate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Blue"));
        jButtonPKCS12Generate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonPKCS12Generate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonPKCS12Generate.setText("Generate keystore (PKCS#12)");
        jButtonPKCS12Generate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonPKCS12Generate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonPKCS12GenerateActionPerformed(evt);
            }
        });

        jDateChooserP12Expiry.setName("JDateChooserExpiry"); // NOI18N

        jLabel31.setText("Expiry Date :");

        jLabel40.setText("Target Filename : ");

        jTextFieldP12TargetFilename.setText("keystore.p12");

        jCheckBoxP12Write.setText("Make crt and key file");
        jCheckBoxP12Write.setActionCommand("Write crt and key ?");

        jLabelCertaintyValue.setText("5");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jLabel1))
                        .addGap(16, 16, 16))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jTextFieldCN)
                    .addComponent(jTextFieldKeystorePW)
                    .addComponent(jTextFieldPKCS8PW, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel4)
                    .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel40))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jSpinnerKeySize, javax.swing.GroupLayout.DEFAULT_SIZE, 150, Short.MAX_VALUE)
                            .addComponent(jTextFieldP12TargetFilename))
                        .addGap(14, 14, 14)
                        .addComponent(jCheckBoxP12Write))
                    .addComponent(jComboBoxAC, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(44, 44, 44)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9)
                    .addComponent(jLabel10)
                    .addComponent(jLabel11))
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jSpinnerP12Expo)
                            .addComponent(jComboBoxAlgoP12, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jSliderP12Certainty, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jCheckBoxP12Expo)
                        .addGap(10, 10, 10)
                        .addComponent(jLabel31, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jCheckBoxP12Certainty)
                        .addGap(18, 18, 18)
                        .addComponent(jLabelCertaintyValue)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jDateChooserP12Expiry, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonPKCS12Generate, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2)
                            .addComponent(jTextFieldCN, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(5, 5, 5)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel1)
                            .addComponent(jTextFieldKeystorePW, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel40)
                            .addComponent(jTextFieldP12TargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jCheckBoxP12Write))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jComboBoxAC, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel6)
                            .addComponent(jTextFieldPKCS8PW, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel3))
                        .addGap(44, 44, 44))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(jSpinnerKeySize, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jLabel4)
                                .addComponent(jLabel9)
                                .addComponent(jComboBoxAlgoP12, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jLabel31))
                            .addComponent(jDateChooserP12Expiry, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel10)
                                    .addComponent(jSpinnerP12Expo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jCheckBoxP12Expo))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jSliderP12Certainty, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jCheckBoxP12Certainty)
                                    .addComponent(jLabelCertaintyValue)
                                    .addComponent(jLabel11)))
                            .addComponent(jButtonPKCS12Generate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addContainerGap())))
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "PKCS#8 - Private Key", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jButtonPkGenerate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Red"));
        jButtonPkGenerate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonPkGenerate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonPkGenerate.setText("Generate Private Key (PKCS#8)");
        jButtonPkGenerate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonPkGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonPkGenerateActionPerformed(evt);
            }
        });

        jLabel12.setText("Key Size : ");

        jSpinnerKeySizePkSize.setValue(new Integer(2048));

        jTextFieldPkTargetFilename.setText("private.key");

        jSliderPkCertainty.setToolTipText("");
        jSliderPkCertainty.setValue(5);
        jSliderPkCertainty.setEnabled(false);
        jSliderPkCertainty.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jSliderPkCertaintyStateChanged(evt);
            }
        });

        jLabel14.setText("Certainty : ");

        jCheckBoxPkCertainty.setSelected(true);
        jCheckBoxPkCertainty.setText("auto");
        jCheckBoxPkCertainty.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxPkCertaintyActionPerformed(evt);
            }
        });

        jLabel15.setText("Public Exponent :");
        jLabel15.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel15MouseEntered(evt);
            }
        });

        jSpinnerPkExpo.setEnabled(false);
        jSpinnerPkExpo.setValue(new Integer(65537));

        jCheckBoxPkExpo.setSelected(true);
        jCheckBoxPkExpo.setText("auto");
        jCheckBoxPkExpo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxPkExpoActionPerformed(evt);
            }
        });

        jComboBoxAlgoPk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxAlgoPkActionPerformed(evt);
            }
        });

        jLabel16.setText("Algorithm :");

        jLabel17.setText("Private Key Password : ");

        jLabel27.setText("Target Filename : ");

        jLabel59.setText("Key Name :");

        jTextFieldPkTargetKeyName.setText("MyPrivateKey");

        jLabelCertaintyValuePk.setText("5");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addComponent(jLabel17)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(jTextFieldPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addComponent(jLabel27)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jTextFieldPkTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel16)
                        .addGap(66, 66, 66)
                        .addComponent(jComboBoxAlgoPk, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(137, 137, 137)
                        .addComponent(jLabel12)
                        .addGap(59, 59, 59))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel14)
                            .addComponent(jLabel15))
                        .addGap(18, 18, 18)))
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jSpinnerKeySizePkSize, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(80, 80, 80)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addGap(73, 73, 73)
                                .addComponent(jTextFieldPkTargetKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel59))
                        .addContainerGap(443, Short.MAX_VALUE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addComponent(jSpinnerPkExpo, javax.swing.GroupLayout.PREFERRED_SIZE, 135, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jCheckBoxPkExpo))
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addComponent(jSliderPkCertainty, javax.swing.GroupLayout.PREFERRED_SIZE, 135, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jCheckBoxPkCertainty)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabelCertaintyValuePk, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 423, Short.MAX_VALUE)
                        .addComponent(jButtonPkGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18))))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(jLabel59)
                                .addComponent(jTextFieldPkTargetKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(jLabel12)
                                .addComponent(jSpinnerKeySizePkSize, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addGap(2, 2, 2)
                                .addComponent(jButtonPkGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(jLabelCertaintyValuePk, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(jPanel3Layout.createSequentialGroup()
                                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                            .addComponent(jLabel15)
                                            .addComponent(jSpinnerPkExpo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(jCheckBoxPkExpo))
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                            .addComponent(jLabel14)
                                            .addComponent(jSliderPkCertainty, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(jCheckBoxPkCertainty)))))))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel27)
                            .addComponent(jTextFieldPkTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(4, 4, 4)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jComboBoxAlgoPk, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel16))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel17)
                            .addComponent(jTextFieldPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(84, 84, 84))
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "Certificate", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jLabel19.setText("CN :");

        jLabel20.setText("Private Key Password : ");

        jLabel21.setText("Private Key File :");

        jLabel22.setText("Public Key File :");

        jButtonBrowseCertPub.setText("Import Key");
        jButtonBrowseCertPub.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseCertPubActionPerformed(evt);
            }
        });

        jButtonBrowseCertPk.setText("Import Key");
        jButtonBrowseCertPk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseCertPkActionPerformed(evt);
            }
        });

        jLabel28.setText("Target Filename : ");

        jTextFieldCertTargetFilename.setText("enigma.crt");

        jDateChooserExpiry.setName("JDateChooserExpiry"); // NOI18N

        jLabel30.setText("Expiry Date :");

        jComboBoxCertAlgo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxCertAlgoActionPerformed(evt);
            }
        });

        jLabel61.setText("Algorithm :");

        jLabel66.setText("Certificate Version :");

        jComboBoxCertVersion.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxCertVersionActionPerformed(evt);
            }
        });

        jLabel67.setText("Certificate Name :");

        jTextFieldPubTargetCertName.setText("Enigma");

        jButtonCertGenerate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButtonCertGenerate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonCertGenerate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonCertGenerate.setText("Generate Certificate");
        jButtonCertGenerate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonCertGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCertGenerateActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel21)
                    .addComponent(jLabel22)
                    .addComponent(jLabel19))
                .addGap(37, 37, 37)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jTextFieldCertCN, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jComboBoxCertPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonBrowseCertPub, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jComboBoxCertPk, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonBrowseCertPk, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGap(43, 43, 43)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel28)
                        .addGap(37, 37, 37)
                        .addComponent(jTextFieldCertTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel20)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jTextFieldCertPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel67)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jTextFieldPubTargetCertName, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(38, 38, 38)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(jPanel4Layout.createSequentialGroup()
                            .addComponent(jLabel30, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(31, 31, 31)
                            .addComponent(jDateChooserExpiry, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGroup(jPanel4Layout.createSequentialGroup()
                            .addComponent(jLabel61)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jComboBoxCertAlgo, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel66)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jComboBoxCertVersion, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButtonCertGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(19, 19, 19))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel19)
                                    .addComponent(jTextFieldCertCN, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel21)
                                    .addComponent(jButtonBrowseCertPk)
                                    .addComponent(jComboBoxCertPk, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(13, 13, 13))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel20)
                                    .addComponent(jTextFieldCertPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jTextFieldPubTargetCertName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jLabel67)
                                    .addComponent(jLabel61))
                                .addGap(9, 9, 9)))
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel22)
                            .addComponent(jButtonBrowseCertPub)
                            .addComponent(jComboBoxCertPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel28)
                            .addComponent(jTextFieldCertTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel66)
                            .addComponent(jComboBoxCertVersion, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(jLabel30)
                                .addGap(6, 6, 6))
                            .addComponent(jDateChooserExpiry, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jButtonCertGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jComboBoxCertAlgo, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "Public Key", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jButtonPubGenerate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Yellow"));
        jButtonPubGenerate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonPubGenerate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonPubGenerate.setText("Generate Public Key");
        jButtonPubGenerate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonPubGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonPubGenerateActionPerformed(evt);
            }
        });

        jLabel23.setText("Private Key File :");

        jLabel24.setText("Private Key Password : ");

        jTextFieldPubPrivkeyPW.setMaximumSize(new java.awt.Dimension(6, 20));

        jLabel26.setText("Target Filename : ");

        jTextFieldPubTargetFilename.setText("public.key");

        jComboBoxPubPK.setMaximumSize(new java.awt.Dimension(29, 22));
        jComboBoxPubPK.setName(""); // NOI18N
        jComboBoxPubPK.setVerifyInputWhenFocusTarget(false);

        jLabel60.setText("Key Name :");

        jTextFieldPubTargetKeyName.setText("MyPublicKey");

        jButtonBrowsePubPk.setText("Import Key");
        jButtonBrowsePubPk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowsePubPkActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel23)
                    .addComponent(jLabel24))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jTextFieldPubPrivkeyPW, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jComboBoxPubPK, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonBrowsePubPk)
                .addGap(45, 45, 45)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel26)
                    .addComponent(jLabel60))
                .addGap(18, 18, 18)
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldPubTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextFieldPubTargetKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(480, 480, 480)
                .addComponent(jButtonPubGenerate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(20, 20, 20))
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jComboBoxPubPK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButtonBrowsePubPk))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jTextFieldPubPrivkeyPW, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(jLabel60)
                                .addComponent(jTextFieldPubTargetKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(jLabel23))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel24)
                            .addComponent(jLabel26)
                            .addComponent(jTextFieldPubTargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jButtonPubGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(18, Short.MAX_VALUE))
        );

        jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(), "PKCS#10", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jButtonCSRGenerate.setBackground(new java.awt.Color(248, 130, 0));
        jButtonCSRGenerate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonCSRGenerate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonCSRGenerate.setText("Generate CSR (PKCS#10)");
        jButtonCSRGenerate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonCSRGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCSRGenerateActionPerformed(evt);
            }
        });

        jLabel32.setText("Private Key File : ");

        jButtonBrowseP10Pk.setText("Import Key");
        jButtonBrowseP10Pk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseP10PkActionPerformed(evt);
            }
        });

        jLabel34.setText("Private Key Password : ");

        jTextFieldP10PkPw.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldP10PkPwActionPerformed(evt);
            }
        });

        jLabel36.setText("Requested CN :");

        jLabel37.setText("Target Filename : ");

        jTextFieldP10TargetFilename.setText("request.p10");

        jCheckBoxP10PubKey.setText("Use a specific Public Key ?");
        jCheckBoxP10PubKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxP10PubKeyActionPerformed(evt);
            }
        });

        jComboBoxCSRPubK.setEnabled(false);

        jButtonBrowseP10PubK.setText("Import Key");
        jButtonBrowseP10PubK.setEnabled(false);
        jButtonBrowseP10PubK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseP10PubKActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel34, javax.swing.GroupLayout.PREFERRED_SIZE, 128, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel36)
                            .addComponent(jLabel32))
                        .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel6Layout.createSequentialGroup()
                                .addGap(40, 40, 40)
                                .addComponent(jTextFieldP10CN, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel6Layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jTextFieldP10PkPw)
                                    .addComponent(jComboBoxCSRPk, 0, 146, Short.MAX_VALUE))))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonBrowseP10Pk)))
                .addGap(45, 45, 45)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addComponent(jCheckBoxP10PubKey)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jComboBoxCSRPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonBrowseP10PubK))
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addComponent(jLabel37)
                        .addGap(54, 54, 54)
                        .addComponent(jTextFieldP10TargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 324, Short.MAX_VALUE)
                .addComponent(jButtonCSRGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(14, 14, 14))
        );
        jPanel6Layout.setVerticalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel36)
                        .addComponent(jTextFieldP10CN, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jTextFieldP10TargetFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel37)))
                .addGap(18, 18, 18)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jCheckBoxP10PubKey)
                        .addComponent(jComboBoxCSRPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jButtonBrowseP10PubK))
                    .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel32)
                        .addComponent(jComboBoxCSRPk, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jButtonBrowseP10Pk)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextFieldP10PkPw, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel34))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addComponent(jButtonCSRGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, 127, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(35, 35, 35))
        );

        jTabbedPaneGenerate.addTab("X509", jPanel2);

        jTabbedPaneScreens.addTab("Generate", jTabbedPaneGenerate);

        jPanel11.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Sign", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanel11.setMaximumSize(new java.awt.Dimension(1427, 149));
        jPanel11.setMinimumSize(new java.awt.Dimension(1427, 149));
        jPanel11.setName(""); // NOI18N

        jLabel41.setText("Target File :");

        jLabel42.setText("Private Key for sign :");

        jTextFieldSignFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
                jTextFieldSignFileInputMethodTextChanged(evt);
            }
        });
        jTextFieldSignFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldSignFileActionPerformed(evt);
            }
        });

        jButtonBrowseSignFile.setText("Browse...");
        jButtonBrowseSignFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseSignFileActionPerformed(evt);
            }
        });

        jLabel43.setText("Algorithm :");

        jComboBoxAlgoSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxAlgoSignActionPerformed(evt);
            }
        });

        jButtonSign.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Blue"));
        jButtonSign.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonSign.setForeground(new java.awt.Color(255, 255, 255));
        jButtonSign.setText("Sign File");
        jButtonSign.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonSign.setMaximumSize(new java.awt.Dimension(219, 24));
        jButtonSign.setMinimumSize(new java.awt.Dimension(219, 24));
        jButtonSign.setPreferredSize(new java.awt.Dimension(219, 24));
        jButtonSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonSignActionPerformed(evt);
            }
        });

        jLabel46.setText("Private Key Password :");

        jCheckBox2.setText("Use custom name");
        jCheckBox2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox2ActionPerformed(evt);
            }
        });

        jLabel52.setText("Signer certificate :");

        jLabel44.setText("Output Filename : ");

        jTextFieldSignOutputFilename.setEnabled(false);
        jTextFieldSignOutputFilename.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldSignOutputFilenameActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
        jPanel11.setLayout(jPanel11Layout);
        jPanel11Layout.setHorizontalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(jLabel41)
                        .addGap(78, 78, 78)
                        .addComponent(jTextFieldSignFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(8, 8, 8)
                        .addComponent(jButtonBrowseSignFile, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(jLabel52, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jComboBoxSignSignerCert, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(jLabel42, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jComboBoxSignPK, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 105, Short.MAX_VALUE)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel43)
                    .addComponent(jLabel46)
                    .addComponent(jLabel44))
                .addGap(18, 18, 18)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addComponent(jComboBoxAlgoSign, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(637, Short.MAX_VALUE))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addComponent(jTextFieldSignOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(2, 2, 2)
                                .addComponent(jCheckBox2))
                            .addComponent(jTextFieldSignPkPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButtonSign, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(14, 14, 14))))
        );
        jPanel11Layout.setVerticalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel11Layout.createSequentialGroup()
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel43)
                            .addComponent(jComboBoxAlgoSign, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(10, 10, 10)
                        .addComponent(jButtonSign, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel11Layout.createSequentialGroup()
                        .addGap(3, 3, 3)
                        .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel41)
                                    .addComponent(jTextFieldSignFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jButtonBrowseSignFile))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel42)
                                    .addComponent(jComboBoxSignPK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel52)
                                    .addComponent(jComboBoxSignSignerCert, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(jPanel11Layout.createSequentialGroup()
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel46)
                                    .addComponent(jTextFieldSignPkPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jTextFieldSignOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jCheckBox2)
                                    .addComponent(jLabel44))))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel13.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Encrypt", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jLabel47.setText("Target File :");

        jTextFieldCipherFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
                jTextFieldCipherFileInputMethodTextChanged(evt);
            }
        });
        jTextFieldCipherFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldCipherFileActionPerformed(evt);
            }
        });

        jButtonBrowseCipherFile.setText("Browse...");
        jButtonBrowseCipherFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseCipherFileActionPerformed(evt);
            }
        });

        jButtonCipher.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Red"));
        jButtonCipher.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonCipher.setForeground(new java.awt.Color(255, 255, 255));
        jButtonCipher.setText("Encrypt File");
        jButtonCipher.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonCipher.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCipherActionPerformed(evt);
            }
        });

        jComboBoxAlgoCipher.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxAlgoCipherActionPerformed(evt);
            }
        });

        jLabel51.setText("Algorithm :");

        jLabel69.setText("Output Filename : ");

        jTextFieldCipherOutputFilename.setEnabled(false);

        jCheckBoxCustomCipher.setText("Use custom name");
        jCheckBoxCustomCipher.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxCustomCipherActionPerformed(evt);
            }
        });

        jLabel70.setText("Certificate for cipher :");

        javax.swing.GroupLayout jPanel13Layout = new javax.swing.GroupLayout(jPanel13);
        jPanel13.setLayout(jPanel13Layout);
        jPanel13Layout.setHorizontalGroup(
            jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel13Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel13Layout.createSequentialGroup()
                        .addComponent(jLabel47)
                        .addGap(78, 78, 78)
                        .addComponent(jTextFieldCipherFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(8, 8, 8)
                        .addComponent(jButtonBrowseCipherFile, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel13Layout.createSequentialGroup()
                        .addComponent(jLabel70, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jComboBoxCipherCert, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(102, 102, 102)
                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel51)
                    .addComponent(jLabel69))
                .addGap(43, 43, 43)
                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jComboBoxAlgoCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel13Layout.createSequentialGroup()
                        .addComponent(jTextFieldCipherOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(2, 2, 2)
                        .addComponent(jCheckBoxCustomCipher)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButtonCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(17, 17, 17))
        );
        jPanel13Layout.setVerticalGroup(
            jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel13Layout.createSequentialGroup()
                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel13Layout.createSequentialGroup()
                        .addGap(23, 23, 23)
                        .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel13Layout.createSequentialGroup()
                                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel51)
                                    .addComponent(jComboBoxAlgoCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jTextFieldCipherOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jCheckBoxCustomCipher)
                                    .addComponent(jLabel69)))
                            .addGroup(jPanel13Layout.createSequentialGroup()
                                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel47)
                                    .addComponent(jTextFieldCipherFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jButtonBrowseCipherFile))
                                .addGap(18, 18, 18)
                                .addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(jLabel70)
                                    .addComponent(jComboBoxCipherCert, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)))))
                    .addGroup(jPanel13Layout.createSequentialGroup()
                        .addGap(30, 30, 30)
                        .addComponent(jButtonCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(39, Short.MAX_VALUE))
        );

        jPanel15.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Decrypt", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jLabel45.setText("Target File :");

        jButtonBrowseEncrypt.setText("Browse...");
        jButtonBrowseEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseEncryptActionPerformed(evt);
            }
        });

        jLabel73.setText("Private Key for sign :");

        jLabel74.setText("Private Key Password :");

        jLabel75.setText("Output Filename : ");

        jTextFieldDecryptOutputFilename.setEnabled(false);
        jTextFieldDecryptOutputFilename.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldDecryptOutputFilenameActionPerformed(evt);
            }
        });

        jCheckBoxCustomDecrypt.setText("Use custom name");
        jCheckBoxCustomDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxCustomDecryptActionPerformed(evt);
            }
        });

        jButtonDecrypt.setBackground(new java.awt.Color(248, 130, 0));
        jButtonDecrypt.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonDecrypt.setForeground(new java.awt.Color(255, 255, 255));
        jButtonDecrypt.setText("Decrypt File");
        jButtonDecrypt.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDecryptActionPerformed(evt);
            }
        });

        jCheckBoxCustomDecryptTryAll.setText("Try everything !");
        jCheckBoxCustomDecryptTryAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxCustomDecryptTryAllActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel15Layout = new javax.swing.GroupLayout(jPanel15);
        jPanel15.setLayout(jPanel15Layout);
        jPanel15Layout.setHorizontalGroup(
            jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel15Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel15Layout.createSequentialGroup()
                        .addComponent(jLabel45)
                        .addGap(78, 78, 78)
                        .addComponent(jTextFieldDecryptFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(8, 8, 8)
                        .addComponent(jButtonBrowseEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel15Layout.createSequentialGroup()
                        .addComponent(jLabel73, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jCheckBoxCustomDecryptTryAll)
                            .addComponent(jComboBoxDecryptPK, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 100, Short.MAX_VALUE)
                .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel15Layout.createSequentialGroup()
                        .addComponent(jLabel75)
                        .addGap(37, 37, 37)
                        .addComponent(jTextFieldDecryptOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBoxCustomDecrypt))
                    .addGroup(jPanel15Layout.createSequentialGroup()
                        .addComponent(jLabel74)
                        .addGap(18, 18, 18)
                        .addComponent(jTextFieldDecryptPW, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(258, 258, 258)
                .addComponent(jButtonDecrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(17, 17, 17))
        );
        jPanel15Layout.setVerticalGroup(
            jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel15Layout.createSequentialGroup()
                .addContainerGap(21, Short.MAX_VALUE)
                .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel15Layout.createSequentialGroup()
                        .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel45)
                            .addComponent(jTextFieldDecryptFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButtonBrowseEncrypt)
                            .addComponent(jLabel75)
                            .addComponent(jTextFieldDecryptOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jCheckBoxCustomDecrypt))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel73)
                            .addComponent(jComboBoxDecryptPK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel74)
                            .addComponent(jTextFieldDecryptPW, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jButtonDecrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jCheckBoxCustomDecryptTryAll)
                .addGap(22, 22, 22))
        );

        jPanel16.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Verify Signature", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jCheckBoxCustomVerify.setText("Use custom name");
        jCheckBoxCustomVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxCustomVerifyActionPerformed(evt);
            }
        });

        jTextFieldVerifyOutputFilename.setEnabled(false);

        jLabel71.setText("Output Filename : ");

        jLabel72.setText("Validation certificate :");

        jLabel68.setText("Target File :");

        jTextFieldVerifyFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
                jTextFieldVerifyFileInputMethodTextChanged(evt);
            }
        });
        jTextFieldVerifyFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldVerifyFileActionPerformed(evt);
            }
        });

        jButtonBrowseVerifyFile.setText("Browse...");
        jButtonBrowseVerifyFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseVerifyFileActionPerformed(evt);
            }
        });

        jButtonValidate.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButtonValidate.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonValidate.setForeground(new java.awt.Color(255, 255, 255));
        jButtonValidate.setText("Validate Signature");
        jButtonValidate.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonValidate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonValidateActionPerformed(evt);
            }
        });

        jCheckBoxCustomVerifyTryAll.setText("Try everything !");
        jCheckBoxCustomVerifyTryAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBoxCustomVerifyTryAllActionPerformed(evt);
            }
        });

        jButtonVerify.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Yellow"));
        jButtonVerify.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonVerify.setForeground(new java.awt.Color(255, 255, 255));
        jButtonVerify.setText("Verify Signature");
        jButtonVerify.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jButtonVerify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonVerifyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel16Layout = new javax.swing.GroupLayout(jPanel16);
        jPanel16.setLayout(jPanel16Layout);
        jPanel16Layout.setHorizontalGroup(
            jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel16Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel16Layout.createSequentialGroup()
                        .addComponent(jLabel68)
                        .addGap(78, 78, 78)
                        .addComponent(jTextFieldVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(8, 8, 8)
                        .addComponent(jButtonBrowseVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel16Layout.createSequentialGroup()
                        .addComponent(jLabel72, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jCheckBoxCustomVerifyTryAll)
                            .addComponent(jComboBoxVerifyCert, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(101, 101, 101)
                .addComponent(jLabel71)
                .addGap(44, 44, 44)
                .addComponent(jTextFieldVerifyOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jCheckBoxCustomVerify)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 250, Short.MAX_VALUE)
                .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonVerify, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonValidate, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(17, 17, 17))
        );
        jPanel16Layout.setVerticalGroup(
            jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel16Layout.createSequentialGroup()
                .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel16Layout.createSequentialGroup()
                        .addGap(22, 22, 22)
                        .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel68)
                            .addComponent(jTextFieldVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButtonBrowseVerifyFile)
                            .addComponent(jLabel71)
                            .addComponent(jTextFieldVerifyOutputFilename, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jCheckBoxCustomVerify))
                        .addGap(34, 34, 34)
                        .addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel72)
                            .addComponent(jComboBoxVerifyCert, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBoxCustomVerifyTryAll))
                    .addGroup(jPanel16Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jButtonVerify, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jButtonValidate, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanel9Layout = new javax.swing.GroupLayout(jPanel9);
        jPanel9.setLayout(jPanel9Layout);
        jPanel9Layout.setHorizontalGroup(
            jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel15, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel16, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jPanel11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        jPanel9Layout.setVerticalGroup(
            jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel9Layout.createSequentialGroup()
                .addComponent(jPanel11, javax.swing.GroupLayout.PREFERRED_SIZE, 144, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(7, 7, 7)
                .addComponent(jPanel13, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel16, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(12, 12, 12)
                .addComponent(jPanel15, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("X509", jPanel9);

        javax.swing.GroupLayout jPanelTransformLayout = new javax.swing.GroupLayout(jPanelTransform);
        jPanelTransform.setLayout(jPanelTransformLayout);
        jPanelTransformLayout.setHorizontalGroup(
            jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1432, Short.MAX_VALUE)
            .addGroup(jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jTabbedPane1))
        );
        jPanelTransformLayout.setVerticalGroup(
            jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 662, Short.MAX_VALUE)
            .addGroup(jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jTabbedPane1))
        );

        jTabbedPaneScreens.addTab("Transform", jPanelTransform);

        jLabel7.setFont(new java.awt.Font("Malgun Gothic", 1, 16)); // NOI18N
        jLabel7.setText("Target file : ");

        jTextFieldDrop.setFont(new java.awt.Font("Segoe UI", 0, 16)); // NOI18N
        jTextFieldDrop.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(204, 204, 204)));

        jButton7.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Red"));
        jButton7.setFont(new java.awt.Font("Leelawadee UI", 1, 16)); // NOI18N
        jButton7.setForeground(new java.awt.Color(255, 255, 255));
        jButton7.setText("Browse...");
        jButton7.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton7ActionPerformed(evt);
            }
        });

        jEditorPaneIdentifierResults.setEditable(false);
        jEditorPaneIdentifierResults.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jScrollPane3.setViewportView(jEditorPaneIdentifierResults);

        jLabel8.setFont(new java.awt.Font("Malgun Gothic", 1, 14)); // NOI18N
        jLabel8.setText("Results");

        jPanel12.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Drag & Drop Zone", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 14))); // NOI18N
        jPanel12.setName(""); // NOI18N

        jTextAreaDrop.setBackground(new java.awt.Color(227, 227, 227));
        jTextAreaDrop.setColumns(20);
        jTextAreaDrop.setRows(5);
        jTextAreaDrop.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jTextAreaDrop.setFocusable(false);
        jScrollPane4.setViewportView(jTextAreaDrop);

        javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
        jPanel12.setLayout(jPanel12Layout);
        jPanel12Layout.setHorizontalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane4)
                .addContainerGap())
        );
        jPanel12Layout.setVerticalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel12Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 111, Short.MAX_VALUE)
                .addContainerGap())
        );

        jButton8.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Blue"));
        jButton8.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jButton8.setForeground(new java.awt.Color(255, 255, 255));
        jButton8.setText("Start Analysis");
        jButton8.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButton8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton8ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanelAnalyzeLayout = new javax.swing.GroupLayout(jPanelAnalyze);
        jPanelAnalyze.setLayout(jPanelAnalyzeLayout);
        jPanelAnalyzeLayout.setHorizontalGroup(
            jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                .addGroup(jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                        .addGroup(jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel8))
                            .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                                .addGap(600, 600, 600)
                                .addComponent(jButton8, javax.swing.GroupLayout.PREFERRED_SIZE, 206, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                                .addGap(435, 435, 435)
                                .addGroup(jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jPanel12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                                        .addComponent(jLabel7)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jTextFieldDrop, javax.swing.GroupLayout.PREFERRED_SIZE, 302, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton7, javax.swing.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)))))
                        .addGap(0, 488, Short.MAX_VALUE))
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 1431, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanelAnalyzeLayout.setVerticalGroup(
            jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelAnalyzeLayout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addGroup(jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldDrop)
                    .addGroup(jPanelAnalyzeLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel7)
                        .addComponent(jButton7, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel12, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton8, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(14, 14, 14)
                .addComponent(jLabel8)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 353, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        jTabbedPaneScreens.addTab("Analyze", jPanelAnalyze);

        jPanel18.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Base64 Encode/Decode", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N
        jPanel18.setFont(new java.awt.Font("Segoe UI Semibold", 0, 12)); // NOI18N

        jTextAreaOriginalData.setColumns(20);
        jTextAreaOriginalData.setFont(new java.awt.Font("Malgun Gothic", 0, 14)); // NOI18N
        jTextAreaOriginalData.setRows(5);
        jScrollPane5.setViewportView(jTextAreaOriginalData);

        jTextAreaBase64Data.setColumns(20);
        jTextAreaBase64Data.setFont(new java.awt.Font("Malgun Gothic", 0, 14)); // NOI18N
        jTextAreaBase64Data.setRows(5);
        jScrollPane8.setViewportView(jTextAreaBase64Data);

        jLabel54.setFont(new java.awt.Font("Malgun Gothic", 1, 18)); // NOI18N
        jLabel54.setText("Base64 Data");

        jLabel55.setFont(new java.awt.Font("Malgun Gothic", 1, 18)); // NOI18N
        jLabel55.setText("ASCII Data");

        jButtonEncodeBase64.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Blue"));
        jButtonEncodeBase64.setFont(new java.awt.Font("Corbel", 1, 18)); // NOI18N
        jButtonEncodeBase64.setForeground(new java.awt.Color(255, 255, 255));
        jButtonEncodeBase64.setText("< ENCODE BASE64 <");
        jButtonEncodeBase64.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonEncodeBase64ActionPerformed(evt);
            }
        });

        jButtonDecodeBase64.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButtonDecodeBase64.setFont(new java.awt.Font("Corbel", 1, 18)); // NOI18N
        jButtonDecodeBase64.setForeground(new java.awt.Color(255, 255, 255));
        jButtonDecodeBase64.setText("> DECODE BASE64 >");
        jButtonDecodeBase64.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDecodeBase64ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel18Layout = new javax.swing.GroupLayout(jPanel18);
        jPanel18.setLayout(jPanel18Layout);
        jPanel18Layout.setHorizontalGroup(
            jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
                .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel18Layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jButtonDecodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 223, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButtonEncodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 223, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18))
                    .addGroup(jPanel18Layout.createSequentialGroup()
                        .addGap(217, 217, 217)
                        .addComponent(jLabel54)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel18Layout.createSequentialGroup()
                        .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 561, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(22, 22, 22))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
                        .addComponent(jLabel55, javax.swing.GroupLayout.PREFERRED_SIZE, 119, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(224, 224, 224))))
            .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel18Layout.createSequentialGroup()
                    .addGap(20, 20, 20)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 553, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(837, Short.MAX_VALUE)))
        );
        jPanel18Layout.setVerticalGroup(
            jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel18Layout.createSequentialGroup()
                .addContainerGap(20, Short.MAX_VALUE)
                .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
                        .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel54)
                            .addComponent(jLabel55))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 299, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
                        .addComponent(jButtonDecodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(55, 55, 55)
                        .addComponent(jButtonEncodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(56, 56, 56))))
            .addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
                    .addContainerGap(40, Short.MAX_VALUE)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 298, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap()))
        );

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Convert PEM/DER", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N
        jPanel7.setFont(new java.awt.Font("Segoe UI Semibold", 0, 12)); // NOI18N

        jRadioButtonDER.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jRadioButtonDER.setText("DER");
        jRadioButtonDER.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButtonDERActionPerformed(evt);
            }
        });

        jLabel33.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jLabel33.setText("Source file :");

        jButtonConvertSourceFile.setText("Browse...");
        jButtonConvertSourceFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonConvertSourceFileActionPerformed(evt);
            }
        });

        jRadioButtonPEM.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jRadioButtonPEM.setSelected(true);
        jRadioButtonPEM.setText("PEM");
        jRadioButtonPEM.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButtonPEMActionPerformed(evt);
            }
        });

        jRadioButtonPEMorDER.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jRadioButtonPEMorDER.setText("I don't know");
        jRadioButtonPEMorDER.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButtonPEMorDERActionPerformed(evt);
            }
        });

        jButtonConvertPEM.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Yellow"));
        jButtonConvertPEM.setFont(new java.awt.Font("Corbel", 1, 18)); // NOI18N
        jButtonConvertPEM.setForeground(new java.awt.Color(255, 255, 255));
        jButtonConvertPEM.setText("Convert to PEM");
        jButtonConvertPEM.setMargin(new java.awt.Insets(10, 14, 7, 14));
        jButtonConvertPEM.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonConvertPEMActionPerformed(evt);
            }
        });

        jButtonConvertDER.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Red"));
        jButtonConvertDER.setFont(new java.awt.Font("Corbel", 1, 18)); // NOI18N
        jButtonConvertDER.setForeground(new java.awt.Color(255, 255, 255));
        jButtonConvertDER.setText("Convert to DER");
        jButtonConvertDER.setMargin(new java.awt.Insets(10, 14, 7, 14));
        jButtonConvertDER.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonConvertDERActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel33)
                    .addComponent(jRadioButtonPEM, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(jRadioButtonDER, javax.swing.GroupLayout.PREFERRED_SIZE, 55, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jRadioButtonPEMorDER))
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(jTextFieldConvertSourceFile, javax.swing.GroupLayout.PREFERRED_SIZE, 363, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonConvertSourceFile, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(437, 437, 437)
                .addComponent(jButtonConvertPEM, javax.swing.GroupLayout.PREFERRED_SIZE, 161, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonConvertDER, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(59, 59, 59))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jButtonConvertDER, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonConvertPEM, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel7Layout.createSequentialGroup()
                        .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel33)
                            .addComponent(jTextFieldConvertSourceFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButtonConvertSourceFile))
                        .addGap(13, 13, 13)
                        .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jRadioButtonPEM)
                            .addComponent(jRadioButtonDER)
                            .addComponent(jRadioButtonPEMorDER))))
                .addContainerGap(12, Short.MAX_VALUE))
        );

        jPanel10.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Build PKCS12 from Certificate and Private Key", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N
        jPanel10.setFont(new java.awt.Font("Segoe UI Semibold", 0, 12)); // NOI18N

        jLabel35.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jLabel35.setText("Private Key :");

        jButtonBuildPKCS12Maker.setBackground(new java.awt.Color(144, 118, 197));
        jButtonBuildPKCS12Maker.setFont(new java.awt.Font("Corbel", 1, 18)); // NOI18N
        jButtonBuildPKCS12Maker.setForeground(new java.awt.Color(255, 255, 255));
        jButtonBuildPKCS12Maker.setText("Build PKCS12");
        jButtonBuildPKCS12Maker.setMargin(new java.awt.Insets(10, 14, 7, 14));
        jButtonBuildPKCS12Maker.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBuildPKCS12MakerActionPerformed(evt);
            }
        });

        jLabel90.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jLabel90.setText("Certificate :");

        jComboBoxPKCS12MakerPK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxPKCS12MakerPKActionPerformed(evt);
            }
        });

        jLabel91.setFont(new java.awt.Font("Malgun Gothic", 0, 12)); // NOI18N
        jLabel91.setText("Password : ");

        jPasswordFieldPKCS12Maker.setText("jPasswordField1");

        javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
        jPanel10.setLayout(jPanel10Layout);
        jPanel10Layout.setHorizontalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel91, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel35, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel90, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jPasswordFieldPKCS12Maker)
                    .addComponent(jComboBoxPKCS12MakerPK, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jComboBoxPKCS12MakerCert, javax.swing.GroupLayout.PREFERRED_SIZE, 363, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(538, 538, 538)
                .addComponent(jButtonBuildPKCS12Maker, javax.swing.GroupLayout.PREFERRED_SIZE, 354, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel10Layout.setVerticalGroup(
            jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel10Layout.createSequentialGroup()
                .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(19, 19, 19)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jComboBoxPKCS12MakerPK, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel35))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel90)
                            .addComponent(jComboBoxPKCS12MakerCert, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel91)
                            .addComponent(jPasswordFieldPKCS12Maker, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel10Layout.createSequentialGroup()
                        .addGap(38, 38, 38)
                        .addComponent(jButtonBuildPKCS12Maker, javax.swing.GroupLayout.PREFERRED_SIZE, 59, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(23, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout jPanelConvertLayout = new javax.swing.GroupLayout(jPanelConvert);
        jPanelConvert.setLayout(jPanelConvertLayout);
        jPanelConvertLayout.setHorizontalGroup(
            jPanelConvertLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel18, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(jPanelConvertLayout.createSequentialGroup()
                .addGroup(jPanelConvertLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel10, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanelConvertLayout.setVerticalGroup(
            jPanelConvertLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelConvertLayout.createSequentialGroup()
                .addComponent(jPanel18, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel10, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        jPanel7.getAccessibleContext().setAccessibleName("Convert Certificate PEM/DER");

        jTabbedPaneScreens.addTab("Convert", jPanelConvert);

        jPanel27.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "RSA Breaking Pollard Algorithm", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Malgun Gothic", 1, 12))); // NOI18N
        jPanel27.setFont(new java.awt.Font("Segoe UI Semibold", 0, 12)); // NOI18N

        jLabel58.setText("Public Key :");

        jTextFieldBrutePubKey.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
                jTextFieldBrutePubKeyInputMethodTextChanged(evt);
            }
        });
        jTextFieldBrutePubKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldBrutePubKeyActionPerformed(evt);
            }
        });

        jButtonBrowseBrutePublicKey.setText("Browse...");
        jButtonBrowseBrutePublicKey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseBrutePublicKeyActionPerformed(evt);
            }
        });

        jLabel79.setText("Ciphered File :");

        jTextFieldBruteFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
            public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
            }
            public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
                jTextFieldBruteFileInputMethodTextChanged(evt);
            }
        });
        jTextFieldBruteFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldBruteFileActionPerformed(evt);
            }
        });

        jButtonBrowseBruteFile.setText("Browse...");
        jButtonBrowseBruteFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseBruteFileActionPerformed(evt);
            }
        });

        jButtonBruteForce.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Blue"));
        jButtonBruteForce.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jButtonBruteForce.setForeground(new java.awt.Color(255, 255, 255));
        jButtonBruteForce.setText("Start Brute Forcing");
        jButtonBruteForce.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonBruteForce.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBruteForceActionPerformed(evt);
            }
        });

        jButtonBruteForceCancel.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Red"));
        jButtonBruteForceCancel.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jButtonBruteForceCancel.setForeground(new java.awt.Color(255, 255, 255));
        jButtonBruteForceCancel.setText("Cancel Brute Force");
        jButtonBruteForceCancel.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonBruteForceCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBruteForceCancelActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel27Layout = new javax.swing.GroupLayout(jPanel27);
        jPanel27.setLayout(jPanel27Layout);
        jPanel27Layout.setHorizontalGroup(
            jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel27Layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(jPanel27Layout.createSequentialGroup()
                        .addComponent(jLabel58, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jTextFieldBrutePubKey, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jButtonBrowseBrutePublicKey, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel27Layout.createSequentialGroup()
                        .addComponent(jLabel79, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jTextFieldBruteFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jButtonBrowseBruteFile, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 805, Short.MAX_VALUE)
                .addGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jButtonBruteForce, javax.swing.GroupLayout.PREFERRED_SIZE, 206, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonBruteForceCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 206, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(34, 34, 34))
        );
        jPanel27Layout.setVerticalGroup(
            jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel27Layout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel58)
                    .addComponent(jTextFieldBrutePubKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonBrowseBrutePublicKey)
                    .addComponent(jButtonBruteForce, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel79)
                        .addComponent(jTextFieldBruteFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jButtonBrowseBruteFile))
                    .addComponent(jButtonBruteForceCancel, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jEditorPaneIBruteForceResult.setEditable(false);
        jEditorPaneIBruteForceResult.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jScrollPane10.setViewportView(jEditorPaneIBruteForceResult);

        jLabel18.setFont(new java.awt.Font("Malgun Gothic", 1, 14)); // NOI18N
        jLabel18.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel18.setText("Results");

        jLabelLoading.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelLoading.setIcon(new javax.swing.ImageIcon(getClass().getResource("/loading.gif"))); // NOI18N
        jLabelLoading.setAlignmentY(0.0F);
        jLabelLoading.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanelBruteForceLayout = new javax.swing.GroupLayout(jPanelBruteForce);
        jPanelBruteForce.setLayout(jPanelBruteForceLayout);
        jPanelBruteForceLayout.setHorizontalGroup(
            jPanelBruteForceLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelBruteForceLayout.createSequentialGroup()
                .addGroup(jPanelBruteForceLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel27, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(jPanelBruteForceLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jScrollPane10)))
                .addContainerGap())
            .addGroup(jPanelBruteForceLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel18)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabelLoading, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanelBruteForceLayout.setVerticalGroup(
            jPanelBruteForceLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelBruteForceLayout.createSequentialGroup()
                .addComponent(jPanel27, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanelBruteForceLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabelLoading, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel18))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane10, javax.swing.GroupLayout.DEFAULT_SIZE, 472, Short.MAX_VALUE)
                .addContainerGap())
        );

        jTabbedPaneScreens.addTab("Brute Force", jPanelBruteForce);

        jListEvents.setModel(new DefaultListModel<String>());
        jScrollPaneForEvents.setViewportView(jListEvents);

        javax.swing.GroupLayout jPanelEventsLayout = new javax.swing.GroupLayout(jPanelEvents);
        jPanelEvents.setLayout(jPanelEventsLayout);
        jPanelEventsLayout.setHorizontalGroup(
            jPanelEventsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelEventsLayout.createSequentialGroup()
                .addGroup(jPanelEventsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jProgressBarEnigma, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jScrollPaneForEvents, javax.swing.GroupLayout.Alignment.LEADING))
                .addGap(0, 0, 0))
        );
        jPanelEventsLayout.setVerticalGroup(
            jPanelEventsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelEventsLayout.createSequentialGroup()
                .addComponent(jScrollPaneForEvents, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jProgressBarEnigma, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        jTextFieldGlobalOutput.setMargin(new java.awt.Insets(1, 5, 1, 1));

        jLabelGlobalDir.setFont(new java.awt.Font("Malgun Gothic", 1, 14)); // NOI18N
        jLabelGlobalDir.setText("Global Output Directory :");

        jButtonBrowseGlobalOutput.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jButtonBrowseGlobalOutput.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonBrowseGlobalOutput.setForeground(new java.awt.Color(255, 255, 255));
        jButtonBrowseGlobalOutput.setIcon(new javax.swing.ImageIcon(getClass().getResource("/look.png"))); // NOI18N
        jButtonBrowseGlobalOutput.setText("Set output dir");
        jButtonBrowseGlobalOutput.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonBrowseGlobalOutput.setIconTextGap(8);
        jButtonBrowseGlobalOutput.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseGlobalOutputActionPerformed(evt);
            }
        });

        jButtonBrowseGlobalOutput1.setBackground(javax.swing.UIManager.getDefaults().getColor("Actions.Yellow"));
        jButtonBrowseGlobalOutput1.setFont(new java.awt.Font("Lato", 1, 16)); // NOI18N
        jButtonBrowseGlobalOutput1.setForeground(new java.awt.Color(255, 255, 255));
        jButtonBrowseGlobalOutput1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/directory.png"))); // NOI18N
        jButtonBrowseGlobalOutput1.setText("Open Explorer");
        jButtonBrowseGlobalOutput1.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        jButtonBrowseGlobalOutput1.setIconTextGap(8);
        jButtonBrowseGlobalOutput1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBrowseGlobalOutput1ActionPerformed(evt);
            }
        });

        menuBar.setVerifyInputWhenFocusTarget(false);

        fileMenu.setMnemonic('f');
        fileMenu.setText("File");

        openMenuItem.setMnemonic('o');
        openMenuItem.setText("Import");
        fileMenu.add(openMenuItem);

        saveMenuItem.setMnemonic('s');
        saveMenuItem.setText("Export");
        fileMenu.add(saveMenuItem);

        exitMenuItem.setMnemonic('x');
        exitMenuItem.setText("Quit");
        exitMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        editMenu.setMnemonic('e');
        editMenu.setText("Fonctions");

        cutMenuItem.setMnemonic('t');
        cutMenuItem.setText("Generate");
        editMenu.add(cutMenuItem);

        copyMenuItem.setMnemonic('y');
        copyMenuItem.setText("Analyze");
        copyMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                copyMenuItemActionPerformed(evt);
            }
        });
        editMenu.add(copyMenuItem);

        pasteMenuItem.setMnemonic('p');
        pasteMenuItem.setText("Transform");
        editMenu.add(pasteMenuItem);

        deleteMenuItem.setMnemonic('d');
        deleteMenuItem.setText("Convert");
        editMenu.add(deleteMenuItem);

        jMenuItem1.setText("X509 PKI");
        editMenu.add(jMenuItem1);

        menuBar.add(editMenu);

        helpMenu.setMnemonic('h');
        helpMenu.setText("Help");

        aboutMenuItem.setMnemonic('a');
        aboutMenuItem.setText("About");
        aboutMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aboutMenuItemActionPerformed(evt);
            }
        });
        helpMenu.add(aboutMenuItem);

        menuBar.add(helpMenu);

        setJMenuBar(menuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 6, Short.MAX_VALUE)
                .addComponent(jTabbedPaneScreens, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addComponent(jPanelEvents, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabelGlobalDir)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextFieldGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 900, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonBrowseGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 172, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonBrowseGlobalOutput1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(jTabbedPaneScreens, javax.swing.GroupLayout.PREFERRED_SIZE, 693, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextFieldGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabelGlobalDir)
                    .addComponent(jButtonBrowseGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonBrowseGlobalOutput1, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 7, Short.MAX_VALUE)
                .addComponent(jPanelEvents, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButtonDashX514ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX514ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(6);
    }//GEN-LAST:event_jButtonDashX514ActionPerformed

    private void jButtonDashX513ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX513ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(4);
    }//GEN-LAST:event_jButtonDashX513ActionPerformed

    private void jButtonDashX512ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX512ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(1);
    }//GEN-LAST:event_jButtonDashX512ActionPerformed

    private void jButtonDashX510ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX510ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(2);
    }//GEN-LAST:event_jButtonDashX510ActionPerformed

    private void jButtonDashX509ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX509ActionPerformed
        // TODO add your handling code here:
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.YEAR, 2);
        Date newDate = c.getTime();
        jDateChooserWExpiry.setDate(newDate);
        jTextFieldCountry.setText("US");
        jFrameCertWizard.setVisible(true);
    }//GEN-LAST:event_jButtonDashX509ActionPerformed

    private void jButtonDashAboutActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashAboutActionPerformed
        // TODO add your handling code here:
        jFrameAbout.setDefaultCloseOperation(jFrameAbout.EXIT_ON_CLOSE);
        jFrameAbout.setVisible(true);
    }//GEN-LAST:event_jButtonDashAboutActionPerformed

    private void jButtonDashConvertActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashConvertActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(5);
    }//GEN-LAST:event_jButtonDashConvertActionPerformed

    private void jButtonDashAnalyzeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashAnalyzeActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(4);
    }//GEN-LAST:event_jButtonDashAnalyzeActionPerformed

    private void jButtonDashTransformActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashTransformActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(3);
    }//GEN-LAST:event_jButtonDashTransformActionPerformed

    private void jButtonDashGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashGenerateActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(2);
    }//GEN-LAST:event_jButtonDashGenerateActionPerformed

    private void jButtonDashX517ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX517ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonDashX517ActionPerformed

    private void jButtonDashX518ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX518ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonDashX518ActionPerformed

    private void jButtonDashX519ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX519ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonDashX519ActionPerformed

    private void jButtonDashX520ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX520ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonDashX520ActionPerformed

    private void jButtonDashX521ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX521ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(3);
    }//GEN-LAST:event_jButtonDashX521ActionPerformed

    private void jButtonDashX522ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX522ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(3);
    }//GEN-LAST:event_jButtonDashX522ActionPerformed

    private void jButtonDashX523ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX523ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(3);
    }//GEN-LAST:event_jButtonDashX523ActionPerformed

    private void jButtonDashX524ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX524ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(3);
    }//GEN-LAST:event_jButtonDashX524ActionPerformed

    private void jButtonDashX525ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX525ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(5);
    }//GEN-LAST:event_jButtonDashX525ActionPerformed

    private void jButtonDashX526ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDashX526ActionPerformed
        // TODO add your handling code here:
        jTabbedPaneScreens.setSelectedIndex(5);
    }//GEN-LAST:event_jButtonDashX526ActionPerformed

    private void jButtonBrowseP10PubKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseP10PubKActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonBrowseP10PubKActionPerformed

    private void jCheckBoxP10PubKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxP10PubKeyActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jButtonBrowseP10PubK.setEnabled(true);
            jComboBoxCSRPubK.setEnabled(true);
        } else {
            jButtonBrowseP10PubK.setEnabled(false);
            jComboBoxCSRPubK.setEnabled(false);
        }
    }//GEN-LAST:event_jCheckBoxP10PubKeyActionPerformed

    private void jTextFieldP10PkPwActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextFieldP10PkPwActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldP10PkPwActionPerformed

    private void jButtonBrowseP10PkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseP10PkActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonBrowseP10PkActionPerformed

    private void jButtonCSRGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCSRGenerateActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.buildCSRfromKeyPair(jTextFieldP10CN.getText(), ((String) jComboBoxCSRPk.getSelectedItem()),
                jTextFieldP10PkPw.getText(), (String) jComboBoxPubPK.getSelectedItem(),
                jTextFieldP10TargetFilename.getText(), jTextFieldGlobalOutput.getText());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }//GEN-LAST:event_jButtonCSRGenerateActionPerformed

    private void jButtonBrowsePubPkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowsePubPkActionPerformed
        // TODO add your handling code here:
        jDialogFileImport.setVisible(true);
    }//GEN-LAST:event_jButtonBrowsePubPkActionPerformed

    private void jButtonPubGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonPubGenerateActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.generatePublicKeyFromPrivateKey((String) jComboBoxPubPK.getSelectedItem(),
                jTextFieldPubPrivkeyPW.getText(), jTextFieldGlobalOutput.getText(),
                jTextFieldPubTargetFilename.getText(), (String) jTextFieldPubTargetKeyName.getText());
        refreshX509KeyTable();
        refreshPubKObjects();
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }//GEN-LAST:event_jButtonPubGenerateActionPerformed

    private void jButtonCertGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCertGenerateActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.generateCertificateFromPublicKeyAndPrivateKey(jTextFieldCertCN.getText(),
                (String) jComboBoxCertPubK.getSelectedItem(), (String) jComboBoxCertPk.getSelectedItem(),
                jTextFieldCertPkPw.getText(), jTextFieldGlobalOutput.getText(), jTextFieldCertTargetFilename.getText(),
                jDateChooserExpiry.getDate(), (String) jComboBoxCertAlgo.getSelectedItem(),
                (String) jComboBoxCertVersion.getSelectedItem(), jTextFieldPubTargetCertName.getText());
        refreshX509CertOutline();
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }//GEN-LAST:event_jButtonCertGenerateActionPerformed

    private void jComboBoxCertVersionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxCertVersionActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBoxCertVersionActionPerformed

    private void jComboBoxCertAlgoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxCertAlgoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBoxCertAlgoActionPerformed

    private void jButtonBrowseCertPkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseCertPkActionPerformed
        // TODO add your handling code here:
        jDialogFileImport.setVisible(true);
    }//GEN-LAST:event_jButtonBrowseCertPkActionPerformed

    private void jButtonBrowseCertPubActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseCertPubActionPerformed
        // TODO add your handling code here:
        jDialogFileImportPublic.setVisible(true);
    }//GEN-LAST:event_jButtonBrowseCertPubActionPerformed

    private void jComboBoxAlgoPkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxAlgoPkActionPerformed
        // TODO add your handling code here:
        if ("DH".equals(((String) jComboBoxAlgoPk.getSelectedItem()))) {
            jSpinnerKeySizePkSize.setEnabled(false);
            jSpinnerKeySizePkSize.setValue(2048);
        } else {
            jSpinnerKeySizePkSize.setEnabled(true);
        }
    }//GEN-LAST:event_jComboBoxAlgoPkActionPerformed

    private void jCheckBoxPkExpoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxPkExpoActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jSpinnerPkExpo.setEnabled(false);
        } else {
            jSpinnerPkExpo.setEnabled(true);
        }
    }//GEN-LAST:event_jCheckBoxPkExpoActionPerformed

    private void jLabel15MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel15MouseEntered
        // TODO add your handling code here:
    }//GEN-LAST:event_jLabel15MouseEntered

    private void jCheckBoxPkCertaintyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxPkCertaintyActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jSliderPkCertainty.setEnabled(false);
        } else {
            jSliderPkCertainty.setEnabled(true);
        }
    }//GEN-LAST:event_jCheckBoxPkCertaintyActionPerformed

    private void jSliderPkCertaintyStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jSliderPkCertaintyStateChanged
        // TODO add your handling code here:
        int certainty = jSliderPkCertainty.getValue();
        jLabelCertaintyValuePk.setText("" + certainty);

    }//GEN-LAST:event_jSliderPkCertaintyStateChanged

    private void jButtonPkGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonPkGenerateActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String algo = String.valueOf(jComboBoxAlgoPk.getSelectedItem());
        String outRet = cg.buildPrivateKey(jTextFieldGlobalOutput.getText(), jTextFieldPkPw.getText(),
                jTextFieldPkTargetFilename.getText(), (int) jSpinnerKeySizePkSize.getValue(),
                Integer.toString((Integer) jSpinnerPkExpo.getValue()), jSliderPkCertainty.getValue(), algo,
                jTextFieldPkTargetKeyName.getText());
        refreshX509KeyTable();
        refreshPKObjects();
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }//GEN-LAST:event_jButtonPkGenerateActionPerformed

    private void jButtonPKCS12GenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonPKCS12GenerateActionPerformed
        // TODO add your handling code here:
        Integer pubExpo = (Integer) jSpinnerP12Expo.getValue();
        if (!jSpinnerP12Expo.isEnabled()) {
            pubExpo = new Integer(props.getProperty("defaultPublicExponent"));
        }
        int certainty = jSliderP12Certainty.getValue();
        if (!jSliderP12Certainty.isEnabled()) {
            certainty = Integer.parseInt(props.getProperty("defaultCertainty"));
        }
        CryptoGenerator.generatePKCS12((int) jSpinnerKeySize.getValue(), jTextFieldCN.getText(),
                jTextFieldKeystorePW.getText(), jTextFieldPKCS8PW.getText(), jTextFieldGlobalOutput.getText(),
                pubExpo.toString(), certainty, jDateChooserP12Expiry.getDate(), jTextFieldP12TargetFilename.getText(),
                jCheckBoxP12Write.isSelected(), (String) jComboBoxAC.getSelectedItem());
        ((DefaultListModel) jListEvents.getModel()).addElement("PKCS#12 successfully generated for "
                + jTextFieldCN.getText() + " in directory " + jTextFieldGlobalOutput.getText() + ".");
    }//GEN-LAST:event_jButtonPKCS12GenerateActionPerformed

    private void jCheckBoxP12CertaintyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxP12CertaintyActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jSliderP12Certainty.setEnabled(false);
        } else {
            jSliderP12Certainty.setEnabled(true);
        }
    }//GEN-LAST:event_jCheckBoxP12CertaintyActionPerformed

    private void jCheckBoxP12ExpoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxP12ExpoActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jSpinnerP12Expo.setEnabled(false);
        } else {
            jSpinnerP12Expo.setEnabled(true);
        }
    }//GEN-LAST:event_jCheckBoxP12ExpoActionPerformed

    private void jSliderP12CertaintyStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jSliderP12CertaintyStateChanged
        int certainty = jSliderP12Certainty.getValue();
        jLabelCertaintyValue.setText("" + certainty);
    }//GEN-LAST:event_jSliderP12CertaintyStateChanged

    private void jLabel10MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel10MouseEntered
        // TODO add your handling code here:
    }//GEN-LAST:event_jLabel10MouseEntered

    private void jComboBoxAlgoP12ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxAlgoP12ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBoxAlgoP12ActionPerformed

    private void jComboBoxACActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxACActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBoxACActionPerformed

    private void jTextFieldKeystorePWActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextFieldKeystorePWActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldKeystorePWActionPerformed

    private void jTextFieldBrutePubKeyInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {//GEN-FIRST:event_jTextFieldBrutePubKeyInputMethodTextChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldBrutePubKeyInputMethodTextChanged

    private void jTextFieldBrutePubKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextFieldBrutePubKeyActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldBrutePubKeyActionPerformed

    private void jButtonBrowseBrutePublicKeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseBrutePublicKeyActionPerformed
        // TODO add your handling code here:
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldBrutePubKey.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_jButtonBrowseBrutePublicKeyActionPerformed

    private void jTextFieldBruteFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {//GEN-FIRST:event_jTextFieldBruteFileInputMethodTextChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldBruteFileInputMethodTextChanged

    private void jTextFieldBruteFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextFieldBruteFileActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldBruteFileActionPerformed

    private void jButtonBrowseBruteFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseBruteFileActionPerformed
        // TODO add your handling code here:
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldBruteFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_jButtonBrowseBruteFileActionPerformed
    private Thread t1Q = new Thread();

    private void jButtonBruteForceActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBruteForceActionPerformed
        // TODO add your handling code here:
        if (jTextFieldBruteFile.getText().equals("") || jTextFieldBrutePubKey.getText().equals("")) {
            jEditorPaneIBruteForceResult.setText("Form wasn't filled properly.");
            jEditorPaneIBruteForceResult.setForeground(Color.red);
            return;
        }
        jEditorPaneIBruteForceResult.setText(jEditorPaneIBruteForceResult.getText() + "Starting " + jTextFieldBruteFile.getText() + " analysis. Results will be displayed here. Estimated time required : " + RSABreaker.estimatePollard(jTextFieldBrutePubKey.getText()) + " hours.\n");
        t1Q = new Thread(new Runnable() {
            @Override
            public void run() {
                jLabelLoading.setVisible(true);
                String solu = RSABreaker.PollardForce(jTextFieldBrutePubKey.getText(), jTextFieldBruteFile.getText(), jTextFieldBrutePubKey.getText() + ".result");
                jEditorPaneIBruteForceResult.setText(jEditorPaneIBruteForceResult.getText() + "Solution found " + solu + ".\n");
                jEditorPaneIBruteForceResult.setText(jEditorPaneIBruteForceResult.getText() + "Resulting file written : " + jTextFieldBrutePubKey.getText() + ".result \n");

            }
        });
        t1Q.start();
    }//GEN-LAST:event_jButtonBruteForceActionPerformed

    private void jButtonBruteForceCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBruteForceCancelActionPerformed
        // TODO add your handling code here:
        t1Q.stop();
        jLabelLoading.setVisible(false);
        jEditorPaneIBruteForceResult.setText(jEditorPaneIBruteForceResult.getText() + "Analysis Thread was interrupted by user.\n");
    }//GEN-LAST:event_jButtonBruteForceCancelActionPerformed

    private void jButtonWCertGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonWCertGenerateActionPerformed
        // TODO add your handling code here:
        String password1 = String.valueOf(jPasswordFieldW1.getPassword());
        String password2 = String.valueOf(jPasswordFieldW2.getPassword());
        if (!password1.equals(password2)) {
            //
            jLabelWConsole.setText("Passwords do not match.");
            jLabelWConsole.setForeground(Color.red);
            return;
        } else if (password1.equals("") || password2.equals("")) {
            jLabelWConsole.setText("Passwords are empty. You must set a password.");
            jLabelWConsole.setForeground(Color.red);
            return;
        }
        String parentCert = String.valueOf(jComboBoxWParents.getSelectedItem());

        String typeCert = String.valueOf(jComboBoxWType.getSelectedItem());
        String aliasCert = jTextFieldWAlias.getText();
        String CNCert = jTextFieldWCN.getText();
        String OUCert = jTextFieldWOU.getText();
        String OrgCert = jTextFieldWOrg.getText();
        Date expiryDateCert = jDateChooserWExpiry.getDate();

        boolean exportCert = jCheckBoxWexport.isSelected();
        if (typeCert.equals("CA Certificate")) {
            CertificateChainBuilder.createCACert(expiryDateCert, CNCert, OrgCert, OUCert, aliasCert, exportCert, jTextFieldGlobalOutput.getText(), password1);
        } else if (typeCert.equals("Intermediate Certificate")) {
            CertificateChainBuilder.createIntermediateCert(expiryDateCert, CNCert, OrgCert, OUCert, aliasCert, exportCert, jTextFieldGlobalOutput.getText(), password1, parentCert);
        } else if (typeCert.equals("End User Client Certificate")) {
            CertificateChainBuilder.createEndUserCert(expiryDateCert, CNCert, OrgCert, OUCert, aliasCert, exportCert, jTextFieldGlobalOutput.getText(), password1, parentCert, CertType.ENDUSER_CLIENT);
        } else if (typeCert.equals("End User Server Certificate")) {
            CertificateChainBuilder.createEndUserCert(expiryDateCert, CNCert, OrgCert, OUCert, aliasCert, exportCert, jTextFieldGlobalOutput.getText(), password1, parentCert, CertType.ENDUSER_SERVER);
        } else if (typeCert.equals("End User Multipurpose Certificate")) {
            CertificateChainBuilder.createEndUserCert(expiryDateCert, CNCert, OrgCert, OUCert, aliasCert, exportCert, jTextFieldGlobalOutput.getText(), password1, parentCert, CertType.ENDUSER_MULTI);
        }
        refreshCertificateCombos();
        refreshPKObjects();
        refreshPubKObjects();
        refreshX509KeyTable();
        refreshX509CertOutline();
        jLabelWConsole.setForeground(javax.swing.UIManager.getDefaults().getColor("Actions.Green"));
        jLabelWConsole.setText("Generation successful.");

        ((DefaultListModel) jListEvents.getModel()).addElement("Certificate " + aliasCert + " successfully generated.");
    }//GEN-LAST:event_jButtonWCertGenerateActionPerformed

    private void jPasswordFieldW2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jPasswordFieldW2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jPasswordFieldW2ActionPerformed

    private void jComboBoxWTypeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxWTypeActionPerformed
        // TODO add your handling code here:
        if ("CA Certificate".equals(((String) jComboBoxWType.getSelectedItem()))) {
            jComboBoxWParents.setEnabled(false);
            //jComboBoxWParents.setSelectedItem("None");
        } else {
            jComboBoxWParents.setEnabled(true);
        }
    }//GEN-LAST:event_jComboBoxWTypeActionPerformed

    private void jCheckBoxWexportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxWexportActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBoxWexportActionPerformed

    private void jCheckBoxCustomDecryptTryAllActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBoxCustomDecryptTryAllActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jComboBoxDecryptPK.setEnabled(false);
        } else {
            jComboBoxDecryptPK.setEnabled(true);
        }
    }//GEN-LAST:event_jCheckBoxCustomDecryptTryAllActionPerformed

    private void jButtonBrowseEncryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBrowseEncryptActionPerformed
        // TODO add your handling code here:
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldDecryptFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_jButtonBrowseEncryptActionPerformed

    private void jButtonBuildPKCS12MakerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonBuildPKCS12MakerActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.buildPKCS12fromCertAndKey((String) jComboBoxPKCS12MakerCert.getSelectedItem(), (String) jComboBoxPKCS12MakerPK.getSelectedItem(), new String (jPasswordFieldPKCS12Maker.getPassword()), jTextFieldGlobalOutput.getText());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }//GEN-LAST:event_jButtonBuildPKCS12MakerActionPerformed

    private void jComboBoxPKCS12MakerPKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxPKCS12MakerPKActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBoxPKCS12MakerPKActionPerformed

    private void jButton8ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton8ActionPerformed
        // TODO add your handling code here:
        FileAnalyzer analyzer = new FileAnalyzer(jTextFieldDrop.getText());
        for (String dd : analyzer.getResults()) {
            jEditorPaneIdentifierResults.setText(jEditorPaneIdentifierResults.getText() + dd + "\n");
        }
    }// GEN-LAST:event_jButton8ActionPerformed

    private void jButton7ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton7ActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldDrop.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }// GEN-LAST:event_jButton7ActionPerformed

    private void jButtonConvertSourceFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertSourceFileActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldConvertSourceFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonConvertSourceFileActionPerformed

    private void jButtonBrowseSignFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseSignFileActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            // un fichier a été choisi (sortie par OK)
            // nom du fichier choisi
            // jFileChooser1.getSelectedFile().getName();
            // chemin absolu du fichier choisi
            jTextFieldSignFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        } // TODO add your handling code here:
    }// GEN-LAST:event_jButtonBrowseSignFileActionPerformed

    private void jComboBoxAlgoSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoSignActionPerformed

    }// GEN-LAST:event_jComboBoxAlgoSignActionPerformed

    private void jButtonSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonSignActionPerformed
        CryptoGenerator cg = new CryptoGenerator();
        String algo = String.valueOf(jComboBoxAlgoSign.getSelectedItem());
        String outRet = cg.signFile(jTextFieldSignFile.getText(), (String) jComboBoxSignPK.getSelectedItem(),
                jTextFieldSignPkPassword.getText(), jTextFieldGlobalOutput.getText(),
                jTextFieldSignOutputFilename.getText(), algo, (String) jComboBoxSignSignerCert.getSelectedItem());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonSignActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton1ActionPerformed
        jFrameAbout.setVisible(false);
    }// GEN-LAST:event_jButton1ActionPerformed

    private void jCheckBox2ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBox2ActionPerformed
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jTextFieldSignOutputFilename.setEnabled(true);
        } else {
            jTextFieldSignOutputFilename.setEnabled(false);
            jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
        }
    }// GEN-LAST:event_jCheckBox2ActionPerformed

    private void jTextFieldSignFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignFileActionPerformed

    }// GEN-LAST:event_jTextFieldSignFileActionPerformed

    private void jTextFieldSignFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldSignFileInputMethodTextChanged

    }// GEN-LAST:event_jTextFieldSignFileInputMethodTextChanged

    private void jButtonDashScenariosActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashScenariosActionPerformed
        // jTabbedPaneScreens.setSelectedIndex(6);
    }// GEN-LAST:event_copyMenuItemActionPerformed

    private void copyMenuItemActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashScenariosActionPerformed
        // jTabbedPaneScreens.setSelectedIndex(6);
    }// GEN-LAST:event_copyMenuItemActionPerformed

    private void jButtonDashPGPActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashPGPActionPerformed
        // jTabbedPaneScreens.setSelectedIndex(6);
    }// GEN-LAST:event_jButtonDashPGPActionPerformed

    private void jButtonDecodeBase64ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDecodeBase64ActionPerformed
        String b64datas = jTextAreaBase64Data.getText();
        if (b64datas != null && !"".equals(b64datas)) {
            byte[] valueDecoded = Base64.decode(b64datas);
            String decoded = new String(valueDecoded);
            jTextAreaOriginalData.setText(decoded);
        }
    }// GEN-LAST:event_jButtonDecodeBase64ActionPerformed

    private void jButtonEncodeBase64ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonEncodeBase64ActionPerformed
        String originalDatas = jTextAreaOriginalData.getText();
        if (originalDatas != null && !"".equals(originalDatas)) {
            byte[] valueEncoded = Base64.encode(originalDatas.getBytes());
            String encoded = new String(valueEncoded);
            jTextAreaBase64Data.setText(encoded);
        }
    }// GEN-LAST:event_jButtonEncodeBase64ActionPerformed

    private void jButton16ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton16ActionPerformed

        jFrameCertWizard.setVisible(true);
    }// GEN-LAST:event_jButton16ActionPerformed

    private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton5ActionPerformed
        //jFrameCertWizard.setVisible(false);
        CryptoGenerator g = new CryptoGenerator();
        //g.generateCertificateFromPublicKeyAndPrivateKey(propFile, propFile, propFile, propFile, propFile, propFile, expiryDate, propFile, propFile, propFile);
    }// GEN-LAST:event_jButton5ActionPerformed

    private void jButtonKeyNameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonKeyNameActionPerformed
        jDialogFileImport.setVisible(false);
        if (!"".equals(jTextFieldImportKeyName.getText())) {
            CryptoGenerator cg = new CryptoGenerator();
            String outRet = null;
            try {
                outRet = cg.importPrivateKey(jFileChooserFileOnly.getSelectedFile().getAbsolutePath(),
                        jTextFieldImportKeyName.getText());
            } catch (EnigmaException ex) {
                outRet = ex.getMsg();
            }
            refreshPKObjects();
            refreshX509KeyTable();
            ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
        }
    }// GEN-LAST:event_jButtonKeyNameActionPerformed

    private void jButtonImportKeyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonImportKeyActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldImportKeyFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonImportKeyActionPerformed

    private void jButtonKeyName1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonKeyName1ActionPerformed
        jDialogFileImportPublic.setVisible(false);
        if (!"".equals(jTextFieldImportKeyName.getText())) {
            CryptoGenerator cg = new CryptoGenerator();
            String outRet = null;
            try {
                outRet = cg.importPublicKey(jFileChooserFileOnly.getSelectedFile().getAbsolutePath(),
                        jTextFieldImportKeyName.getText());
            } catch (EnigmaException ex) {
                outRet = ex.getMsg();
            }
            refreshPubKObjects();
            refreshX509KeyTable();
            ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
        }
    }// GEN-LAST:event_jButtonKeyName1ActionPerformed

    private void jButtonImportKey1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonImportKey1ActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            jTextFieldImportKeyFile1.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonImportKey1ActionPerformed

    private void jRadioButtonPEMActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPEMActionPerformed
        if (jRadioButtonPEM.isSelected()) {
            jButtonConvertPEM.setEnabled(false);
            jButtonConvertDER.setEnabled(true);
        }
    }// GEN-LAST:event_jRadioButtonPEMActionPerformed

    private void jRadioButtonDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonDERActionPerformed
        if (jRadioButtonDER.isSelected()) {
            jButtonConvertPEM.setEnabled(true);
            jButtonConvertDER.setEnabled(false);
        }
    }// GEN-LAST:event_jRadioButtonDERActionPerformed

    private void exitMenuItemActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_exitMenuItemActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_exitMenuItemActionPerformed

    private void aboutMenuItemActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_aboutMenuItemActionPerformed
        // TODO add your handling code here:
        jFrameAbout.setVisible(true);
    }// GEN-LAST:event_aboutMenuItemActionPerformed

    private void jRadioButtonPEMorDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPEMorDERActionPerformed
        if (jRadioButtonPEMorDER.isSelected()) {
            jButtonConvertPEM.setEnabled(true);
            jButtonConvertDER.setEnabled(true);
        }
    }// GEN-LAST:event_jRadioButtonPEMorDERActionPerformed

    private void jButtonConvertPEMActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertPEMActionPerformed
        // TODO add your handling code here:
        ExportManager xm = new ExportManager();
        //String outRet = xm.convertDERtoPEM(jTextFieldConvertSourceFile.getText());
        String outRet = xm.ToPem(jTextFieldConvertSourceFile.getText());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonConvertPEMActionPerformed

    private void jButtonConvertDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertDERActionPerformed
        // TODO add your handling code here:
        ExportManager xm = new ExportManager();
        String outRet = xm.convertPEMToDER(jTextFieldConvertSourceFile.getText());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonConvertDERActionPerformed

    private void jTextFieldCipherFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldCipherFileInputMethodTextChanged
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldCipherFileInputMethodTextChanged

    private void jTextFieldCipherFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldCipherFileActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldCipherFileActionPerformed

    private void jButtonBrowseCipherFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseCipherFileActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            // un fichier a été choisi (sortie par OK)
            // nom du fichier choisi
            // jFileChooser1.getSelectedFile().getName();
            // chemin absolu du fichier choisi
            jTextFieldCipherFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        } // TODO add your handling code here:
    }// GEN-LAST:event_jButtonBrowseCipherFileActionPerformed

    private void jButtonCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonCipherActionPerformed
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.cipherFile(jTextFieldCipherFile.getText(), (String) jComboBoxCipherCert.getSelectedItem(),
                jTextFieldGlobalOutput.getText(), jTextFieldCipherOutputFilename.getText(),
                (String) jComboBoxAlgoCipher.getSelectedItem());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonCipherActionPerformed

    private void jComboBoxAlgoCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoCipherActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jComboBoxAlgoCipherActionPerformed

    private void jCheckBoxCustomCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomCipherActionPerformed
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jTextFieldCipherOutputFilename.setEnabled(true);
        } else {
            jTextFieldCipherOutputFilename.setEnabled(false);
            jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".sig");
        }
    }// GEN-LAST:event_jCheckBoxCustomCipherActionPerformed

    private void jButtonBrowseGlobalOutputActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseGlobalOutputActionPerformed
        int retour = jFileChooserDirectoriesOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            // un fichier a été choisi (sortie par OK)
            // nom du fichier choisi
            // jFileChooser1.getSelectedFile().getName();
            // chemin absolu du fichier choisi
            jTextFieldGlobalOutput.setText(jFileChooserDirectoriesOnly.getSelectedFile().getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonBrowseGlobalOutputActionPerformed

    private void jTextFieldSignOutputFilenameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignOutputFilenameActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldSignOutputFilenameActionPerformed

    private void jButtonBrowseGlobalOutput1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseGlobalOutput1ActionPerformed
        try {
            Desktop.getDesktop().open(new File(jTextFieldGlobalOutput.getText()));
        } catch (IOException ex) {
            Logger.getLogger(PKIZ.class.getName()).log(Level.SEVERE, null, ex);
        }
    }// GEN-LAST:event_jButtonBrowseGlobalOutput1ActionPerformed

    private void jTextFieldVerifyFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldVerifyFileInputMethodTextChanged
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldVerifyFileInputMethodTextChanged

    private void jTextFieldVerifyFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldVerifyFileActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldVerifyFileActionPerformed

    private void jButtonBrowseVerifyFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseVerifyFileActionPerformed
        int retour = jFileChooserFileOnly.showOpenDialog(this);
        if (retour == JFileChooser.APPROVE_OPTION) {
            // un fichier a été choisi (sortie par OK)
            // nom du fichier choisi
            // jFileChooser1.getSelectedFile().getName();
            // chemin absolu du fichier choisi
            jTextFieldVerifyFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
        } // TODO add your handling code here:
    }// GEN-LAST:event_jButtonBrowseVerifyFileActionPerformed

    private void jButtonValidateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonValidateActionPerformed

    }// GEN-LAST:event_jButtonValidateActionPerformed

    private void jCheckBoxCustomVerifyTryAllActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomVerifyTryAllActionPerformed
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jComboBoxVerifyCert.setEnabled(true);
        } else {
            jComboBoxVerifyCert.setEnabled(false);
        }
    }// GEN-LAST:event_jCheckBoxCustomVerifyTryAllActionPerformed

    private void jCheckBoxCustomVerifyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomVerifyActionPerformed
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jTextFieldVerifyOutputFilename.setEnabled(true);
        } else {
            jTextFieldVerifyOutputFilename.setEnabled(false);
            jTextFieldVerifyOutputFilename.setText(getFileName(jTextFieldVerifyOutputFilename.getText()) + ".sig");
        }
    }// GEN-LAST:event_jCheckBoxCustomVerifyActionPerformed

    private void jButtonVerifyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonVerifyActionPerformed
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = cg.verifyFile(jTextFieldVerifyFile.getText(), (String) jComboBoxVerifyCert.getSelectedItem(),
                jTextFieldGlobalOutput.getText(), jTextFieldVerifyOutputFilename.getText(),
                jCheckBoxCustomVerifyTryAll.isSelected());
        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonVerifyActionPerformed

    private void jTextFieldSignFile1InputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldSignFile1InputMethodTextChanged
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldSignFile1InputMethodTextChanged

    private void jTextFieldSignFile1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignFile1ActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldSignFile1ActionPerformed

    private void jButtonBrowseSignFile1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseSignFile1ActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jButtonBrowseSignFile1ActionPerformed

    private void jTextFieldDecryptOutputFilenameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldDecryptOutputFilenameActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldDecryptOutputFilenameActionPerformed

    private void jCheckBoxCustomDecryptActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomDecryptActionPerformed
        // TODO add your handling code here:
        JCheckBox cbLog = (JCheckBox) evt.getSource();
        if (cbLog.isSelected()) {
            jTextFieldDecryptOutputFilename.setEnabled(true);
            jTextFieldDecryptOutputFilename.setText("");
        } else {
            jTextFieldDecryptOutputFilename.setEnabled(false);
            jTextFieldDecryptOutputFilename.setText(getFileName(jTextFieldDecryptFile.getText()) + ".decrypted");
        }
    }// GEN-LAST:event_jCheckBoxCustomDecryptActionPerformed

    private void jButtonDecryptActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDecryptActionPerformed
        // TODO add your handling code here:
        CryptoGenerator cg = new CryptoGenerator();
        String outRet = "";
        String targetFileName = jTextFieldDecryptOutputFilename.getText();
        if (jCheckBoxCustomDecrypt.isSelected()) {
            targetFileName = jTextFieldDecryptFile.getText() + ".decrypted";
        }
        if (jCheckBoxCustomDecryptTryAll.isSelected()) {
            outRet = cg.decipherFileTryEverything(jTextFieldDecryptFile.getText(), (String) jComboBoxDecryptPK.getSelectedItem(), jTextFieldDecryptPW.getText(), jTextFieldGlobalOutput.getText(), targetFileName);
        } else {
            outRet = cg.decipherFile(jTextFieldDecryptFile.getText(), (String) jComboBoxDecryptPK.getSelectedItem(), jTextFieldDecryptPW.getText(), jTextFieldGlobalOutput.getText(), targetFileName);
        }

        ((DefaultListModel) jListEvents.getModel()).addElement(outRet);
    }// GEN-LAST:event_jButtonDecryptActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
//        try {
//            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
//                if ("Nimbus".equals(info.getName())) {
//                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
//                    break;
//                }
//            }
//        } catch (ClassNotFoundException ex) {
//            java.util.logging.Logger.getLogger(AAAA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (InstantiationException ex) {
//            java.util.logging.Logger.getLogger(AAAA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (IllegalAccessException ex) {
//            java.util.logging.Logger.getLogger(AAAA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
//            java.util.logging.Logger.getLogger(AAAA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
//        }
        FlatLightLaf.setup();
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new PKIZ().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem aboutMenuItem;
    private javax.swing.JMenuItem copyMenuItem;
    private javax.swing.JMenuItem cutMenuItem;
    private javax.swing.JMenuItem deleteMenuItem;
    private javax.swing.JMenu editMenu;
    private javax.swing.JMenuItem exitMenuItem;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JButton jButtonBrowseBruteFile;
    private javax.swing.JButton jButtonBrowseBrutePublicKey;
    private javax.swing.JButton jButtonBrowseCertPk;
    private javax.swing.JButton jButtonBrowseCertPub;
    private javax.swing.JButton jButtonBrowseCipherFile;
    private javax.swing.JButton jButtonBrowseEncrypt;
    private javax.swing.JButton jButtonBrowseGlobalOutput;
    private javax.swing.JButton jButtonBrowseGlobalOutput1;
    private javax.swing.JButton jButtonBrowseP10Pk;
    private javax.swing.JButton jButtonBrowseP10PubK;
    private javax.swing.JButton jButtonBrowsePubPk;
    private javax.swing.JButton jButtonBrowseSignFile;
    private javax.swing.JButton jButtonBrowseVerifyFile;
    private javax.swing.JButton jButtonBruteForce;
    private javax.swing.JButton jButtonBruteForceCancel;
    private javax.swing.JButton jButtonBuildPKCS12Maker;
    private javax.swing.JButton jButtonCSRGenerate;
    private javax.swing.JButton jButtonCertGenerate;
    private javax.swing.JButton jButtonCipher;
    private javax.swing.JButton jButtonConvertDER;
    private javax.swing.JButton jButtonConvertPEM;
    private javax.swing.JButton jButtonConvertSourceFile;
    private javax.swing.JButton jButtonDashAbout;
    private javax.swing.JButton jButtonDashAnalyze;
    private javax.swing.JButton jButtonDashConvert;
    private javax.swing.JButton jButtonDashGenerate;
    private javax.swing.JButton jButtonDashTransform;
    private javax.swing.JButton jButtonDashX509;
    private javax.swing.JButton jButtonDashX510;
    private javax.swing.JButton jButtonDashX512;
    private javax.swing.JButton jButtonDashX513;
    private javax.swing.JButton jButtonDashX514;
    private javax.swing.JButton jButtonDashX517;
    private javax.swing.JButton jButtonDashX518;
    private javax.swing.JButton jButtonDashX519;
    private javax.swing.JButton jButtonDashX520;
    private javax.swing.JButton jButtonDashX521;
    private javax.swing.JButton jButtonDashX522;
    private javax.swing.JButton jButtonDashX523;
    private javax.swing.JButton jButtonDashX524;
    private javax.swing.JButton jButtonDashX525;
    private javax.swing.JButton jButtonDashX526;
    private javax.swing.JButton jButtonDecodeBase64;
    private javax.swing.JButton jButtonDecrypt;
    private javax.swing.JButton jButtonEncodeBase64;
    private javax.swing.JButton jButtonImportKey;
    private javax.swing.JButton jButtonImportKey1;
    private javax.swing.JButton jButtonKeyName;
    private javax.swing.JButton jButtonKeyName1;
    private javax.swing.JButton jButtonPKCS12Generate;
    private javax.swing.JButton jButtonPkGenerate;
    private javax.swing.JButton jButtonPubGenerate;
    private javax.swing.JButton jButtonSign;
    private javax.swing.JButton jButtonValidate;
    private javax.swing.JButton jButtonVerify;
    private javax.swing.JButton jButtonWCertGenerate;
    private javax.swing.JCheckBox jCheckBox2;
    private javax.swing.JCheckBox jCheckBoxCustomCipher;
    private javax.swing.JCheckBox jCheckBoxCustomDecrypt;
    private javax.swing.JCheckBox jCheckBoxCustomDecryptTryAll;
    private javax.swing.JCheckBox jCheckBoxCustomVerify;
    private javax.swing.JCheckBox jCheckBoxCustomVerifyTryAll;
    private javax.swing.JCheckBox jCheckBoxP10PubKey;
    private javax.swing.JCheckBox jCheckBoxP12Certainty;
    private javax.swing.JCheckBox jCheckBoxP12Expo;
    private javax.swing.JCheckBox jCheckBoxP12Write;
    private javax.swing.JCheckBox jCheckBoxPkCertainty;
    private javax.swing.JCheckBox jCheckBoxPkExpo;
    private javax.swing.JCheckBox jCheckBoxWexport;
    private javax.swing.JComboBox<String> jComboBoxAC;
    private javax.swing.JComboBox<String> jComboBoxAlgoCipher;
    private javax.swing.JComboBox<String> jComboBoxAlgoP12;
    private javax.swing.JComboBox<String> jComboBoxAlgoPk;
    private javax.swing.JComboBox<String> jComboBoxAlgoSign;
    private javax.swing.JComboBox<String> jComboBoxCSRPk;
    private javax.swing.JComboBox<String> jComboBoxCSRPubK;
    private javax.swing.JComboBox<String> jComboBoxCertAlgo;
    private javax.swing.JComboBox<String> jComboBoxCertPk;
    private javax.swing.JComboBox<String> jComboBoxCertPubK;
    private javax.swing.JComboBox<String> jComboBoxCertVersion;
    private javax.swing.JComboBox<String> jComboBoxCipherCert;
    private javax.swing.JComboBox<String> jComboBoxDecryptPK;
    private javax.swing.JComboBox<String> jComboBoxPKCS12MakerCert;
    private javax.swing.JComboBox<String> jComboBoxPKCS12MakerPK;
    private javax.swing.JComboBox<String> jComboBoxPubPK;
    private javax.swing.JComboBox<String> jComboBoxSignPK;
    private javax.swing.JComboBox<String> jComboBoxSignSignerCert;
    private javax.swing.JComboBox<String> jComboBoxVerifyCert;
    private javax.swing.JComboBox<String> jComboBoxWParents;
    private javax.swing.JComboBox<String> jComboBoxWType;
    private com.toedter.calendar.JDateChooser jDateChooserExpiry;
    private com.toedter.calendar.JDateChooser jDateChooserP12Expiry;
    private com.toedter.calendar.JDateChooser jDateChooserWExpiry;
    private javax.swing.JDialog jDialogFileImport;
    private javax.swing.JDialog jDialogFileImportPublic;
    private javax.swing.JEditorPane jEditorPaneIBruteForceResult;
    private javax.swing.JEditorPane jEditorPaneIdentifierResults;
    private javax.swing.JFileChooser jFileChooserDirectoriesOnly;
    private javax.swing.JFileChooser jFileChooserExportCRL;
    private javax.swing.JFileChooser jFileChooserExportCert;
    private javax.swing.JFileChooser jFileChooserFileOnly;
    private javax.swing.JFrame jFrameAbout;
    private javax.swing.JFrame jFrameCertWizard;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel20;
    private javax.swing.JLabel jLabel21;
    private javax.swing.JLabel jLabel22;
    private javax.swing.JLabel jLabel23;
    private javax.swing.JLabel jLabel24;
    private javax.swing.JLabel jLabel25;
    private javax.swing.JLabel jLabel26;
    private javax.swing.JLabel jLabel27;
    private javax.swing.JLabel jLabel28;
    private javax.swing.JLabel jLabel29;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel30;
    private javax.swing.JLabel jLabel31;
    private javax.swing.JLabel jLabel32;
    private javax.swing.JLabel jLabel33;
    private javax.swing.JLabel jLabel34;
    private javax.swing.JLabel jLabel35;
    private javax.swing.JLabel jLabel36;
    private javax.swing.JLabel jLabel37;
    private javax.swing.JLabel jLabel38;
    private javax.swing.JLabel jLabel39;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel40;
    private javax.swing.JLabel jLabel41;
    private javax.swing.JLabel jLabel42;
    private javax.swing.JLabel jLabel43;
    private javax.swing.JLabel jLabel44;
    private javax.swing.JLabel jLabel45;
    private javax.swing.JLabel jLabel46;
    private javax.swing.JLabel jLabel47;
    private javax.swing.JLabel jLabel48;
    private javax.swing.JLabel jLabel49;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel50;
    private javax.swing.JLabel jLabel51;
    private javax.swing.JLabel jLabel52;
    private javax.swing.JLabel jLabel54;
    private javax.swing.JLabel jLabel55;
    private javax.swing.JLabel jLabel56;
    private javax.swing.JLabel jLabel57;
    private javax.swing.JLabel jLabel58;
    private javax.swing.JLabel jLabel59;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel60;
    private javax.swing.JLabel jLabel61;
    private javax.swing.JLabel jLabel62;
    private javax.swing.JLabel jLabel63;
    private javax.swing.JLabel jLabel64;
    private javax.swing.JLabel jLabel65;
    private javax.swing.JLabel jLabel66;
    private javax.swing.JLabel jLabel67;
    private javax.swing.JLabel jLabel68;
    private javax.swing.JLabel jLabel69;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel70;
    private javax.swing.JLabel jLabel71;
    private javax.swing.JLabel jLabel72;
    private javax.swing.JLabel jLabel73;
    private javax.swing.JLabel jLabel74;
    private javax.swing.JLabel jLabel75;
    private javax.swing.JLabel jLabel76;
    private javax.swing.JLabel jLabel77;
    private javax.swing.JLabel jLabel78;
    private javax.swing.JLabel jLabel79;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel80;
    private javax.swing.JLabel jLabel81;
    private javax.swing.JLabel jLabel82;
    private javax.swing.JLabel jLabel83;
    private javax.swing.JLabel jLabel84;
    private javax.swing.JLabel jLabel85;
    private javax.swing.JLabel jLabel86;
    private javax.swing.JLabel jLabel87;
    private javax.swing.JLabel jLabel88;
    private javax.swing.JLabel jLabel89;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JLabel jLabel90;
    private javax.swing.JLabel jLabel91;
    private javax.swing.JLabel jLabelCertaintyValue;
    private java.awt.Label jLabelCertaintyValuePk;
    private javax.swing.JLabel jLabelGlobalDir;
    private javax.swing.JLabel jLabelLoading;
    private javax.swing.JLabel jLabelWConsole;
    private javax.swing.JList<String> jListEvents;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel13;
    private javax.swing.JPanel jPanel15;
    private javax.swing.JPanel jPanel16;
    private javax.swing.JPanel jPanel18;
    private javax.swing.JPanel jPanel19;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel20;
    private javax.swing.JPanel jPanel21;
    private javax.swing.JPanel jPanel22;
    private javax.swing.JPanel jPanel23;
    private javax.swing.JPanel jPanel24;
    private javax.swing.JPanel jPanel25;
    private javax.swing.JPanel jPanel26;
    private javax.swing.JPanel jPanel27;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPanel jPanel9;
    private javax.swing.JPanel jPanelACManagement;
    private javax.swing.JPanel jPanelAnalyze;
    private javax.swing.JPanel jPanelBruteForce;
    private javax.swing.JPanel jPanelCertWizard;
    private javax.swing.JPanel jPanelConvert;
    private javax.swing.JPanel jPanelDashboard;
    private javax.swing.JPanel jPanelEvents;
    private javax.swing.JPanel jPanelPGPKeyring;
    private javax.swing.JPanel jPanelTransform;
    private javax.swing.JPasswordField jPasswordFieldPKCS12Maker;
    private javax.swing.JPasswordField jPasswordFieldW1;
    private javax.swing.JPasswordField jPasswordFieldW2;
    private javax.swing.JProgressBar jProgressBarEnigma;
    private javax.swing.JRadioButton jRadioButtonDER;
    private javax.swing.JRadioButton jRadioButtonPEM;
    private javax.swing.JRadioButton jRadioButtonPEMorDER;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane10;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane8;
    private javax.swing.JScrollPane jScrollPane9;
    private javax.swing.JScrollPane jScrollPaneForEvents;
    private javax.swing.JSlider jSliderP12Certainty;
    private javax.swing.JSlider jSliderPkCertainty;
    private javax.swing.JSpinner jSpinnerKeySize;
    private javax.swing.JSpinner jSpinnerKeySizePkSize;
    private javax.swing.JSpinner jSpinnerP12Expo;
    private javax.swing.JSpinner jSpinnerPkExpo;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTabbedPane jTabbedPaneGenerate;
    private javax.swing.JTabbedPane jTabbedPaneScreens;
    private javax.swing.JTable jTableCRL;
    private javax.swing.JTable jTablePK;
    private javax.swing.JTextArea jTextAreaBase64Data;
    private javax.swing.JTextArea jTextAreaDrop;
    private javax.swing.JTextArea jTextAreaOriginalData;
    private javax.swing.JTextField jTextFieldBruteFile;
    private javax.swing.JTextField jTextFieldBrutePubKey;
    private javax.swing.JTextField jTextFieldCN;
    private javax.swing.JTextField jTextFieldCertCN;
    private javax.swing.JTextField jTextFieldCertPkPw;
    private javax.swing.JTextField jTextFieldCertTargetFilename;
    private javax.swing.JTextField jTextFieldCipherFile;
    private javax.swing.JTextField jTextFieldCipherOutputFilename;
    private javax.swing.JTextField jTextFieldConvertSourceFile;
    private javax.swing.JTextField jTextFieldCountry;
    private javax.swing.JTextField jTextFieldDecryptFile;
    private javax.swing.JTextField jTextFieldDecryptOutputFilename;
    private javax.swing.JTextField jTextFieldDecryptPW;
    private javax.swing.JTextField jTextFieldDrop;
    private javax.swing.JTextField jTextFieldGlobalOutput;
    private javax.swing.JTextField jTextFieldImportKeyFile;
    private javax.swing.JTextField jTextFieldImportKeyFile1;
    private javax.swing.JTextField jTextFieldImportKeyName;
    private javax.swing.JTextField jTextFieldImportKeyName1;
    private javax.swing.JTextField jTextFieldKeystorePW;
    private javax.swing.JTextField jTextFieldP10CN;
    private javax.swing.JTextField jTextFieldP10PkPw;
    private javax.swing.JTextField jTextFieldP10TargetFilename;
    private javax.swing.JTextField jTextFieldP12TargetFilename;
    private javax.swing.JTextField jTextFieldPKCS8PW;
    private javax.swing.JTextField jTextFieldPkPw;
    private javax.swing.JTextField jTextFieldPkTargetFilename;
    private javax.swing.JTextField jTextFieldPkTargetKeyName;
    private javax.swing.JTextField jTextFieldPubPrivkeyPW;
    private javax.swing.JTextField jTextFieldPubTargetCertName;
    private javax.swing.JTextField jTextFieldPubTargetFilename;
    private javax.swing.JTextField jTextFieldPubTargetKeyName;
    private javax.swing.JTextField jTextFieldSignFile;
    private javax.swing.JTextField jTextFieldSignOutputFilename;
    private javax.swing.JTextField jTextFieldSignPkPassword;
    private javax.swing.JTextField jTextFieldVerifyFile;
    private javax.swing.JTextField jTextFieldVerifyOutputFilename;
    private javax.swing.JTextField jTextFieldWAlias;
    private javax.swing.JTextField jTextFieldWCN;
    private javax.swing.JTextField jTextFieldWOU;
    private javax.swing.JTextField jTextFieldWOrg;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JMenuItem openMenuItem;
    private org.netbeans.swing.outline.Outline outline;
    private javax.swing.JMenuItem pasteMenuItem;
    private javax.swing.JMenuItem saveMenuItem;
    // End of variables declaration//GEN-END:variables
}
