package com.company;

import javax.crypto.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;
import java.util.List;
import java.util.*;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.BufferedBlockCipher;

import static com.company.CommonMethods.initCipher;
import static com.company.CommonMethods.readFile;
import static com.company.Constants.*;
import static com.company.SecretCode.getApprovedUsersList;
import static com.company.User.*;

public class MainWindow extends JFrame {
    private JPanel contentPanel;

    //Szyfrowanie
    private JTabbedPane tabbedPanel;
    private JButton chooseFileBtn;
    private JTextField outFileNameField;
    private JComboBox keySizeCBox;
    private JComboBox modeCBox;
    private JComboBox blockSizeCBox;
    private JComboBox subBlockSizeCBox;
    private JTextArea outputArea;
    private JList<ListModel<String>> jUsersList;
    private JButton runBtn;
    private JFormattedTextField filePathField;
    private JButton chooseReceivierBtn;
    private JList jReceivierList;
    private JButton removeFromReceivierBtn;

    //Odszyfrowywanie
    private JPasswordField passwordField;
    private JButton chooseFileEnBtn;
    private JTextField fileNameOutEnField;
    private JFormattedTextField filePathEnField;
    private JButton runEnBtn;
    private JTextArea outputEnField;
    private JButton chooseReceivierEnBtn;
    private JList jUserListEn;
    private JTextField receivierField;
    private JMenuBar identityBar;


    private File choosenFile;
    private File choosenFileEn;
    private File publickKeyFile;

    public static DefaultListModel usersModel = new DefaultListModel();
    public static DefaultListModel usersToEnModel = new DefaultListModel();
    DefaultListModel receivierModel = new DefaultListModel();

    public MainWindow() throws Exception {
        setContentPane(contentPanel);
        setTitle(getApplicationTitle());

        JMenu menu = new JMenu("Tożsamości");
        identityBar.add(menu);


        JMenuItem addUserItem = new JMenuItem("Dodaj użytkownika");
        addUserItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ev) {
                JFrame createUserDialog = new JFrame("Dodawanie użytkownika");

                Container createPane = createUserDialog.getContentPane();

                FlowLayout layout = new FlowLayout(FlowLayout.CENTER);
                createPane.setLayout(layout);

                JLabel emailLabel = new JLabel("E-mail:");
                JTextField emailField = new JTextField(18);
                JLabel passwordLabel = new JLabel("Hasło:");
                JPasswordField passwordField = new JPasswordField(18);
                JLabel repeatPasswordLabel = new JLabel("Pow. hasło:");
                JPasswordField repeatPasswordField = new JPasswordField(18);
                JButton createUserButton = new JButton("Stwórz użytkownika");
                createUserButton.setSize(250,20);
                JTextArea outputArea = new JTextArea(5, 25);

                createPane.add(emailLabel);
                createPane.add(emailField);
                createPane.add(passwordLabel);
                createPane.add(passwordField);
                createPane.add(repeatPasswordLabel);
                createPane.add(repeatPasswordField);
                createPane.add(createUserButton);
                createPane.add(outputArea);


                createUserDialog.setSize(300, 250);
                createUserDialog.setVisible(true);

                createUserButton.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        outputArea.setText("");
                        if (!Arrays.equals(passwordField.getPassword(), repeatPasswordField.getPassword())) {
                            outputArea.setText("Podane hasła są różne!");
                        }
                        else if(passwordField.getPassword().toString().isEmpty()){
                            outputArea.setText("Pole hasło nie może być puste!");
                        }
                        else if(emailField.getText().isEmpty()){
                            outputArea.setText("Pole e-mail nie może być puste!");
                        }
                        else if(!emailField.getText().matches(getEmailRegex())){
                            outputArea.setText("Podany e-mail jest niepoprawny!");
                        }
                        else if(!checkUsers(emailField.getText())){
                            outputArea.setText("Użytkownik o podanym e-mailu już istnieje!");
                        }
                        else {
                            User user = new User(emailField.getText());
                            user.setHashPassword(new String(passwordField.getPassword()));
                            user.generateKeyPair();
                            user.savePasswordFile();
                            if (JOptionPane.showConfirmDialog(createUserDialog,
                                    "Pomyślnie dodano użytkownika: "+user.getUsername()+
                                            " . Czy chcesz zakończyć proces dodawania i wrócić do poprzedniego ekranu?", "Zamykanie okna",
                                    JOptionPane.YES_NO_OPTION,
                                    JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION){
                                usersModel.clear();
                                fillJList();
                                createUserDialog.dispose();
                            }
                            outputArea.setText("Pomyślnie dodano użytkownika: "+user.getUsername());
                        }
                    }
                });
            }
        });

        menu.add(addUserItem);
        JMenuItem importPublicKey = new JMenuItem("Importuj klucz publiczny");
        importPublicKey.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ev) {
                JFrame importUserDialog = new JFrame("Importowanie klucza publicznego");

                Container createPane = importUserDialog.getContentPane();

                FlowLayout layout = new FlowLayout(FlowLayout.CENTER);
                createPane.setLayout(layout);

                JLabel emailLabel = new JLabel("E-mail:");
                JTextField emailField = new JTextField(18);
                JButton chooseKeyPubBtn = new JButton("Wybierz plik");
                chooseKeyPubBtn.setSize(250,20);
                JTextField pathField = new JTextField(15);
                JButton importUserButton = new JButton("Importuj klucz");
                importUserButton.setSize(250,20);
                JTextArea outputArea = new JTextArea(5, 25);

                createPane.add(emailLabel);
                createPane.add(emailField);
                createPane.add(chooseKeyPubBtn);
                createPane.add(pathField);
                createPane.add(importUserButton);
                createPane.add(outputArea);


                importUserDialog.setSize(300, 250);
                importUserDialog.setVisible(true);

                chooseKeyPubBtn.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        JFileChooser chooseFileDialog = new JFileChooser();
                        int openDialog = chooseFileDialog.showOpenDialog(null);
                        if (openDialog == JFileChooser.APPROVE_OPTION) {
                            publickKeyFile = chooseFileDialog.getSelectedFile();
                            pathField.setText(publickKeyFile.getName());
                        }
                    }
                });

                importUserButton.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        outputArea.setText("");
                        if(emailField.getText().isEmpty()){
                            outputArea.setText("Pole e-mail nie może być puste!");
                        }
                        else if(!emailField.getText().matches(getEmailRegex())){
                            outputArea.setText("Podany e-mail jest niepoprawny!");
                        }
                        else if(!checkUsers(emailField.getText())){
                            outputArea.setText("Użytkownik o podanym e-mailu już istnieje!");
                        }
                        else {
                            User user = new User(emailField.getText());
                            user.setPublicKey(publickKeyFile);
                            user.savePublicKeyFile();
                            if (JOptionPane.showConfirmDialog(importUserDialog,
                                    "Pomyślnie zaimportowano klucz publiczny użytkownika: "+user.getUsername()+
                                            " . Czy chcesz zakończyć proces dodawania i wrócić do poprzedniego ekranu?", "Zamykanie okna",
                                    JOptionPane.YES_NO_OPTION,
                                    JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION){
                                usersModel.clear();
                                fillJList();
                                importUserDialog.dispose();
                            }
                            outputArea.setText("Pomyślnie zaimportowano klucz publiczny użytkownika: "+user.getUsername());
                        }
                    }
                });
            }
        });
        menu.add(importPublicKey);



        //Szyfrowanie
        createUserList();
        fillJList();

        blockSizeCBox.addItem("128");
        blockSizeCBox.setEnabled(false);

        modeCBox.setModel(new DefaultComboBoxModel<>(WorkMode.values()));

        keySizeCBox.addItem("128");
        keySizeCBox.addItem("192");
        keySizeCBox.addItem("256");


        int oneByte = 8;
        for(int i=1; i<=8;i++){
            subBlockSizeCBox.addItem(oneByte*i);
        }
        subBlockSizeCBox.setEnabled(false);

        chooseFileBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JFileChooser chooseFileDialog = new JFileChooser();
                int openDialog = chooseFileDialog.showOpenDialog(null);
                if (openDialog == JFileChooser.APPROVE_OPTION) {
                    choosenFile = chooseFileDialog.getSelectedFile();
                    filePathField.setText(choosenFile.getName());
                }
            }
        });

        chooseReceivierBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(!receivierModel.contains(jUsersList.getSelectedValue())){
                    receivierModel.addElement(jUsersList.getSelectedValue());
                    jReceivierList.setModel(receivierModel);

                }

            }
        });

        removeFromReceivierBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(receivierModel.contains(jReceivierList.getSelectedValue())){
                    receivierModel.removeElement(jReceivierList.getSelectedValue());
                    jReceivierList.setModel(receivierModel);
                }

            }
        });

        runBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int keySize = Integer.parseInt(keySizeCBox.getSelectedItem().toString());
                int subBlockSize = Integer.parseInt(subBlockSizeCBox.getSelectedItem().toString());
                List<User> receivierList = createReceivierList();

                byte[] fileToEncode = readFile(choosenFile.getAbsolutePath());
                byte[] iv = generateIV();

                RC6Engine rc6eng=new RC6Engine();


                KeyGenerator keyGen = null;

                try {
                    keyGen = KeyGenerator.getInstance(getAlgorithmName());
                } catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
                }

                keyGen.init(keySize);

                SecretKey sessionKey = keyGen.generateKey();

                KeyParameter keyParameter = new KeyParameter(sessionKey.getEncoded());

                BufferedBlockCipher cipher = initCipher((WorkMode)modeCBox.getSelectedItem(), rc6eng, keyParameter, iv, subBlockSize, true);

                byte[] cipherFile = new byte[cipher.getOutputSize(fileToEncode.length)];

                //System.out.println ("Output size= "+cipher.getOutputSize(fileToEncode.length));
                int ptLength = cipher.processBytes(fileToEncode,0,fileToEncode.length,cipherFile,0);
                try {
                    ptLength += cipher.doFinal(cipherFile,ptLength);
                } catch (Exception ex) {
                }

                SecretCode secretCode = new SecretCode((WorkMode)modeCBox.getSelectedItem(), blockSizeCBox.getSelectedItem().toString(), subBlockSizeCBox.getSelectedItem().toString(),
                        keySizeCBox.getSelectedItem().toString(), iv, receivierList, cipherFile,
                        outFileNameField.getText(), sessionKey.getEncoded());

                outputArea.setText(secretCode.printStatus());

            }
        });

        modeCBox.addActionListener (new ActionListener () {
            public void actionPerformed(ActionEvent e) {
                if(modeCBox.getSelectedItem() == WorkMode.ECB || modeCBox.getSelectedItem() == WorkMode.CBC){
                    subBlockSizeCBox.setEnabled(false);
                }
                else{
                    subBlockSizeCBox.setEnabled(true);
                }
            }
        });

        //Odszyfrowywanie
        chooseFileEnBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                JFileChooser chooseFileDialog = new JFileChooser(getCipheredFilePath());
                int openDialog = chooseFileDialog.showOpenDialog(null);
                if (openDialog == JFileChooser.APPROVE_OPTION) {
                    choosenFileEn = chooseFileDialog.getSelectedFile();
                    filePathEnField.setText(choosenFileEn.getName());
                    try{
                        fillJList(getApprovedUsersList(choosenFileEn));
                    } catch (Exception ex){

                    }

                }
            }
        });

        chooseReceivierEnBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                receivierField.setText(jUserListEn.getSelectedValue().toString());
            }
        });

        runEnBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(!SecretCode.decode(choosenFileEn, fileNameOutEnField.getText(), receivierField.getText(), new String(passwordField.getPassword()))){
                    outputEnField.setText("Wystąpił błąd podczasz odszyfrowania pliku!");
                }
                else{
                    outputEnField.setText("Odszyfrowanie pliku powiodło się!");
                }
            }
        });
    }


    public static void main(String[] args) throws Exception{
        MainWindow dialog = new MainWindow();
        dialog.setDefaultCloseOperation(EXIT_ON_CLOSE);
        dialog.pack();
        dialog.setVisible(true);
    }

    public byte [] generateIV(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        return iv;
    }

    private void fillJList(){
        for (User user : mainUsersList) {
            usersModel.addElement(user.getUsername());
            jUsersList.setModel(usersModel);
        }
    }

    private void fillJList(String [] approvedUsers){
        usersToEnModel.clear();
        for (int i=0; i<approvedUsers.length;i++) {
            if(existInUsersPath(approvedUsers[i])){
                usersToEnModel.addElement(approvedUsers[i]);
            }
        }
        jUserListEn.setModel(usersToEnModel);
    }

    private List<User> createReceivierList(){
        List<User> receivierList = new ArrayList<>();
        for(int i = 0; i< receivierModel.getSize(); i++){
            for(User user: mainUsersList){
                if(user.getUsername().equals(receivierModel.get(i).toString())){
                    receivierList.add(user);
                }
            }
        }
        return receivierList;
    }
}
