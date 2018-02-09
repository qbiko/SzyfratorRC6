package com.company;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.company.CommonMethods.createHashPassword;
import static com.company.CommonMethods.readFromFile;
import static com.company.Constants.*;

public class User {
    public static List<User> mainUsersList;
    private String username;
    private byte[] hashPassword;
    private RSAPublicKey publicKey;
    private PrivateKey privateKey;

    public User(String username){
        this.username = username;
        mainUsersList.add(this);
    }

    public String getUsername() {
        return username;
    }

    public void setPublicKey() {
        setPublicKey(new File(getPublicPath()+"\\"+username+getPublExt()));
    }

    public void setPublicKey(File file) {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        Document doc = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(file);
        } catch (Exception e) {
        }

        doc.getDocumentElement().normalize();

        String sModulus = new String();
        String sExponent = new String();

        NodeList nList = doc.getElementsByTagName("User");
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                sModulus = eElement.getElementsByTagName("Modulus").item(0).getTextContent();
                sExponent = eElement.getElementsByTagName("Exponent").item(0).getTextContent();
            }
        }
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(Base64.getDecoder().decode(sModulus)), new BigInteger(Base64.getDecoder().decode(sExponent)));

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey)factory.generatePublic(spec);
        } catch (Exception e) {
        }

    }

    private void setPrivateKey(){
        byte[] privateKeyInBytes = getCipherPrivKeyBase64FromFile();
        RC6Engine rc6eng=new RC6Engine();
        KeyParameter keyParameter = new KeyParameter(hashPassword);
        BufferedBlockCipher buffCipher = new PaddedBufferedBlockCipher(rc6eng);
        buffCipher.init(false, keyParameter);

        byte[] decodedKey = new byte[buffCipher.getOutputSize(privateKeyInBytes.length)];

        int proces1 = buffCipher.processBytes(privateKeyInBytes, 0, privateKeyInBytes.length, decodedKey, 0);
        try {
            int proces2 = buffCipher.doFinal(decodedKey, proces1);
        } catch (InvalidCipherTextException e) {
        }

        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        } catch (InvalidKeySpecException e) {
        } catch (NoSuchAlgorithmException e) {
        }
    }

    private byte [] getCipherPrivKeyBase64FromFile(){
        File file = new File(getPrivatePath()+"\\"+username+getPrivExt());
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        Document doc = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(file);
        } catch (Exception e) {

        }

        doc.getDocumentElement().normalize();

        String sPrivKey = new String();

        NodeList nList = doc.getElementsByTagName("User");
        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node nNode = nList.item(temp);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;
                sPrivKey = eElement.getElementsByTagName("RSAPrivateKeyBase64").item(0).getTextContent();
            }
        }

        byte[] privateKeyInBytes = Base64.getDecoder().decode(sPrivKey);

        return privateKeyInBytes;
    }

    public PrivateKey getPrivateKeyToDecode(byte [] password){
        byte[] privateKeyInBytes = getCipherPrivKeyBase64FromFile();
        PrivateKey pKey = null;
        RC6Engine rc6eng=new RC6Engine();
        KeyParameter keyParameter = new KeyParameter(password);
        BufferedBlockCipher buffCipher = new PaddedBufferedBlockCipher(rc6eng);
        buffCipher.init(false, keyParameter);

        byte[] decodedKey = new byte[buffCipher.getOutputSize(privateKeyInBytes.length)];

        int proces1 = buffCipher.processBytes(privateKeyInBytes, 0, privateKeyInBytes.length, decodedKey, 0);
        try {
            int proces2 = buffCipher.doFinal(decodedKey, proces1);
        } catch (InvalidCipherTextException e) {
        }

        try {
            pKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        } catch(Exception e){
        }

        return pKey;
    }

    public void generateKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(2048);
            keyPair = keyGenerator.generateKeyPair();
            publicKey = (RSAPublicKey)keyPair.getPublic();
            savePublicKeyFile();
            privateKey = keyPair.getPrivate();
            savePrivateKeyFile();
        } catch (NoSuchAlgorithmException e) {
        }
    }

    private byte [] encodePrivateKey(PrivateKey privateKey){
        RC6Engine rc6eng=new RC6Engine();
        KeyParameter keyParameter = new KeyParameter(hashPassword);
        BufferedBlockCipher buffCipher = new PaddedBufferedBlockCipher(rc6eng);
        buffCipher.init(true, keyParameter);

        byte [] keyToEncode = privateKey.getEncoded();

        byte[] encodedKey = new byte[buffCipher.getOutputSize(keyToEncode.length)];

        int proces1 = buffCipher.processBytes(keyToEncode, 0, keyToEncode.length, encodedKey, 0);
        try {
            int proces2 = buffCipher.doFinal(encodedKey, proces1);
        } catch (InvalidCipherTextException e) {
        }

        return encodedKey;

    }

    private void saveToFile(String name, byte [] content, final String destination){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(destination+"\\"+name);
            fos.write(Base64.getEncoder().encode(content));
            fos.close();
        } catch (IOException e) {
        }
    }

    public void savePasswordFile(){
        saveToFile(username+getPassExt(), hashPassword, getUsersPath());
    }

    public void savePublicKeyFile(){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getPublicPath()+"\\"+username+getPublExt());
            fos.write("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n".getBytes());
            fos.write("<User>\n".getBytes());
            fos.write(("\t<Email>"+username+"</Email>\n").getBytes());
            fos.write("\t<RSAPublicKeyBase64>\n".getBytes());
            fos.write("\t\t<Exponent>".getBytes());
            fos.write(Base64.getEncoder().encode(publicKey.getPublicExponent().toByteArray()));
            fos.write("</Exponent>\n".getBytes());
            fos.write("\t\t<Modulus>".getBytes());
            fos.write(Base64.getEncoder().encode(publicKey.getModulus().toByteArray()));
            fos.write("</Modulus>\n".getBytes());
            fos.write("\t</RSAPublicKeyBase64>\n".getBytes());
            fos.write("</User>".getBytes());
            fos.close();
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }
    }

    public void savePrivateKeyFile(){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getPrivatePath()+"\\"+username+getPrivExt());
            fos.write("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n".getBytes());
            fos.write("<User>\n".getBytes());
            fos.write(("\t<Email>"+username+"</Email>\n").getBytes());
            fos.write("\t<RSAPrivateKeyBase64>".getBytes());
            fos.write(Base64.getEncoder().encode(encodePrivateKey(privateKey)));
            fos.write("</RSAPrivateKeyBase64>\n".getBytes());
            fos.write("</User>".getBytes());
            fos.close();
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }
    }

    public void setHashPassword(String password){
        hashPassword = createHashPassword(password);
    }

    public void setHashPassword(byte[] password){
            hashPassword = password;
    }


    public static boolean checkUsers(String username){
        for (User user : mainUsersList) {
            if(user.getUsername().equals(username)){
                return false;
            }
        }
        return true;
    }

    public static void createUserList(){
        mainUsersList = new ArrayList<>();
        File usersDirectory = new File(getUsersPath());
        for (final File fileEntry : usersDirectory.listFiles()) {
            User user = new User(fileEntry.getName().replace(getPassExt(), ""));
            user.setHashPassword(readFromFile(fileEntry.getAbsolutePath()));
            user.setPublicKey();
            user.setPrivateKey();
        }
        File publicKeyDirectory = new File(getPublicPath());
        for (final File fileEntry : publicKeyDirectory.listFiles()) {
            if(checkUsers(fileEntry.getName().replace(getPublExt(), ""))){
                User user = new User(fileEntry.getName().replace(getPublExt(), ""));
                user.setPublicKey();
            }
        }
    }

    public byte [] encodeSessionKey(byte [] sessionKey){
        byte[] cipherSessionKey = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherSessionKey = cipher.doFinal(sessionKey);
        } catch (Exception e) {
        }
        return cipherSessionKey;
    }

    public byte [] encodeRsaSessionKey(byte [] sessionKey){
        byte[] cipherSessionKey = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherSessionKey = cipher.doFinal(sessionKey);
        } catch (Exception e) {
        }
        return cipherSessionKey;
    }

    public static User getUserFromListByName(String username){
        for (User user : mainUsersList) {
            if(user.getUsername().equals(username)) return user;
        }
        return null;
    }

    public static boolean existInUsersPath(String username){
        File usersDirectory = new File(getUsersPath());
        for (final File fileEntry : usersDirectory.listFiles()) {
            if(username.equals(fileEntry.getName().replace(getPassExt(), ""))) return true;
        }
        return false;
    }
}
