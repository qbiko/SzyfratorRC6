package com.company;

import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.*;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;


import static com.company.CommonMethods.*;
import static com.company.Constants.*;
import static com.company.User.getUserFromListByName;

public class SecretCode {
    boolean status = false;

    public SecretCode(WorkMode workMode, String blockSize, String subBlockSize, String keySize,
                      byte[] iv, List<User> receivierList, byte[] code, String fileName, byte[] cipherSessionKey) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getCipheredFilePath()+fileName);
            fos.write("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n".getBytes());
            fos.write("<EncryptedFile>\n".getBytes());
            fos.write(("\t<Algorithm>"+getAlgorithmName()+"</Algorithm>\n").getBytes());
            fos.write(("\t<CipherMode>"+workMode+"</CipherMode>\n").getBytes());
            fos.write(("\t<BlockSize>"+blockSize+"</BlockSize>\n").getBytes());
            fos.write("\t<SegmentSize>".getBytes());
            if(workMode == WorkMode.CFB || workMode == WorkMode.OFB){
                fos.write(subBlockSize.getBytes());
            }
            else {
                fos.write("0".getBytes());
            }
            fos.write("</SegmentSize>\n".getBytes());
            fos.write(("\t<KeySize>"+keySize+"</KeySize>\n").getBytes());
            fos.write(("\t<IV>").getBytes());
            if(workMode == WorkMode.ECB){
                fos.write("0".getBytes());
            }
            else {
                fos.write(Base64.getEncoder().encode(iv));
            }
            fos.write("</IV>\n".getBytes());
            fos.write("\t<ApprovedUsers>\n".getBytes());
            for (User user : receivierList) {
                fos.write("\t\t<User>\n".getBytes());
                fos.write(("\t\t\t<Email>"+user.getUsername()+"</Email>\n").getBytes());
                fos.write("\t\t\t<SessionKey>".getBytes());
                fos.write(Base64.getEncoder().encode(user.encodeSessionKey(cipherSessionKey)));
                fos.write("</SessionKey>\n".getBytes());
                fos.write("\t\t</User>\n".getBytes());
            }
            fos.write("\t</ApprovedUsers>\n".getBytes());
            fos.write("</EncryptedFile>\n".getBytes());
            fos.write(code);
            fos.close();
            status = true;
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }

    }

    public boolean isStatus() {
        return status;
    }

    public String printStatus(){
        return status ? "Szyfrowanie pliku powiodło się!" : "Wystąpił błąd podczasz szyfrowania pliku!";
    }

    public static boolean checkIfUserIsApproved(String username, NodeList approvedUsersList){
        for (int temp = 0; temp < approvedUsersList.getLength(); temp++) {
            Node approvedUser = approvedUsersList.item(temp);
            if(approvedUser.getNodeType() == Node.ELEMENT_NODE){
                Element userElement = (Element) approvedUser;
                String approvedName = userElement.getElementsByTagName("Email").item(0).getTextContent();
                if(approvedName.equals(username)){
                    return true;
                }

            }
        }
        return false;
    }

    public static String[] getApprovedUsersList(File file) throws Exception {
        prepareCipherFile(file);

        File xmlFile = new File(getTempDirectory()+getXmlTemp());
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(xmlFile);
        doc.getDocumentElement().normalize();
        NodeList approvedUsersList = doc.getElementsByTagName("User");
        String [] approvedUsersNames = new String[approvedUsersList.getLength()];
        for (int temp = 0; temp < approvedUsersList.getLength(); temp++) {
            Node approvedUser = approvedUsersList.item(temp);
            if(approvedUser.getNodeType() == Node.ELEMENT_NODE){
                Element userElement = (Element) approvedUser;
                String approvedName = userElement.getElementsByTagName("Email").item(0).getTextContent();
                approvedUsersNames[temp]=approvedName;
            }
        }
        xmlFile.delete();
        File cTempFile = new File(getTempDirectory()+getCipherTemp());
        cTempFile.delete();
        return approvedUsersNames;
    }

    public static byte[] getDecodedSessionKey(String username, NodeList approvedUsersList){
        for (int temp = 0; temp < approvedUsersList.getLength(); temp++) {
            Node approvedUser = approvedUsersList.item(temp);
            if(approvedUser.getNodeType() == Node.ELEMENT_NODE){
                Element userElement = (Element) approvedUser;
                String approvedName = userElement.getElementsByTagName("Email").item(0).getTextContent();
                if(approvedName.equals(username)){
                    return Base64.getDecoder().decode(userElement.getElementsByTagName("SessionKey").item(0).getTextContent());
                }

            }
        }
        return null;
    }

    public static byte [] decodeSessionKey(byte[] cipherSessionKey, PrivateKey privateKey){
        byte[] decodedSessionKey = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decodedSessionKey = cipher.doFinal(cipherSessionKey);
        } catch (Exception e) {
        }
        return decodedSessionKey;
    }

    public static boolean decode(File file, String newFileName, String username, String password){
        prepareCipherFile(file);

        File xmlFile = new File(getTempDirectory()+getXmlTemp());
        try{
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(xmlFile);
            doc.getDocumentElement().normalize();
            NodeList approvedUsersList = doc.getElementsByTagName("User");
            if(!checkIfUserIsApproved(username, approvedUsersList)) return false;

            User receivier = getUserFromListByName(username);

            byte[] decodedSessionKey = getDecodedSessionKey(username, approvedUsersList);

            String ivString = new String();
            String subBlockSize = new String();
            String workMode = new String();

            NodeList nList = doc.getElementsByTagName("EncryptedFile");
            for (int temp = 0; temp < nList.getLength(); temp++) {
                Node nNode = nList.item(temp);
                if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element eElement = (Element) nNode;
                    ivString = eElement.getElementsByTagName("IV").item(0).getTextContent();
                    subBlockSize = eElement.getElementsByTagName("SegmentSize").item(0).getTextContent();
                    workMode = eElement.getElementsByTagName("CipherMode").item(0).getTextContent();
                }
            }
            byte [] iv = null;
            if(WorkMode.valueOf(workMode)==WorkMode.ECB){
                iv = ivString.getBytes();
            }
            else{
                iv = Base64.getDecoder().decode(ivString.getBytes());
            }

            RC6Engine rc6eng=new RC6Engine();

            KeyParameter keyPar;
            try{
                keyPar=new KeyParameter(decodeSessionKey(decodedSessionKey, receivier.getPrivateKeyToDecode(createHashPassword(password))));
            }
            catch(Exception e){
                keyPar= new KeyParameter(password.getBytes());
            }


            BufferedBlockCipher cipher = initCipher(WorkMode.valueOf(workMode), rc6eng, keyPar, iv, Integer.parseInt(subBlockSize), false);

            Path cipherTempFile = Paths.get(getTempDirectory()+getCipherTemp());
            byte[] cipherFile = null;
            try {
                cipherFile = Files.readAllBytes(cipherTempFile);
            } catch (IOException e1) {
            }

            byte[] plainText = new byte[cipher.getOutputSize (cipherFile.length)];
            int ptLength = cipher.processBytes(cipherFile, 0, cipherFile.length, plainText, 0);
            try {
                ptLength += cipher.doFinal(plainText, ptLength);
            } catch (Exception ex) {
            }

            saveFile(newFileName, plainText);

            //System.out.println(" bytes: " +ptLength);

            File cTempFile = new File(getTempDirectory()+getCipherTemp());

            xmlFile.delete();
            cTempFile.delete();

        } catch (Exception e){
            return false;
        }

        return true;
    }
}


