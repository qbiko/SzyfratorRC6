package com.company;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

import static com.company.Constants.getDecryptedFilePath;
import static com.company.Constants.getTempDirectory;

public class CommonMethods {

    public static byte [] readFromFile(String path) {
        Path file = Paths.get(path);
        byte[] data = null;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException e1) {
        }
        return Base64.getDecoder().decode(data);
    }

    public static void prepareCipherFile(File file){
        try{
            FileInputStream fis = new FileInputStream(file);
            BufferedReader br = new BufferedReader(new InputStreamReader(fis));
            BufferedWriter xml = new BufferedWriter(new FileWriter(getTempDirectory()+"tempXml"));

            boolean stopXml = false;
            String all = new String();
            String line = null;
            while ((line = br.readLine()) != null && !stopXml) {
                xml.write(line+"\n");
                all +=line+"\n";
                if(line.equals("</EncryptedFile>")){
                    stopXml = true;
                    all +=line;
                }
                else{
                    all +=line+"\n";
                }
            }
            xml.close();
            br.close();
        }catch(Exception e){
        }
        Path path = Paths.get(getTempDirectory()+"tempXml");
        byte[] data = null;
        try {
            data = Files.readAllBytes(path);
        } catch (IOException e) {
        }
        FileInputStream inputStream;
        FileOutputStream filePart;
        int fileSize = (int) file.length();
        int nChunks = 0, read = 0, readLength = data.length;
        byte[] byteChunkPart;
        try {
            inputStream = new FileInputStream(file);

            byteChunkPart = new byte[readLength];
            read = inputStream.read(byteChunkPart, 0, readLength);
            fileSize -= read;
            assert (read == byteChunkPart.length);
            filePart = new FileOutputStream(new File(getTempDirectory()+"tempXml"));
            filePart.write(byteChunkPart);
            filePart.flush();
            filePart.close();
            byteChunkPart = null;
            filePart = null;

            byteChunkPart = new byte[fileSize];
            read = inputStream.read(byteChunkPart, 0, fileSize);
            assert (read == byteChunkPart.length);
            nChunks++;
            filePart = new FileOutputStream(new File(getTempDirectory()+"tempCipher"));
            filePart.write(byteChunkPart);
            filePart.flush();
            filePart.close();
            byteChunkPart = null;
            filePart = null;
            inputStream.close();
        } catch (IOException exception) {
        }

    }

    public static byte [] readFile(String path) {
        Path file = Paths.get(path);
        byte[] data = null;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException e1) {
        }
        return data;
    }

    public static void saveFile(String name, byte [] content){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getDecryptedFilePath()+name);
            fos.write(content);
            fos.close();
        } catch (IOException e) {
        }
    }

    public static BufferedBlockCipher initCipher(WorkMode workMode, RC6Engine rc6eng, KeyParameter keyParameter, byte[] iv, int subBlockSize, boolean cipherMode){
        BufferedBlockCipher cipher = null;
        switch (workMode){
            case ECB: {
                cipher = new PaddedBufferedBlockCipher(rc6eng);
                cipher.init(cipherMode, keyParameter);
                break;
            }
            case CBC: {
                cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(rc6eng));
                ParametersWithIV parWithIV=new ParametersWithIV(keyParameter,iv);
                cipher.init(cipherMode, parWithIV);
                break;
            }
            case CFB:{
                cipher = new BufferedBlockCipher(new CFBBlockCipher(rc6eng, subBlockSize));
                ParametersWithIV parWithIV=new ParametersWithIV(keyParameter,iv);
                cipher.init(cipherMode, parWithIV);
                break;
            }
            case OFB: {
                cipher = new BufferedBlockCipher(new OFBBlockCipher(rc6eng, subBlockSize));
                ParametersWithIV parWithIV=new ParametersWithIV(keyParameter,iv);
                cipher.init(cipherMode, parWithIV);
                break;
            }
        }
        return cipher;
    }

    public static byte [] createHashPassword(String password){
        byte [] hashPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes("UTF-8"));
            hashPassword =  md.digest();
        } catch (Exception e) {
        }
        return hashPassword;
    }
}
