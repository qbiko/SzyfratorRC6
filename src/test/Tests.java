package test;

import com.company.MainWindow;
import com.company.SecretCode;
import com.company.User;
import com.company.WorkMode;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.MessageDigest;

import static com.company.CommonMethods.initCipher;
import static com.company.CommonMethods.readFile;
import static com.company.Constants.*;
import static com.company.SecretCode.decode;
import static com.company.User.createUserList;
import static com.company.User.mainUsersList;
import static org.junit.jupiter.api.Assertions.*;

class Tests {

    private static final WorkMode workMode = WorkMode.CFB;
    private static final int subBlockSize = 8;
    private static final int keySize = 128;
    private static final String fileInName = "plikDoSzyfr.mp3";
    private static final String cipherFileName = "plikZaszyfr";
    private static final String decodedFileName = "plikOdszyfr.mp3";
    private static final String mail = "test@wp.pl";
    private static final String password = "test";
    private static final String wrongPassword = "test1";
    private static final String newUserName = "newUserTestName@o2.pl";
    private static final String newPassword = "newUserTestPassword";
    private static final String publickKeyFileName = "kluczPubTest.txt";

    @BeforeEach
    void init() {
        clearData();
    }

    @Test
    public void encodeAndDecodeFile() throws Exception {
        MainWindow window = new MainWindow();
        byte [] iv = window.generateIV();
        createUserList();
        File file = new File(getWorkingDirectory()+"/"+fileInName);
        byte[] fileToEncode = readFile(file.getAbsolutePath());

        MessageDigest fileBeforeEncoding = MessageDigest.getInstance("SHA-256");
        fileBeforeEncoding.update(fileToEncode);

        RC6Engine rc6eng=new RC6Engine();

        KeyGenerator keyGen = KeyGenerator.getInstance(getAlgorithmName());
        keyGen.init(keySize);
        SecretKey sessionKey = keyGen.generateKey();

        KeyParameter keyParameter = new KeyParameter(sessionKey.getEncoded());

        BufferedBlockCipher cipher = initCipher(workMode, rc6eng, keyParameter, iv, subBlockSize, true);

        byte[] cipherFile = new byte[cipher.getOutputSize(fileToEncode.length)];

        int ptLength = cipher.processBytes(fileToEncode,0,fileToEncode.length,cipherFile,0);
        ptLength += cipher.doFinal(cipherFile,ptLength);

        SecretCode secretCode = new SecretCode(workMode, "128", Integer.toString(subBlockSize), Integer.toString(keySize), iv, mainUsersList,
                cipherFile, cipherFileName, sessionKey.getEncoded());
        assertTrue(secretCode.isStatus());

        File encodingFile = new File(getCipheredFilePath()+"/"+cipherFileName);
        boolean correctDecoding = decode(encodingFile, decodedFileName, mail, password);
        assertTrue(correctDecoding);

        File decodedFile = new File(getDecryptedFilePath()+"/"+decodedFileName);
        byte[] decodedFileBytes = readFile(decodedFile.getAbsolutePath());

        MessageDigest fileAfterDecoding = MessageDigest.getInstance("SHA-256");
        fileAfterDecoding.update(decodedFileBytes);

        assertTrue(MessageDigest.isEqual(fileBeforeEncoding.digest(),fileAfterDecoding.digest()));

    }

    @Test
    public void encodeAndDecodeFileWithWrongPassword() throws Exception {
        MainWindow window = new MainWindow();
        byte [] iv = window.generateIV();
        createUserList();
        File file = new File(getWorkingDirectory()+"/"+fileInName);
        byte[] fileToEncode = readFile(file.getAbsolutePath());

        MessageDigest fileBeforeEncoding = MessageDigest.getInstance("SHA-256");
        fileBeforeEncoding.update(fileToEncode);

        RC6Engine rc6eng=new RC6Engine();

        KeyGenerator keyGen = KeyGenerator.getInstance(getAlgorithmName());
        keyGen.init(keySize);
        SecretKey sessionKey = keyGen.generateKey();

        KeyParameter keyParameter = new KeyParameter(sessionKey.getEncoded());

        BufferedBlockCipher cipher = initCipher(workMode, rc6eng, keyParameter, iv, subBlockSize, true);

        byte[] cipherFile = new byte[cipher.getOutputSize(fileToEncode.length)];

        int ptLength = cipher.processBytes(fileToEncode,0,fileToEncode.length,cipherFile,0);
        ptLength += cipher.doFinal(cipherFile,ptLength);

        SecretCode secretCode = new SecretCode(workMode, "128", Integer.toString(subBlockSize), Integer.toString(keySize), iv, mainUsersList,
                cipherFile, cipherFileName, sessionKey.getEncoded());
        assertTrue(secretCode.isStatus());

        File encodingFile = new File(getCipheredFilePath()+"/"+cipherFileName);
        boolean correctDecoding = decode(encodingFile, decodedFileName, mail, wrongPassword);
        assertTrue(correctDecoding);

        File decodedFile = new File(getDecryptedFilePath()+"/"+decodedFileName);
        byte[] decodedFileBytes = readFile(decodedFile.getAbsolutePath());

        MessageDigest fileAfterDecoding = MessageDigest.getInstance("SHA-256");
        fileAfterDecoding.update(decodedFileBytes);

        assertFalse(MessageDigest.isEqual(fileBeforeEncoding.digest(),fileAfterDecoding.digest()));
        assertEquals(file.length(),decodedFile.length());

    }

    @Test
    public void addingNewUser(){
        createUserList();
        int passCount = new File(getUsersPath()).listFiles().length;
        int pubCount = new File(getPublicPath()).listFiles().length;
        int privCount = new File(getPrivatePath()).listFiles().length;

        User user = new User(newUserName);
        user.setHashPassword(newPassword);
        user.generateKeyPair();
        user.savePasswordFile();

        int newPassCount = new File(getUsersPath()).listFiles().length;
        int newPubCount = new File(getPublicPath()).listFiles().length;
        int newPrivCount = new File(getPrivatePath()).listFiles().length;

        assertEquals(passCount+1, newPassCount);
        assertEquals(pubCount+1, newPubCount);
        assertEquals(privCount+1, newPrivCount);
    }

    @Test
    public void importPublicKey(){
        createUserList();
        int passCount = new File(getUsersPath()).listFiles().length;
        int pubCount = new File(getPublicPath()).listFiles().length;
        int privCount = new File(getPrivatePath()).listFiles().length;

        File publickKeyFile = new File(getWorkingDirectory()+"/"+publickKeyFileName);

        User user = new User(newUserName);
        user.setPublicKey(publickKeyFile);
        user.savePublicKeyFile();

        int newPassCount = new File(getUsersPath()).listFiles().length;
        int newPubCount = new File(getPublicPath()).listFiles().length;
        int newPrivCount = new File(getPrivatePath()).listFiles().length;

        assertEquals(passCount, newPassCount);
        assertEquals(pubCount+1, newPubCount);
        assertEquals(privCount, newPrivCount);
    }

    @AfterAll
    static void tearDownAll() {
        clearData();
    }

    private static void clearData(){
        File cipherFile = new File(getCipheredFilePath()+"/"+cipherFileName);
        cipherFile.delete();
        File decodedFile = new File(getDecryptedFilePath()+"/"+decodedFileName);
        decodedFile.delete();
        File userPass = new File(getUsersPath()+"/"+newUserName+getPassExt());
        userPass.delete();
        File userPubKey = new File(getPublicPath()+"/"+newUserName+getPublExt());
        userPubKey.delete();
        File userPrivKey = new File(getPrivatePath()+"/"+newUserName+getPrivExt());
        userPrivKey.delete();
        File publickKeyFile = new File(getPublicPath()+"/"+publickKeyFileName);
        publickKeyFile.delete();
    }

}