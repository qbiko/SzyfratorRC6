package com.company;

import java.io.File;

/**
 * Created by jakub on 04.05.2017.
 */
public class Constants {
    private static final String APPLICATION_TITLE = "Szyfrator RC6";
    private static final String PUBLIC_PATH = "/keys/public";
    private static final String PRIVATE_PATH = "/keys/private";
    private static final String USERS_PATH = "/users";
    private static final String PASS_EXT = ".pass";
    private static final String PUBL_EXT = ".publ";
    private static final String PRIV_EXT = ".priv";
    private static final String ALGORITHM_NAME = "RC6";
    private static final String EMAIL_REGEX = "^[\\w-_\\.+]*[\\w-_\\.]\\@([\\w]+\\.)+[\\w]+[\\w]$";
    private static final String DECRYPTED_FILE_PATH = "/decryptedFiles/";
    private static final String CIPHERED_FILE_PATH = "/cipheredFiles/";
    private static final String WORKING_DIRECTORY = new File("").getAbsolutePath();
    private static final String XML_TEMP = "tempXml";
    private static final String CIPHER_TEMP = "tempCipher";
    private static final String TEMP_DIRECTORY = "/temp/";

    public static String getApplicationTitle() {
        return APPLICATION_TITLE ;
    }

    public static String getPublicPath() {
        return getWorkingDirectory()+PUBLIC_PATH;
    }

    public static String getPrivatePath() {
        return getWorkingDirectory()+PRIVATE_PATH;
    }

    public static String getUsersPath() {
        return getWorkingDirectory()+USERS_PATH;
    }

    public static String getAlgorithmName() {
        return ALGORITHM_NAME;
    }

    public static String getPassExt() {
        return PASS_EXT;
    }

    public static String getPublExt() {
        return PUBL_EXT;
    }

    public static String getPrivExt() {
        return PRIV_EXT;
    }

    public static String getEmailRegex() {
        return EMAIL_REGEX;
    }

    public static String getDecryptedFilePath() {
        return getWorkingDirectory()+DECRYPTED_FILE_PATH;
    }

    public static String getCipheredFilePath() {
        return getWorkingDirectory()+CIPHERED_FILE_PATH;
    }

    public static String getWorkingDirectory() {
        return WORKING_DIRECTORY;
    }

    public static String getXmlTemp() {
        return XML_TEMP;
    }

    public static String getCipherTemp() {
        return CIPHER_TEMP;
    }

    public static String getTempDirectory() {
        return getWorkingDirectory()+TEMP_DIRECTORY;
    }
}
