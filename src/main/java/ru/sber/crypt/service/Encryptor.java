package ru.sber.crypt.service;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
public class Encryptor {

    public  void encryptedFile(String secretKey, String fileInputPath, String fileOutPath)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        File fileInput = new File(fileInputPath);
        FileInputStream inputStream = new FileInputStream(fileInput);
        byte[] inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        File fileEncryptOut = new File(fileOutPath);
        FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

    }

    public  void decryptedFile(String secretKey, String fileInputPath, String fileOutPath)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        File fileInput = new File(fileInputPath);
        FileInputStream inputStream = new FileInputStream(fileInput);
        byte[] inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        File fileEncryptOut = new File(fileOutPath);
        FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

    }








//    private static final String ALGORITHM = "AES";
//    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
//
//    public static void encrypt(String key, File inputFile, File outputFile)
//            throws CryptoException {
//        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
//    }
//
//    public static void decrypt(String key, File inputFile, File outputFile)
//            throws CryptoException {
//        doCrypto2(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
//    }
//
//    private static void doCrypto(int cipherMode, String key, File inputFile,
//                                 File outputFile) throws CryptoException {
//        try {
//            SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM).generateKey();
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//            cipher.init(cipherMode, secretKey);
//
//            FileInputStream inputStream = new FileInputStream(inputFile);
//            byte[] inputBytes = new byte[(int) inputFile.length()];
//            inputStream.read(inputBytes);
//
//            byte[] outputBytes = cipher.doFinal(inputBytes);
//
//            FileOutputStream outputStream = new FileOutputStream(outputFile);
//            outputStream.write(outputBytes);
//
//            inputStream.close();
//            outputStream.close();
//
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException
//                | InvalidKeyException | BadPaddingException
//                | IllegalBlockSizeException | IOException ex) {
//            throw new CryptoException("Error encrypting/decrypting file", ex);
//        }
//    }
//
//    private static void doCrypto2(int cipherMode, String key, File inputFile,
//                                 File outputFile) throws CryptoException {
//        try {
//            FileInputStream inputStream = new FileInputStream(inputFile);
//            SecretKey secretKey = KeyGenerator.getInstance(ALGORITHM).generateKey();
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//
//            byte[] fileIv = new byte[16];
//            inputStream.read(fileIv);
////            inputStream.close();
//
//            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(fileIv));
//
////            FileInputStream inputStream2 = new FileInputStream(inputFile);
//
////            byte[] inputBytes = new byte[(int) inputFile.length()];
////            inputStream.read(inputBytes);
//
//            byte[] outputBytes = cipher.doFinal(inputStream.readAllBytes());
//
//            FileOutputStream outputStream = new FileOutputStream(outputFile);
//            outputStream.write(outputBytes);
//
//            inputStream.close();
//            outputStream.close();
//
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException  | IOException | InvalidAlgorithmParameterException ex) {
//            throw new CryptoException("Error encrypting/decrypting file", ex);
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        }
//    }


















    //    String decrypt(String fileName) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException {
//
//        String content;
//
//        try (FileInputStream fileIn = new FileInputStream(fileName)) {
//            byte[] fileIv = new byte[16];
//            fileIn.read(fileIv);
//            this.cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(fileIv));
//
//            try (
//                    CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher);
//                    InputStreamReader inputReader = new InputStreamReader(cipherIn);
//                    BufferedReader reader = new BufferedReader(inputReader)
//            ) {
//
//                StringBuilder sb = new StringBuilder();
//                String line;
//                while ((line = reader.readLine()) != null) {
//                    sb.append(line);
//                }
//                content = sb.toString();
//            }
//
//        }
//        return content;
//    }

//    private SecretKey secretKey;
//    private Cipher cipher;
//
//    void encrypt(String content, String fileName, SecretKey secretKey, String cipher) throws InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException {
//        this.secretKey = secretKey;
//        this.cipher = Cipher.getInstance(cipher);
//        this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//        byte[] iv = this.cipher.getIV();
//
//        try (
//                FileOutputStream fileOut = new FileOutputStream(fileName);
//                CipherOutputStream cipherOut = new CipherOutputStream(fileOut, this.cipher)
//        ) {
//            fileOut.write(iv);
//            cipherOut.write(content.getBytes());
//        }
//
//    }
//

}
