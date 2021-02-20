package ru.sber.crypt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.sber.crypt.excep.CryptoException;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
public class ExecutionService {

    @Autowired
    private Encryptor encryptor;

    @PostConstruct
    public void testEncrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        var key = "jackrutorial.com";

        encryptor.encryptedFile(key, "res/sample.txt", "res/file.encr");
        encryptor.decryptedFile(key, "res/file.encr", "res/file.decr");

    }
}
