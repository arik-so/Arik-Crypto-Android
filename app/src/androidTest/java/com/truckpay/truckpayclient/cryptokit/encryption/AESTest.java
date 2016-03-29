package com.truckpay.truckpayclient.cryptokit.encryption;


import android.test.InstrumentationTestCase;
import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by arik on 3/29/16.
 */
public class AESTest extends InstrumentationTestCase {

    public void testGenerationLength(){

        String key = AES.generateKey();
        String iv = AES.generateInitializationVector();

        byte[] rawKey = Base64.decode(key, Base64.DEFAULT);
        byte[] rawIV = Base64.decode(iv, Base64.DEFAULT);

        assertEquals(rawKey.length, 32);
        assertEquals(rawIV.length, 16);

    }

    public void testAESEncryption() throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

        String key = AES.generateKey();
        String iv = AES.generateInitializationVector();

        String someData = "Hello World!";
        String encryptedData = AES.encrypt(someData, key, iv);
        String decryptedData = AES.decrypt(encryptedData, key, iv);

        assertEquals(someData, decryptedData);
    }



}
