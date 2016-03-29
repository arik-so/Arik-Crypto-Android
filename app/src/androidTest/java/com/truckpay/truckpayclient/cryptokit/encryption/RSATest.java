package com.truckpay.truckpayclient.cryptokit.encryption;

import android.test.InstrumentationTestCase;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by arik on 3/29/16.
 */
public class RSATest extends InstrumentationTestCase {

    public void testKeyGeneration() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BadPaddingException {

        RSA.RSAKeyPair keyPair = RSA.generateKeyPair();

        final String original = "Hello World";
        String encrypted = RSA.encryptWithPublic(original, keyPair.getPublicKey());
        String decrypted = RSA.decryptWithPrivate(encrypted, keyPair.getPrivateKey());

        String signed = RSA.encryptWithPrivate(original, keyPair.getPrivateKey());
        String verified = RSA.decryptWithPublic(signed, keyPair.getPublicKey());

        assertEquals(original, decrypted);
        assertEquals(original, verified);

    }

    public void testKeyFiltration(){

        final String unfilteredKey = "-----BEGIN PRIVATE KEY-----\nasdfasdfwerasdf\n-----END PRIVATE KEY-----\n";
        String filteredKey = RSA.filter(unfilteredKey);
        System.out.println("did it work?");

    }



}
