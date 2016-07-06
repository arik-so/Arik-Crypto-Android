package com.truckpay.truckpayclient.cryptokit.encryption;

import android.util.Base64;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPrivateKeyStructure;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.InvalidPropertiesFormatException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by arik on 3/29/16.
 */
public class RSA {

    private static final String ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static RSAKeyPair generateKeyPair() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {

        return generateKeyPair(4096);
        // return null;

    }

    public static RSAKeyPair generateKeyPair(int size) throws IOException {

        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // this should never happen because the algorithm is fixed
        }

        keyGen.initialize(size);
        KeyPair keyPair = keyGen.generateKeyPair();

        return new RSAKeyPair(exportPrivateKey(keyPair.getPrivate()), exportPublicKey(keyPair.getPublic()));

    }



    public static String encryptWithPublic(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeySpecException, InvalidKeyException {

        // initialize
        byte[] byteData = data.getBytes(); // convert string to byte array
        PublicKey keyObject = extractPublicKey(publicKey);

        // encrypt
        Cipher cipher = null; // create conversion processing object
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        cipher.init(Cipher.ENCRYPT_MODE, keyObject); // initialize object's mode and key
        byte[] encryptedByteData = cipher.doFinal(byteData); // use object for encryption

        // return
        return Base64.encodeToString(encryptedByteData, Base64.DEFAULT);

    }

    public static String decryptWithPrivate(String encryptedData, String privateKey) throws IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {

        // initialize
        byte[] encryptedByteData = Base64.decode(encryptedData, Base64.DEFAULT);
        PrivateKey keyObject = extractPrivateKey(privateKey);

        String normalizedPrivateKey = exportPrivateKey(keyObject);

        // encrypt
        Cipher cipher = null; // create conversion processing object
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        cipher.init(Cipher.DECRYPT_MODE, keyObject); // initialize object's mode and key
        byte[] byteData = cipher.doFinal(encryptedByteData); // use object for encryption

        // return
        return new String(byteData);

    }

    public static String encryptWithPrivate(String data, String privateKey) throws IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // initialize
        byte[] byteData = data.getBytes(); // convert string to byte array
        PrivateKey keyObject = extractPrivateKey(privateKey);

        // encrypt
        Cipher cipher = null; // create conversion processing object
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        cipher.init(Cipher.ENCRYPT_MODE, keyObject); // initialize object's mode and key
        byte[] encryptedByteData = cipher.doFinal(byteData); // use object for encryption

        // return
        return Base64.encodeToString(encryptedByteData, Base64.DEFAULT);

    }

    public static String decryptWithPublic(String encryptedData, String publicKey) throws IOException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        // initialize
        byte[] encryptedByteData = Base64.decode(encryptedData, Base64.DEFAULT);
        PublicKey keyObject = extractPublicKey(publicKey);

        // encrypt
        Cipher cipher = null; // create conversion processing object
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        cipher.init(Cipher.DECRYPT_MODE, keyObject); // initialize object's mode and key
        byte[] byteData = cipher.doFinal(encryptedByteData); // use object for encryption

        // return
        return new String(byteData);

    }

    private static PublicKey extractPublicKey(String publicKey) throws IOException, InvalidKeySpecException {

        byte[] publicKeyBytes = normalizeKey(publicKey);

        PublicKey keyObject = null;
        try {
            keyObject = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        return keyObject;

    }

    private static String exportPublicKey(PublicKey publicKey) {
        String encodedPublicKey = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        return "-----BEGIN PUBLIC KEY-----\n" + wrap(encodedPublicKey, 64) + "-----END PUBLIC KEY-----\n";
    }

    private static String exportPrivateKey(PrivateKey privateKey) {

        try {
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            RSAPrivateKeyStructure cryptographyStandard1PrivateKey = RSAPrivateKeyStructure.getInstance(pki.getPrivateKey());
            byte[] cryptographyStandard1PrivateKeyBytes = cryptographyStandard1PrivateKey.getEncoded();

            String encodedPrivateKey = Base64.encodeToString(cryptographyStandard1PrivateKeyBytes, Base64.NO_WRAP);
            String legacyPrivateKeyFormat = "-----BEGIN PRIVATE KEY-----\n" + wrap(encodedPrivateKey, 64) + "-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            e.printStackTrace();
        }

        String encodedPrivateKey = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        return "-----BEGIN PRIVATE KEY-----\n" + wrap(encodedPrivateKey, 64) + "-----END PRIVATE KEY-----\n";
    }

    private static PrivateKey extractPrivateKey(String privateKey) throws InvalidKeySpecException, IOException {

        byte[] privateKeyBytes = normalizeKey(privateKey);

        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // should never happen
        }

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        PrivateKey key = null;
        InvalidKeySpecException exception = null;

        try {
            key = kf.generatePrivate(pkcs8KeySpec);
            return key;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        try {
            RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(privateKeyBytes));
            RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
            key = kf.generatePrivate(rsaPrivKeySpec);
            return key;
        } catch (InvalidKeySpecException e) {
            exception = e;
        }

        throw exception;

    }

    private static byte[] normalizeKey(String formattedKey){
        String filteredKey = filter(formattedKey);
        return Base64.decode(filteredKey, Base64.NO_WRAP);
    }

    public static String filter(String input){
        return input.replaceAll("-----[a-zA-Z ]*-----", "").replaceAll("\n", "").replaceAll("\r", "");
    }

    private static String wrap(String string, int length){
        String response = "";
        for (int i = 0; i < string.length(); i += length){
            String currentSubstring = string.substring(i);
            if (currentSubstring.length() > length) {
                currentSubstring = currentSubstring.substring(0, length);
            }
            response += currentSubstring + "\n";
        }
        return response;
    }

    public static class RSAKeyPair{

        private String privateKey;
        private String publicKey;

        private RSAKeyPair(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String encrypt(String data) throws IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BadPaddingException, IOException {
            return RSA.encryptWithPublic(data, this.getPublicKey());
        }

        public String decrypt(String data) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
            return RSA.decryptWithPrivate(data, this.getPrivateKey());
        }

    }

}
