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

    public void testKeyFiltration() {

        final String unfilteredKey = "-----BEGIN PRIVATE KEY-----\nasdfasdfwerasdf\n-----END PRIVATE KEY-----\n";
        String filteredKey = RSA.filter(unfilteredKey);
        assertEquals("asdfasdfwerasdf", filteredKey);

    }

    public void testPHPImportedSigning() throws IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BadPaddingException, IOException, NoSuchAlgorithmException {

        final String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0qo9A9VYGWskfzkabUXS\n" +
                "JcwiIx2KgSc8bAvtOm5uDgyop3tLpSvrhBXJj2WnPzkF3mIlBHuAiyNnWN8Iogil\n" +
                "08QlOwISmM1mexRGJPjX+ove4faexEtV5TqOSnbOC0QnDO5DWIhbIja0Go4X/sny\n" +
                "9X2jvlRzmUyjw9rl7DVA/HUSuTCVEV5HbqdN1HdKgQFvk4IEwe5KUa3ubHa7NHvr\n" +
                "T9XlsH9ln669MK3GcVusnjBTKL1Okdrgq4MRUMObZqFMtuxQoKPQYjilEo1/g1TX\n" +
                "zwne9jtpZ9s1WfHNTpDt/TO9Ip/vyDrCbJ4jBi70KPpHADFkXMT2Qy2EIp8YmVSL\n" +
                "CQIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";

        final String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSqj0D1VgZayR/\n" +
                "ORptRdIlzCIjHYqBJzxsC+06bm4ODKine0ulK+uEFcmPZac/OQXeYiUEe4CLI2dY\n" +
                "3wiiCKXTxCU7AhKYzWZ7FEYk+Nf6i97h9p7ES1XlOo5Kds4LRCcM7kNYiFsiNrQa\n" +
                "jhf+yfL1faO+VHOZTKPD2uXsNUD8dRK5MJURXkdup03Ud0qBAW+TggTB7kpRre5s\n" +
                "drs0e+tP1eWwf2Wfrr0wrcZxW6yeMFMovU6R2uCrgxFQw5tmoUy27FCgo9BiOKUS\n" +
                "jX+DVNfPCd72O2ln2zVZ8c1OkO39M70in+/IOsJsniMGLvQo+kcAMWRcxPZDLYQi\n" +
                "nxiZVIsJAgMBAAECggEAdo/BDys/De8y9zcYHG+zOfqNK94wWUfPxa9gsAX+goG1\n" +
                "Wa0WgbsaLZhlfALmAbsCBoqN8tvfGG+wdl/v5+GeEnTNz0v3U3AmQRbD84LpauTV\n" +
                "Z67449jSWtR9yILcq5KLt8dQt77mK3dGHbvi3U6jIm63fSLifGCZuly0EiBWlr33\n" +
                "g/A1mgUAvLqljVRIPJ2gZi7tzLTh47s0fyFETMZiGytkZXytOj3+JnMsD8puj68B\n" +
                "QYV2Dsm1Dce2sUKt+6LV7XNhJK20PijNZIBHFtriaqG2Tu8khgvi1bGh7U/H46+S\n" +
                "RFa5Iyd/LSqmbzZ7tmvtNd/463N7CxID2V2g9Nz5kQKBgQDrO/0M2txKGyFOnM3D\n" +
                "2o8KRYYNZxE82NljANOc3J/YMHoOzoYeAjNd/x8EeaqNYy6o2jfleaXeYlm+ke6E\n" +
                "xZOjmzuWuCbXiNxzRGqBJdlrloOO9b7l7EukVU1IXHeXhUtPRKzWsZzU9V8KolLR\n" +
                "NXkZuyDx5Py5I1EaEreakMrs9wKBgQDlQwM22koq2FgzTOpsoVp1DCLAOICczn+W\n" +
                "0JH3EpK0opxHl94b5XnetGTm3xOpzqpfbVGiz799jkkGZCZa6Mlae29TtpQs4JlU\n" +
                "xvZaoG6dhFDj+QIVc2VONceH3jydp9ud8+AR/u5P74B6r1ciAEAMTY0qZl9HRJVu\n" +
                "uwX8x9ZH/wKBgQCsiwDvF+3zcXj516xaV4sKJrrQQ+Rx9EFoDCgr6+xXQB+Xksbv\n" +
                "Zf/Vl5dhyfhe4vxLoFzVtmgC+bMIRLRmsSG9JNUNlZ/wApRo/Cr+9gtHjkyLZRgU\n" +
                "QEGvlV4tkJ2sB3qY9y+r/vWhgyWmgDAtAoMEa60boTH6frwzWr1P45rlOwKBgC3K\n" +
                "nr+8BghcwfEtMb2U1N6AGAjQwE+Rp0ZWTnFNEmRl/lUGbmSgByGGYokCkYjfMIRy\n" +
                "71VXrWXEn61ZH5gU2vLpqKjN1PbJvZaDTv13AeEQZp/CQrpKHDfs4fevWegbePAp\n" +
                "n924T51DtyPKFdtCtYg/jSyk2e8AMeC2FlIRECm9AoGAJNVFgaoUciGwqz+JxPB5\n" +
                "QybtzZBOrarAQuTrpNPVvmd0oXNRw1k6AG5IwpmlTYQ7LXVldt8WxeZDrkXeadof\n" +
                "HQ4HN8GXnizq9YmJ8PeoyqGptchBRbz6kjMr32yTObReTpZg2SCRkpdtRqd505an\n" +
                "zAhpbxoywsSo9sZ6c72rSms=\n" +
                "-----END PRIVATE KEY-----\n";

        final String original = "Hello World";

        String encrypted = RSA.encryptWithPublic(original, publicKey);
        String decrypted = RSA.decryptWithPrivate(encrypted, privateKey);

        String signed = RSA.encryptWithPrivate(original, privateKey);
        String verified = RSA.decryptWithPublic(signed, publicKey);

        assertEquals(original, decrypted);
        assertEquals(original, verified);

    }


}
