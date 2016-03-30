package com.truckpay.truckpayclient.rest;

import android.test.InstrumentationTestCase;
import android.util.Base64;

import com.truckpay.truckpayclient.REST;
import com.truckpay.truckpayclient.cryptokit.Hashing;
import com.truckpay.truckpayclient.cryptokit.encoding.HexBinary;
import com.truckpay.truckpayclient.cryptokit.encryption.AES;
import com.truckpay.truckpayclient.cryptokit.encryption.RSA;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Created by arik on 3/29/16.
 */
public class AuthenticationTest extends InstrumentationTestCase {

    public void testLogin() throws JSONException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {

        String domain = "https://f9cec573.ngrok.io";

        // logging in

        String username = "testnewaes2@truckpay.com";
        String password = "abc12345";

        String hashedPassword = Hashing.sha256(password + '|' + username);

        JSONObject object = new JSONObject();
        object.put("email", username);
        object.put("password", hashedPassword);

        String responseJSON = REST.post(domain + "/users/login", object);
        JSONObject response = new JSONObject(responseJSON);


        // processing login response

        int userID = response.getJSONObject("response").getInt("user_id");
        String initVector = response.getJSONObject("response").getString("initialization_vector");
        String publicKey = response.getJSONObject("response").getString("public_key");
        String encryptedPrivateKey = response.getJSONObject("response").getString("private_key");
        String encryptedToken = response.getJSONObject("response").getString("token");

        String symmetricKeyHex = Hashing.sha256(username + '|' + password);
        String symmetricKey = Base64.encodeToString(HexBinary.hexToBinary(symmetricKeyHex), Base64.DEFAULT);

        // for Ben's IV format, now to be deprecated
        String alternativeIV = Base64.encodeToString(initVector.getBytes(StandardCharsets.US_ASCII), Base64.DEFAULT);

        String privateKey = AES.decrypt(encryptedPrivateKey, symmetricKey, initVector);
        String token = RSA.decryptWithPrivate(encryptedToken, privateKey);


        // sending authenticated request (getProfile)

        String url = domain + "/users/profile/" + userID;

        String timestamp = "" + ((new Date()).getTime() / 1000); // we need it in seconds, not ms
        String requestHashInput = timestamp + '|' + token + '|';
        String requestHash = Hashing.sha256(requestHashInput);
        String requestSignature = RSA.encryptWithPrivate(requestHash, privateKey)
        .replaceAll("\r", "").replaceAll("\n", "");

        JSONObject headers = new JSONObject();
        headers.put("token", token);
        headers.put("timestamp", timestamp);
        headers.put("signature", requestSignature);

        String profileResponse = REST.get(url, headers);
        System.out.println("here");

    }

}
