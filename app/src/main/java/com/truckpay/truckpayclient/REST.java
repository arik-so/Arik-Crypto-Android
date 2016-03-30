package com.truckpay.truckpayclient;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;

/**
 * Created by arik on 3/30/16.
 */
public class REST {

    public static String get(String url, JSONObject headers) throws IOException, JSONException {
        HttpClient httpClient = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(url);
        if (headers != null) {
            Iterator<?> keys = headers.keys();
            while (keys.hasNext()) {
                String currentKey = (String) keys.next();
                String currentValue = headers.getString(currentKey);
                httpGet.setHeader(currentKey, currentValue);
            }
        }
        HttpResponse response = httpClient.execute(httpGet);

        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        String responseString = "";
        String line = "";
        while ((line = rd.readLine()) != null) {
            responseString += line;
        }
        return responseString;
    }

    public static String post(String url, JSONObject data) throws IOException {
        HttpClient httpClient = new DefaultHttpClient();
        HttpPost httpPost = new HttpPost(url);
        if (data != null) {
            httpPost.setEntity(new StringEntity(data.toString()));
        }
        HttpResponse response = httpClient.execute(httpPost);

        BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
        String responseString = "";
        String line = "";
        while ((line = rd.readLine()) != null) {
            responseString += line;
        }
        return responseString;
    }

}
