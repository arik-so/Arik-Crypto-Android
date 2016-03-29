package com.truckpay.truckpayclient.cryptokit.encoding;

import android.test.InstrumentationTestCase;
import android.util.Base64;

/**
 * Created by arik on 3/29/16.
 */
public class HexBinaryTest extends InstrumentationTestCase {

    public void testBinaryToHex() throws Exception {

        byte[] bytes = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // Hello
        String expectedHex = "48656c6c6f";

        String actualHex = HexBinary.binaryToHex(bytes);
        assertEquals("bin2hex", expectedHex, actualHex);

    }

    public void testHexToBinary() throws Exception {

        String hex = "48656c6c6f";
        byte[] expectedBytes = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // Hello

        byte[] actualBytes = HexBinary.hexToBinary(hex);

        // base64 this shit
        String expectedString = Base64.encodeToString(expectedBytes, Base64.DEFAULT);
        String actualString = Base64.encodeToString(actualBytes, Base64.DEFAULT);

        assertEquals("hex2bin", expectedString, actualString);

    }

}
