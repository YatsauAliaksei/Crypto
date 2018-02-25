package by.mrj.crypto.util;

import com.google.common.io.BaseEncoding;

public class EncodingUtils {


    public static class HEX {

        public static String encode(byte[] toEncode) {
            return BaseEncoding.base16().encode(toEncode);
        }

        public static byte[] decode(String toDecode) {
            return BaseEncoding.base16().decode(toDecode);
        }
    }

}
