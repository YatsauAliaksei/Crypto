package by.mrj.crypto.hash;

import lombok.SneakyThrows;

import javax.annotation.Nonnull;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * This hash function is used as a second hashing function for address in Bitcoin blockchain.
 */
public class Ripemd160 {

    private static String DEFAULT_CHARSET_NAME = "US-ASCII";

    @SneakyThrows
    public static String hash(@Nonnull String toHash) {

        byte[] r = toHash.getBytes(DEFAULT_CHARSET_NAME);

        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(r, 0, r.length);
        byte[] o = new byte[digest.getDigestSize()];
        digest.doFinal(o, 0);

        return new String(Hex.encode(o, 0, o.length), DEFAULT_CHARSET_NAME);
    }
}
