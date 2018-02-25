package by.mrj.crypto.util;

import org.junit.Test;

import static by.mrj.crypto.util.CryptoUtils.doubleSha256;
import static org.assertj.core.api.Assertions.assertThat;


public class CryptoUtilsTest {

    @Test
    public void doubleSha256_Success() { // Online calculated value.
        assertThat(doubleSha256("123")).isEqualTo("173af653133d964edfc16cafe0aba33c8f500a07f3ba3f81943916910c257705");
    }
}