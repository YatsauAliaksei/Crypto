package by.mrj.crypto.hash;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class RipemD160Test {

    @Test
    public void hash_Success() {
        String hash = Ripemd160.hash("Aliaksei");
        assertThat(hash).isEqualTo("d0103c0fd64a50485568a05359b914d2d60d2e6a");
    }

}