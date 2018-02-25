package by.mrj.crypto.util;

import by.mrj.crypto.curve.Secp256k1;
import by.mrj.crypto.hash.Ripemd160;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import com.google.common.hash.Hashing;

public class CryptoUtils {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public static final byte[] privateKey = generatePrivateKey(); // FIXME: tmp solution while app is not persistent.
    public static final byte[] pubKey = getPublicKey(privateKey, false); // FIXME: tmp solution while app is not persistent.


    public static String doubleSha256(String toHash) {
        return sha256(sha256(toHash));
    }

    public static String sha256(String toHash) {
        return Hashing.sha256()
                .hashString(toHash, StandardCharsets.UTF_8)
                .toString();
    }

    public static String sha256ripemd160(String toHash) {
        return Ripemd160.hash(CryptoUtils.sha256(toHash)); // used for address. In Bitcoin toHash is a PubK.
    }

    /**
     * Converts a private key into its corresponding public key.
     */
    @SneakyThrows
    public static byte[] getPublicKey(byte[] privateKey, boolean compressed) {
        ECPoint pointQ = Secp256k1.getG().multiply(new BigInteger(1, privateKey));

        return pointQ.getEncoded(compressed);
    }

    // BC docs
    @SneakyThrows
    public static byte[] generatePrivateKey() {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(Secp256k1.ecParamSpec(), new SecureRandom());
        return g.generateKeyPair().getPrivate().getEncoded();
    }

    /**
     * Sign data using the ECDSA algorithm.
     */
    @SneakyThrows
    public static byte[] sign(byte[] data, byte[] privateKey) {
        ECDSASigner ecdsaSigner = new ECDSASigner();
        ECPrivateKeyParameters privateKeyParms = new ECPrivateKeyParameters(new BigInteger(1, privateKey), Secp256k1.domainParams());
        ParametersWithRandom params = new ParametersWithRandom(privateKeyParms);

        ecdsaSigner.init(true, params);

        BigInteger[] sig = ecdsaSigner.generateSignature(data);
/*            List<byte[]> sigData = new LinkedList<>();
            byte[] publicKey = getPublicKey(privateKey, false);
            byte recoveryId = getRecoveryId(sig[0].toByteArray(), sig[1].toByteArray(), data, publicKey);
            for (BigInteger sigChunk : sig) {
                sigData.add(sigChunk.toByteArray());
            }
            sigData.add(new byte[]{recoveryId});
            return sigData.toArray(new byte[][]{});*/
        return combine(sig[0], sig[1]);
    }

    public static boolean verifySignature(byte[] message, byte[] pubKey, byte[] signature) {
        ECDSASigner ecdsaSigner = new ECDSASigner();
        ECPoint ecPointQ = Secp256k1.curve().decodePoint(pubKey);
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(ecPointQ, Secp256k1.domainParams());

        ecdsaSigner.init(false, publicKeyParameters);

        BigInteger[] rAndS = splitSig(signature);

        return ecdsaSigner.verifySignature(message, rAndS[0], rAndS[1]);
    }

    @SneakyThrows
    private static BigInteger[] splitSig(byte[] signature) {
        DLSequence derSeq = (DLSequence) DERSequence.fromByteArray(signature);
        DERTaggedObject rTagged = (DERTaggedObject) derSeq.getObjectAt(0);
        DERTaggedObject sTagged = (DERTaggedObject) derSeq.getObjectAt(1);

        return new BigInteger[]{
                ((ASN1Integer) rTagged.getObject()).getValue(),
                ((ASN1Integer) sTagged.getObject()).getValue()
        };
    }

    @SneakyThrows
    private static byte[] combine(BigInteger r, BigInteger s) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, new ASN1Integer(r)));
        v.add(new DERTaggedObject(true, 1, new ASN1Integer(s)));

        DERSequence derSequence = new DERSequence(v);
        return derSequence.getEncoded();
    }
}
