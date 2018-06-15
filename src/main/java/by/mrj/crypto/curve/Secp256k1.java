package by.mrj.crypto.curve;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
//import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

public class Secp256k1 {

    private final static ECParameterSpec ecParamSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    private final static ECCurve curve = ecParamSpec.getCurve();
    private final static ECPoint G = ecParamSpec.getG();
    private final static ECDomainParameters domainParams = new ECDomainParameters(curve, G, getN());

    public static ECDomainParameters domainParams() {
        return domainParams;
    }

    public static ECParameterSpec ecParamSpec() {
        return ecParamSpec;
    }

    private static ECPoint getPoint(BigInteger k) {
        return G.multiply(k.mod(ecParamSpec.getN()));
    }

    public static ECPoint getG() {
        return G;
    }

    public static BigInteger getN() {
        return ecParamSpec.getN();
    }

    private static int getFieldSize() {
        return ecParamSpec.getCurve().getFieldSize();
    }

    public static ECCurve curve() {
        return curve;
    }
}
