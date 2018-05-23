import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class KeyGeneration {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), 512, 80));
        AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();

        System.out.println(bytesToHex(privateKey.getExponent().toByteArray()));
        System.out.println(bytesToHex(privateKey.getModulus().toByteArray()));

        System.out.println(bytesToHex(publicKey.getExponent().toByteArray()));
        System.out.println(bytesToHex2(publicKey.getModulus().toByteArray()));
    }

    public static String bytesToHex2(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < hexChars.length; i += 2) {
            builder.append("(byte)0x")
                    .append(hexChars[i])
                    .append(hexChars[i + 1])
                    .append(", ")
            ;
        }

        return builder.toString();
    }
}