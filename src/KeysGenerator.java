import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeysGenerator {

    public static String DEFAULT_ALGORITHM = "RSA";
    public static int DEFAULT_KEY_SIZE = 1024;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return generateKeyPair(DEFAULT_ALGORITHM, DEFAULT_KEY_SIZE);
    }

    public static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        if (algorithm == null)
            algorithm = DEFAULT_ALGORITHM;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);

        return keyPairGenerator.generateKeyPair();
    }

}
