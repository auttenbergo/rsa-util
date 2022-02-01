import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeysReader {

    public static String DEFAULT_ALGORITHM = "RSA";

    private static byte[] readFileBytes(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        return Files.readAllBytes(path);
    }

    public static PrivateKey readPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readPrivateKey(DEFAULT_ALGORITHM, filePath);
    }

    public static PrivateKey readPrivateKey(String algorithm, String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (algorithm == null) algorithm = DEFAULT_ALGORITHM;
        byte[] privateKeyBytes = readFileBytes(filePath);

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        return keyFactory.generatePrivate(ks);
    }

    public static PublicKey readPublicKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readPublicKey(DEFAULT_ALGORITHM, filePath);
    }

    public static PublicKey readPublicKey(String algorithm, String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (algorithm == null) algorithm = DEFAULT_ALGORITHM;
        byte[] publicKeyBytes = readFileBytes(filePath);

        X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        return keyFactory.generatePublic(ks);
    }
}
