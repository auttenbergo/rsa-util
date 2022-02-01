import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Encryptor {

    public static String DEFAULT_TRANSFORMATION = "RSA";

    private static byte[] encryptMessageWithKey(String message, Key key, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (transformation == null) transformation = DEFAULT_TRANSFORMATION;

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encoded = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    public static byte[] encryptMessageWithPublicKey(String message, PublicKey publicKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptMessageWithPublicKey(message, publicKey, DEFAULT_TRANSFORMATION);
    }

    public static byte[] encryptMessageWithPublicKey(String message, PublicKey publicKey, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encryptMessageWithKey(message, publicKey, transformation);
    }

    public static byte[] encryptMessageWithPrivateKey(String message, PrivateKey privateKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return encryptMessageWithPrivateKey(message, privateKey, DEFAULT_TRANSFORMATION);
    }

    public static byte[] encryptMessageWithPrivateKey(String message, PrivateKey privateKey, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encryptMessageWithKey(message, privateKey, transformation);
    }
}
