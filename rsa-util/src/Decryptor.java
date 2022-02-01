import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class Decryptor {

    public static String DEFAULT_TRANSFORMATION = "RSA";

    private static String decryptMessageWithKey(byte[] encryptedMessage, Key key, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (transformation == null) transformation = DEFAULT_TRANSFORMATION;

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decrypted = cipher.doFinal(encryptedMessage);
        return new String(decrypted);
    }

    public static String decryptMessageWithPublicKey(byte[] encryptedMessage, PublicKey publicKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return decryptMessageWithPublicKey(encryptedMessage, publicKey, DEFAULT_TRANSFORMATION);
    }

    public static String decryptMessageWithPublicKey(byte[] encryptedMessage, PublicKey publicKey, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decryptMessageWithKey(encryptedMessage, publicKey, transformation);
    }

    public static String decryptMessageWithPrivateKey(byte[] encryptedMessage, PrivateKey privateKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return decryptMessageWithPrivateKey(encryptedMessage, privateKey, DEFAULT_TRANSFORMATION);
    }

    public static String decryptMessageWithPrivateKey(byte[] encryptedMessage, PrivateKey privateKey, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decryptMessageWithKey(encryptedMessage, privateKey, transformation);
    }
}
