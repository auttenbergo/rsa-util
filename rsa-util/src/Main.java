import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Main {

    private static void printKeyValues(KeyPair keyPair) {
        System.out.println("---------------------");
        System.out.println("Public key:\n" + KeysUtils.getKeyValueAsString(keyPair.getPublic()));
        System.out.println("\n\n");
        System.out.println("Private key:\n" + KeysUtils.getKeyValueAsString(keyPair.getPrivate()));
        System.out.println("---------------------");
    }

    private static void saveAndRetrieveCheck(KeyPair keyPair) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("Checking saving...");
        KeysWriter.saveKeys(keyPair);
        System.out.println("Saved");

        System.out.println("Checking reading...");
        PrivateKey readPrivateKey = KeysReader.readPrivateKey("./privateKey.key");
        PublicKey readPublicKey = KeysReader.readPublicKey("./publicKey.pem");
        System.out.println("Read");
        System.out.println("Checking equality");
        assert keyPair.getPrivate().equals(readPrivateKey);
        assert keyPair.getPublic().equals(readPublicKey);
        System.out.println("Check succeeded !\n");
    }

    private static void encryptPrivateDecryptPublicCheck(KeyPair keyPair) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String message = "Hello World!";

        System.out.println("Checking encryption with private key and decryption with public...");
        byte[] encrypted = Encryptor.encryptMessageWithPrivateKey(message, keyPair.getPrivate());
        String decrypted = Decryptor.decryptMessageWithPublicKey(encrypted, keyPair.getPublic());
        assert message.equals(decrypted);
        System.out.println("Check Succeeded !");
    }

    private static void encryptPublicDecryptPrivateCheck(KeyPair keyPair) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String message = "Hello World: Returns!";

        System.out.println("Checking encryption with public key and decryption with private...");
        byte[] encrypted = Encryptor.encryptMessageWithPublicKey(message, keyPair.getPublic());
        String decrypted = Decryptor.decryptMessageWithPrivateKey(encrypted, keyPair.getPrivate());
        assert message.equals(decrypted);
        System.out.println("Check Succeeded !");
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        KeyPair keyPair = KeysGenerator.generateKeyPair();
        saveAndRetrieveCheck(keyPair);
        printKeyValues(keyPair);
        encryptPublicDecryptPrivateCheck(keyPair);
        encryptPrivateDecryptPublicCheck(keyPair);

    }
}
