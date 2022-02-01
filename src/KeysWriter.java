import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public class KeysWriter {

    public static final String PRIVATE_KEY_FILE_FORMAT = ".key";
    public static final String PUBLICK_KEY_FILE_FORMAT = ".pem";

    public static final String DEFAULT_FOLDER_PATH = "./";
    public static final String DEFAULT_PRIVATE_KEY_FILE_NAME = "privateKey";
    private static final String DEFAULT_PUBLIC_KEY_FILE_NAME = "publicKey";

    private static String getFullFilePath(String folderPath, String fileName, String extension) {
        return folderPath + fileName + extension;
    }

    private static void saveFile(String outFile, Key key) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(outFile);
        fileOutputStream.write(key.getEncoded());
        fileOutputStream.close();
    }

    public static void savePrivateKey(PrivateKey privateKey, String folderPath, String fileName) throws IOException {
        if (folderPath == null) folderPath = DEFAULT_FOLDER_PATH;
        if (fileName == null) fileName = DEFAULT_PRIVATE_KEY_FILE_NAME;

        String outFile = getFullFilePath(folderPath, fileName, PRIVATE_KEY_FILE_FORMAT);
        saveFile(outFile, privateKey);

    }

    public static void savePublicKey(PublicKey publicKey, String folderPath, String fileName) throws IOException {
        if (folderPath == null) folderPath = DEFAULT_FOLDER_PATH;
        if (fileName == null) fileName = DEFAULT_PUBLIC_KEY_FILE_NAME;

        String outFile = getFullFilePath(folderPath, fileName, PUBLICK_KEY_FILE_FORMAT);
        saveFile(outFile, publicKey);
    }

    public static void saveKeys(KeyPair keyPair) throws IOException {
        saveKeys(keyPair, DEFAULT_FOLDER_PATH);
    }

    public static void saveKeys(KeyPair keyPair, String folderPath) throws IOException {
        Objects.requireNonNull(keyPair, "Parameter 'keyPair' is required");
        if (folderPath == null) folderPath = DEFAULT_FOLDER_PATH;

        PrivateKey privateKey = keyPair.getPrivate();
        savePrivateKey(privateKey, folderPath, DEFAULT_PRIVATE_KEY_FILE_NAME);

        PublicKey publicKey = keyPair.getPublic();
        savePublicKey(publicKey, folderPath, DEFAULT_PUBLIC_KEY_FILE_NAME);
    }
}
