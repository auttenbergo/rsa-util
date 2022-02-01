import java.security.Key;
import java.util.Base64;

public class KeysUtils {

    public static String getKeyValueAsString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static byte[] getKeyValueAsByteArray(String keyValue) {
        return Base64.getDecoder().decode(keyValue);
    }

}
