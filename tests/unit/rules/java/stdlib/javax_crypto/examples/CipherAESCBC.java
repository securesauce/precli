// level: NONE
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


public class CipherAESCBC {
    public static void main(String [] args) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        } catch (NoSuchPaddingException exception) {
            exception.printStackTrace();
        }
    }
}
