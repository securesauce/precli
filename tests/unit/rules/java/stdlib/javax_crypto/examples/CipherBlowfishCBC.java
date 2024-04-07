// level: ERROR
// start_line: 14
// end_line: 14
// start_column: 40
// end_column: 64
import java.security.*;
import javax.crypto.*;


public class CipherBlowfishCBC {
    public static void main(String [] args) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("Blowfish/CBC/NoPadding");
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        } catch (NoSuchPaddingException exception) {
            exception.printStackTrace();
        }
    }
}
