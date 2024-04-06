// level: ERROR
// start_line: 15
// end_line: 15
// start_column: 40
// end_column: 59
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


public class Example {
    public static void main(String [] args) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        } catch (NoSuchPaddingException exception) {
            exception.printStackTrace();
        }
    }
}
