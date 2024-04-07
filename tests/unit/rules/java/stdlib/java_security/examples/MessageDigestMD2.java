// level: ERROR
// start_line: 13
// end_line: 13
// start_column: 57
// end_column: 62
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class MessageDigestMD2 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("MD2 hashing algorithm not available.");
        }
    }
}
