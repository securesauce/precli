// level: ERROR
// start_line: 13
// end_line: 13
// start_column: 57
// end_column: 63
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class MessageDigestSHA1 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA1 hashing algorithm not available.");
        }
    }
}
