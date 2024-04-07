// level: ERROR
// start_line: 12
// end_line: 12
// start_column: 57
// end_column: 63
import java.security.*;


public class MessageDigestSHA1 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA1 hashing algorithm not available.");
        }
    }
}
