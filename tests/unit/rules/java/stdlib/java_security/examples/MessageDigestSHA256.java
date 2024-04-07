// level: NONE
import java.security.*;


public class MessageDigestSHA256 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA256 hashing algorithm not available.");
        }
    }
}
