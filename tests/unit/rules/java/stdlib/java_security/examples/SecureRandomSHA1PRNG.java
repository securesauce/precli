// level: WARNING
// start_line: 12
// end_line: 12
// start_column: 55
// end_column: 65
import java.security.*;


public class SecureRandomSHA1PRNG {
    public static void main(String[] args) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA1PRNG random algorithm not available.");
        }
    }
}
