// level: ERROR
// start_line: 13
// end_line: 13
// start_column: 40
// end_column: 43
import java.security.*;

public class KeyPairGeneratorDSA {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            SecureRandom random = new SecureRandom();
            keyPairGenerator.initialize(512, random);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("DSA algorithm not available.");
        }
    }
}
