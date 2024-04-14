// level: WARNING
// start_line: 9
// end_line: 9
// start_column: 83
// end_column: 93
public class JavaSecuritySecureRandomSHA1PRNG {
    public static void main(String[] args) {
        try {
            java.security.SecureRandom sr = java.security.SecureRandom.getInstance("SHA1PRNG");
        } catch (java.security.NoSuchAlgorithmException e) {
            System.err.println("SHA1PRNG random algorithm not available.");
        }
    }
}
