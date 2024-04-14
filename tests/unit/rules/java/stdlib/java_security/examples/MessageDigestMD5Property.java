// level: NONE
// False negative
import java.security.*;
import java.util.*;


public class MessageDigestMD5 {
    public static void main(String[] args) {
        try {
            Properties hashProps = new Properties();
            hashProps.setProperty("hashMd5", "MD5")
            String algorithm = hashProps.getProperty("hashMd5", "SHA256");
            MessageDigest md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("MD5 hashing algorithm not available.");
        }
    }
}
