import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SecureFileStorageSystem {
    private static final String SECRET_KEY = "ThisIsASecretKey123"; // Replace with a secure key management solution

    private static Map<String, String> userCredentials = new HashMap<>(); // username -> encryptedPassword
    private static Map<String, String> userRoles = new HashMap<>(); // username -> role

    public static void main(String[] args) {
        // Initialize users with encrypted passwords and roles
        addUser("user1", encrypt("password1", SECRET_KEY), "admin");
        addUser("user2", encrypt("password2", SECRET_KEY), "user");

        // Simulate user authentication
        String username = "user1";
        String password = "password1";

        if (authenticateUser(username, password)) {
            String role = getUserRole(username);

            // Simulate file access based on user role
            if ("admin".equals(role)) {
                System.out.println("User has admin privileges. Access granted.");
            } else {
                System.out.println("User has regular privileges. Access granted.");
            }

            // Simulate file modification and log the action
            log(username, "Modified file: file.txt");
        } else {
            System.out.println("Authentication failed. Access denied.");
        }
    }

    // Encryption and Decryption methods
    private static String encrypt(String plainText, String secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES");
        Key key = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedText, String secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES");
        Key key = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    // User Authentication and Access Control methods
    private static void addUser(String username, String encryptedPassword, String role) {
        userCredentials.put(username, encryptedPassword);
        userRoles.put(username, role);
    }

    private static boolean authenticateUser(String username, String password) {
        try {
            String decryptedPassword = decrypt(userCredentials.get(username), SECRET_KEY);
            return decryptedPassword.equals(password);
        } catch (Exception e) {
            return false;
        }
    }

    private static String getUserRole(String username) {
        return userRoles.get(username);
    }

    // Audit Trails and Logging method
    private static void log(String username, String action) {
        String logMessage = String.format("[%s] User %s: %s", LocalDateTime.now(), username, action);

        try (FileWriter fileWriter = new FileWriter("audit_log.txt", true)) {
            fileWriter.write(logMessage + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
