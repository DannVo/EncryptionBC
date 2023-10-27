import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class aes_encrypt {
    public static void main(String[] args) throws Exception {
        // Generate a new AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Create a cipher instance with the key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt a message
        String message = "Hello, AES encryption!";
        byte[] encryptedMessage = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Decrypt the message
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));
        System.out.println("Decrypted Message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
    }
}
