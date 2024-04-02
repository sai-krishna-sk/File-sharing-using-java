
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class FileDecryptor {

    public static void main(String[] args) {
        String encryptedFilePath = "C:\\Users\\terli\\OneDrive\\Documents\\NetBeansProjects\\JavaApplication2\\received_files\\encrypted_test.txt";
        String decryptedFilePath = "C:\\Users\\terli\\OneDrive\\Documents\\NetBeansProjects\\JavaApplication2\\received_files\\test.txt";

        try {
            decryptFile(encryptedFilePath, decryptedFilePath);
            System.out.println("File decrypted successfully.");
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.err.println("Exception during file decryption: " + e.getMessage());
        }
    }

    private static void decryptFile(String encryptedFilePath, String decryptedFilePath)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        // Initialize input and output streams
        FileInputStream fileInputStream = new FileInputStream(encryptedFilePath);
        FileOutputStream fileOutputStream = new FileOutputStream(decryptedFilePath);

        // Create Cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec("1234567890123456".getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Initialize buffer for reading from file
        byte[] buffer = new byte[1024]; // Use larger buffer size
        int bytesRead;

        // Read and decrypt file chunk by chunk
        while ((bytesRead = fileInputStream.read(buffer)) != -1) {
            byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
            if (decryptedBytes != null) {
                fileOutputStream.write(decryptedBytes);
            }
        }

        // Finalize decryption
        byte[] finalDecryptedBytes = cipher.doFinal();
        if (finalDecryptedBytes != null && finalDecryptedBytes.length > 0) {
            fileOutputStream.write(finalDecryptedBytes);
        }

        // Close streams
        fileInputStream.close();
        fileOutputStream.close();
    }
}
