import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Server {

    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
    private static final String ENCRYPTED_FOLDER = "encrypted_files/";
    private static final String DECRYPTED_FOLDER = "decrypted_files/";
    private static final String CREDENTIALS_FILE = "credentials.txt";
    private static Scanner scanner = new Scanner(System.in);
    private static boolean isClientConnected = false; // Flag to track client connection status

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(900)) {
            System.out.println("Server is Starting on Port: 900");

            // Listen for client connections in a loop
            while (true) {
                Socket clientSocket = serverSocket.accept();

                // Check if a client is already connected
                if (isClientConnected) {
                    System.out.println("Another client tried to connect, but the server is already busy.");
                    clientSocket.close();
                    continue; // Skip handling this client and continue listening for new connections
                }

                System.out.println("Connected");
                isClientConnected = true; // Set the flag to true since a client is connected

                // Initialize input and output streams for this client
                dataInputStream = new DataInputStream(clientSocket.getInputStream());
                dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

                // Handle client operation (login/register)
                String operation = dataInputStream.readUTF();
                if (operation.equals("login")) {
                    authenticateUser();
                } else if (operation.equals("register")) {
                    registerUser();
                } else {
                    System.out.println("Invalid operation.");
                    dataInputStream.close();
                    dataOutputStream.close();
                    clientSocket.close();
                    isClientConnected = false; // Reset the flag since the client disconnected
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void authenticateUser() throws Exception {
        String username = dataInputStream.readUTF();
        String password = dataInputStream.readUTF();
        String hashedPassword = hashPassword(password);

        try (BufferedReader reader = new BufferedReader(new FileReader(CREDENTIALS_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 2 && parts[0].trim().equals(username) && parts[1].trim().equals(hashedPassword)) {
                    dataOutputStream.writeBoolean(true);
                    dataOutputStream.flush();
                    System.out.println("User authenticated.");
                    receiveEncryptedFile(ENCRYPTED_FOLDER + "encrypted_file.txt"); // Receive encrypted file
                    receiveEncryptedFile(DECRYPTED_FOLDER); // Receive file for decryption
                    return;
                }
            }
        }
        dataOutputStream.writeBoolean(false);
        dataOutputStream.flush();
        System.out.println("Authentication failed.");
    }

    private static void registerUser() throws Exception {
        String username = dataInputStream.readUTF();
        String password = dataInputStream.readUTF();
        String hashedPassword = hashPassword(password);

        System.out.println("User " + username + " wants to register. Allow registration? (yes/no)");

        // Use Scanner to read input from the server console
        String allowRegistration = scanner.nextLine();

        if (allowRegistration.equalsIgnoreCase("yes")) {
            // Check if the username already exists
            boolean userExists = false;
            try (BufferedReader reader = new BufferedReader(new FileReader(CREDENTIALS_FILE))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(",");
                    if (parts.length >= 1 && parts[0].trim().equals(username)) {
                        userExists = true;
                        break;
                    }
                }
            }

            if (!userExists) {
                // Append new user to the credentials file
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(CREDENTIALS_FILE, true))) {
                    writer.write("\n" + username + "," + hashedPassword);
                    writer.newLine();
                    writer.flush();
                }
                dataOutputStream.writeBoolean(true);
                dataOutputStream.flush();
                System.out.println("User registered.");
                // Receive encrypted file after successful registration
                receiveEncryptedFile(ENCRYPTED_FOLDER + "encrypted_file.txt");
                receiveEncryptedFile(DECRYPTED_FOLDER); // Receive file for decryption
            } else {
                dataOutputStream.writeBoolean(false);
                dataOutputStream.flush();
                System.out.println("User already exists. Registration rejected.");
            }
        } else {
            // If server doesn't allow registration, send rejection to the client
            dataOutputStream.writeBoolean(false);
            dataOutputStream.flush();
            System.out.println("Registration not allowed by the server.");
        }
    }

    private static void receiveEncryptedFile(String filePath) {
        try {
            // Receive the filename from the client
            FileOutputStream fileOutputStream = new FileOutputStream(filePath);

            // Read the total file size
            long fileSize = dataInputStream.readLong();

            // Decrypt and write file content
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec("1234567890123456".getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            while (fileSize > 0) {
                // Read the length of the encrypted chunk
                int encryptedLength = dataInputStream.readInt();
                byte[] encryptedBytes = new byte[encryptedLength];
                // Read the encrypted chunk
                int bytesRead = dataInputStream.read(encryptedBytes, 0, encryptedLength);
                if (bytesRead == -1) {
                    throw new EOFException("Unexpected end of file data.");
                }
                // Decrypt the chunk
                byte[] decryptedBytes = cipher.update(encryptedBytes, 0, bytesRead);
                if (decryptedBytes != null) {
                    // Write the decrypted chunk to the file
                    fileOutputStream.write(decryptedBytes);
                    fileSize -= bytesRead; // Adjust remaining file size
                }
            }

            // Write the final block of decrypted bytes
            byte[] finalDecryptedBytes = cipher.doFinal();
            if (finalDecryptedBytes != null && finalDecryptedBytes.length > 0) {
                fileOutputStream.write(finalDecryptedBytes);
            }

            System.out.println("File received successfully: " + filePath);
            fileOutputStream.close();
        } catch (EOFException e) {
            System.err.println("EOFException: " + e.getMessage());
            // Handle EOFException gracefully
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.err.println("Exception during file reception: " + e.getMessage());
        }
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes());
            StringBuilder stringBuilder = new StringBuilder();
            for (byte b : hashBytes) {
                stringBuilder.append(String.format("%02x", b));
            }
            return stringBuilder.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
