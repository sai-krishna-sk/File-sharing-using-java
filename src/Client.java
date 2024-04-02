import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        try {
            System.out.print("Enter server's IP address: ");
            String serverIP = scanner.nextLine();

            System.out.print("Enter server's port number: ");
            int serverPort = scanner.nextInt();
            scanner.nextLine();

            try (Socket socket = new Socket(serverIP, serverPort)) {
                dataInputStream = new DataInputStream(socket.getInputStream());
                dataOutputStream = new DataOutputStream(socket.getOutputStream());

                System.out.println("1. Login");
                System.out.println("2. Register");
                System.out.print("Choose an option: ");
                int choice = scanner.nextInt();
                scanner.nextLine();
                switch (choice) {
                    case 1:
                        login();
                        break;
                    case 2:
                        register();
                        break;
                    default:
                        System.out.println("Invalid choice.");
                        break;
                }

                dataOutputStream.close();
                dataInputStream.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    private static String readPassword() {
        if (System.console() != null) {
            return new String(System.console().readPassword("Enter password: "));
        } else {
            System.out.print("Enter password: ");
            return scanner.nextLine();
        }
    }

    private static void login() throws IOException {
        try {
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            String password = readPassword();

            dataOutputStream.writeUTF("login");
            dataOutputStream.writeUTF(username);
            dataOutputStream.writeUTF(password);
            dataOutputStream.flush();

            boolean authenticated = dataInputStream.readBoolean();
            if (authenticated) {
                System.out.println("Login successful.");
                try {
                    sendFile();
                } catch (Exception ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                System.out.println("Login failed.");
            }
        } catch (IOException e) {
            System.err.println("Error during login: " + e.getMessage());
            throw e;
        }
    }

    private static void register() throws IOException, Exception {
        try {
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            String password = readPassword();

            dataOutputStream.writeUTF("register");
            dataOutputStream.writeUTF(username);
            dataOutputStream.writeUTF(password);
            dataOutputStream.flush();

            boolean registered = dataInputStream.readBoolean();

            if (registered) {
                System.out.println("Registration successful.");
                try {
                    sendFile();
                } catch (Exception ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                System.out.println("Registration failed.");
            }
        } catch (IOException e) {
            System.err.println("Error during registration: " + e.getMessage());
            throw e;
        }
    }

    private static void sendFile() throws Exception {
        try {
            int bytes;
            System.out.println("Enter the file path (Example: C:\\Users\\Username\\Documents\\example.txt)  ");
            System.out.println("The file can be of any type(.txt,.jpg,.png.....): ");
            String filePath = scanner.nextLine();

            File file = new File(filePath);
            FileInputStream fileInputStream = new FileInputStream(file);

            dataOutputStream.writeUTF(file.getName());
            dataOutputStream.flush();

            dataOutputStream.writeLong(file.length());

            // Generate a random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // 128-bit key
            SecretKey secretKey = keyGen.generateKey();

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Send the AES key to the server
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(dataOutputStream);
            objectOutputStream.writeObject(secretKey);
            objectOutputStream.flush();

            byte[] buffer = new byte[16];
            while ((bytes = fileInputStream.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.update(buffer, 0, bytes);
                if (encryptedBytes != null) {
                    int paddedLength = ((encryptedBytes.length + 15) / 16) * 16;
                    dataOutputStream.writeInt(paddedLength);
                    dataOutputStream.write(encryptedBytes);
                    dataOutputStream.flush();
                }
            }

            byte[] finalEncryptedBytes = cipher.doFinal();
            if (finalEncryptedBytes != null) {
                int paddedLength = ((finalEncryptedBytes.length + 15) / 16) * 16;
                dataOutputStream.writeInt(paddedLength);
                dataOutputStream.write(finalEncryptedBytes);
                dataOutputStream.flush();
            }

            System.out.println("File sent successfully.");

            fileInputStream.close();
        } catch (IOException e) {
            System.err.println("Error during file sending: " + e.getMessage());
            throw e;
        }
    }
}
