import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {

    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("192.168.1.7", 900);
            dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());

            System.out.println("1. Login");
            System.out.println("2. Register");
            System.out.print("Choose an option: ");
            int choice = System.in.read();
            System.in.skip(System.in.available());

            switch (choice) {
                case '1':
                    login();
                    break;
                case '2':
                    register();
                    break;
                default:
                    System.out.println("Invalid choice.");
                    break;
            }

            dataOutputStream.close();
            dataInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void login() throws IOException {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            System.out.print("Enter username: ");
            String username = reader.readLine();
            System.out.print("Enter password: ");
            String password = reader.readLine();

            dataOutputStream.writeUTF("login");
            dataOutputStream.writeUTF(username);
            dataOutputStream.writeUTF(password);
            dataOutputStream.flush();

            boolean authenticated = dataInputStream.readBoolean();
            if (authenticated) {
                System.out.println("Login successful.");
                sendFile();
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
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            System.out.print("Enter username: ");
            String username = reader.readLine();
            System.out.print("Enter password: ");
            String password = reader.readLine();

            dataOutputStream.writeUTF("register");
            dataOutputStream.writeUTF(username);
            dataOutputStream.writeUTF(password);
            dataOutputStream.flush();

            boolean registered = dataInputStream.readBoolean();

            if (registered) {
                System.out.println("Registration successful.");
                sendFile();
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
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            System.out.print("Enter the file path: ");
            String filePath = reader.readLine();

            File file = new File(filePath);
            FileInputStream fileInputStream = new FileInputStream(file);

            dataOutputStream.writeUTF(file.getName());
            dataOutputStream.flush();

            dataOutputStream.writeLong(file.length());

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec("1234567890123456".getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] buffer = new byte[16];
            int bytes;
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
