import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.Cipher;

public class ServerCP2 {

    public static void main(String[] args) {

        int port = 65535;
        if (args.length > 0)
            port = Integer.parseInt(args[0]);

        // Socket variables
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        // AP Variables
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        BufferedReader input = null;
        PrintWriter output = null;

        // AES Variables
        byte[] eSKey;
        SecretKey sessionKey;
        Cipher sessionCipher;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            input = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            output = new PrintWriter(connectionSocket.getOutputStream(), true);

            while (true) {
                String request = input.readLine();
                if (request.equals("Starting Authentication Handshake Protocol...")) {
                    System.out.println("Client: " + request);
                    break;
                } else {
                    System.out.println("Request failed...");
                }
            }

            // AP protocol
            ServerAP serverAP = new ServerAP(ServerAP.path);

            fromClient.read(serverAP.getNonce());
            System.out.println("Received Nonce");
            serverAP.encryptNonce();

            System.out.println("Nonce Encrypted, sending it to client");
            toClient.write(serverAP.getEncryptedNonce());
            toClient.flush();

            // Waiting to receive certificate request from client
            while (true) {
                String request = input.readLine();
                if (request.equals("Request certificate")) {
                    System.out.println("Client: " + request);

                    // Send certificate to client
                    System.out.println("Sending certificate to client...");
                    toClient.write(serverAP.getCertificate());
                    toClient.flush();
                    break;
                } else {
                    System.out.println("Request failed...");
                }
            }

            // Waiting for client to finish verification
            System.out.println("Client: " + input.readLine());

            // Starts file transfer
            System.out.println("Authentication Handshake Protocol Complete. Starting file transfer...");

            // Get session key from client
            sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            int signal = fromClient.readInt();
            BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

            if (signal == 3) {
                // Client is sending session key
                int eSKeySize = fromClient.readInt();
                eSKey = new byte[eSKeySize];
                fromClient.readFully(eSKey);

                String printSKey = new String(eSKey, 0, eSKeySize);

                // Decrypt session key using private key
                System.out.println("Received encrypted session key of size: " + eSKeySize);
                System.out.println("Encrypted session key: " + printSKey);
                System.out.println("Decrypting session key...");
                byte[] decryptedSKey = serverAP.decryptMsg(eSKey);
                sessionKey = new SecretKeySpec(decryptedSKey, 0, decryptedSKey.length, "AES");
                sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);
            }

            // Get number of files from client
            int numFiles = fromClient.readInt();
            System.out.println("Preparing to recieve " + numFiles + " files...");

            // for each file...
            for (int i = 0; i < numFiles; i++) {

                // Get the file size from client
                int fileSize = fromClient.readInt();
                System.out.println("File size: " + fileSize);
                int size = 0;

                while (size < fileSize) {

                    int packetType = fromClient.readInt();

                    if (packetType == 0) {
                        // Client is sending file name
                        int numBytes = fromClient.readInt();
                        byte[] filename = new byte[numBytes];

                        // Must use read fully!
                        // See:
                        // https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                        fromClient.readFully(filename, 0, numBytes);
                        String name = new String(filename, 0, numBytes);
                        System.out.println("Recieving file: " + name);

                        fileOutputStream = new FileOutputStream("recv_" + name);
                        bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                        // If the packet is for transferring a chunk of the file
                    } else if (packetType == 1) {

                        int decryptedBytes = fromClient.readInt(); // encryptedMsg.length
                        int fSize = fromClient.readInt(); // numbytes

                        size += fSize;

                        byte[] msg = new byte[decryptedBytes];
                        fromClient.readFully(msg, 0, decryptedBytes);

                        // decrypt message with session key
                        byte[] decryptedMsg = sessionCipher.doFinal(msg);

                        if (decryptedBytes > 0) {
                            bufferedFileOutputStream.write(decryptedMsg, 0, fSize);
                            bufferedFileOutputStream.flush();

                        }
                    }
                }
                System.out.println("File successfully recieved.");
            }

            output.println("Ending transfer");
            System.out.println("All files recieved. Closing connection...");

            if (bufferedFileOutputStream != null)
                bufferedFileOutputStream.close();
            if (bufferedFileOutputStream != null)
                fileOutputStream.close();
            fromClient.close();
            toClient.close();
            connectionSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
