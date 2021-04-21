import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class ServerCP1 {

    public static void main(String[] args) {

        int port = 65535;
        if (args.length > 0)
            port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        BufferedReader input = null;
        PrintWriter output = null;

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

            // Get number of files from client
            int numFiles = fromClient.readInt();
            System.out.println("Preparing to recieve " + numFiles + " files...");

            long allFilesStart = System.nanoTime();

            // for each file...
            for (int i = 0; i < numFiles; i++) {

                long currentFileStart = System.nanoTime();

                // Get the file size from client
                int fileSize = fromClient.readInt();
                System.out.println("File size: " + fileSize);
                int size = 0;

                while (size < fileSize) {

                    int packetType = fromClient.readInt();
                    // If the packet is for transferring the filename
                    if (packetType == 0) {

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

                        int numBytes = fromClient.readInt();
                        int decryptedBytes = fromClient.readInt();
                        size += decryptedBytes;

                        byte[] msg = new byte[numBytes];
                        fromClient.read(msg);

                        byte[] decryptedMsg = ServerAP.decryptMsg(msg);

                        if (numBytes > 0) {
                            bufferedFileOutputStream.write(decryptedMsg, 0, decryptedBytes);
                            bufferedFileOutputStream.flush();

                        }
                    }
                }
                System.out.println("File successfully recieved.");
                long currentFileEnd = System.nanoTime() - currentFileStart;
                System.out.println("Time taken for file: " + currentFileEnd / 1000000.0 + "ms");
            }

            long allFilesEnd = System.nanoTime() - allFilesStart;
            System.out.println("Time taken for all files: " + allFilesEnd / 1000000.0 + "ms");

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
