import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.io.*;
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

            // Starts file transfer
            System.out.println("Authentication Handshake Protocol Complete. Starting file transfer...");

            // Get the file size from client
            int fileSize = fromClient.readInt();
            System.out.println("File size: " + fileSize);
            int size = 0;

            while (size < fileSize) {

                int packetType = fromClient.readInt();
                System.out.println("Packet Type: " + packetType);

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file name...");

                    int numBytes = fromClient.readInt();
                    byte[] filename = new byte[numBytes];
                    // Must use read fully!
                    // See:
                    // https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {

                    System.out.println("Receiving file content...");

                    int numBytes = fromClient.readInt();
                    int decryptedNumBytes = fromClient.readInt();
                    size += decryptedNumBytes;

                    byte[] block = new byte[numBytes];
                    fromClient.read(block);

                    byte[] decryptedBlock = ServerAP.decryptMsg(block);

                    if (numBytes > 0) {
                        bufferedFileOutputStream.write(decryptedBlock, 0, decryptedNumBytes);
                        bufferedFileOutputStream.flush();

                    }
                }
            }

            output.println("Ending transfer");
            System.out.println("Closing connection...");

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
