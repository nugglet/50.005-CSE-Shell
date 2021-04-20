import java.io.*;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;

import java.security.cert.CertificateFactory;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

public class ClientCP1 {

    public static void main(String[] args) {

        String filename[] = new String[1];
        if (args.length == 0) {
            filename[0] = "100.txt";
        } else {
            filename = new String[args.length];
            for (int i = 0; i < args.length; i++) {
                filename[i] = args[i];
            }
        }

        String serverAddress = "localhost";
        int port = 65535;

        int numBytes = 0;
        int numFiles = filename.length;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        byte[] decryptedNonce;
        PrintWriter output = null;
        BufferedReader input = null;

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            output = new PrintWriter(clientSocket.getOutputStream(), true);
            input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // AP Protocol

            ClientAP clientAP = new ClientAP(ClientAP.path);
            System.out.println("Starting Authentication Handshake Protocol...");
            output.println("Starting Authentication Handshake Protocol...");
            clientAP.verify();

            // Generate and Send Nonce
            System.out.println("Generating nonce...");
            clientAP.generateNonce();

            System.out.println("Sending nonce to server...");
            toServer.write(clientAP.getNonce());

            // Recieve Nonce and Certificate
            fromServer.read(clientAP.getEncryptedNonce());
            output.println("Request certificate");
            clientAP.getCertificate(fromServer);

            System.out.println("Server certificate recieved. Verifying....");
            clientAP.verify();
            System.out.println("Certificate verified. Now decrypting nonce...");

            // Decrypt Nonce
            clientAP.getPublicKey();
            decryptedNonce = clientAP.decryptNonce(clientAP.getEncryptedNonce());

            if (clientAP.validateNonce(decryptedNonce)) {
                System.out.println("Server verified.");
                output.println("Server verified");
            } else {

                System.out.println("Server verification failed. Connection compromised, closing all connections...");
                toServer.close();
                fromServer.close();
                clientSocket.close();
                return;
            }

            System.out.println("Authentication Handshake Protocol complete.");

            System.out.println("Sending files...");
            toServer.writeInt(numFiles);

            for (String file : filename) {

                byte[] fromFileBuffer = new byte[117];

                // Open the file
                fileInputStream = new FileInputStream(file);
                bufferedFileInputStream = new BufferedInputStream(fileInputStream);

                // Send file size
                int fileSize = fileInputStream.available();
                toServer.writeInt(fileSize);
                toServer.flush();

                // Send the filename
                System.out.println("Sending file: " + file);
                toServer.writeInt(0);
                toServer.writeInt(file.getBytes().length);
                toServer.write(file.getBytes());
                // toServer.flush();

                // Send the file
                for (boolean fileEnded = false; !fileEnded;) {
                    numBytes = bufferedFileInputStream.read(fromFileBuffer);

                    // Encrypt message
                    byte[] encryptedMsg = clientAP.encryptMsg(fromFileBuffer);
                    fileEnded = numBytes < fromFileBuffer.length;
                    int encryptedBytes = encryptedMsg.length;

                    toServer.writeInt(1);
                    toServer.writeInt(encryptedBytes);
                    toServer.writeInt(numBytes);
                    toServer.write(encryptedMsg);
                    toServer.flush();
                }

            }

            // Terminate if signal recieved from server
            while (true) {
                String signal = input.readLine();
                if (signal.equals("Ending transfer")) {
                    System.out.println("Server: " + signal);
                    break;
                } else
                    System.out.println("End request failed...");
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    }

}
