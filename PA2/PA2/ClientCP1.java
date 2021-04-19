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

        String filename = "100.txt";
        if (args.length > 0)
            filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1)
            filename = args[1];

        int port = 4321;
        if (args.length > 2)
            port = Integer.parseInt(args[2]);

        int numBytes = 0;

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

            // Recieve Nonce and Certififate
            fromServer.read(clientAP.getEncryptedNonce());
            output.println("Request certificate");
            clientAP.getCertificate(fromServer);

            System.out.println("Server certificate recieved. Verifying....");
            clientAP.verify();
            System.out.println("Certificate verified. Now decrypting nonce...");

            // Decrypt Nonce
            clientAP.getPublicKey();
            decryptedNonce = clientAP.decryptNonce(clientAP.getEncryptedNonce());

            if (clientAP.getNonce() == decryptedNonce) {
                System.out.println("Server verified.");
            } else {
                System.out.println("Server verification failed. Connection compromised, closing all connections...");
                toServer.close();
                fromServer.close();
                clientSocket.close();
            }

            System.out.println("Authentication Handshake Protocol complete.");

            System.out.println("Sending file...");

            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());
            // toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte[] fromFileBuffer = new byte[117];

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

            // Terminate if signal recieved from server
            while (true) {
                String signal = fromServer.readUTF();
                if (signal.equals("Ending transfer...")) {
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
