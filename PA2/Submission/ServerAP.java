import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerAP {

    private InputStream fis;
    private CertificateFactory cf = null;
    private byte[] certificate;
    private X509Certificate ServerCert;
    private PublicKey serverPublicKey;
    private static PrivateKey privateKey;

    // Nonce
    private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];
    private static Cipher eCipher;
    private static Cipher dCipher;

    private final String keyPath = "private_key.der";
    public static final String path = "certificate_1004289.crt";

    public ServerAP(String fis) throws IOException {

        this.fis = new FileInputStream(fis);

        try {

            this.cf = CertificateFactory.getInstance("X.509");

            // Get signed server certificate
            this.ServerCert = (X509Certificate) cf.generateCertificate(this.fis);
            this.certificate = this.ServerCert.getEncoded();

            // Get server public key
            this.serverPublicKey = this.ServerCert.getPublicKey();

            // Get server private key
            privateKey = getPrivateKey(keyPath);

        } catch (Exception e) {
            e.printStackTrace();
        }

        this.fis.close();
    }

    public PrivateKey getPrivateKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public PublicKey getPublicKey(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // encrypt plaintext nonce sent by client
    public void encryptNonce() throws Exception {
        eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        eCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        encryptedNonce = eCipher.doFinal(nonce);
    }

    // CP1, decrypt message sent by client using private key
    public static byte[] decryptMsg(byte[] fileByte) throws Exception {
        dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        dCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return dCipher.doFinal(fileByte);
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getEncryptedNonce() {
        return encryptedNonce;
    }

    public byte[] getCertificate() {
        return certificate;
    }

}
