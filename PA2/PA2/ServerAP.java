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
    private KeyFactory kf = null;
    private byte[] certificate;
    private X509Certificate ServerCert;
    private PublicKey serverKey;
    private PrivateKey privateKey;

    private final String path = "private_key.der";

    public ServerAP(String fis) throws IOException {

        this.fis = new FileInputStream(fis);

        try {

            this.cf = CertificateFactory.getInstance("X.509");

            // Get signed server certificate
            this.ServerCert = (X509Certificate) cf.generateCertificate(this.fis);
            this.certificate = this.ServerCert.getEncoded();

            // Get server public key
            this.serverKey = this.ServerCert.getPublicKey();

            // Get server private key
            this.privateKey = getPrivateKey(path);

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
}
