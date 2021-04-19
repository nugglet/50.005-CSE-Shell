import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;
import java.nio.file.*;
import java.security.spec.*;

public class ClientAP {
    private InputStream fis;
    private CertificateFactory cf = null;
    private X509Certificate CAcert;
    private X509Certificate ServerCert;
    private PublicKey CAkey;
    private PublicKey serverKey;

    public static final String path = "cacsertificate.crt";

    public ClientAP(String fis) throws IOException {
        this.fis = new FileInputStream(fis);

        try {
            this.cf = CertificateFactory.getInstance("X.509");
            this.CAcert = (X509Certificate) cf.generateCertificate(this.fis);
            this.CAkey = this.CAcert.getPublicKey();

        } catch (Exception e) {
            e.printStackTrace();
        }
        this.fis.close();
    }

    public void getCertificate(InputStream certificate) throws CertificateException {
        // Get signed server certificate
        this.ServerCert = (X509Certificate) this.cf.generateCertificate(certificate);
    }

    public void getPublicKey() {
        // Get server public key from certificate
        this.serverKey = this.ServerCert.getPublicKey();
    }

    public void verify() {
        try {
            this.CAcert.checkValidity();
            this.CAcert.verify(this.CAkey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
