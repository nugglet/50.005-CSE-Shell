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
    private PublicKey serverPublicKey;
    private static Cipher dCipher;
    private static Cipher eCipher;


    private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];

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
        this.serverPublicKey = this.ServerCert.getPublicKey();
    }

    public void verify() {
        try {
            this.CAcert.checkValidity();
            this.CAcert.verify(this.CAkey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

        // Generate nonce
        public void generateNonce(){
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);
        }
    
        // Decrypt encrypted nonce with public key
        public byte[] decryptNonce(byte[] encryptedNonce) throws Exception {
            dCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            return dCipher.doFinal(encryptedNonce);
        }

        // CP1, encrypt message using public key
        public byte[] encryptMsg(byte[] fileByte) throws Exception {
            eCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            eCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            return eCipher.doFinal(fileByte);
        }
    
        // Checks that decrypted nonce equals to original nonce
        public boolean validateNonce(byte[] decryptedNonce){
            return Arrays.equals(nonce, decryptedNonce);
        }
    
        public byte[] getEncryptedNonce(){
            return encryptedNonce;
        }
    
        public byte[] getNonce(){
            return nonce;
        }
}
