package no.jpro.examples.jceproviders;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.*;

@WebServlet(urlPatterns = "/status")
public class JceStatusServlet extends HttpServlet {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String ASYMMETRIC_KEY_ALG = "RSA";
    private static final String ASYMMETRIC_CIPHER_ALG = "RSA/ECB/PKCS1Padding";
    private static final String BOUNCY_CASTLE_NAME = "BC";
    private static final String MY_SECRET = "My secret";

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        PrintWriter writer = response.getWriter();

        printWhetherBouncyCastleIsAvailable(writer);
        printEncryptionReport(writer);
        printWhetherBouncyCastleCanBeInstantiated(writer);
        writer.println();
        printRegisteredJceProviders(writer);
    }

    private void printWhetherBouncyCastleIsAvailable(final PrintWriter writer) {
        Provider bcProvider = Security.getProvider(BOUNCY_CASTLE_NAME);
        writer.println("BouncyCastle (BC) is available: " + (bcProvider != null));
    }

    @SuppressWarnings({"unused", "MismatchedReadAndWriteOfArray"})
    private void printEncryptionReport(final PrintWriter writer) throws ServletException {
        try {
            KeyPair keyPair = generateKeyPair();
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_CIPHER_ALG);

            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
            byte[] encryptedBytes = cipher.doFinal(MY_SECRET.getBytes(UTF8));

            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            String decryptedString = new String(decryptedBytes, UTF8);

            writer.println("Successfully encrypted/decrypted using RSA with provider: " + cipher.getProvider().getName());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new ServletException(e);
        }
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_KEY_ALG);
        return keyGen.genKeyPair();
    }

    private void printWhetherBouncyCastleCanBeInstantiated(final PrintWriter writer) {
        writer.println("Can instantiate BouncyCastleProvider: " + canInstantiateBouncyCastleProvider());
    }

    private boolean canInstantiateBouncyCastleProvider() {
        try {
            new BouncyCastleProvider();
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private void printRegisteredJceProviders(PrintWriter writer) {
        writer.println("Registered JCE providers:");

        int index = 1;
        for (Provider provider : Security.getProviders()) {
            writer.println(index++ + ": " + provider.toString());
        }
    }
}
