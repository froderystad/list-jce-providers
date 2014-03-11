package no.jpro.examples.jceproviders;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@WebServlet(urlPatterns = "/JceStatus")
public class JceStatusServlet extends HttpServlet {
	private static final Charset UTF8 = Charset.forName("UTF-8");
	private static final String MY_SECRET = "My secret";

	@Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
		PrintWriter writer = response.getWriter();

		Provider bcProvider = Security.getProvider("BC");
		writer.println("BouncyCastle (BC) is available: " + (bcProvider != null));

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, generateKeyPair().getPrivate());
			@SuppressWarnings({"unused", "MismatchedReadAndWriteOfArray"})
			byte[] encryptedBytes = cipher.doFinal(MY_SECRET.getBytes(UTF8));

			writer.println("Successfully encrypted with provider: " + cipher.getProvider().getName());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new ServletException(e);
		}

		writer.print("Can instantiate BouncyCastleProvider: ");
		writer.println(canInstantiateBouncyCastleProvider());
	}

	private boolean canInstantiateBouncyCastleProvider() {
		try {
			new BouncyCastleProvider();
			return true;
		} catch (Throwable e) {
			return false;
		}
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		return keyGen.genKeyPair();
	}
}
