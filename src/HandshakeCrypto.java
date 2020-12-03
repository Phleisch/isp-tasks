import java.io.FileInputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;

/**
 * Methods and attributes for performing RSA encryption/decryption on data and
 * for extracting public / private keys from key and certificate files.
 */
public class HandshakeCrypto {

	// Description of cryptographic algorithm, feedback mode and padding scheme
	final private static String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

	/**
	 * Use RSA with the given key (public or private) for encryption of the
	 * given plaintext input.
	 *
	 * @param plaintext	Plaintext to encrypt
	 * @param key		Key - public or private - to use for RSA encryption
	 *
	 * @return a byte array representing the encrypted plaintext
	 */
	public static byte[] encrypt(byte[] plaintext, Key key) throws Exception {
		Cipher rsaEncrypter = Cipher.getInstance(TRANSFORMATION);

		// Set the cipher up to encrypt any given data using the given key
		rsaEncrypter.init(Cipher.ENCRYPT_MODE, key);

		// Completely encrypt the plaintext using RSA in one step and return
		// the ciphertext result
		return rsaEncrypter.doFinal(plaintext);
	}

	/**
	 * Use RSA with the given key (public or private) for decryption of the
	 * given ciphertext input; reverse operation of encrypt function
	 *
	 * @param ciphertext	Ciphertext to decrypt
	 * @param key			Key - public or private - to use for RSA decryption
	 *
	 * @return a byte array representing the decrypted ciphertext
	 */
	public static byte[] decrypt(byte[] ciphertext, Key key) throws Exception {
		Cipher rsaDecrypter = Cipher.getInstance(TRANSFORMATION);

		// Set the cipher up to decrypt any given data using the given key
		rsaDecrypter.init(Cipher.DECRYPT_MODE, key);

		// Completely decrypt the ciphertext using RSA in one step and return
		// the plaintext result
		return rsaDecrypter.doFinal(ciphertext);
	}

	/**
	 * Extract a public key from the file specified by the filename given.
	 *
	 * @param certFile	Certificate file to extract a key from
	 *
	 * @return public key from the certificate file
	 */
	public static PublicKey getPublicKeyFromCertFile(String certFile) throws Exception {
		// Get certificate file as a file stream
		FileInputStream stream = new FileInputStream(certFile);

		// Get instance of X.509 certificate
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		// Get public key from the X509 Certificate
		X509Certificate cert = (X509Certificate) cf.generateCertificate(stream);
		return cert.getPublicKey();
	}

	/**
	 * Extract a private key from the certificate specified by the filename.
	 *
	 * @param certFile	Certificate file to extract a key from
	 *
	 * @return public key from the certificate file
	 */
	public static PrivateKey getPrivateKeyFromKeyFile(String certFile) throws Exception {
		// Byte array representation of the certificate file
		byte[] keyBytes = Files.readAllBytes(Paths.get(certFile));

		// Get key as PKCS8 key spec
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

		// Get an instance of this key as an RSA private key
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}
}
