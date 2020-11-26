import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.NoSuchPaddingException;

/**
 * Methods and attributes for performing decryption (using AES in CTR mode) on
 * a stream of data; the stream of data may be a file, network socket, etc.
 */
public class SessionDecrypter {

	// Description of cryptographic algorithm, feedback mode and padding scheme 
	final private String TRANSFORMATION = "AES/CTR/NoPadding";

	// Operation mode of the cipher created by a SessionDecrypter instance
	final private int MODE_OF_OPERATION = Cipher.DECRYPT_MODE;

	// Private key used by the AES algorithm for decryption
	final private SessionKey sessionKey;

	// Intial value of the counter used by CTR mode with AES
	final private IvParameterSpec initializationVector;

	/**
	 * Take in the keyBytes and IVBytes used for encryption in order to perform
	 * symmetric decryption.
	 *
	 * @param keyBytes	Secret key to use for AES
	 * @param ivBytes	Initialization vector to use for CTR mode
	 */
	public SessionDecrypter(byte[] keyBytes, byte[] IVBytes) {
		this.sessionKey = new SessionKey(keyBytes);
		this.initializationVector = new IvParameterSpec(IVBytes);
	}

	/**
	 * From a given stream of input, create and return a wrapper stream that
	 * has an associated cipher for decrypting the stream of input with the
	 * specs of this SessionDecrypter instance.
	 *
	 * @param input	Stream of encrypted input to wrap and decrypt
	 *
	 * @return a wrapper stream for decrypting any data given to it
	 */
	public CipherInputStream openCipherInputStream(InputStream input) 
		throws NoSuchAlgorithmException, InvalidKeyException,
		NoSuchPaddingException, InvalidAlgorithmParameterException {

		// Get a Cipher object that specifies a given transformation; in this
		// case the Cipher specifies AES in CTR mode with no padding scheme
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		// Initialize a Cipher with a given secret key and set of parameters
		// specific to the algorithm being used with the Cipher. In this case
		// AES is being used in CTR, and we require an IV to pass along
		cipher.init(
			MODE_OF_OPERATION,
			this.sessionKey.getSecretKey(),
			initializationVector
		);

		// Return an InputStream using the newly created cipher to decrypt any
		// given information
		return new CipherInputStream(input, cipher);
	}

}
