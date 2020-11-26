import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.NoSuchPaddingException;

/**
 * Methods and attributes for performing encryption (using AES in CTR mode) on
 * a stream of data; the stream of data may be a file, network socket, etc.
 */
public class SessionEncrypter {

	final private int BITS_PER_BYTE = 8;

	// Description of cryptographic algorithm, feedback mode and padding scheme 
	final private String TRANSFORMATION = "AES/CTR/NoPadding";

	// Operation mode of the cipher created by a SessionEncypter instance
	final private int MODE_OF_OPERATION = Cipher.ENCRYPT_MODE;

	// Private key used by the AES algorithm for encryption
	final private SessionKey sessionKey;

	// Intial value of the counter used by CTR mode with AES
	final private IvParameterSpec initializationVector;

	/**
	 * Easy SessionEncrypter constructor where most of the work with creating
	 * a key to use for AES, along with an IV (AKA Counter) for CTR mode are
	 * handled by class; user simply defines desired AES secret key length.
	 *
	 * @param keyLength	Length of key to use for encryption with AES
	 */
	public SessionEncrypter(Integer keyLength) {
		this.sessionKey = new SessionKey(keyLength);
		
		// Fill a byte array with random bytes to create an IV
		SecureRandom secureRandom = new SecureRandom();
		byte[] IVBytes = new byte[keyLength / BITS_PER_BYTE];
		secureRandom.nextBytes(IVBytes);

		this.initializationVector = new IvParameterSpec(IVBytes);
	}

	/**
	 * More involved SessionEncrypter constructor where most of the work is done
	 * by the caller of the constructor - the class does not need to create its
	 * own secrey key for AES and IV (AKA Counter) for CTR from scratch.
	 *
	 * @param keyBytes	Secret key to use for AES
	 * @param ivBytes	Initialization vector to use for CTR mode
	 */
	public SessionEncrypter(byte[] keyBytes, byte[] IVBytes) {
		this.sessionKey = new SessionKey(keyBytes);
		this.initializationVector = new IvParameterSpec(IVBytes);
	}

	/**
	 * @return the key bytes used in the Session Key of this SessionEncrypter
	 */
	public byte[] getKeyBytes() {
		return this.sessionKey.getKeyBytes();
	}

	/**
	 * @return the bytes of the IV used by CTR mode for AES block encryption
	 */
	public byte[] getIVBytes() {
		return initializationVector.getIV();
	}

	/**
	 * From a given stream of output, create and return a wrapper stream that
	 * has an associated cipher for encrypting the stream of output with the
	 * specs of this SessionEncrypter instance.
	 *
	 * @param output	Stream of output to wrap and encrypt
	 *
	 * @return a wrapper stream for encrypting any data given to it
	 */
	public CipherOutputStream openCipherOutputStream(OutputStream output) 
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

		// Return an OutputStream using the newly created cipher to encrypt
		// any given information
		return new CipherOutputStream(output, cipher);
	}

}
