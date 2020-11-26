import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.IllegalArgumentException;

/**
 * Methods and attributes for creating and manipulating Session Keys
 */
public class SessionKey {
	final private int BITS_PER_BYTE = 8;
	
	// Encryption algorithm this session key is associated with
	final private String ENCRYPTION_ALGORITHM = "AES";
	
	// Internal storage of the Session Key is as an SecretKey
	final private SecretKey secretKey;

	/**
	 * Create a random SessionKey of length equal to keyLength bits where
	 * keyLength should be a positive multiple of 8 (number of bits in a byte)
	 *
	 * @param keyLength	Number of bits in size the SessionKey should be
	 */
	public SessionKey(Integer keyLength) {
		// Ensure keyLengths are positive multiples of 8
		if (keyLength < 0 || keyLength % BITS_PER_BYTE != 0) {
			throw new IllegalArgumentException(
				"keyLength must be a positive multiple of 8"
			);
		}

		// Fill a byte array with random bytes to create a key
		SecureRandom secureRandom = new SecureRandom();
		byte[] keyBytes = new byte[keyLength / BITS_PER_BYTE];
		secureRandom.nextBytes(keyBytes);

		this.secretKey = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
	}

	/**
	 * Create a SessionKey from an array of bytes.
	 *
	 * @param keyBytes	Array of bytes from which to create a session key
	 */
	public SessionKey(byte[] keyBytes) {
		this.secretKey = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
	}

	/**
	 * @return the SecretKey contained within this SessionKey object
	 */
	public SecretKey getSecretKey() {
		return secretKey;
	}

	/**
	 * @return this SessionKey as a sequence of bytes
	 */
	public byte[] getKeyBytes() {
		return secretKey.getEncoded();
	}
}
