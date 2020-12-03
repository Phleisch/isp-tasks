import java.io.IOException;
import java.io.FileInputStream;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;

public class VerifyCertificate {

	/**
	 * Take in file for a CA certificate and a file for a user certificate
	 * and verify the two certificates
	 */
	public static void main(String[] args) throws
			IOException, CertificateException {
		// Get a stream of input from the CA certificate file, assumed to be
		// the first arg (arg 0)
		FileInputStream CA_stream = new FileInputStream(args[0]);

		// Get a stream of input from the user certificate file, assumed to be
		// the second arg (arg 1)
		FileInputStream user_stream = new FileInputStream(args[1]);

		// Certificates are of type X.509, so get an instance of
		// CertificateFactory for generating X.509 certificates
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		// Generate X.509 Certificates from the streams of the CA and user
		// certificates files
		X509Certificate CA_certificate = (X509Certificate)
			cf.generateCertificate(CA_stream);
		X509Certificate user_certificate = (X509Certificate)
			cf.generateCertificate(user_stream);

		// Print the DN's of the CA and user certificates
		System.out.println(CA_certificate.getSubjectX500Principal());
		System.out.println(user_certificate.getSubjectX500Principal());

		try {
			// Check that the certificates are currently active and have not
			// expired
			CA_certificate.checkValidity();
			user_certificate.checkValidity();
			
			// Check that the signatures of the certificates are correct
			CA_certificate.verify(CA_certificate.getPublicKey());
			user_certificate.verify(CA_certificate.getPublicKey());
			System.out.println("Pass");
		} catch(NoSuchAlgorithmException | CertificateException |
				InvalidKeyException | NoSuchProviderException |
				SignatureException exception) {
			System.out.printf("Fail: %s\n", exception.getMessage());
		}
	}
}
