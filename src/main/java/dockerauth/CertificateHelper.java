package dockerauth;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

// http://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.cert.X509v3CertificateBuilder
// http://www.programcreek.com/java-api-examples/index.php?source_dir=mockserver-master/mockserver-core/src/main/java/org/mockserver/socket/KeyStoreFactory.java
public class CertificateHelper {
	public static void main(String[] args) throws Exception {
		KeyPair keyPair = generateKeyPair();
		X509Certificate cert = createCACert(keyPair.getPublic(), keyPair.getPrivate());
		String path = args[1];
		writeKeyPairAndCert(
				keyPair, 
				cert,
				"DM CHALLENGE SOFTLAYER PRIVATE KEY",
				(new File(path, "privatekey.pem")).getAbsolutePath(),
				"DM CHALLENGE SOFTLAYER PUBLIC KEY",
				(new File(path, "publickey.pem")).getAbsolutePath(),
				"DM CHALLENGE SOFTLAYER CERT",
				(new File(path, "cert.pem")).getAbsolutePath()
				);
	}
	
	// from https://botbot.me/freenode/cryptography-dev/2015-12-04/?page=1
	// SPKI DER SHA-256 hash, strip of the last two bytes, base32 encode it and then add a : every four chars.
	public static String computeKeyId(PublicKey publicKey) {
		try {
		// http://stackoverflow.com/questions/3103652/hash-string-via-sha-256-in-java
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(publicKey.getEncoded());
		byte[] digest = md.digest();
		// use bytes 0->digest.length-2
		Base32 base32 = new Base32();
		byte[] skipLastTwoBytes = new byte[digest.length-2];
		System.arraycopy(digest, 0, skipLastTwoBytes, 0, skipLastTwoBytes.length);
		String base32Encoded = base32.encodeAsString(skipLastTwoBytes);
		StringBuilder sb = new StringBuilder();
		if ((base32Encoded.length() % 4)!=0) 
			throw new IllegalStateException("Expected string length to be a multiple of 4 but found "+base32Encoded);
		boolean firsttime = true;
		for (int i=0; i<base32Encoded.length(); i+=4) {
			if (firsttime) firsttime=false; else sb.append(":");
			sb.append(base32Encoded.substring(i, i+4));
		}
		return sb.toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static final String KEY_GENERATION_ALGORITHM = "EC";
	
	private static final String RNG_GENERATION_ALGORITHM = "SHA1PRNG";
	
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME; 
    
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    
    

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

    /**
     * Current time minus 1 year, just in case software clock goes back due to 
     * time synchronization 
     */ 
    private static final Date NOT_BEFORE = new Date(System.currentTimeMillis() - 86400000L * 365); 
 
    /**
     * The maximum possible value in X.509 specification: 9999-12-31 23:59:59, 
     * new Date(253402300799000L), but Apple iOS 8 fails with a certificate 
     * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6). 
     *  
     * Hundred years in the future from starting the proxy should be enough. 
     */ 
    private static final Date NOT_AFTER = new Date(System.currentTimeMillis() + 86400000L * 365 * 100); 
 
	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM);
		SecureRandom random = SecureRandom.getInstance(RNG_GENERATION_ALGORITHM, "SUN");

		keyGen.initialize(256, random);

		return keyGen.generateKeyPair();

	}
	
	public static void printKeyPairAndCert(KeyPair keyPair, X509Certificate cert) throws Exception {

		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(System.out));
		try {
			PemObject pemObject = new PemObject("private key", keyPair.getPrivate().getEncoded());
			pemWriter.writeObject(pemObject);
			pemObject = new PemObject("public key", keyPair.getPublic().getEncoded());
			pemWriter.writeObject(pemObject);
			pemObject = new PemObject("cert", cert.getEncoded());
			pemWriter.writeObject(pemObject);
		} finally {
			pemWriter.close();
		}
		System.out.flush();

	}
	
	private static void writeToFile(PemObject pemObject, String filename) throws IOException {
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
		try {
			pemWriter.writeObject(pemObject);
			pemWriter.flush();
		} finally {
			pemWriter.close();
		}
	}
	
//	public static void writeKeyPairAndCert(
//			KeyPair keyPair, 
//			X509Certificate cert) throws Exception {
//		writeKeyPairAndCert(keyPair, 
//				cert, 
//				"private key", 
//				"src/main/resources/privatekey.pem",
//				"public key",
//				"src/main/resources/publickey.pem",
//				"cert",
//				"src/main/resources/cert.pem"
//				);
//	}
	
	public static void writeKeyPairAndCert(
			KeyPair keyPair, 
			X509Certificate cert,
			String privateKeyLabel,
			String privateKeyFilePath,
			String publicKeyLabel,
			String publicKeyFilePath,
			String certificatelabel,
			String certificateFilePath) throws Exception {
			PemObject pemObject = new PemObject(privateKeyLabel, keyPair.getPrivate().getEncoded());
			writeToFile(pemObject, privateKeyFilePath);
			pemObject = new PemObject(publicKeyLabel, keyPair.getPublic().getEncoded());
			writeToFile(pemObject, publicKeyFilePath);
			pemObject = new PemObject(certificatelabel, cert.getEncoded());
			writeToFile(pemObject, certificateFilePath);
	}
	
	/**
	 * Create a certificate to use by a Certificate Authority, signed by a self signed certificate.
	 */
	public static X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey) throws Exception {

	    //
	    // signers name
	    //
	    X500Name issuerName = new X500Name("CN=synapse.org, O=SageBionetworks, L=Seattle, ST=Washington, C=US");

	    //
	    // subjects name - the same as we are self signed.
	    //
	    X500Name subjectName = issuerName;

	    //
	    // serial
	    //
	    // Docker registry says:
	    // unable to parse token auth root certificate: x509: negative serial number
	    // so we make sure it's positive
	    BigInteger serial = BigInteger.valueOf(new Random().nextInt(Integer.MAX_VALUE));

	    //
	    // create the certificate - version 3
	    //
	    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, NOT_BEFORE, NOT_AFTER, subjectName, publicKey);
	    builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey));
	    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

	    KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
	    builder.addExtension(Extension.keyUsage, false, usage);

	    ASN1EncodableVector purposes = new ASN1EncodableVector();
	    purposes.add(KeyPurposeId.id_kp_serverAuth);
	    purposes.add(KeyPurposeId.id_kp_clientAuth);
	    purposes.add(KeyPurposeId.anyExtendedKeyUsage);
	    builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

	    X509Certificate cert = signCertificate(builder, privateKey);
	    cert.checkValidity(new Date());
	    cert.verify(publicKey);

	    return cert;
	}
	
    private static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey signedWithPrivateKey) throws OperatorCreationException, CertificateException { 
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(signedWithPrivateKey); 
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateBuilder.build(signer)); 
    } 
	
    private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) throws IOException { 
        ASN1InputStream is = null; 
        try { 
            is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded())); 
            ASN1Sequence seq = (ASN1Sequence) is.readObject(); 
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq); 
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info); 
        } finally { 
            if (is!=null) try {is.close();} catch(IOException e) {}
        } 
    } 


}
