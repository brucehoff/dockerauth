
package dockerauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

// implements this spec:
// https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md
// a request might look like:
// https://auth.docker.io/token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push
//
// response looks like:
// HTTP/1.1 200 OK
// Content-Type: application/json
//
//{ "expires_in" : "3600",
//"issued_at" : "2009-11-10T23:00:00Z",
//"token" : "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IlBZWU86VEVXVTpWN0pIOjI2SlY6QVFUWjpMSkMzOlNYVko6WEdIQTozNEYyOjJMQVE6WlJNSzpaN1E2In0.eyJpc3MiOiJhdXRoLmRvY2tlci5jb20iLCJzdWIiOiJqbGhhd24iLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuY29tIiwiZXhwIjoxNDE1Mzg3MzE1LCJuYmYiOjE0MTUzODcwMTUsImlhdCI6MTQxNTM4NzAxNSwianRpIjoidFlKQ08xYzZjbnl5N2tBbjBjN3JLUGdiVjFIMWJGd3MiLCJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InNhbWFsYmEvbXktYXBwIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.QhflHPfbd6eVF4lM9bwYpFZIV0PfikbyXuLx959ykRTBpe3CYnzs6YBK8FToVb5R47920PVLrh8zuLzdCr9t3w"
//}

public class DockerAuth extends HttpServlet {
	private Logger logger = Logger.getLogger("DockerAuth");

	private static final String ISSUER = "registry.com";
	private static final long TIME_WINDOW_SEC = 1200;
	private static final String ACCESS = "access";


	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) throws Exception {
		PrivateKey key = readPrivateKey();
		X509Certificate cert = readCertificate("cert.pem");
		String keyId = computeKeyId(cert.getPublicKey());
		String s = createToken(key, keyId, "userName", "repository", "docker.sagebase.org", "user/helloworld", 
				Arrays.asList(new String[]{"push", "pull"}));

		System.out.println(s);
		
		createToken(key, keyId, "userName", null, "docker.sagebase.org", null, null);
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
	
	private static PrivateKey readPrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemReader pemReader = new PemReader(new InputStreamReader(DockerAuth.class.getClassLoader().getResourceAsStream(filename)));
		try {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			return factory.generatePrivate(privKeySpec);
		} finally {
			pemReader.close();
		}
	}
	
	public static final String KEY_GENERATION_ALGORITHM = "EC";
	
	public static PrivateKey readPrivateKey() {
		try {
			KeyFactory factory = KeyFactory.getInstance(KEY_GENERATION_ALGORITHM);
			PrivateKey priv = readPrivateKey(factory,"privatekey.pem");
			return priv;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static X509Certificate readCertificate(String filename) throws IOException {
		PemReader pemReader = new PemReader(new InputStreamReader(DockerAuth.class.getClassLoader().getResourceAsStream(filename)));
		try {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			Certificate certificate = Certificate.getInstance(content);
			return new X509CertificateObject(certificate);
		} catch (CertificateParsingException e) {
			throw new RuntimeException(e);
		} finally {
			pemReader.close();
		}
		
	}

	@SuppressWarnings("all")
	public static String createToken(
			PrivateKey key, String keyId, String userName, String type, 
			String registry, String repository, List<String> actions) {

		long now = System.currentTimeMillis();

		JSONArray access = new JSONArray();
		JSONObject accessEntry = new JSONObject();
		access.add(accessEntry);
		if (type!=null) accessEntry.put("type", type);
		if (repository!=null) accessEntry.put("name", repository);
		JSONArray actionArray = new JSONArray();
		if (actions!=null) actionArray.addAll(actions);
		accessEntry.put("actions", actionArray);

		Claims claims = Jwts.claims()
				.setIssuer(ISSUER)
				.setAudience(registry)
				.setExpiration(new Date(now+TIME_WINDOW_SEC*1000L))
				.setNotBefore(new Date(now-TIME_WINDOW_SEC*1000L))
				.setIssuedAt(new Date(now))
				.setId(UUID.randomUUID().toString())
				.setSubject(userName);
		claims.put(ACCESS, access);

		String s = Jwts.builder().setClaims(claims).
				setHeaderParam(Header.TYPE, Header.JWT_TYPE).
				setHeaderParam("kid", keyId).
				signWith(SignatureAlgorithm.ES256, key).compact();

		// the signature is wrong.  regenerate it
		try {
			String[] pieces = s.split("\\.");
			if (pieces.length!=3) throw new RuntimeException("Expected 3 pieces but found "+pieces.length);

			// sign
			System.out.println("Will resign:\n"+pieces[0]+"."+pieces[1]);
			String messageToSign = pieces[0]+"."+pieces[1];
			System.out.println("original signature:    "+pieces[2]);

			Base64 base64 = new Base64();
			// what are the original signature bytes?
			byte[] originalSigBytes = base64.decode(pieces[2]);

			int shouldBe48 = originalSigBytes[0];
			int lengthOfRemaining = originalSigBytes[1]; // # of bytes, from originalSigBytes[2] to end
			if (lengthOfRemaining>originalSigBytes.length-2) throw
			new IllegalStateException("Expected <="+(originalSigBytes.length-2)+" but found "+lengthOfRemaining);
			int shouldBe2 = originalSigBytes[2];
			if (shouldBe2!=2) throw new IllegalStateException("Exected 2 but found "+shouldBe2);
			int lengthOfVR = originalSigBytes[3]; // should be 32
			if (lengthOfVR!=32 && lengthOfVR!=33) throw new IllegalStateException("Exected 32 or 33 but found "+lengthOfVR);
			// VR goes from originalSigBytes[4], for lengthOfVR bytes
			// for Java, you can simply perform new BigInteger(1, byte[] r).toByteArray() as the default Java encoding of a BigInteger is identical to the ASN.1 encoding of INTEGER
			shouldBe2 = originalSigBytes[4+lengthOfVR];
			if (shouldBe2!=2) throw new IllegalStateException("Exected 2 but found "+shouldBe2);
			int lengthOfVS = originalSigBytes[5+lengthOfVR];
			if (lengthOfVS!=32 && lengthOfVS!=33) throw new IllegalStateException("Exected 32 or 33 but found "+lengthOfVS);
			// VS goes from originalSigBytes[6+lengthOfVR] for lengthOfVS bytes
			// originalSigBytes.length should be >= 6+lengthOfVR+lengthOfVS
			if (lengthOfVS>originalSigBytes.length-6-lengthOfVR) throw
			new IllegalStateException("Expected <="+(originalSigBytes.length-6-lengthOfVR)+" but found "+lengthOfVS);

			byte[] p1363Signature = new byte[64];


			// r and s each occupy half the array
			// Remove padding bytes
			int numVRBytes = lengthOfVR > 32 ? 32 : lengthOfVR;
			System.arraycopy(originalSigBytes, 4+(lengthOfVR > 32 ? 1 : 0), 
					p1363Signature, 0, numVRBytes);

			int numVSBytes = lengthOfVS > 32 ? 32 : lengthOfVS;
			if (numVRBytes+numVSBytes!=p1363Signature.length)
				throw new IllegalStateException("Source bytes number: "+(numVRBytes+numVSBytes)
						+" but destination array has length "+p1363Signature.length);
			System.arraycopy(originalSigBytes, 6+lengthOfVR+(lengthOfVS > 32 ? 1 : 0), 
					p1363Signature, numVRBytes, numVSBytes);



			String base64Encoded = base64.encodeBase64URLSafeString(p1363Signature);
			while (base64Encoded.endsWith("=")) 
				base64Encoded = base64Encoded.substring(0, base64Encoded.length()-1);

			s = pieces[0]+"."+pieces[1]+"."+base64Encoded;

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return s;

	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			throw new RuntimeException(e);
		}
	}
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws IOException {
		
		String header = req.getHeader("Authorization");
		if (header!=null && header.startsWith("Basic ")) {
			String base64EncodedCredentials = header.substring("Basic ".length());
			String basicCredentials = new String(Base64.decodeBase64(base64EncodedCredentials));
			int colon = basicCredentials.indexOf(":");
			if (colon>0 && colon<basicCredentials.length()-1) {
				String name = basicCredentials.substring(0, colon);
				String password = basicCredentials.substring(colon+1);
				logger.info("basic credentials: name: "+name+" password: "+password);
			} else {
				logger.info("basic credentials: "+basicCredentials);
			}
		} else {
			logger.info("no 'Authorization: Basic ' header.");
			resp.setStatus(401);
			return;
		}

		String service = req.getParameter("service");
		logger.info("service: "+service);
		String scope = req.getParameter("scope");
		logger.info("scope: "+scope);
		String type = null;
		String repository = null;
		String accessTypes = null;
		if (scope==null) {
			// this is an authentication request
		} else {
			String[] scopeParts = scope.split(":");
			if (scopeParts.length!=3) throw new RuntimeException("Expected 3 parts but found "+scopeParts.length);
			type = scopeParts[0];
			repository = scopeParts[1];
			accessTypes = scopeParts[2];
		}

		String userName = "synPrincipal"; // empty string for anonymous
		logger.info("userName: "+userName+" type: "+type+" service: "+
				service+" repository: "+repository+" accessTypes: "+accessTypes);

		PrivateKey key = readPrivateKey();
		X509Certificate cert = readCertificate("cert.pem");
		String keyId = computeKeyId(cert.getPublicKey());

		String token = createToken(key, keyId, userName, type, service, repository, 
				accessTypes==null?null:Arrays.asList(accessTypes.split(","))
				);

		logger.info("token: "+token);

		JSONObject responseJson = new JSONObject();
		responseJson.put("token", token);
		// TODO fill in 'issuedAt' and 'expiresIn'

		resp.setContentType("application/json");
		resp.getOutputStream().println(responseJson.toString());
		resp.setStatus(200);
	}
}
