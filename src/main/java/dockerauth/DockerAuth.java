
package dockerauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
		KeyPair keyPair = readKeyPair();
		String s = createToken(keyPair, "userName", "repository", "docker.sagebase.org", "user/helloworld", 
				Arrays.asList(new String[]{"push", "pull"}));

		System.out.println(s);
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

	// TODO instead of reading public key from 'publickey.pem' read in 'cert.pem' and extract the public key
	private static PublicKey readPublicKey(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemReader pemReader = new PemReader(new InputStreamReader(DockerAuth.class.getClassLoader().getResourceAsStream(filename)));
		try {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			return factory.generatePublic(pubKeySpec);
		} finally {
			pemReader.close();
		}
	}

	public static KeyPair readKeyPair() {
		try {
			KeyFactory factory = KeyFactory.getInstance(CertificateHelper.KEY_GENERATION_ALGORITHM, "BC");
			PrivateKey priv = readPrivateKey(factory,"privatekey.pem");
			PublicKey pub = readPublicKey(factory, "publickey.pem");
			return new KeyPair(pub, priv);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("all")
	public static String createToken(
			KeyPair keyPair, String userName, String type, 
			String registry, String repository, List<String> actions) {

		ECPrivateKey key = (ECPrivateKey)keyPair.getPrivate();
		ECPublicKey  validatingKey = (ECPublicKey)keyPair.getPublic();

		long now = System.currentTimeMillis();

		JSONArray access = new JSONArray();
		JSONObject accessEntry = new JSONObject();
		access.add(accessEntry);
		accessEntry.put("type", type);
		accessEntry.put("name", repository);
		JSONArray actionArray = new JSONArray();
		actionArray.addAll(actions);
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

		// TODO don't compute the key's ID each time
		String keyId = CertificateHelper.computeKeyId(keyPair.getPublic());

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

		String service = req.getParameter("service");
		String scope = req.getParameter("scope");
		String[] scopeParts = scope.split(":");
		if (scopeParts.length!=3) throw new RuntimeException("Expected 3 parts but found "+scopeParts.length);
		String type = scopeParts[0];
		String repository = scopeParts[1];
		String accessTypes = scopeParts[2];

		String userName = "synPrincipal"; // empty string for anonymous
		logger.info("userName: "+userName+" type: "+type+" service: "+
				service+" repository: "+repository+" accessTypes: "+accessTypes);

		// TODO check what access 'userName' has to 'repository'
		// TODO and return the subset of 'accessTypes' which 'userName' is permitted
		// TODO cache KeyPair so we don't read it each time
		KeyPair keyPair = readKeyPair();
		String token = createToken(keyPair, userName, type, service, repository, Arrays.asList(accessTypes.split(",")));

		logger.info("token: "+token);

		JSONObject responseJson = new JSONObject();
		responseJson.put("token", token);
		// TODO fill in 'issuedAt' and 'expiresIn'

		resp.setContentType("application/json");
		resp.getOutputStream().println(responseJson.toString());
		resp.setStatus(200);
	}
}
