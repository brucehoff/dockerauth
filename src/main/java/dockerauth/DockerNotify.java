
package dockerauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;


public class DockerNotify extends HttpServlet {
	private Logger logger = Logger.getLogger("DockerNotify");


	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
//		ContentType contentType = ContentType.parse(req.getContentType());
//		Charset charset = contentType.getCharset();
		try {
			IOUtils.copy(req.getInputStream(), baos);
		} finally {
			baos.close();
		}
//		String requestBody = baos.toString(charset==null? "ISO-8859-1" : charset.toString());
		String requestBody = baos.toString("ISO-8859-1");
		
		logger.info(requestBody);

		resp.setStatus(200);
	}
}
