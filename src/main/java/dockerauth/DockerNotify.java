/**
 * Copyright 2012 Google Inc. All Rights Reserved. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dockerauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.repackaged.com.google.api.client.util.IOUtils;


public class DockerNotify extends HttpServlet {
	private Logger logger = Logger.getLogger("DockerNotify");


	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
//		ContentType contentType = ContentType.parse(req.getContentType());
//		Charset charset = contentType.getCharset();
		try {
			IOUtils.copy(req.getInputStream(), baos, true);
		} finally {
			baos.close();
		}
//		String requestBody = baos.toString(charset==null? "ISO-8859-1" : charset.toString());
		String requestBody = baos.toString("ISO-8859-1");
		
		logger.info(requestBody);

		resp.setStatus(200);
	}
}
