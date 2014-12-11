/**
 * @author yunus durmus
 * @email yunus@yanis.co
 *
 */
package org.eclipse.californium.scandium.dtls;

import java.nio.charset.Charset;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;

/**
 * If both parties support, before the certificate a webid uri (http://www.w3.org/2005/Incubator/webid/spec/) 
 * is exchanged from both sides. This message is only required in case of Raw Public Keys since WebID uri can be
 * embedded in the SubjectAltName field of the X509v3 certificates. 
 * WebID uri is used to authenticate and authorize the peer. Without a need for certificate authority,
 * self-signed and raw public keys can be verified. Later, the decentralized social network of the devices
 * and their owners are employed in establishing a trust link.
 */
public class WebIDUriMessage extends HandshakeMessage {
	
		// Logging ///////////////////////////////////////////////////////////

		private static final Logger LOGGER = Logger.getLogger(CertificateMessage.class.getCanonicalName());
	
		// DTLS-specific constants ///////////////////////////////////////////
		
		
		private static final int MAX_WEBID_URI_LENGTH = 50;
		

		private static final int URI_LENGTH_BITS = 16;
		
		private static final Charset CHAR_SET = Charset.forName("UTF8");

		// Members ////////////////////////////////////////////////////////

		private byte[] uriEncoded;

		/** The identity in cleartext. */
		private String webidUri;
	
		// Constructors ///////////////////////////////////////////////////
		
		public WebIDUriMessage(String identity) {
			this.webidUri = identity;
			this.uriEncoded = identity.getBytes(CHAR_SET);
		}
		
		public WebIDUriMessage(byte[] uriEncoded) {
			this.uriEncoded = uriEncoded;
			this.webidUri = new String(uriEncoded, CHAR_SET);
		}


	/* (non-Javadoc)
	 * @see org.eclipse.californium.scandium.dtls.HandshakeMessage#getMessageType()
	 */
	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.WEBID_URI;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.scandium.dtls.HandshakeMessage#getMessageLength()
	 */
	@Override
	public int getMessageLength() {
		/* 2 bytes for the length field, rest is the uri in bytes */
		return 2 + uriEncoded.length;
	}

	// Serialization //////////////////////////////////////////////////

		@Override
		public byte[] fragmentToByteArray() {
			DatagramWriter writer = new DatagramWriter();
			
			writer.write(uriEncoded.length, URI_LENGTH_BITS);
			writer.writeBytes(uriEncoded);
			
			if(uriEncoded.length > MAX_WEBID_URI_LENGTH)
				LOGGER.severe("WebID URI length is "+ uriEncoded.length +
						" but it can be at most "+MAX_WEBID_URI_LENGTH+
						"; the 'https://' can be omitted to save space.");
			
			
			return writer.toByteArray();
		}
		
		public static HandshakeMessage fromByteArray(byte[] byteArray) {
			DatagramReader reader = new DatagramReader(byteArray);
			
			int length = reader.read(URI_LENGTH_BITS);
			byte[] uriEncoded = reader.readBytes(length);
			
			return new WebIDUriMessage(uriEncoded);
		}
	
	public String getWebidUri() {
			return webidUri;
		}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		sb.append(super.toString());
		sb.append("\t\tWebID uri: " + webidUri + "\n");

		return sb.toString();
	}

}
