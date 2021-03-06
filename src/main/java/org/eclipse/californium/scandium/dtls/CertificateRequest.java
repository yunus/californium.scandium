/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.util.DatagramReader;
import org.eclipse.californium.scandium.util.DatagramWriter;


/**
 * A non-anonymous server can optionally request a certificate from the client,
 * if appropriate for the selected cipher suite. This message, if sent, will
 * immediately follow the {@link ServerKeyExchange} message (if it is sent;
 * otherwise, this message follows the server's {@link CertificateMessage}
 * message). For further details see <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246, 7.4.4.
 * Certificate Request</a>.
 */
public class CertificateRequest extends HandshakeMessage {

	// DTLS-specific constants ////////////////////////////////////////

	/* See http://tools.ietf.org/html/rfc5246#section-7.4.4 for message format. */

	private static final int CERTIFICATE_TYPES_LENGTH_BITS = 8;

	private static final int CERTIFICATE_TYPE_BITS = 8;

	private static final int SUPPORTED_SIGNATURE_LENGTH_BITS = 16;

	private static final int CERTIFICATE_AUTHORITIES_LENGTH_BITS = 16;
	
	private static final int CERTIFICATE_AUTHORITY_LENGTH_BITS = 16;

	private static final int SUPPORTED_SIGNATURE_BITS = 8;

	// Members ////////////////////////////////////////////////////////

	/** A list of the types of certificate types that the client may offer. */
	private List<ClientCertificateType> certificateTypes;

	/**
	 * A list of the hash/signature algorithm pairs that the server is able to
	 * verify, listed in descending order of preference.
	 */
	private List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms;

	/**
	 * A list of the distinguished names of acceptable certificate_authorities,
	 * represented in DER-encoded format. The list is between 0 and
	 * 2<sup>16</sup>-1 bytes long, while one distinguished name can range from
	 * 1 to 2<sup>16</sup>-1 bytes length. Therefore, the length in the
	 * serialization must be handled carefully.
	 */
	private List<DistinguishedName> certificateAuthorities;

	// Constructors ///////////////////////////////////////////////////
	
	/**
	 * Initializes an empty certificate request.
	 */
	public CertificateRequest() {
		this.certificateTypes = new ArrayList<ClientCertificateType>();
		this.supportedSignatureAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		this.certificateAuthorities = new ArrayList<DistinguishedName>();
	}

	/**
	 * 
	 * @param certificateTypes
	 *            the list of allowed client certificate types.
	 * @param supportedSignatureAlgorithms
	 *            the list of supported signature and hash algorithms.
	 * @param certificateAuthorities
	 *            the list of allowed certificate authorities.
	 */
	public CertificateRequest(List<ClientCertificateType> certificateTypes, List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, List<DistinguishedName> certificateAuthorities) {
		this.certificateTypes = certificateTypes;
		this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
		this.certificateAuthorities = certificateAuthorities;
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CERTIFICATE_REQUEST;
	}

	@Override
	public int getMessageLength() {
		// fixed: certificate type length field (1 byte) + supported signature
		// algorithms length field (2 bytes) + certificate authorities length
		// field (2 bytes) = 5 bytes
		

		return 5 + certificateTypes.size() + (supportedSignatureAlgorithms.size() * 2) + getCertificateAuthoritiesLength();
	}
	
	private int getCertificateAuthoritiesLength() {
		// each distinguished name has a variable length, therefore we need an
		// additional 2 bytes length field for each name
		int certificateAuthLength = 0;
		for (DistinguishedName distinguishedName : certificateAuthorities) {
			certificateAuthLength += distinguishedName.getName().length + 2;
		}
		
		return certificateAuthLength;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(super.toString());
		if (certificateTypes.size() > 0) {
			sb.append("\t\tClient certificate type:\n");
			for (ClientCertificateType type : certificateTypes) {
				sb.append("\t\t\t" + type.toString() + "\n");
			}
		}
		if (supportedSignatureAlgorithms.size() > 0) {
			sb.append("\t\tSignature and hash algorithm:\n");
			for (SignatureAndHashAlgorithm algo : supportedSignatureAlgorithms) {
				sb.append("\t\t\t" + algo.toString() + "\n");
			}
		}
		if (certificateAuthorities.size() > 0) {
			sb.append("\t\tCertificate authorities:\n");
			for (DistinguishedName name : certificateAuthorities) {
				X500Principal principal = new X500Principal(name.getName());
				sb.append("\t\t\t" + principal.getName() + "\n");
			}
		}
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(certificateTypes.size(), CERTIFICATE_TYPES_LENGTH_BITS);
		for (ClientCertificateType certificateType : certificateTypes) {
			writer.write(certificateType.getCode(), CERTIFICATE_TYPE_BITS);
		}

		writer.write(supportedSignatureAlgorithms.size() * 2, SUPPORTED_SIGNATURE_LENGTH_BITS);
		for (SignatureAndHashAlgorithm signatureAndHashAlgorithm : supportedSignatureAlgorithms) {
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), SUPPORTED_SIGNATURE_BITS);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), SUPPORTED_SIGNATURE_BITS);
		}
		
		writer.write(getCertificateAuthoritiesLength(), CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		for (DistinguishedName distinguishedName : certificateAuthorities) {
			// since a distinguished name has variable length, we need to write length field for each name as well, has influence on total length!
			writer.write(distinguishedName.getName().length, CERTIFICATE_AUTHORITY_LENGTH_BITS);
			writer.writeBytes(distinguishedName.getName());
		}

		return writer.toByteArray();
	}

	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		DatagramReader reader = new DatagramReader(byteArray);
		
		int length = reader.read(CERTIFICATE_TYPES_LENGTH_BITS);
		List<ClientCertificateType> certificateTypes = new ArrayList<ClientCertificateType>();
		for (int i = 0; i < length; i++) {
			int code = reader.read(CERTIFICATE_TYPE_BITS);
			certificateTypes.add(ClientCertificateType.getTypeByCode(code));
		}
		
		length = reader.read(SUPPORTED_SIGNATURE_LENGTH_BITS);
		List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new ArrayList<SignatureAndHashAlgorithm>();
		for (int i = 0; i < length; i += 2) {
			int codeHash = reader.read(SUPPORTED_SIGNATURE_BITS);
			int codeSignature = reader.read(SUPPORTED_SIGNATURE_BITS);
			supportedSignatureAlgorithms.add(new SignatureAndHashAlgorithm(HashAlgorithm.getAlgorithmByCode(codeHash), SignatureAlgorithm.getAlgorithmByCode(codeSignature)));
		}
		
		length = reader.read(CERTIFICATE_AUTHORITIES_LENGTH_BITS);
		List<DistinguishedName> certificateAuthorities = new ArrayList<DistinguishedName>();
		while (length > 0) {
			int nameLength = reader.read(CERTIFICATE_AUTHORITY_LENGTH_BITS);
			byte[] name = reader.readBytes(nameLength);
			certificateAuthorities.add(new DistinguishedName(name));
			
			length -= 2 + name.length;
			
		}
		
		return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);

	}

	// Enums //////////////////////////////////////////////////////////

	/**
	 * Certificate types that the client may offer. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246</a> for
	 * details.
	 */
	public enum ClientCertificateType {
		RSA_SIGN(1), DSS_SIGN(2), RSA_FIXED_DH(3), DSS_FIXED_DH(4), RSA_EPHEMERAL_DH_RESERVED(5), DSS_EPHEMERAL_DH_RESERVED(6), FORTEZZA_DMS_RESERVED(20), ECDSA_SIGN(64), RSA_FIXED_ECDH(65), ECDSA_FIXED_ECDH(66);

		private int code;

		private ClientCertificateType(int code) {
			this.code = code;
		}

		public int getCode() {
			return code;
		}
		
		public static ClientCertificateType getTypeByCode(int code) {
			switch (code) {
			case 1:
				return RSA_SIGN;
			case 2:
				return DSS_SIGN;
			case 3:
				return RSA_FIXED_DH;
			case 4:
				return DSS_FIXED_DH;
			case 5:
				return RSA_EPHEMERAL_DH_RESERVED;
			case 6:
				return DSS_EPHEMERAL_DH_RESERVED;
			case 20:
				return FORTEZZA_DMS_RESERVED;
			case 64:
				return ECDSA_SIGN;
			case 65:
				return RSA_FIXED_ECDH;
			case 66:
				return ECDSA_FIXED_ECDH;

			default:
				return null;
			}
		}
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC
	 * 5246</a> for details. Code is at most 255 (1 byte needed for
	 * representation).
	 */
	public enum HashAlgorithm {
		NONE(0), MD5(1), SHA1(2), SHA224(3), SHA256(4), SHA384(5), SHA512(6);

		private int code;

		private HashAlgorithm(int code) {
			this.code = code;
		}
		
		public static HashAlgorithm getAlgorithmByCode(int code) {
			switch (code) {
			case 0:
				return NONE;
			case 1:
				return MD5;
			case 2:
				return SHA1;
			case 3:
				return SHA224;
			case 4:
				return SHA256;
			case 5:
				return SHA384;
			case 6:
				return SHA512;

			default:
				return null;
			}
		}

		public int getCode() {
			return code;
		}

		public void setCode(int code) {
			this.code = code;
		}

		@Override
		public String toString() {
			switch (code) {
			case 0:
				return "NONE";
			case 1:
				return "MD5";
			case 2:
				return "SHA1";
			case 3:
				return "SHA224";
			case 4:
				return "SHA256";
			case 5:
				return "SHA384";
			case 6:
				return "SHA512";

			default:
				return "";
			}
		}
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC
	 * 5246</a> for details. Code is at most 255 (1 byte needed for
	 * representation).
	 */
	public enum SignatureAlgorithm {
		ANONYMOUS(0), RSA(1), DSA(2), ECDSA(3);

		private int code;

		private SignatureAlgorithm(int code) {
			this.code = code;
		}
		
		public static SignatureAlgorithm getAlgorithmByCode(int code) {
			switch (code) {
			case 0:
				return ANONYMOUS;
			case 1:
				return RSA;
			case 2:
				return DSA;
			case 3:
				return ECDSA;

			default:
				return null;
			}
		}

		public int getCode() {
			return code;
		}

		public void setCode(int code) {
			this.code = code;
		}
		
		@Override
		public String toString() {
			switch (code) {
			case 0:
				return "Anonymous";
			case 1:
				return "RSA";
			case 2:
				return "DSA";
			case 3:
				return "ECDSA";

			default:
				return "";
			}
		}
	}

	/**
	 * A distinguished name is between 1 and 2<sup>16</sup>-1 bytes long. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246 -
	 * Certificate Request</a> for details.
	 */
	public static class DistinguishedName {
		private byte[] name;

		public DistinguishedName(byte[] name) {
			this.name = name;
		}

		public byte[] getName() {
			return name;
		}

	}
	
	// Getters and Setters ////////////////////////////////////////////

	public void addCertificateType(ClientCertificateType certificateType) {
		certificateTypes.add(certificateType);
	}

	public void addSignatureAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
		supportedSignatureAlgorithms.add(signatureAndHashAlgorithm);
	}

	public void addCertificateAuthority(DistinguishedName authority) {
		certificateAuthorities.add(authority);
	}
	
	/**
	 * Takes a list of trusted certificates, extracts the subject principal and
	 * adds the DER-encoded distinguished name to the certificate authorities.
	 * 
	 * @param certificateAuthorities
	 *            trusted certificates.
	 */
	public void addCertificateAuthorities(Certificate[] certificateAuthorities) {
		if (certificateAuthorities != null){
			for (Certificate certificate : certificateAuthorities) {
				byte[] ca = ((X509Certificate) certificate).getSubjectX500Principal().getEncoded();
				addCertificateAuthority(new DistinguishedName(ca));
			}
		}
	}

	public List<ClientCertificateType> getCertificateTypes() {
		return certificateTypes;
	}

	public List<SignatureAndHashAlgorithm> getSupportedSignatureAlgorithms() {
		return supportedSignatureAlgorithms;
	}

	public List<DistinguishedName> getCertificateAuthorities() {
		return certificateAuthorities;
	}

}
