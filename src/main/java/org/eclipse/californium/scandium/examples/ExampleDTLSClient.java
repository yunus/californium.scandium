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
package org.eclipse.californium.scandium.examples;

import java.io.FileInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.logging.Level;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;

public class ExampleDTLSClient {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINEST);
	}

	private static final int DEFAULT_PORT = 5684;
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	private DTLSConnector dtlsConnector;
	
	
	public ExampleDTLSClient() {
	    try {
	    	
	    	
	        // load key store
            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
    
            // load trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
            
            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");
    
    		dtlsConnector = new DTLSConnector(new InetSocketAddress(0), trustedCertificates);
    		dtlsConnector.getConfig().webIDURI = "example.org/client-scandium/";
    		dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
    		dtlsConnector.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("client"), true);
    		
    		//dtlsConnector.setRawDataReceiver(new RawDataChannelImpl());
    		
	    } catch (GeneralSecurityException | IOException e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
	}
	
	public void test(String uri) {
		try {
			
			CoapClient client = new CoapClient(uri);
    		client.setEndpoint(new CoAPEndpoint(dtlsConnector, NetworkConfig.getStandard()));
    		//dtlsConnector.start();
    		client.setTimeout(0);
			CoapResponse response = client.get();
			
			if (response!=null) {
				
				System.out.println(response.getCode());
				System.out.println(response.getOptions());
				System.out.println(response.getResponseText());
				
				System.out.println("\nADVANCED\n");
				// access advanced API with access to more details through .advanced()
				System.out.println(Utils.prettyPrint(response));
				
			} else {
				System.out.println("No response received.");
			}
			
			//dtlsConnector.start();
			//dtlsConnector.send(new RawData("HELLO WORLD".getBytes(), InetAddress.getByName(uri) , DEFAULT_PORT));
			dtlsConnector.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	
	public static void main(String[] args) throws InterruptedException {
		
		ExampleDTLSClient client = new ExampleDTLSClient();
		client.test("coaps://[aaaa::ff:fe02:232]/hello");
		
		// Connector threads run as daemons so wait in main thread until handshake is done
		synchronized (ExampleDTLSClient.class) {
			ExampleDTLSClient.class.wait();
		}
	}
}
