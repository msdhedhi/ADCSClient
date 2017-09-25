package com.dhedhi.utils.adcsclient;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.dhedhi.utils.adcsclient.exceptions.ADCSCertificateException;

public class ADCSClient {

    private static final Logger logger = LogManager.getRootLogger();

    private SSLContext sc = null;;
        
    private final String adcsWebServiceURI; // this is typically of the form https://<server-name>/CES/service.svc/CES
    private final String sUsername;  // the username of the user for which the certificate will be issued.
    private final String sPassword;  // the password of the user for which the certificate will be issued.
    private boolean verifyServerCerts = true; // should we verify the server certs on SSL/TLS connection.

    private MessageDigest sha1; // used to compute issuer hashes

    private Map<String,X509Certificate> caCerts = new HashMap<String,X509Certificate>();
    
    static {
        // Add bouncy castle as the security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    public ADCSClient( String sURI, String sUsername, String sPassword ) {
    
        this.adcsWebServiceURI = sURI;
        this.sUsername = sUsername;
        this.sPassword = sPassword;
        
        try {
            sha1 = MessageDigest.getInstance("SHA1"); // we should always find SHA1 provider
        } catch (NoSuchAlgorithmException e) {
        }
  
    }
    
    // ------------------------------------------------------------------------------------------------
    // Load the CAs from a folder. We will use these CAs to verify our connections to SSL servers
    // ------------------------------------------------------------------------------------------------
    public synchronized void loadCAStore( String sCAStorePath ) {
        File caFilePath = new File(sCAStorePath);
        
        if( caFilePath.exists() == false ) {
            throw new ADCSCertificateException("Directory: " + sCAStorePath + " does not exist." );
        }
        if( caFilePath.isDirectory() == false ) {
            throw new ADCSCertificateException("Directory: " + sCAStorePath + " does not exist." );
        }
        
        for (File fileEntry : caFilePath.listFiles()) {
            InputStream in = null;
            try {
                in = new FileInputStream(sCAStorePath + "/" + fileEntry.getName());
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate anchorCert = (X509Certificate) factory.generateCertificate(in);
                
                // add this CA certificate to our caCerts map. Use the issuers subject hash for easy lookup.
                sha1.reset();
                sha1.update(anchorCert.getSubjectX500Principal().getEncoded());
                String sIssuerHash = String.valueOf(convertBytesToHex(sha1.digest()));
                caCerts.put(sIssuerHash , anchorCert);
                
            } catch( Exception e ) {
                throw new ADCSCertificateException("Unable to read file: " + sCAStorePath + "/" + fileEntry.getName() );
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch( IOException e ) {
                        logger.error( "Unable to close file. Readon: " + e.getMessage());
                    }
                }
            }
        }
    }
    
    // ------------------------------------------------------------------------------------------------
    // Signs a Certificate signing request using Windows Active Directory Certificate Service
    // ------------------------------------------------------------------------------------------------
    public synchronized X509Certificate signCSR(String sCSR) {
        
        if( sc == null ) {
            X509TrustManager trustAllCerts = new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    // Not using client certs
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                    
                    // Never do this in production.
                    if( verifyServerCerts == false ) {
                        logger.warn( "You are trusting all certificates. Make sure you are not running in production.");
                        return;
                    }
                    
                    for( int i = 0; i < certs.length; i++ ) {
                        
                        // Compute the issuer's hash and then try to look it up in our caCerts hash map
                        sha1.reset();
                        sha1.update(certs[i].getIssuerX500Principal().getEncoded());
                        String sIssuerHash = String.valueOf(convertBytesToHex(sha1.digest()));
                        
                        if( caCerts.containsKey(sIssuerHash ) == false ) {
                            throw new CertificateException( "Server certificate with isuser hash: " + sIssuerHash + " and subject: " + certs[i].getIssuerX500Principal().getName() + " was not found in CA store.");
                        }
                        
                        X509Certificate trustAnchor = caCerts.get(sIssuerHash);
                        
                        // Now verify this certificate as signed using the caCert we have identified
                        try {
                            certs[i].verify(trustAnchor.getPublicKey());
                            logger.info( "Server certificate verified using CA: " + trustAnchor.getSubjectDN().getName());
                        } catch (Exception e) {
                            throw new CertificateException( "Unable to verify server certificate: " + certs[i].getSubjectDN().getName() + " using CA with hash: " + sIssuerHash);
                        } 
                        
                        // Add more checks for CRL, OCSP and expiry
                    }
                }
            };   
            try {
                sc = SSLContext.getInstance("SSL");
                sc.init(null, new TrustManager[] { trustAllCerts}, new java.security.SecureRandom());            
            } catch( Exception e ) {
                sc = null;
                logger.error( "Unable to initialize trust manager. Reason: " + e.getMessage() );
                throw new ADCSCertificateException("Unable to initialize trust manager. Reason: " + e.getMessage() );
            }
        }
        // replace the beginning/ending tags. Windows ADCS does not like them
        String csrAsPEMStr = sCSR.toString().replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").trim();

        // This does all the magic of sending the SOAP request to the windows ADCS web service
        String signedCRTAsString = doSoapMagic(csrAsPEMStr );
        
        // add back the beginning/ending tags to the signed certificate
        signedCRTAsString = "-----BEGIN CERTIFICATE-----\n" + signedCRTAsString + "-----END CERTIFICATE-----\n";

        // load the returned PEM certificate as a X509 Certificate
        //logger.info("Certificate from ADCS: " + certStr);
        X509Certificate signedCert = null;
        InputStream in = null;
        try {
            in = new ByteArrayInputStream( signedCRTAsString.getBytes( "ASCII" ) );
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            signedCert = (X509Certificate) factory.generateCertificate(in);
        } catch ( Exception e ) {
            logger.error( "Unable to convert signed cert to X509 object. Reason: " + e.getMessage() );
            throw new ADCSCertificateException("Unable to convert signed cert to X509 object. Reason: " + e.getMessage() );
        } finally {
            if( in != null ) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error( "Unable to close input stream while creating X509 signed certificate. Reason: " + e.getMessage() );
                }
            }
        }
        
        return signedCert;
    }
    
    
    // ------------------------------------------------------------------------------------------------
    // Constructs a SOAP request and sends it to ADCS to sign the CSR
    // ------------------------------------------------------------------------------------------------    
    private String doSoapMagic(String soapenvbody) {

        String sHostname;
        try {
            sHostname = InetAddress.getLocalHost().getHostName() ;
        } catch ( Exception e ) {
            logger.error( "Unable to get hostname. Reason: " + e.getMessage() );
            throw new ADCSCertificateException("Unable to get hostname. Reason: " + e.getMessage() );
        }  
        
        String body ="";
        body += "<s:Envelope xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">";
        body += "<s:Header>";
        body += "<a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>";
        body += "<a:MessageID>urn:uuid:" + UUID.randomUUID().toString() + "</a:MessageID>";
        body += "<a:To s:mustUnderstand=\"1\">" + adcsWebServiceURI + "</a:To>";
        body += "<o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";
        body += "<o:UsernameToken><o:Username>" + sUsername + "</o:Username>";
        body += "<o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" + sPassword + "</o:Password>";
        body += "</o:UsernameToken></o:Security>";
        body += "</s:Header>";
        body += "<s:Body>";
        body += "<RequestSecurityToken PreferredLanguage=\"en-US\" xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">";
        body += "<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>";
        body += "<RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>";
        body += "<BinarySecurityToken ValueType=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary\" a:Id=\"\" xmlns:a=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">";

        body += soapenvbody;

        body += "</BinarySecurityToken>";
        body += "<AdditionalContext xmlns=\"http://schemas.xmlsoap.org/ws/2006/12/authorization\">";
        body += "<ContextItem Name=\"ccm\"><Value>" + sHostname +"</Value></ContextItem>";
        body += "</AdditionalContext>";
        body += "</RequestSecurityToken>";
        body += "</s:Body>";
        body += "</s:Envelope>";

        body = body.replace("\n", "");

        //System.out.println("Soap Body:" + body);
        InputStream in = null;
        OutputStream out = null;

        try {
            URI uri = new URI(adcsWebServiceURI);

            URL url = uri.toURL();
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            if( con instanceof HttpsURLConnection ) {
                HttpsURLConnection conn = (HttpsURLConnection)con;
                    //Trusting all certificates for now. We should improve this later
                conn.setSSLSocketFactory( sc.getSocketFactory() );
                conn.setHostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String arg0, SSLSession arg1) {
                        return true;
                    }
                });
            }
            
            con.setConnectTimeout(60000); // 60 seconds
            con.setReadTimeout(60000);
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", "application/soap+xml; charset=utf-8");
            byte[] bytes = body.getBytes();

            con.setRequestProperty("Content-length", String.valueOf(bytes.length));
            out = con.getOutputStream();
            out.write(bytes);
            out.flush();

            // Check the response
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {

                in = con.getErrorStream();
                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                String inputLine = "";
                StringBuilder result = new StringBuilder();
                while ((inputLine = br.readLine()) != null) {
                    result.append(inputLine.trim());
                }

                //System.out.println( "ERROR = " + result.toString());
                logger.error("ADCS webservice returned error code: " + con.getResponseCode() + " message: " + result.toString());
                throw new ADCSCertificateException( "Unable to sign certificate using ADCS. Error Code: " + con.getResponseCode() + ". Error Message: " + result.toString() );


            } else {
                in = con.getInputStream();
                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                String inputLine = "";
                StringBuilder result = new StringBuilder();
                while ((inputLine = br.readLine()) != null) {
                    result.append(inputLine.trim());
                }

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                DocumentBuilder builder;
                try
                {
                    builder = factory.newDocumentBuilder();
                    Document document = builder.parse( new InputSource( new StringReader( result.toString() ) ) );
                    javax.xml.xpath.XPath xPath =  XPathFactory.newInstance().newXPath();

                    NodeList permissionsNodeList = (NodeList) xPath.compile("//RequestedSecurityToken/BinarySecurityToken").evaluate(document, XPathConstants.NODESET);
                    if( permissionsNodeList != null && permissionsNodeList.getLength() > 0 ) {
                            org.w3c.dom.Node activityNode = permissionsNodeList.item(0);

                            //System.out.println( "CERTIFICATE FROM SERVER:" + activityNode.getFirstChild().getNodeValue() );
                            return activityNode.getFirstChild().getNodeValue();
                    }




                } catch( Exception e ) {
                    logger.error("Unable to parse xml response from ADCS", e);
                    throw new ADCSCertificateException( "Unable to parse xml response from ADCS. Error Message: " + e.getMessage() );
                }

                return "";
            }
        } catch( Exception e ) {
            logger.error("Unable to send request to adcs", e);
            throw new ADCSCertificateException( "Unable to send SOAP request to ADCS. Error Message: " + e.getMessage() );
        } finally {
            if( in != null ) {
                try {
                    in.close();
                } catch (IOException e) {
                    logger.error("Unable to close input stream", e);
                }
            }
            if( out != null ) {
                try {
                    out.close();
                } catch (IOException e) {
                    logger.error("Unable to close output stream", e);
                }
            }
        }
    }

    public boolean isVerifyServerCerts() {
        return verifyServerCerts;
    }

    public void setVerifyServerCerts(boolean verifyServerCerts) {
        this.verifyServerCerts = verifyServerCerts;
    }
    
    private static char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    private char[] convertBytesToHex(byte[] bytes) {
        char buf[] = new char[bytes.length * 2];
        int index = 0;
        for (byte b : bytes) {
            buf[index++] = hex[(b >> 4) & 0xf];
            buf[index++] = hex[b & 0xf];
        }
        return buf;
    }
    
    
    
}
