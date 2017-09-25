import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.junit.BeforeClass;
import org.junit.Test;

import com.dhedhi.utils.adcsclient.CertUtil;
import com.dhedhi.utils.adcsclient.ADCSClient;


public class TestADCSClient {

	public static final String resourcesFolder = "src/test/resources";
	public static final String caStore = "src/test/resources/ca_store";
	
    private static org.apache.logging.log4j.Logger LOGGER = null;
    
    @BeforeClass
    public static void setLogger() throws MalformedURLException
    {
        System.setProperty("log4j.configurationFile","log4j2-test.xml");
        LOGGER = LogManager.getLogger();
    }
	
    /*
     * This test creats a public/private key, then creates a CSR, then signs it using ADCS web service
     * and then verifies the result;
     */
    @Test
    public void TestAllGood() throws IOException {
    	CertUtil certUtil = new CertUtil();
    	// Create a public/private key pair
    	KeyPair keyPair = null;
        try {
            keyPair = certUtil.createPublicPrivateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create Public/private key pair");
            return;
        }
    	
        // Create a Certificate signing request using the key pair created above
    	String sCSR;
		try {
		    sCSR = certUtil.createCSR(keyPair, "TestUser", "www.mytestserver.com", "support@mytestserver.com");
		    System.out.println( "CSR: " + sCSR );
		} catch (Exception e) {
			e.printStackTrace();
			fail("Unable to create CSR");
            return;
		}
		
        // Now Sign the CSR using ADCS web service
		X509Certificate signedCertificate;
		ADCSClient client = new ADCSClient("https://<server-name>/CES/service.svc/CES", "<username>", "<userpassword>");
		client.loadCAStore(caStore); // load all the CAs we trust
		try {
		    signedCertificate = client.signCSR( sCSR );
		}catch (Exception e) {
            e.printStackTrace();
            fail("Unable to sign certificate");
            return;
        }
		
        // Now convert the signed certificate and private key into a pkcs12 byte array.
		// 123456 is the password we will use to encrypt the pkcs12 structure.
		String sPKCS12Password = "123456";
		String sPKCS12Alias = "testalias";
		byte[] pkcs12;
        try {
            pkcs12 = certUtil.getPKCS12(signedCertificate, keyPair.getPrivate(), sPKCS12Password, sPKCS12Alias);
        }catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create pkcs12");
            return;
        }
		
        
        // Read the public key back from the above generated pkcs12 byte array and make sure it matches 
        // what we originally generated in the very first step above.
        PublicKey publicKey;
        try {
            publicKey = certUtil.getPKCS12PublicKey(pkcs12, sPKCS12Password, sPKCS12Alias);
        }catch (Exception e) {
            e.printStackTrace();
            fail("Unable to get publickey back from pkcs12");
            return;
        }
        
        assert( publicKey.equals( keyPair.getPublic() ) == true );
		
    }
    
    /*
     * This test creates an Elliptic curve public/private key
     */    
    @Test
    public void TestECPublicPrivateKey() throws IOException {
        CertUtil certUtil = new CertUtil();
        
        // Create a public/private key pair
        try {
            certUtil.setHashAlgorithm("SHA256WITHECDSA");
            certUtil.setKeySize(256);
            certUtil.setKeyType("EC");;
            
            certUtil.createPublicPrivateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create Public/private key pair");
            return;
        }
    }
    
    /*
     * This test creates an Elliptic curve public/private key but should fail
     * since the hash algorithm is still using RSA
     */    
    @Test
    public void TestECPublicPrivateKeyBad() throws IOException {
        CertUtil certUtil = new CertUtil();
        
        // Create a public/private key pair
        KeyPair keyPair = null;
        try {
            //certUtil.setHashAlgorithm("SHA256WITHECDSA");
            certUtil.setKeySize(256);
            certUtil.setKeyType("EC");;
            
            keyPair = certUtil.createPublicPrivateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unable to create Public/private key pair");
        }
        
        // Create a Certificate signing request using the key pair created above. This should fail
        try {
            certUtil.createCSR(keyPair, "HyporiUser", "www.mytestserver.com", "support@mytestserver.com");
            fail("This should fail since hash algorithm is still using RSA");
        } catch (Exception e) {
        }        
        
    }

    
}
