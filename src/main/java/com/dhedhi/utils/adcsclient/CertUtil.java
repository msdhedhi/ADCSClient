package com.dhedhi.utils.adcsclient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import com.dhedhi.utils.adcsclient.exceptions.ADCSCertificateException;

public class CertUtil {

    private static final Logger logger = LogManager.getRootLogger();

    // This is the default keyType. Use "EC" for elliptic curve key
    private String keyType = "RSA"; 
    
    // This is the default keysize. Use "EC" supported key size if keyType above is set to EC
    // See https://www.globalsign.com/en/blog/elliptic-curve-cryptography/ for what key sizes to use.
    private int keySize = 2048;  
    
    // If using "EC" for keyType, the use SHA256WITHECDSA
    private String hashAlgorithm = "SHA256WITHRSA"; 
    
    static {
        // Add bouncy castle as the security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /*
     * Generate a public/private key pair
     */    
    public KeyPair createPublicPrivateKeyPair( ) {
        // First Create a public/private key pair
        KeyPairGenerator keyGen = null;
        KeyPair pair = null;
        try {
            keyGen = KeyPairGenerator.getInstance(keyType,BouncyCastleProvider.PROVIDER_NAME);
            keyGen.initialize(keySize, new SecureRandom());
            pair = keyGen.generateKeyPair();
        } catch ( Exception e) {
            logger.error("Unable to generate public/private key pair generator", e);
            throw new ADCSCertificateException( "Unable to generate private/public key pair. Reason: " + e.getMessage() );
        } 
        
        return pair;
    }

    /*
     * Create a certificae signing request and return it
     * sADCSTemplate: The template in ADCS which we are targeting or want to use
     */
    public String createCSR( KeyPair pair, String sADCSTemplate, String sCertificateCNSubject, String sCertificateEmailSubject ) {

        if( StringUtils.isBlank(sADCSTemplate) ) {
            logger.error("ADCSTemplate must be specified.");
            throw new ADCSCertificateException( "ADCSTemplate must be specified." );
        }
        
        if( StringUtils.isBlank(sCertificateCNSubject) ) {
            logger.error("Certificate CN subject must be specified.");
            throw new ADCSCertificateException( "Certificate CN subject." );
        }
       
        
        // We now have a public key and a private key
        PublicKey pubKey = pair.getPublic();
        PrivateKey privKey = pair.getPrivate();
        
        ExtensionsGenerator extGen;
        try {
            // Add Extension for usage and the target ADCS Certificate Template to use.
            extGen = new ExtensionsGenerator();
            // this is the OID for setting the ADCS template to use. This is Microsoft specific OID.
            extGen.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2"), false, new DERBMPString(sADCSTemplate)  );
            
            // usage OID. Adding most common usages. Customize this as needed.
            KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign
                    | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                    | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
            extGen.addExtension(Extension.keyUsage, false, usage);
            
            // Purpose OID. Adding most common usages. Customize this as needed.
            ASN1EncodableVector purposes = new ASN1EncodableVector();
            purposes.add(KeyPurposeId.id_kp_serverAuth);  // can be used as a server certificate
            purposes.add(KeyPurposeId.id_kp_clientAuth);  // can be used as a client certificate...used for mutual authentication
            purposes.add(KeyPurposeId.anyExtendedKeyUsage);
            extGen.addExtension(Extension.extendedKeyUsage, false,new DERSequence(purposes));
                
            // Add the Subject Alternative name since AD CS removes the UID we previously added to certificateSubject
            X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
            x500NameBld.addRDN(BCStyle.CN, new DERUTF8String(sCertificateCNSubject));
            GeneralName[] subjectAltName = new GeneralName[1];
            subjectAltName[0] = new GeneralName(  x500NameBld.build() );
            extGen.addExtension(Extension.subjectAlternativeName , false, new GeneralNames(subjectAltName));
        } catch ( Exception e ) {
            logger.error("Unable to add extensions to CSR", e);
            throw new ADCSCertificateException( "Unable to add extensions to CSR. Reason: " + e.getMessage() );
        }

        // Build a Subject for the Certificate. We are setting this to the CN field. 
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, new DERUTF8String(sCertificateCNSubject) );  
        if( !StringUtils.isBlank(sCertificateEmailSubject) ) {
            x500NameBld.addRDN(BCStyle.EmailAddress, new DERUTF8String(sCertificateEmailSubject) );  
        }
        X500Name certificateSubject = x500NameBld.build();
        
        // Now create a CSR and return it
        byte[] pemEncoedCSR = null;
        try {

            PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(certificateSubject, pubKey);
            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

            PKCS10CertificationRequest csrBuilder = null;
            csrBuilder = requestBuilder.build(new JcaContentSignerBuilder(hashAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privKey));
            pemEncoedCSR = csrBuilder.getEncoded();
            //SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
            //csrBuilder = new PKCS10CertificationRequest( new CertificationRequest( new CertificationRequestInfo(new org.bouncycastle.asn1.x500.X500Name(certificateSubject), publicKeyInfo, null ), new org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder().find(hashingAlgorithm), null ) );
        } catch (Exception e) {
            throw new ADCSCertificateException( "Unable to create certificate signing request. Reason: " + e.getMessage() );
        }        
        
        
        StringWriter csrAsPEM = new StringWriter();
        JcaPEMWriter pemWriter = null;;
        try {
            String type = "CERTIFICATE REQUEST";
            PemObject pemObject = new PemObject(type, pemEncoedCSR);
            pemWriter = new JcaPEMWriter(csrAsPEM);
            pemWriter.writeObject(pemObject);
        } catch( Exception e ) {
            logger.error("Unable to convert CSR to PEM format", e);
            throw new ADCSCertificateException( "Unable to convert CSR to PEM format. Reason: " + e.getMessage() );
        } finally {
            try {
                if( pemWriter != null ) {
                    pemWriter.close();
                }
            } catch (IOException e) {
                logger.error("Unable to close pemWriter", e);
            }
            try {
                csrAsPEM.close();
            } catch (IOException e) {
                logger.error("Unable to close csrWriter", e);
            }
        }
        
        return csrAsPEM.toString();
        
        
    }
    
    /*
     * Given a certificate and a private key, return a pkcs12 byte array
     */
    public byte[] getPKCS12( X509Certificate signedCert, Key privateKey, String sPassword, String keyAlias ) {

        // convert the signed cert and private key to a pkcs12 byte array
        Certificate cert[] = {(Certificate) signedCert};
        KeyStore outStore;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            outStore.load(null, sPassword.toCharArray());
            outStore.setKeyEntry(keyAlias, (Key)privateKey, sPassword.toCharArray(), cert);

            outStore.store(outputStream, sPassword.toCharArray());

            // return the bytes...this is the pkcs12 file
            byte pkcs12[] = outputStream.toByteArray();
            return pkcs12;
        } catch (Exception e) {
            
            logger.error("Unable to convert Certificate and privatekey to pkcs12 format", e);
            throw new ADCSCertificateException( "Unable to convert Certificate and privatekey to pkcs12 format. Reason: " + e.getMessage() );

        } finally {
            // make sure that we are closing the stream no matter what
            try {
                if(outputStream != null) {
                    outputStream.flush();
                    outputStream.close();
                }
            } catch(IOException e) {
                logger.error("Error while trying to close stream during client/device certificate generation:", e);
            }
        }
    }

    /*
     * Given a pkcs12 byte array, return its public key
     */
    
    public PublicKey getPKCS12PublicKey(byte pkcs12[], String password, String alias ) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
        java.security.KeyStore keyStoreFile = java.security.KeyStore.getInstance("PKCS12");
        InputStream fis = new ByteArrayInputStream(pkcs12);
        PublicKey publicKey = null;
        try {
            keyStoreFile.load(fis, password.toCharArray());
            
            Enumeration<String> aliasEnum = keyStoreFile.aliases();
            String aliasesFound = "";
            while(aliasEnum.hasMoreElements()) {
                String defaultAlias = (String) aliasEnum.nextElement();
                if( aliasesFound.length() == 0 ) {
                    aliasesFound = defaultAlias;
                } else {
                    aliasesFound = "," + aliasesFound + defaultAlias;                   
                }
            }
            
            publicKey = (PublicKey) keyStoreFile.getCertificate(alias).getPublicKey();
            if( publicKey == null ) {
                logger.error("Alias " + alias + " not found for cert");
                throw new ADCSCertificateException( "Alias " + alias + " not found for cert" );
            }

        } finally {
            fis.close();
        }

        return publicKey;
    }   
    
    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

	
}
