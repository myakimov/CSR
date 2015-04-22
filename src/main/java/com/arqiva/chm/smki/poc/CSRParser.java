package com.arqiva.chm.smki.poc;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.security.Security;

/**
 * Created by Marin on 22.4.2015 г..
 */
public class CSRParser {

    String getSerialNumber(String CSR) {
        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(CSR);

        Attribute[] certAttributes = csr.getAttributes();
        for (Attribute attribute : certAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));

                GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                GeneralName[] names = gns.getNames();
                for(int k=0; k < names.length; k++) {
                    String title = "";
                    if(names[k].getTagNo() == 0) {
                        title = "otherNames";
                    }

                    ASN1Sequence seq = (ASN1Sequence) names[k].getName();
                    ASN1Sequence otherName = (ASN1Sequence) seq.getObjectAt(1);
                    System.out.println(title + ": " + names[k].getName());

                    return otherName.getObjectAt(1).toString();
                }
            }
        }

        return "";
    }

    private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            //LOG.error("UnsupportedEncodingException, convertPemToPublicKey", ex);
        }

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            System.out.println("PemParser returned: " + parsedObj);

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

            }
        } catch (IOException ex) {
            //LOG.error("IOException, convertPemToPublicKey", ex);
        }

        return csr;
    }

}

