package com.arqiva.chm.smki.poc;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;

/**
 * Created by Marin on 22.4.2015 г..
 */
public class CSRGenerator {

    public String generateCSR() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2056, new SecureRandom());
        KeyPair pair = kpGen.generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(""), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = null;
        signer = csBuilder.build(pair.getPrivate());

        ExtensionsGenerator extnGen = new ExtensionsGenerator();

        ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8"));

        ASN1EncodableVector hw = new ASN1EncodableVector();
        hw.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.1"));
        hw.add(new DERInteger(2106821234L));

        otherName.add(new DERSequence(hw));

        ASN1Object genName = new DERTaggedObject(false, 0, new DERSequence(otherName));
        ASN1EncodableVector genNames = new ASN1EncodableVector();
        genNames.add(genName);

        extnGen.addExtension(Extension.subjectAlternativeName, true, new DERSequence(genNames));

        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extnGen.generate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(str);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        System.out.println(str);

        return str.toString();
    }
}


