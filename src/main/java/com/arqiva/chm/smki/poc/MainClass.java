package com.arqiva.chm.smki.poc;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by Marin on 22.4.2015 г..
 */
public class MainClass {

    public static void main(String args[]) {
        System.out.println("Called ...");

        try {
            String csr = new CSRGenerator().generateCSR();
            System.out.println("CSR : " + csr);

            String id = new CSRParser().getSerialNumber(csr);

            System.out.println("Identifier : " + id);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
    }

}
