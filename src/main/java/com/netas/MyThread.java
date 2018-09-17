package com.netas;
import com.genband.wae.security.crypto.AppCipher;

public class MyThread extends Thread{

    AppCipher appcipher;

    public MyThread(AppCipher appcipher){
        this.appcipher = appcipher;
    }

    @Override
    public void run() {
        try {
            String encrypted = appcipher.encrypt("u1234");
            System.out.println("Thread ID: " + Thread.currentThread().getId() + " | Encrypted: " + encrypted);
            String decrypted = appcipher.decrypt(encrypted);
            System.out.println("Thread ID: " + Thread.currentThread().getId() + " | Decrypted: " + decrypted);

        }
        catch (Exception e)
        {
            // Throwing an exception
            System.out.println ("Exception is caught");
        }
    }
}
