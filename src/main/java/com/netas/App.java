package com.netas;

import com.genband.wae.security.crypto.AppCipher;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Hello world!
 *
 */
public class App 
{

    private static final int threadNum = 10000;

    public static void main( String[] args )
    {

        AppCipher appCipherObj = AppCipher.getInstance();
        List<MyThread> threads = new ArrayList<MyThread>();

        long start = System.nanoTime();

        for(int i = 0; i < threadNum; i++){
            MyThread t = new MyThread(appCipherObj);
            t.start();
            threads.add(t);
        }

        for(int i = 0; i < threads.size(); i++){
            try{
                threads.get(i).join();
            }catch (Exception e){
                e.printStackTrace();
            }


        }

        long end = System.nanoTime();
        System.out.println("TIME ---------> " + (end-start));

    }
}
