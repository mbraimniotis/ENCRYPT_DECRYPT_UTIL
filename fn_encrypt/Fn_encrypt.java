/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fn_encrypt;

import java.util.Arrays;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author mbraimni
 */

public class Fn_encrypt {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
    	String encryption_mode = args[0];
		String symmetric_key = args[1];
		String str = args[2];
     	if (encryption_mode.toUpperCase().equals("CBC")) {
     		try {
     	    	System.out.println("Encryption Mode --> " + encryption_mode.toUpperCase());
     	    	System.out.println("Encryption Symmetric Key --> " + symmetric_key);
     	    	if (symmetric_key.length() < 16) {
     	    		System.out.println("Symmetric Key should be at least 16 characters for CBC Mode");
     	    		symmetric_key = "oraclefinancials";
     	    		System.out.println("Default Symmetric Key will be used --> " + symmetric_key);}
     	    	System.out.println("String for Encryption --> " + str);
     			System.out.println("Encrypted String : " + Fn_encrypt.encrypt(symmetric_key,str));
        	 	} 
     		catch (Exception e) { System.out.println("Bomb 1");
     							  System.err.println(e.toString());}
    	} else if (encryption_mode.toUpperCase().equals("ECB")){    	
    		try {
    	     	System.out.println("Decryption Mode --> " + encryption_mode.toUpperCase());
    	     	System.out.println("Decryption Symmetric Key --> " + symmetric_key);
    	     	System.out.println("String for Decryption --> " + str);
    			Fn_encrypt encryptStr = new Fn_encrypt();
    			String encryptedStr = encryptStr.fn_encrypt_password(str, symmetric_key);
    			System.out.println("Encrypted String : " + encryptedStr);
        	 	} 
    		catch (Exception e) { System.out.println("Bomb 2");
    							  System.err.println(e.toString());}};
        	 
    }
    
    public String fn_encrypt_password(String pwd, String userid) {
         String str = "";
        try {
          str = new String(Base64.encodeBase64(aesEncrypt(pwd.getBytes(), userid.getBytes())));
       } catch (Exception localException) {
        }
         return str;
    }
    
    public static byte[] aesEncrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) throws Exception {
        return doAESCrypt(paramArrayOfByte1, paramArrayOfByte2, 1);
    }
      
    public static byte[] doAESCrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, int paramInt)
      throws Exception
    {
      MessageDigest localMessageDigest = MessageDigest.getInstance("SHA-512");
      byte[] arrayOfByte1 = localMessageDigest.digest(paramArrayOfByte2);
      byte[] arrayOfByte2 = Arrays.copyOf(arrayOfByte1, 16);
      Cipher localCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      SecretKeySpec localSecretKeySpec = new SecretKeySpec(arrayOfByte2, "AES");
      localCipher.init(paramInt, localSecretKeySpec);
      byte[] arrayOfByte3 = localCipher.doFinal(paramArrayOfByte1);
      localCipher = null;
      localSecretKeySpec = null;
      return arrayOfByte3;
    }
    
    public static String encrypt(String key, String plainText)
    	    throws Exception
    	  {
    	    return new String(Base64.encodeBase64(doCrypt(plainText.getBytes(), 1, key)));
    	  }
    	  
    	  public static byte[] doCrypt(byte[] inputText, int operation, String key)
    	    throws Exception
    	  {
    	    MessageDigest mDigest = MessageDigest.getInstance("SHA-512");
    	    byte[] secretKey = key.getBytes();
    	    byte[] digestSeed = mDigest.digest(secretKey);
    	    byte[] hashKey = Arrays.copyOf(digestSeed, 16);
    	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	    SecretKeySpec skspec = new SecretKeySpec(hashKey, "AES");
    	    String ivTemp = new String(secretKey);
    	    IvParameterSpec ivParams = new IvParameterSpec(ivTemp.substring(0, 16).getBytes());
    	    cipher.init(operation, skspec, ivParams);
    	    byte[] ret_array = cipher.doFinal(inputText);
    	    cipher = null;
    	    skspec = null;
    	    return ret_array;
    	  }
    	  
    	  public static String decrypt(String key, String encryptedText)
    	   throws Exception
    	  {
    	    return new String(doCrypt(Base64.decodeBase64(encryptedText.getBytes()), 2, key));
    	  }
}
