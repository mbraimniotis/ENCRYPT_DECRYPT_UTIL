/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fn_decrypt;
//10OCT2018 Added libraries for fn_decrypt_password2
import java.util.Arrays;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;
/**
 *
 * @author mbraimni
 */
public class Fn_decrypt {
     public static void main(String[] args) {
        // TODO code application logic here
        String pwd = "O40fjmATqNKRRdNFP9UR3bGH4dwl4sHevUxuKh/7BDjEx+OKnkO1W2kMSO+N48PzH/PPsRadF5Dj6Int4MejlA=="; //args[0];
        Fn_decrypt decryptUser = new Fn_decrypt();
	//String SchemaPass = decryptUser.fn_decrypt_password("ug13APSverj/ll+6FUd2BQ==", symmetric_key);//lUserPass;
	String SchemaPass = decryptUser.fn_decrypt_password(pwd, symmetric_key);//lUserPass;
        System.out.println("Decrypted SchemaPass : " + SchemaPass);
        
        //Fn_encrypt encryptUser = new Fn_encrypt();
        //String encPass = encryptUser.fn_encrypt_password("Fccuat123#", "mbencryptkey");
        //System.out.println("EncryptedPass : " + encPass);
    } 
    public String fn_decrypt_password(String pwd, String userid) {
         String str = "";
        try {
          str = new String(aesDecrypt(Base64.decodeBase64(pwd.getBytes()), userid.getBytes()));
       } catch (Exception localException) {
        }
         return str;
    }
            
    public static byte[] aesDecrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) throws Exception {
        return doAESCrypt(paramArrayOfByte1, paramArrayOfByte2, 2);
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
      
    public static String symmetric_key = "mbencryptkey";

}
