/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fn_encrypt;

//10OCT2018 Added libraries for fn_decrypt_password2
import java.util.Arrays;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;
import fn_decrypt.Fn_decrypt;

/**
 *
 * @author mbraimni
 */

public class Fn_encrypt {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here            
        Fn_encrypt encryptUser = new Fn_encrypt();
        String SchemaPass = encryptUser.fn_encrypt_password(args[0], "mbencryptkey");
        System.out.println("Encrypted SchemaPass : " + SchemaPass);
        
        // Decrypt created hash to verify
        Fn_decrypt decryptUser = new Fn_decrypt();
	//String SchemaPassD = decryptUser.fn_decrypt_password("ug13APSverj/ll+6FUd2BQ==", "mbencryptkey");//lUserPass;
	String SchemaPassD = decryptUser.fn_decrypt_password(SchemaPass, Fn_decrypt.symmetric_key);//lUserPass;
        System.out.println("Decrypted SchemaPass : " + SchemaPassD);        
    }
    
    public String fn_encrypt_password(String pwd, String userid) {
         String str = "";
        try {
          //str = new String(aesEncrypt(Base64.encodeBase64(pwd.getBytes()), userid.getBytes()));
          str = new String(Base64.encodeBase64(aesEncrypt(pwd.getBytes(), userid.getBytes())));
       } catch (Exception localException) {
        }
         return str;
    }
    
    public static byte[] aesEncrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) throws Exception {
        return Fn_decrypt.doAESCrypt(paramArrayOfByte1, paramArrayOfByte2, 1);
    }
}
