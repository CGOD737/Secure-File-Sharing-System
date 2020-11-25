import java.util.*;

import javax.crypto.*;
import java.security.*;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AES {

    private static Cipher cipher;

    public static byte[] encrypt(SecretKey key, byte[] data) throws Exception {

        cipher = Cipher.getInstance("AES", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedtext = cipher.doFinal(data);

        return encryptedtext;
    }

    public static byte[] decrypt(SecretKey key, byte[] data) throws Exception {

        cipher = Cipher.getInstance("AES", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedtext = cipher.doFinal(data);

        return decryptedtext;
    }
    public static SecretKey generateAESKey(int bits, String Mode) throws Exception{

        KeyGenerator generator = KeyGenerator.getInstance(Mode, "BC");

        generator.init(bits);

        return generator.generateKey();
    }
    //converts an incoming object to a byte Array
    public static byte[] convertByte(Object input) throws Exception {

      ByteArrayOutputStream bout = new ByteArrayOutputStream();

      ObjectOutputStream out = null;

      out = new ObjectOutputStream(bout);
      out.writeObject(input);
      out.flush();

      byte[] arr = bout.toByteArray();

      bout.close();

      return arr;


    }
    //converts a byte Array to it's root object.
    public static Object convertObject(byte[] input) throws Exception{

      ByteArrayInputStream bin = new ByteArrayInputStream(input);

      ObjectInputStream in = new ObjectInputStream(bin);
      Object o = in.readObject();

      if (in != null)
        in.close();

      return o;
    }

    //a static function to add BouncyCastle as the security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
