import java.util.*;

import javax.crypto.*;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSA {

    private static Cipher cipher;

    public static byte[] encrypt(String data, PrivateKey key) throws Exception {

        cipher = Cipher.getInstance("RSA", "BC");

        byte[] plaintext = data.getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedtext = cipher.doFinal(plaintext);

        return encryptedtext;
    }

    public static String decrypt(byte[] data, PublicKey key) throws Exception {

        cipher = Cipher.getInstance("RSA", "BC");

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedtext = cipher.doFinal(data);

        return new String(decryptedtext, "UTF-8");
    }

    public static KeyPair generateKeys() throws GeneralSecurityException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(2048);

        return generator.genKeyPair();
    }

    //a static function to add BouncyCastle as the security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}