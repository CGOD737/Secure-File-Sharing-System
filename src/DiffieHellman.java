import java.util.*;
import java.math.*;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;

import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DiffieHellman {

    // known secure group of values of g and q for Diffie-Hellman
    private static BigInteger g = new BigInteger("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA", 16);

    private static BigInteger p = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);

    public static KeyPair generateKeys() throws GeneralSecurityException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH", "BC");

        DHParameterSpec dhps = new DHParameterSpec(p, g);

        generator.initialize(dhps);

        return generator.genKeyPair();
    }

    public static byte[] generateSharedKey(PrivateKey privatekey, PublicKey publickey) throws GeneralSecurityException {

        KeyAgreement a = KeyAgreement.getInstance("DH", "BC");

        a.init(privatekey);

        a.doPhase(publickey, true);

        SecretKey key = a.generateSecret("AES[256]");

        return key.getEncoded();
    }
    //Generates a generalized that will be mainly used use for file encryption and can be stored.
    public static SecretKey generateAESKey(int bits, String Mode) throws Exception{

        KeyGenerator generator = KeyGenerator.getInstance(Mode, "BC");

        generator.init(bits);

        return generator.generateKey();
    }

    // a static function to add BouncyCastle as the security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
