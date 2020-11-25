
import java.util.*;

import javax.crypto.*;
import java.security.*;
import javax.crypto.Mac.*;
import javax.crypto.SecretKey;

import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class Hasher {

  private String text;

  public Hasher(String txt){
    this.text = txt;
  }
  //creates a random 32 byte salt to be attached to the hashed password.
  public static byte[] createSalt() throws Exception {

    Random rand = new SecureRandom();
    byte[] salt = new byte[32];

    rand.nextBytes(salt);

    return salt;
  }
  //Hashes the String
  public static String hashString(String txt, byte[] salt) throws Exception {

    //random salt attached to the string to be hashed.

    String salted = new String(salt, "UTF-8");
    String toHash = txt+salted;
    //converts the combined salt to an array of bytes.
    byte[] byteArr = toHash.getBytes("UTF-8");

    //creates a messageDigest that will use SHA-256 method using the BouncyCastleProvider
    MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");

    byte[] hashedStr = md.digest(byteArr);
    //iterative hash
    int iterations = 100000;
    for ( int i = 0; i < iterations; i++)
      hashedStr = md.digest(hashedStr);

    String finalHash = new String(hashedStr, "UTF-8");

    return finalHash;

  }
  //Hashes the String with No Salt
  public static byte[] hashStringNS(String txt) throws Exception {

    String toHash = txt;
    //converts the combined salt to an array of bytes.
    byte[] byteArr = toHash.getBytes("UTF-8");

    //creates a messageDigest that will use SHA-256 method using the BouncyCastleProvider
    MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");

    byte[] hashedStr = md.digest(byteArr);
    //iterative hash
    int iterations = 100000;
    for ( int i = 0; i < iterations; i++)
      hashedStr = md.digest(hashedStr);

    return hashedStr;

  }
  //genetates an hmac and returns a byte[] as a result
  public static byte[] hmac(SecretKey key, byte[] input) throws Exception {
    Mac HMAC = Mac.getInstance("HMacSHA256", "BC");
    HMAC.init(key);

    return HMAC.doFinal(input);
  }
  //comparison function to check if two hmac's are equal
  public static boolean compareHMAC(SecretKey key, byte[] hmac, byte[] input ) throws Exception {
    return Arrays.equals(hmac(key, input), hmac);
  }
  //Actually compares to see if a String is the same as the stored value.
  public static boolean compare(String txt, byte[] salt, String storedHash) throws Exception {
    return storedHash.equals(hashString(txt, salt));
  }
  //a static function to add BouncyCastle as the security provider
  static {
      Security.addProvider(new BouncyCastleProvider());
  }

}
