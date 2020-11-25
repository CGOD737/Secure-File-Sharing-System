/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileNotFoundException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Random;

import java.security.*;
import java.security.Security;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.security.*;

public class FileThread extends Thread {
    private final Socket socket;
    private KeyPair authkeys;
    private SecretKey sharedkey;
    private int counter = 0;

    public FileThread(Socket _socket) {
        socket = _socket;
        Security.addProvider(new BouncyCastleProvider());
    }
    //verifys the userToken using the corresponding Group Server's Public Key.
    public boolean verifyTok(UserToken tok) throws Exception{
      byte[] sigbytes = tok.getSignedHash();
      //opens publickey file
        ObjectInputStream userStream;
        FileInputStream fis = new FileInputStream("pubKey.bin");
        userStream = new ObjectInputStream(fis);
        RSAPublicKey gsPub = (RSAPublicKey)userStream.readObject();
        //recreates the token string from the token that was passed in,
        String tokSer = tok.getIssuer() + tok.getSubject();
        List<String> gMember = tok.getGroups();
        //iterates through the group list and creates a string
        for ( String member : gMember )
          tokSer = tokSer + member;
        //Hashes the token string that was created
        byte[] tokHash = Hasher.hashStringNS(tokSer);
        //verifies the signature.
        Signature ver = verifySignature(gsPub, tokHash);

        //will return true or false depending if it's verified.
        return ver.verify(sigbytes);

    }
    //method to verify the RSA signature.
    public static Signature verifySignature(PublicKey Key, byte[] input) throws Exception{
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(Key);
      signature.update(input);
      return signature;
    }

    public void run() {
        boolean proceed = true;
        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;

            do {
                Envelope e = (Envelope) input.readObject();
                System.out.println("Request received: " + e.getMessage());

                if(e.getMessage().equals("SECURE")) {
                    if(e.getObjContents().size() < 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    }else {
                        if(e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADKEY");
                        }
                        else {
                            response = new Envelope("OK");

                            // retrieve the clint's public key
                            PublicKey clientpublickey = (PublicKey)e.getObjContents().get(0);

                            // generate a keypair for this server
                            authkeys = DiffieHellman.generateKeys();

                            // calculate the shared key between this server and the client
                            byte[] temp = DiffieHellman.generateSharedKey(authkeys.getPrivate(), clientpublickey);

                            // convert the byte[] to a secretkey
                            sharedkey = new SecretKeySpec(temp, 0, temp.length, "AES");

                            // send back this server's public key for the client to generate the shared key
                            response.addObject(authkeys.getPublic());
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    output.writeObject(response);
                }
                if(e.getMessage().equals("AUTH")) {

                    response = new Envelope("UNINITIALIZED");
                    // return an ArrayList containing this Fileserver's public key
                    // and a message encrypted with its private key.

                    PublicKey fs_publickey = FileServer.keys.getPublic();

                    byte[] auth_arr = new byte[8];
                    new Random().nextBytes(auth_arr);
                    String auth_str = new String(auth_arr, Charset.forName("UTF-8"));

                    System.out.println("Client requesting to connect with code " + auth_str);

                    byte[] message = RSA.encrypt(auth_str,(FileServer.keys.getPrivate()));

                    response.addObject(fs_publickey);
                    response.addObject(message);

                    output.writeObject(response);
                }
                // Handler to list files that this user is allowed to see
                if(e.getMessage().equals("LFILES")) {

                    if(e.getObjContents().size() < 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    }else {
                        if(e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                        }
                        //checks if Token is empty or it's modified
                        if(e.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                        } else {
                            String group = (String) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(0))));
                            UserToken yourToken = (UserToken) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(1))));
                            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])e.getObjContents().get(2))).getInt();
                            if(loc_counter != counter + 1)
                            {
                                response = new Envelope("REPLAY");
                                response.addObject(null);
                                output.writeObject(response);
                            }
                            else
                            {
                                counter = loc_counter;
                            }

                            if (!verifyTok(yourToken)){
                              System.out.println("Error: user token does not match signed hash");
                              response = new Envelope("USER-FAILEDVERIFICATION");
                            }

                            // check if the user token contains authority to access this group
                          else if (!yourToken.getGroups().contains(group)) {
                                System.out.printf("Error: user missing valid token for group %s\n", group);
                                response = new Envelope("FAIL-UNAUTHORIZED");
                            } else {
                                response = new Envelope("OK");

                                ArrayList<ShareFile> ret = FileServer.fileList.getFiles();

                                response.addObject(ret);
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                }
                if(e.getMessage().equals("UPLOADF")) {

                    if(e.getObjContents().size() < 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        if(e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADPATH");
                        }
                        if(e.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                        }
                        if(e.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                        } else {


                            String remotePath = (String) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(0))));
                            String group = (String) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(1))));
                            UserToken yourToken = (UserToken) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(2))));
                            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])e.getObjContents().get(3))).getInt();

                            if(loc_counter != counter + 1)
                            {
                                response = new Envelope("REPLAY");
                                response.addObject(null);
                                output.writeObject(response);
                            }
                            else
                            {
                                counter = loc_counter;
                            }

                            //verifys userToken
                            if (!verifyTok(yourToken)){
                              System.out.println("Error: user token does not match signed hash");
                              response = new Envelope("USER-FAILEDVERIFICATION");
                            }

                              else if (FileServer.fileList.checkFile(remotePath)) {
                                System.out.printf("Error: file already exists at %s\n", remotePath);
                                response = new Envelope("FAIL-FILEEXISTS"); //Success
                            } else if (!yourToken.getGroups().contains(group)) {
                                System.out.printf("Error: user missing valid token for group %s\n", group);
                                response = new Envelope("FAIL-UNAUTHORIZED"); //Success
                            } else  {
                                File file = new File("shared_files/"+remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

                                response = new Envelope("READY"); //Success
                                counter++;
                                response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                output.writeObject(response);

                                e = (Envelope)input.readObject();
                                while (e.getMessage().compareTo("CHUNK")==0) {
                                    fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
                                    response = new Envelope("READY"); //Success
                                    counter++;
                                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                    output.writeObject(response);
                                    e = (Envelope)input.readObject();
                                }

                                if(e.getMessage().compareTo("EOF")==0) {
                                    System.out.printf("Transfer successful file %s\n", remotePath);
                                    FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
                                    response = new Envelope("OK"); //Success
                                } else {
                                    System.out.printf("Error reading file %s from client\n", remotePath);
                                    response = new Envelope("ERROR-TRANSFER"); //Success
                                }
                                fos.close();
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if (e.getMessage().compareTo("DOWNLOADF")==0) {

                    String remotePath = (String) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(0))));
                    Token t = (Token) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(1))));
                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])e.getObjContents().get(2))).getInt();
                    if(loc_counter != counter + 1)
                    {
                        response = new Envelope("REPLAY");
                        response.addObject(null);
                        output.writeObject(response);
                    }
                    else
                    {
                        counter = loc_counter;
                    }


                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

                    if (!verifyTok(t)){
                      System.out.println("Error: user token does not match signed hash");
                      e = new Envelope("USER-FAILEDVERIFICATION");
                      // Commented out portion for encryption / decryption
                        // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));\
                        counter++;
                        e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                      output.writeObject(e);
                    }

                    else if (sf == null) {
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        e = new Envelope("ERROR_FILEMISSING");
                        // Commented out portion for encryption / decryption
                        // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                        counter++;
                        e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(e);

                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        e = new Envelope("ERROR_PERMISSION");
                        // Commented out portion for encryption / decryption
                        // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                        counter++;
                        e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(e);
                    } else {

                        try {
                            File f = new File("shared_files/_"+remotePath.replace('/', '_'));
                            if (!f.exists()) {
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                e = new Envelope("ERROR_NOTONDISK");
                                // Commented out portion for encryption / decryption
                                // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                                counter++;
                        e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                output.writeObject(e);

                            } else {
                                FileInputStream fis = new FileInputStream(f);

                                do {
                                    byte[] buf = new byte[4096];
                                    if (e.getMessage().compareTo("DOWNLOADF")!=0) {
                                        System.out.printf("Server error: %s\n", e.getMessage());
                                        break;
                                    }
                                    e = new Envelope("CHUNK");
                                    int n = fis.read(buf); //can throw an IOException
                                    if (n > 0) {
                                        System.out.printf(".");
                                    } else if (n < 0) {
                                        System.out.println("Read error");

                                    }


                                    e.addObject(buf);
                                    e.addObject(Integer.valueOf(n));

                                    // Commented out portion for encryption / decryption
                                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                                    counter++;
                                    e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                    output.writeObject(e);

                                    e = (Envelope)input.readObject();


                                } while (fis.available()>0);

                                //If server indicates success, return the member list
                                if(e.getMessage().compareTo("DOWNLOADF")==0) {

                                    e = new Envelope("EOF");
                                    // Commented out portion for encryption / decryption
                                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                                    counter++;
                                    e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                    output.writeObject(e);

                                    e = (Envelope)input.readObject();
                                    if(e.getMessage().compareTo("OK")==0) {
                                        System.out.printf("File data upload successful\n");
                                    } else {

                                        System.out.printf("Upload failed: %s\n", e.getMessage());

                                    }

                                } else {

                                    System.out.printf("Upload failed: %s\n", e.getMessage());

                                }
                            }
                        } catch(Exception e1) {
                            System.err.println("Error: " + e.getMessage());
                            e1.printStackTrace(System.err);

                        }
                    }
                } else if (e.getMessage().compareTo("DELETEF")==0) {

                    String remotePath = (String) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(0))));
                    Token t = (Token) AES.convertObject((AES.decrypt(sharedkey, (byte[])e.getObjContents().get(1))));
                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])e.getObjContents().get(2))).getInt();
                    if(loc_counter != counter + 1)
                    {
                        response = new Envelope("REPLAY");
                        response.addObject(null);
                        output.writeObject(response);
                    }
                    else
                    {
                        counter = loc_counter;
                    }

                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                    //verifies token
                    if (!verifyTok(t)){
                      System.out.println("Error: user token does not match signed hash");
                      e = new Envelope("USER-FAILEDVERIFICATION");
                      // Commented out portion for encryption / decryption
                      // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                      counter++;
                      e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                      output.writeObject(e);
                    }
                    else if (sf == null) {
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        e = new Envelope("ERROR_DOESNTEXIST");
                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        e = new Envelope("ERROR_PERMISSION");
                    } else {

                        try {


                            File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

                            if (!f.exists()) {
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                e = new Envelope("ERROR_FILEMISSING");
                            } else if (f.delete()) {
                                System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
                                FileServer.fileList.removeFile("/"+remotePath);
                                e = new Envelope("OK");
                            } else {
                                System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
                                e = new Envelope("ERROR_DELETE");
                            }


                        } catch(Exception e1) {
                            System.err.println("Error: " + e1.getMessage());
                            e1.printStackTrace(System.err);
                            e = new Envelope(e1.getMessage());
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    e.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(e);

                } else if(e.getMessage().equals("DISCONNECT")) {
                    socket.close();
                    proceed = false;
                }
            } while(proceed);
        }catch(java.net.SocketException s){
            System.out.println("*** " + socket.getInetAddress() + " disconnected***");
        }catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

}
