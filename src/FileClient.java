/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;

import javax.crypto.*;
import java.security.*;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client implements FileClientInterface {

    private int counter = 0;

    // authenticate this file server to the client
    public String[] authenticate() {
        Envelope env = new Envelope("AUTH");
        try {
            output.writeObject(env);

            // the envelope returned contains the server's public key
            // and an encrypted message.
            env = (Envelope)input.readObject();
            if(env.getObjContents().get(0) == null)
            {
                return null;
            }
            PublicKey fs_publickey = (PublicKey)env.getObjContents().get(0);
            byte[] encryptedmessage = (byte[])env.getObjContents().get(1);

            // return the public key's fingerprint
            String public_fingerprint = Long.toString(fs_publickey.serialVersionUID);

            //String enc_string = new String(encryptedmessage, "UTF-8");

            //System.out.print("Public key fingerprint is: " + public_fingerprint + "\n");
            //System.out.print("Encrypted Message is " + enc_string);

            // decrypt the message with the public key
            String decryptedmessage = RSA.decrypt(encryptedmessage, fs_publickey);

            String[] ret = new String[2];
            ret[0] = decryptedmessage;
            ret[1] = public_fingerprint;

            return ret;

        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        } catch (Exception e1) {
            // dont print this to the client, it involves the client attempting to connect
            // to a groupserver via connecting to a fileserver.
        }
        return null;
    }

    public boolean delete(String filename, UserToken token) {
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }
        Envelope env = new Envelope("DELETEF"); //Success
        env.addObject(remotePath);
        env.addObject(token);
        try {
            counter++;
            env.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // // set up streams for serialization
             ser_file_out = new FileOutputStream("ser.txt");
             ser_obj_out = new ObjectOutputStream(ser_file_out);

            // // encrypt the envelope to send to the server
             ser_obj_out.writeObject(env);
             ser_obj_out.close();
             ser_file_out.close();

             ser_file_in = new FileInputStream("ser.txt");
             ser_obj_in = new ObjectInputStream(ser_file_in);

            // // deserialize the envelope as a byte[]
             byte[] encrypted_envelope = (byte[])ser_obj_in.readObject();

            // // encrypt the envelope
             byte[] encrypted_data = AES.encrypt(sharedkey, encrypted_envelope);

            output.writeObject(encrypted_data);
            env = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])env.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || env.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            if (env.getMessage().compareTo("OK")==0) {
                System.out.printf("File %s deleted successfully\n", filename);
            }
            else if(env.getMessage().equals("USER-FAILEDVERIFICATION"))
            {
                System.out.printf("Token failed to verify.\n");
                return false;
            }
            else {
                System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
                return false;
            }
        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        } catch (Exception e1){
            //e1.printStackTrace();
        }

        return true;
    }

    public boolean download(String sourceFile, String destFile, String group, UserToken token) {
        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        File file = new File(destFile);
        try {


            if (!file.exists()) {
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);

                Envelope env = new Envelope("DOWNLOADF"); //Success
                env.addObject(sourceFile);
                env.addObject(token);
                counter++;
                env.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));

                // // set up streams for serialization
                ser_file_out = new FileOutputStream("ser.txt");
                ser_obj_out = new ObjectOutputStream(ser_file_out);

                // // encrypt the envelope to send to the server
                ser_obj_out.writeObject(env);
                ser_obj_out.close();
                ser_file_out.close();

                ser_file_in = new FileInputStream("ser.txt");
                ser_obj_in = new ObjectInputStream(ser_file_in);

                // // deserialize the envelope as a byte[]
                byte[] encrypted_envelope = (byte[])ser_obj_in.readObject();

                // // encrypt the envelope
                byte[] encrypted_data = AES.encrypt(sharedkey, encrypted_envelope);

                output.writeObject(encrypted_data);

                env = (Envelope)input.readObject();

                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])env.getObjContents().get(0))).getInt();
                if((loc_counter != counter + 1) || env.getMessage().equals("REPLAY"))
                {
                    System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
                }
                else
                {
                    counter = loc_counter;
                }

                String G_KEYFILE = group+"_"+"key.bin";
                FileInputStream G_KEY = new FileInputStream(G_KEYFILE);

                ObjectInputStream userStream = new ObjectInputStream(G_KEY);
                int curr_version = (int) userStream.readObject();
                ArrayList<SecretKey> keys = (ArrayList<SecretKey>) userStream.readObject();

                boolean header_found = false;

                while (env.getMessage().compareTo("CHUNK")==0) {

                    if ( header_found == false){
                      byte[] version = (byte[])env.getObjContents().get(0);
                      int ver = (int) AES.convertObject(version);
                      SecretKey enc = keys.get(ver);
                      header_found = true;
                    }
                    else{

                    }

                    fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));


                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF"); //Success
                    output.writeObject(env);
                    env = (Envelope)input.readObject();
                }
                fos.close();

                if(env.getMessage().compareTo("EOF")==0) {
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    env = new Envelope("OK"); //Success
                    output.writeObject(env);
                }
                else if(env.getMessage().equals("USER-FAILEDVERIFICATION"))
                {
                    System.out.printf("Token failed to verify.\n");
                    return false;
                }
                else {
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
                    file.delete();
                    return false;
                }
            }

            else {
                System.out.printf("Error couldn't create file %s\n", destFile);
                return false;
            }


        } catch (IOException e1) {

            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;
        } catch (ClassNotFoundException e1) {
            //e1.printStackTrace();
        } catch (Exception e1) {}
        return true;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        try {
            Envelope message = null, e = null;
            //Tell the server to return the member list
            message = new Envelope("LFILES");
            message.addObject(token); //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // // set up streams for serialization
            ser_file_out = new FileOutputStream("ser.txt");
            ser_obj_out = new ObjectOutputStream(ser_file_out);

            // // encrypt the envelope to send to the server
                ser_obj_out.writeObject(message);
                ser_obj_out.close();
                ser_file_out.close();

                ser_file_in = new FileInputStream("ser.txt");
                ser_obj_in = new ObjectInputStream(ser_file_in);

            // // deserialize the envelope as a byte[]
                byte[] encrypted_envelope = (byte[])ser_obj_in.readObject();

            // // encrypt the envelope
                byte[] encrypted_data = AES.encrypt(sharedkey, encrypted_envelope);

            output.writeObject(encrypted_data);

            e = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])e.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || e.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return the member list
            if(e.getMessage().equals("OK")) {
                return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }
            else if(e.getMessage().equals("FAIL-BADCONTENTS"))
            {
                System.out.printf("Not enough arguments were given to the file server.\n");
                return null;
            }
            else if(e.getMessage().equals("FAIL-BADGROUP") || e.getMessage().equals("FAIL-BADTOKEN"))
            {
                System.out.printf("The server was given bad data.\n");
                return null;
            }
            else if(e.getMessage().equals("FAIL-UNAUTHORIZED"))
            {
                System.out.printf("You do not have the authority to access this group.\n");
            }
            else if(e.getMessage().equals("USER-FAILEDVERIFICATION"))
            {
                System.out.printf("Token failed to verify.\n");
                return null;
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            //e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group,
                          UserToken token) {

        if (destFile.charAt(0)!='/') {
            destFile = "/" + destFile;
        }

        try {
            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(AES.encrypt(sharedkey,AES.convertByte(destFile)));
            message.addObject(AES.encrypt(sharedkey,AES.convertByte(group)));
            message.addObject(AES.encrypt(sharedkey,AES.convertByte(token)));
            counter++;
            message.addObject((byte[])AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));

            // // set up streams for serialization

            output.writeObject(message);

            FileInputStream fis = new FileInputStream(sourceFile);

            env = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])env.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || env.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return the member list
            if(env.getMessage().equals("READY")) {
                System.out.printf("Meta data upload successful\n");

            }
            else if(env.getMessage().equals("USER-FAILEDVERIFICATION"))
            {
                System.out.printf("Token failed to verify.\n");
                return false;
            }
            else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }

            System.out.println("Encrypting File");
            //open group server's key file
            String G_KEYFILE = group+"_"+"key.bin";
            FileInputStream G_KEY = new FileInputStream(G_KEYFILE);

            ObjectInputStream userStream = new ObjectInputStream(G_KEY);
            int version = (int) userStream.readObject();
            ArrayList<SecretKey> keys = (ArrayList<SecretKey>) userStream.readObject();
            SecretKey enc = keys.get(version);

            boolean header_in = false;

            do {
                byte[] buf = new byte[4096];
                if (env.getMessage().compareTo("READY")!=0) {
                    System.out.printf("Server error: %s\n", env.getMessage());
                    return false;
                }
                message = new Envelope("CHUNK");
                int n;
                //sends the header to be written
                if ( header_in == false ){
                  buf = (AES.convertByte(version));
                  header_in = true;
                  n = 0;
                }
                //If it's not the header, then just send the data normally.
                else {
                  n = fis.read(buf); //can throw an IOException
                  if (n > 0) {
                      System.out.printf(".");
                  } else if (n < 0) {
                      System.out.println("Read error");
                      return false;
                  }

                  byte[] enc_buf = AES.encrypt(enc, buf);
                }
                message.addObject(buf);
                message.addObject(Integer.valueOf(n));
                output.writeObject(message);


                env = (Envelope)input.readObject();


            } while (fis.available()>0);

            //If server indicates success, return the member list
            if(env.getMessage().compareTo("READY")==0) {

                message = new Envelope("EOF");
                output.writeObject(message);

                env = (Envelope)input.readObject();
                if(env.getMessage().compareTo("OK")==0) {
                    System.out.printf("\nFile data upload successful\n");
                } else {

                    System.out.printf("\nUpload failed: %s\n", env.getMessage());
                    return false;
                }

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }

        } catch(Exception e1) {
            System.err.println("Error: " + e1.getMessage());
            //e1.printStackTrace(System.err);
            return false;
        }
        return true;
    }

}
