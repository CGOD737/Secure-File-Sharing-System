import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;
    protected FileOutputStream ser_file_out;
    protected ObjectOutputStream ser_obj_out;
    protected FileInputStream ser_file_in;
    protected ObjectInputStream ser_obj_in;
    protected KeyPair authkeys;
    protected SecretKey sharedkey;

    public boolean secure() {
        Envelope env = new Envelope("SECURE");

        try {
            // create the pair of keys for this client-server connection
            authkeys = DiffieHellman.generateKeys();

            // send the public key to the server
            env.addObject(authkeys.getPublic());
            output.writeObject(env);


            // the server sends back its public key, unencrypted
            env = (Envelope)input.readObject();

            System.out.println("Check4");
            if (env.getMessage().compareTo("OK")==0) {
                PublicKey serverpublickey = (PublicKey)env.getObjContents().get(0);

                // generate the shared key on the client side (as a byte[])
                byte[] temp = DiffieHellman.generateSharedKey(authkeys.getPrivate(), serverpublickey);
                // convert the byte[] to a secretkey
                sharedkey = new SecretKeySpec(temp, 0, temp.length, "AES");


                return true;
            }
            else if(env.getMessage().compareTo("FAIL-BADCONTENTS")==0) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }
            else if(env.getMessage().compareTo("FAIL-BADKEY")==0) {
                System.out.printf("There was a problem generating your security keys.\n");
                return false;
            }
            else {
                System.out.printf("There was a problem securing your connection./n");
                return false;
            }
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        return false;

    }

    public boolean connect(final String server, final int port) {
        System.out.println("attempting to connect");

        try {
          sock = new Socket(server, port); //Creates the socket

          output = new ObjectOutputStream(sock.getOutputStream()); //sets the output stream
          input = new ObjectInputStream(sock.getInputStream()); //sets the input stream

        } catch(Exception e){
          e.printStackTrace(); //prints the the stack trace for troubleshooting
        }
        return sock.isConnected(); //runs the isConnected methods and returns whatever boolean is there to confirm connection to the socket.
    }

    public boolean isConnected() {
        if (sock == null || !sock.isConnected()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }
}
