/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

import java.security.*;
import java.security.Security;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server{

    public UserList userList;
    public GroupList groupList;
    private KeyPair pair;

    protected static RSAPrivateKey gsPriv;
    protected static RSAPublicKey gsPub;

    public GroupServer(int _port) {
        super(_port, "alpha");
        Security.addProvider(new BouncyCastleProvider());
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
        String privKeyFile = "privKey.bin";
        String pubKeyFile = "pubKey.bin";

        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(userFile);
            FileInputStream PK = new FileInputStream(privKeyFile);
            FileInputStream PuK = new FileInputStream(pubKeyFile);

            userStream = new ObjectInputStream(fis);
            userList = (UserList)userStream.readObject();

            userStream = new ObjectInputStream(PK);
            gsPriv= (RSAPrivateKey)userStream.readObject();


            userStream = new ObjectInputStream(PuK);
            gsPub = (RSAPublicKey)userStream.readObject();


        } catch(FileNotFoundException e) {
            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            String username = console.next();
            System.out.print("Enter a password: ");
            String password = console.next();

            //basic password length requirement
            while ( password.length() < 7 ){
              System.out.print("Password Must be Greater than 7 characters please enter in a new password: ");
              password = console.next();
            }
            //official create server. Also generates a public and private RSA keypair.
            try {
              byte[] salt = Hasher.createSalt();
              String HashedPW = Hasher.hashString(password, salt);
              userList = new UserList();
              //System.out.println(HashedPW);

              //generates an RSA KeyPair
              pair = generateKeyPair(1024);

              RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
              RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();

              //creates an output stream for that KeyPair
              ObjectOutputStream outStreamPriv;
              ObjectOutputStream outStreamPub;

              gsPriv = privateKey;
              gsPub = publicKey;

              //Stores each public key and private key in their respective files
              outStreamPriv = new ObjectOutputStream(new FileOutputStream(privKeyFile));
              outStreamPub= new ObjectOutputStream(new FileOutputStream(pubKeyFile));

              outStreamPriv.writeObject(privateKey);
              outStreamPub.writeObject(publicKey);

              userList.addUser(username, HashedPW, salt);
              userList.addGroup(username, "ADMIN");
              userList.addOwnership(username, "ADMIN");
            }
            catch(Exception eb){
              eb.printStackTrace();
            }
            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.

        } catch(IOException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

    private static KeyPair generateKeyPair(int bits) throws Exception{
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
      generator.initialize(bits);
      return generator.genKeyPair();
    }
}

//This thread saves the user list
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group and user lists...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
