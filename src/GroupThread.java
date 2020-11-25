/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.nio.ByteBuffer;

import java.security.*;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;
    private KeyPair authkeys;
    private SecretKey sharedkey;

    protected static RSAPrivateKey gsPriv;

    public GroupThread(Socket _socket, GroupServer _gs) {
        Security.addProvider(new BouncyCastleProvider());
        socket = _socket;
        my_gs = _gs;
        gsPriv = my_gs.gsPriv;
    }

    public void run() {
        boolean proceed = true;

        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            int counter = 0;

            do {

                Envelope message = (Envelope)input.readObject();

                System.out.println("Request received: " + message.getMessage());
                Envelope response;

                if(message.getMessage().equals("SECURE")) {
                    if(message.getObjContents().size() < 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    }else {
                        if(message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADKEY");
                        }
                        else {
                            response = new Envelope("OK");

                            // retrieve the clint's public key
                            PublicKey clientpublickey = (PublicKey)message.getObjContents().get(0);

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
                } else if(message.getMessage().equals("GET")) { //Client wants a token
                  System.out.println("processing");
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    String username = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); //Get the username
                    String password = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(1)), "UTF-8"); //Get the password.
                    String fs_fingerprint = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2)), "UTF-8"); // Get the fileserver fingerprint
                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(3))).getInt();
                    if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                    {
                        response = new Envelope("REPLAY");
                        response.addObject(null);
                        output.writeObject(response);
                    }
                    else
                    {
                        counter = loc_counter;
                    }
                    if(username == null || password == null) { //if username is enmpty
                        response = new Envelope("FAIL");
                        response.addObject(null);
                        counter++;
                        response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(response);
                    }
                    else if ( !Hasher.compare(password, my_gs.userList.getPWSALT(username), my_gs.userList.getPW(username) ) ){ //password check does a comparison
                      response = new Envelope("FAIL");
                      response.addObject(null);
                      counter++;
                      response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                      output.writeObject(response);
                    }
                    else {
                        UserToken yourToken = createToken(username, fs_fingerprint); //Create a token

                        //Serializes the Token into a String which will be signed and then hashed
                        String tokSer = yourToken.getIssuer() + yourToken.getSubject();
                        List<String> gMember = yourToken.getGroups();

                        //iterates through the group list and creates a string
                        for ( String member : gMember )
                          tokSer = tokSer + member;

                        //Hashes the token string that was created
                        byte[] tokHash = Hasher.hashStringNS(tokSer);

                        //creates an RSA signature in which case,
                        Signature sig = createSignature(gsPriv, tokHash);
                        byte[] sigArr = sig.sign();

                        //adds the signedHash to the token data Structure
                        yourToken.setSignedHash(sigArr);

                        //sends the token to the client.
                        response = new Envelope("OK");
                        response.addObject(yourToken);
                        // Commented out portion for encryption / decryption
                        // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                        counter++;
                        response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(response);
                    }
                } else if(message.getMessage().equals("CUSER")) { //Client wants to create a user
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 2) {
                        //System.out.println("bad contents");
                        response = new Envelope("FAIL-BADCONTENTS");
                        output.writeObject(response);
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String username = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); //Extract the username
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                String password = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2)), "UTF-8"); //Extract the password
                                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(3))).getInt();
                                if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                {
                                    response = new Envelope("REPLAY");
                                    response.addObject(null);
                                    output.writeObject(response);
                                }
                                else
                                {
                                    counter = loc_counter;
                                }

                                byte[] salt = Hasher.createSalt();
                                String HashedPW = Hasher.hashString(password, salt);

                                String requester = yourToken.getSubject();
                                //Check if requester exists
                                if(my_gs.userList.checkUser(requester)) {
                                    //Get the user's groups
                                    ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
                                    //requester needs to be an administrator
                                    if(temp.contains("ADMIN")) {
                                        //Does user already exist?
                                        if(my_gs.userList.checkUser(username)) {
                                            //System.out.println("user already exists");
                                            response = new Envelope("USERE");
                                        } else {
                                            my_gs.userList.addUser(username, HashedPW, salt);
                                            //System.out.println("ok");
                                            response = new Envelope("OK");
                                        }
                                    } else {
                                        //System.out.println("incorrect priveledge");
                                        response = new Envelope("WRONGPRIV");
                                    }
                                } else {
                                    //System.out.println("requester does not exist");
                                    response = new Envelope("REQUESTERDNE");
                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    //System.out.println("counter = " + counter);
                    //System.out.println("byte[] counter = " + ByteBuffer.allocate(4).putInt(counter).array());
                    //System.out.println("Encrypted object: " + AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("DUSER")) { //Client wants to delete a user
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String username = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); //Extract the username
                                UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
                                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                                if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                {
                                    response = new Envelope("REPLAY");
                                    response.addObject(null);
                                    output.writeObject(response);
                                }
                                else
                                {
                                    counter = loc_counter;
                                }

                                String requester = yourToken.getSubject();

                                //Does requester exist?
                                if(my_gs.userList.checkUser(requester)) {
                                    ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
                                    //requester needs to be an administer
                                    if(temp.contains("ADMIN")) {
                                        //Does user exist?
                                        if(my_gs.userList.checkUser(username)) {
                                            //User needs deleted from the groups they belong
                                            ArrayList<String> deleteFromGroups = new ArrayList<String>();

                                            //This will produce a hard copy of the list of groups this user belongs
                                            for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                                                deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                                            }

                                            //Delete the user from the groups
                                            //If user is the owner, removeMember will automatically delete group!
                                            for(int index = 0; index < deleteFromGroups.size(); index++) {
                                            //  my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                                            }

                                            //If groups are owned, they must be deleted
                                            ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                                            //Make a hard copy of the user's ownership list
                                            for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                                                deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                                            }

                                            //Delete owned groups
                                            // for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                                            //     //Use the delete group method. Token must be created for this action
                                            //     deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
                                            // }

                                            //Delete the user from the user list
                                            my_gs.userList.deleteUser(username);

                                            response = new Envelope("OK");
                                        } else {
                                            //System.out.println("User does not exist");
                                            response = new Envelope("USERDNE");

                                        }
                                    } else {
                                        //System.out.println("requester is not an administer");
                                        response = new Envelope("WRONGPRIV");
                                    }
                                } else {
                                    //System.out.println("requester does not exist");
                                    response = new Envelope("REQUESTERDNE");
                                }

                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    //System.out.println("counter = " + counter);
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("CGROUP")) { //Client wants to create a group
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String group = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); // extract the groupname
                                UserToken token = (UserToken)message.getObjContents().get(1);
                                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                                if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                {
                                    response = new Envelope("REPLAY");
                                    response.addObject(null);
                                    output.writeObject(response);
                                }
                                else
                                {
                                    counter = loc_counter;
                                }

                                if(my_gs.groupList == null)
                                {
                                    my_gs.groupList = new GroupList();
                                }
                                if(my_gs.groupList.containsGroup(group))
                                {
                                    response = new Envelope("GROUPE");
                                }
                                else
                                {
                                    // create the group
                                    my_gs.groupList.createGroup(group, token.getSubject());

                                    my_gs.groupList.addUserToGroup(token.getSubject(), group);

                                    my_gs.userList.addGroup(token.getSubject(), group);

                                    my_gs.userList.addOwnership(token.getSubject(), group);

                                    //generates a file encryption key for the specific group
                                    my_gs.groupList.getGroup(group).setKey(AES.generateAESKey(256, "AES"));

                                    response = new Envelope("OK");
                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    //System.out.println("counter = " + counter);
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("DGROUP")) { //Client wants to delete a group
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String group = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); // extract the groupname
                                UserToken token = (UserToken)message.getObjContents().get(1);
                                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                                if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                {
                                    response = new Envelope("REPLAY");
                                    response.addObject(null);
                                    counter++;
                                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                                    output.writeObject(response);
                                }
                                else
                                {
                                    counter = loc_counter;
                                }

                                // if the group does not exist
                                if(my_gs.groupList == null || !my_gs.groupList.containsGroup(group))
                                {
                                    response = new Envelope("GROUPDNE");
                                }
                                // if this token is not the group leader
                                else if(!my_gs.userList.getUserOwnership(token.getSubject()).contains(group))
                                {
                                    response = new Envelope("USERISNOTOWNER");
                                }
                                else {
                                    response = new Envelope("OK");

                                    my_gs.groupList.deleteGroup(group);

                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    //System.out.println("counter = " + counter);
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                String group = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8"); // extract the groupname
                                UserToken token = (UserToken)message.getObjContents().get(1);
                                int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                                if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                {
                                    response = new Envelope("REPLAY");
                                    response.addObject(null);
                                    output.writeObject(response);
                                }
                                else
                                {
                                    counter = loc_counter;
                                }

                                // if the group does not exist, return false
                                if(my_gs.groupList == null || !my_gs.groupList.containsGroup(group))
                                {
                                    response = new Envelope("GROUPDNE");
                                }
                                // if this token is not the group leader
                                else if(!my_gs.userList.getUserOwnership(token.getSubject()).contains(group))
                                {
                                    response = new Envelope("NOTLEADER");
                                }
                                else {
                                    response = new Envelope("OK");
                                    response.addObject(my_gs.groupList.listUsers(group));
                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                if(message.getObjContents().get(2) != null) {
                                    String user = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8");
                                    String group = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(1)), "UTF-8"); // extract the groupname
                                    UserToken token = (UserToken)message.getObjContents().get(2);
                                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(3))).getInt();
                                    if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                    {
                                        response = new Envelope("REPLAY");
                                        response.addObject(null);
                                        output.writeObject(response);
                                    }
                                    else
                                    {
                                        counter = loc_counter;
                                    }

                                    // if the user does not exist
                                    if(!my_gs.userList.checkUser(user))
                                    {
                                        response = new Envelope("USERDNE");
                                    }
                                    // if the group does not exist
                                    else if(my_gs.groupList == null || !my_gs.groupList.containsGroup(group))
                                    {
                                        response = new Envelope("GROUPDNE");
                                    }
                                    // if this token is not the group leader
                                    else if(!my_gs.userList.getUserOwnership(token.getSubject()).contains(group))
                                    {
                                        response = new Envelope("USERPRIV");
                                    }
                                    // if this user is already in the group
                                    else if(my_gs.groupList.getGroup(group).containsUser(user))
                                    {
                                        response = new Envelope("USERIN");
                                    }
                                    else
                                    {
                                        response = new Envelope("OK");
                                        my_gs.groupList.addUserToGroup(user, group);
                                        my_gs.userList.addGroup(user, group);
                                    }
                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    if(message.getObjContents().size() < 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        response = new Envelope("FAIL");

                        if(message.getObjContents().get(0) != null) {
                            if(message.getObjContents().get(1) != null) {
                                if(message.getObjContents().get(2) != null) {
                                    String user = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(0)), "UTF-8");
                                    String group = new String (AES.decrypt(sharedkey, (byte[])message.getObjContents().get(1)), "UTF-8"); // extract the groupname
                                    UserToken token = (UserToken)message.getObjContents().get(2);
                                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(3))).getInt();
                                    if(loc_counter != counter + 1 || !Hasher.compareHMAC(sharedkey, hmac, mByte))
                                    {
                                        response = new Envelope("REPLAY");
                                        response.addObject(null);
                                        output.writeObject(response);
                                    }
                                    else
                                    {
                                        counter = loc_counter;
                                    }

                                    // if the user is not in the group
                                    if(!my_gs.userList.getUserGroups(user).contains(group) || my_gs.userList.getUserGroups(user) == null)
                                    {
                                        response = new Envelope("USERNOTINGROUP");
                                    }
                                    // if the group does not exist, return false
                                    else if(my_gs.groupList == null || !my_gs.groupList.containsGroup(group))
                                    {
                                        response = new Envelope("GROUPDNE");
                                    }
                                    // if this token is not the group leader
                                    else if(!my_gs.userList.getUserOwnership(token.getSubject()).contains(group))
                                    {
                                        response = new Envelope("NOTLEADER");
                                    }
                                    else
                                    {
                                        my_gs.groupList.deleteUserFromGroup(user, group);
                                        my_gs.userList.removeGroup(user, group);

                                        //updates the userList
                                        my_gs.groupList.getGroup(group).setKey(AES.generateAESKey(256, "AES"));
                                        //update the version of the key

                                        response = new Envelope("OK");
                                    }
                                }
                            }
                        }
                    }
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                } else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
                  byte[] mByte = AES.convertByte(message);
                  byte[] hmac = (byte[])input.readObject();
                    System.out.println("*** " + socket.getInetAddress() + " disconnected***");
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                } else if(message.getMessage().equals("RSERVERPK")){ //pings the server so the owner is notified of a key request

                  if ( (UserToken)message.getObjContents().get(0) == null){
                    response = new Envelope ("FAIL");
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                  }
                  else{
                    UserToken tok = (UserToken)message.getObjContents().get(0);
                    String user = tok.getSubject();
                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                    if(loc_counter != counter + 1)
                    {
                        response = new Envelope("REPLAY");
                        response.addObject(null);
                        counter++;
                        response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(response);
                    }
                    else
                    {
                        counter = loc_counter;
                    }

                    System.out.println("User " + user + " has requested the server's public key");
                    response = new Envelope ("OK");
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                  }
                } else if(message.getMessage().equals("RQSTGPK")){ //request the group's encryption key

                  if ( (UserToken)message.getObjContents().get(0) == null || (String)message.getObjContents().get(1) == null){
                    response = new Envelope ("FAIL");
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                  }
                  else{
                    UserToken tok = (UserToken)message.getObjContents().get(0);
                    String groupname = (String)message.getObjContents().get(1);

                    //checks if the user has is part of the group which they are requesting the key for
                    if (!my_gs.userList.getUserGroups(tok.getSubject()).contains(groupname)){
                      response = new Envelope ("FAIL");

                      System.out.println("The user either does not belong to group or group does not exist");
                      // Commented out portion for encryption / decryption
                      // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                      counter++;
                      response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                      output.writeObject(response);
                    }


                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])message.getObjContents().get(2))).getInt();
                    if(loc_counter != counter + 1)
                    {
                        response = new Envelope("REPLAY");
                        response.addObject(null);
                        counter++;
                        response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                        output.writeObject(response);
                    }
                    else
                    {
                        counter = loc_counter;
                    }


                    response = new Envelope ("OK");

                    //grabs the key arrayList over from the storage
                    ArrayList<SecretKey> GS_KEYS = my_gs.groupList.getGroup(groupname).getKeys();


                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;

                    //sends the check, Buffer, and the current key version.
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    response.addObject(AES.encrypt(sharedkey, (AES.convertByte(GS_KEYS))));
                    response.addObject(AES.encrypt(sharedkey, AES.convertByte(my_gs.groupList.getGroup(groupname).getVersion())));

                    output.writeObject(response);
                  }
                } else {
                    response = new Envelope("FAIL"); //Server does not understand client request
                    // Commented out portion for encryption / decryption
                    // output.writeObject(AES.encrypt(sharedkey, response.toString().getBytes("UTF-8")));
                    counter++;
                    response.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
                    output.writeObject(response);
                }
            } while(proceed);
        }catch(java.net.SocketException s){
            System.out.println("*** " + socket.getInetAddress() + " disconnected***");
        }catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    //Method to create tokens
    private UserToken createToken(String username, String fs_fingerprint) {
        //Check that user exists
        if(my_gs.userList.checkUser(username)) {
            //Issue a new token with server's name, user's name, and user's groups
            UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), fs_fingerprint);
            return yourToken;
        } else {
            return null;
        }
    }
    //method that creates Signature based on the passed in key pair and returns that signature
    private static Signature createSignature(PrivateKey gspriv, byte[] input) throws Exception{
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(gspriv);
      signature.update(input);
      return signature;
    }
}
