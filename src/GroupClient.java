/* Implements the GroupClient Interface */
//Testing
import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.nio.ByteBuffer;
import javax.crypto.SecretKey;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
public class GroupClient extends Client implements GroupClientInterface {


    private int counter = 0;

    public UserToken getToken(String username, String password, String fs_fingerprint) {
        try {
            UserToken token = null;
            Envelope message = null, response = null;

            // Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(AES.encrypt(sharedkey, username.getBytes("UTF-8"))); //Add user name string
            message.addObject(AES.encrypt(sharedkey, password.getBytes("UTF-8"))); //Add password string
            message.addObject(AES.encrypt(sharedkey, fs_fingerprint.getBytes("UTF-8"))); //Add fs_fingerprint
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));

            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);

            boolean attack = true;
            while (attack == true){
                output.writeObject(message);
                output.writeObject(hmac);
            }
            // Get the response from the server
            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 2) {
                    int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])temp.get(1))).getInt();
                    if(loc_counter != counter + 1)
                    {
                        System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure no data is stolen.");
                    }
                    else
                    {
                        counter = loc_counter;
                    }
                    token = (UserToken)temp.get(0);
                    return token;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, String password, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(AES.encrypt(sharedkey, username.getBytes("UTF-8"))); //Add user name string
            message.addObject(token); //Add the requester's token
            message.addObject(AES.encrypt(sharedkey, password.getBytes("UTF-8")));
            counter++;
            //System.out.println(counter);
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);

            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            ArrayList<Object> temp = null;
            temp = response.getObjContents();

            //System.out.println(response.getMessage());
            //System.out.println("counter: " + counter);
            //System.out.println("obj contents: " + temp.get(0));
            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])temp.get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the group server.\n");
                return false;
            }
            else if(response.getMessage().equals("USERE")) {
                System.out.printf("User " + username + " already exists.\n");
                return false;
            }
            else if(response.getMessage().equals("WRONGPRIV")) {
                System.out.printf("You do not have permission to create a user.\n");
                return false;
            }
            else if(response.getMessage().equals("REQUESTERDNE")) {
                System.out.printf("Your token is faulty.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(AES.encrypt(sharedkey, username.getBytes("UTF-8"))); //Add user name string
            message.addObject(token);  //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);
            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }
            else if(response.getMessage().equals("USERDNE")) {
                System.out.printf("User " + username + " does not exist.\n");
                return false;
            }
            else if(response.getMessage().equals("WRONGPRIV")) {
                System.out.printf("You do not have permission to delete a user.\n");
                return false;
            }
            else if(response.getMessage().equals("REQUESTERDNE")) {
                System.out.printf("Your token is faulty.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(AES.encrypt(sharedkey, groupname.getBytes("UTF-8"))); //Add the group name string
            message.addObject(token); //Add the requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);
            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("GROUPE"))
            {
                System.out.printf("Group " + groupname + " already exists.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(AES.encrypt(sharedkey, groupname.getBytes("UTF-8"))); //Add the group name string
            message.addObject(token); //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));

            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);

            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }
            else if(response.getMessage().equals("GROUPDNE"))
            {
                System.out.printf("Group does not exist.\n");
                return false;
            }
            else if(response.getMessage().equals("USERISNOTOWNER"))
            {
                System.out.printf("You are not the owner of this group.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(AES.encrypt(sharedkey, group.getBytes("UTF-8"))); //Add the group name string
            message.addObject(token); //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);

            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }
            else if(response.getMessage().equals("GROUPDNE")) {
                System.out.printf("Group " + group + " Does Not exist.\n");
                return null;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return null;
            }
            else if(response.getMessage().equals("NOTLEADER")) {
                System.out.printf("You are not the leader of this group.\n");
                return null;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return null;
            }
            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(AES.encrypt(sharedkey, username.getBytes("UTF-8"))); //Add user name string
            message.addObject(AES.encrypt(sharedkey, groupname.getBytes("UTF-8"))); //Add the group name string
            message.addObject(token); //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);

            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("USERDNE"))
            {
                System.out.printf("User " + username + " does not exist.\n");
                return false;
            }
            else if(response.getMessage().equals("GROUPDNE"))
            {
                System.out.printf("Group " + groupname + " does not exist.\n");
                return false;
            }
            else if(response.getMessage().equals("USERPRIV"))
            {
                System.out.printf("You do not have priveledges to add a user.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }
            else if(response.getMessage().equals("USERIN"))
            {
                System.out.printf("User " + username + " is already in group " + groupname + ".\n");
                return false;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(AES.encrypt(sharedkey, username.getBytes("UTF-8"))); //Add user name string
            message.addObject(AES.encrypt(sharedkey, groupname.getBytes("UTF-8"))); //Add the group name string
            message.addObject(token); //Add requester's token
            counter++;
            message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
            // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
            byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
            output.writeObject(message);
            output.writeObject(hmac);
            // Get the response from the server
            // Commented out portion for encryption / decryption
            // byte[] enc_response = (byte[])input.readObject();
            // decrypt the response
            // response = (Envelope)AES.decrypt(sharedkey, enc_response);
            response = (Envelope)input.readObject();

            int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
            if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
            {
                System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
            }
            else
            {
                counter = loc_counter;
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            else if(response.getMessage().equals("USERNOTINGROUP"))
            {
                System.out.printf("User " + username + " is not in group " + groupname + ".\n");
                return false;
            }
            else if(response.getMessage().equals("GROUPDNE"))
            {
                System.out.printf("The group " + groupname + " does not exist.\n");
                return false;
            }
            else if(response.getMessage().equals("NOTLEADER"))
            {
                System.out.printf("You must be the leader of this group to delete a user.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL-BADCONTENTS")) {
                System.out.printf("Not enough arguments were given to the server.\n");
                return false;
            }
            else if(response.getMessage().equals("FAIL"))
            {
                System.out.printf("The group server recieved bad data.\n");
                return false;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }
    public boolean requestPK(UserToken token){
      try{
        Envelope message = null, response = null;

        message = new Envelope("RSERVERPK");
        message.addObject(token);
        counter++;
        message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
        // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
        byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
        output.writeObject(message);
        output.writeObject(hmac);

        // Get the response from the server
        // Commented out portion for encryption / decryption
        // byte[] enc_response = (byte[])input.readObject();
        // decrypt the response
        // response = (Envelope)AES.decrypt(sharedkey, enc_response);
        response = (Envelope)input.readObject();

        int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
        if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
        {
            System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
        }
        else
        {
            counter = loc_counter;
        }

        if(response.getMessage().equals("OK")) {
            return true;
        }
        else if(response.getMessage().equals("FAIL"))
        {
            System.out.printf("The request could not be failed at this time.\n");
            return false;
        }
        return false;

      } catch(Exception e) {
          System.err.println("Error: " + e.getMessage());
          e.printStackTrace(System.err);
          return false;
      }

    }
    //Gets the GroupServer's Encryption Key File
    public boolean requestGroupKey(UserToken token, String groupname){
      try{
        Envelope message = null, response = null;

        message = new Envelope("RQSTGPK");
        message.addObject(token);
        message.addObject(groupname);
        counter++;
        message.addObject(AES.encrypt(sharedkey, ByteBuffer.allocate(4).putInt(counter).array()));
        // Commented out portion for encryption / decryption
            // output.writeObject(AES.encrypt(sharedkey, message.toString().getBytes("UTF-8")));
        byte[] hmac = Hasher.hmac(sharedkey,AES.convertByte(message));
        output.writeObject(message);
        output.writeObject(hmac);
        // Get the response from the server
        // Commented out portion for encryption / decryption
        // byte[] enc_response = (byte[])input.readObject();
        // decrypt the response
        // response = (Envelope)AES.decrypt(sharedkey, enc_response);
        response = (Envelope)input.readObject();

        int loc_counter = ByteBuffer.wrap(AES.decrypt(sharedkey, (byte[])response.getObjContents().get(0))).getInt();
        if((loc_counter != counter + 1) || response.getMessage().equals("REPLAY"))
        {
            System.out.println("Your connection may be at risk of attack. Disconnect from the server to ensure your data is not stolen.");
        }
        else
        {
            counter = loc_counter;
        }

        //opens the the byte recieved response from the envelope, then writes it to a file which the user will save
        if(response.getMessage().equals("OK")) {
          ArrayList<SecretKey> G_KEYS = (ArrayList<SecretKey>) AES.convertObject(AES.decrypt(sharedkey,(byte[])response.getObjContents().get(1)));

          int version = (int) AES.convertObject(AES.decrypt(sharedkey,(byte[])response.getObjContents().get(2)));
        //writes the completed list of group keys to a .bin file in which case the client will keep for encryption/decryption. File will be written in form version_group_key.bin
          ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(groupname+"_"+"key.bin"));

        //puts the version in the header of the File.
          outStream.writeObject(version);
          outStream.writeObject(G_KEYS);

          return true;
        }
        else if(response.getMessage().equals("FAIL"))
        {
            System.out.printf("The request could not be processed at this time.\n");
            return false;
        }
        return false;

      } catch(Exception e) {
          System.err.println("Error: " + e.getMessage());
          e.printStackTrace(System.err);
          return false;
      }

    }
}
