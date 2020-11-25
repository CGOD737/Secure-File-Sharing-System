import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.io.ObjectInputStream;
import java.io.ObjectInputStream;   // Used to read objects sent from the server
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.net.Socket;             // Used to connect to the server

// RunClient.java created by duos group

public abstract class RunClient extends Client implements GroupClientInterface, FileClientInterface
{
    public static void main (String[] args)
    {
        GroupClient gc = new GroupClient();
        FileClient fc = new FileClient();

        String input_string = "", username = null , password = null, fs_ip = null, fs_port = null, gs_ip = null, gs_port = null, fs_fingerprint = null;
        Scanner inscan = new Scanner(System.in);
        UserToken token = null;
        boolean gc_con = false, fc_con = false, success = false;
        long token_creation_time = 0;

        // loop until the user wants to leave
        while(!input_string.equals("EXIT") && !input_string.equals("exit"))
        {
            if(!gc_con && !fc_con)
            {
                input_string = "";
                // ask the user to choose which server to connect to
                while(!input_string.equals("1") && !input_string.equals("2"))
                {
                    // print the main menu
                    menu1(username);

                    // get the user input
                    input_string = inscan.nextLine();

                    // determine which server to connect to
                    switch(input_string)
                    {
                        case "1":
                            System.out.print("Enter the GroupServer's address: ");
                            gs_ip = inscan.nextLine();
                            System.out.print("Enter the GroupServer's port number: ");
                            gs_port = inscan.nextLine();
                            gc.connect(gs_ip, Integer.parseInt(gs_port));
                            System.out.println(gc.isConnected());
                            if(gc.isConnected())
                            {
                                // create a shared key to be able to encrypt messages to this server
                                boolean success2 = gc.secure();

                                if(success2)
                                {
                                    System.out.println("Successfully established a secure connection to the GroupServer with address " + gs_ip + " and port number " + gs_port + ".");
                                    gc_con = true;
                                }
                                else
                                {
                                    System.out.println("A secure connection was not established with the GroupServer. Disconnecting.");
                                    fc.disconnect();
                                    fc_con = false;
                                }
                            }
                            else
                            {
                                System.out.println("Could not connect to GroupServer with address " + gs_ip + " and port number " + gs_port + ".");
                                System.out.println("Returning to the main menu.");
                            }
                            break;
                        case "2":
                            if(username == null)
                            {
                                System.out.println("\nYou are not logged in.");
                                System.out.println("Please connect to the GroupServer and grab a token");
                                System.out.println("before connecting to a FileServer.");
                                break;
                            }
                            // client needs to decide to connect to a server or create a new one
                            System.out.println("\nWould you like to:");
                            System.out.println("(1) Connect to an existing FileServer");
                            System.out.println("(2) Connect to a new FileServer");
                            System.out.print("> ");
                            String input_string2 = inscan.nextLine();
                            switch(input_string2)
                            {
                                case "1":   // connect to a pre-existing FileServer
                                    System.out.print("Enter the pre-existing FileServer's address: ");
                                    fs_ip = inscan.nextLine();
                                    System.out.print("Enter the pre-existing FileServer's port number: ");
                                    fs_port = inscan.nextLine();

                                    fc.connect(fs_ip, Integer.parseInt(fs_port));

                                    // if the client cannot make a connection to the server
                                    if(!fc.isConnected())
                                    {
                                        System.out.println("Could not connect to FileServer with address " + fs_ip + " and port number " + fs_port + ".");
                                        System.out.println("Returning to the main menu.");
                                    }
                                    else
                                    {
                                        String input_string3 = "";
                                        while(!input_string3.equals("Y") && !input_string3.equals("y") && !input_string3.equals("N") && !input_string3.equals("n"))
                                        {
                                            // AUTHENTICATE THE FILESERVER
                                            String[] server_data = fc.authenticate();

                                            // make sure this server with this address and port number is a fileserver
                                            if(server_data == null)
                                            {
                                                System.out.println("Could not connect to FileServer with address " + fs_ip + " and port number " + fs_port + ".");
                                                System.out.println("Returning to the main menu.");
                                                fc.disconnect();
                                                fc_con = false;
                                                break;
                                            }

                                            String decryptedmessage = server_data[0];
                                            String fingerprint = server_data[1];

                                            // if the token this client has is not permitted to be used on this fileserver
                                            if(!token.getFSFingerprint().equals(fingerprint))
                                            {
                                                System.out.println("The token you hold does not have accesss to this fileserver.");
                                                System.out.println("Please request a token with the fileserver fingerprint \"" + fingerprint + "\".");
                                                fc.disconnect();
                                                fc_con = false;
                                            }
                                            else
                                            {
                                                System.out.print("This Server's message: " + decryptedmessage + "\n");
                                                System.out.print("This Server's fingerprint: " + fingerprint + "\n");
                                                System.out.println("Do you trust this Server? (Y/N)");
                                                System.out.print("> ");
                                                input_string3 = inscan.nextLine();

                                                // if the user trusts the server
                                                if(input_string3.equals("Y") || input_string3.equals("y"))
                                                {
                                                    System.out.println("Successfully connected to FileServer with address " + fs_ip + " and port number " + fs_port + ".");
                                                    fc_con = true;

                                                    // create a shared key to be able to encrypt messages to this server
                                                    boolean success2 = fc.secure();

                                                    if(success2)
                                                    {
                                                        System.out.println("Successfully established a secure connection to the FileServer.");
                                                    }
                                                    else
                                                    {
                                                        System.out.println("A secure connection was not established with the FileServer. Disconnecting.");
                                                        fc.disconnect();
                                                        fc_con = false;
                                                    }

                                                }
                                                // if the user does not trust the server
                                                else if(input_string3.equals("N") || input_string3.equals("n"))
                                                {
                                                    System.out.println("Server not trusted. Disconnecting...");
                                                    fc.disconnect();
                                                    fc_con = false;
                                                }
                                                else
                                                {
                                                    System.out.println("Please enter either 'Y' for yes or 'N' for no.\n");
                                                }
                                            }
                                        }
                                    }
                                    break;

                                case "2":   // connect to a new FileServer
                                    System.out.println("\nTo start a new file server, please open a new terminal and run 'java RunFileServer'.");
                                    System.out.println("To connect to your new file server, return to the main menu, and follow the steps");
                                    System.out.println("to connect to a pre-existing file server. When prompted to enter the FileServer's");
                                    System.out.println("address, enter 'localhost'.When prompted to enter the port number, enter the port");
                                    System.out.println("number given in the terminal which you are running your FileServer.");
                                    System.out.println("Then place the file with the .bin extension that contains");
                                    System.out.println("your Group Server's Public Key in the File Server's directory.");
                                    System.out.println("If you do not hold the Group Server's Public Key file, then contact the group server's");
                                    System.out.println("administrator for assistance.");
                                    break;
                                default:
                                    System.out.println("Please enter either a 1 or 2.");
                                    System.out.println("Returning to the main menu.\n");
                                    break;

                            }
                            break;
                        case "EXIT":
                        case "exit":
                            System.out.println("Exiting the program.");
                            System.exit(-1);
                            break;
                        default:
                            System.out.println("Please enter either 1 or 2.\n");
                            break;
                    }
                }
            }

            if(gc_con)
            {
                // print the group server menu
                menu2(username);

                // get the user input
                input_string = inscan.nextLine();

                // switch the group server methods
                switch(input_string)
                {
                    case "1":   // disconnect
                        System.out.println("Disconnecting from the group server...\n");
                        gc.disconnect();
                        gc_con = false;
                        break;
                    case "2":   // getToken, Now now has an authentication portion.
                        System.out.print("Enter your username: ");
                        username = inscan.nextLine();
                        System.out.print("Enter your password: ");
                        password = inscan.nextLine();
                        System.out.print("Enter the fingerprint of the fileserver you are going to join: ");
                        fs_fingerprint = inscan.nextLine();

                        token = gc.getToken(username, password, fs_fingerprint);
                        if(token == null)
                        {
                            System.out.println("Error grabbing your token.");
                            username = null;
                        }
                        else
                        {
                            token_creation_time = System.currentTimeMillis();
                            System.out.println("Successfully grabbed your token.");
                        }
                        break;
                    case "3":   // createUser
                        System.out.print("Enter the name of the user you wish to create: ");
                        String newuser = inscan.nextLine();
                        System.out.print("Enter the password for user you wish to create: ");
                        String pw = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.createUser(newuser, pw, token);
                            if(success)
                            {
                                System.out.println("Successfully created user " + newuser + "!\n");
                            }
                            else
                            {
                                System.out.println(newuser + " was not successfully created.\n");
                            }
                        }
                        break;
                    case "4":   // deleteUser
                        System.out.print("Enter the name of the user you wish to delete: ");
                        String deleteduser = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.deleteUser(deleteduser, token);
                            if(success)
                            {
                                System.out.println("Successfully deleted user " + deleteduser + "!\n");
                            }
                            else
                            {
                                System.out.println(deleteduser + " was not successfully deleted.\n");
                            }
                        }
                        break;
                    case "5":   // createGroup
                        System.out.print("Enter the name of the group you wish to create: ");
                        String group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.createGroup(group, token);
                            if(success)
                            {
                                System.out.println("Successfully created group " + group + "!\n");
                            }
                            else
                            {
                                System.out.println(group + " was not successfully created.\n");
                            }
                        }
                        break;
                    case "6":   // deleteGroup
                        System.out.print("Enter the name of the group you wish to delete: ");
                        group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.deleteGroup(group, token);
                            if(success)
                            {
                                System.out.println("Successfully deleted group " + group + "!\n");
                            }
                            else
                            {
                                System.out.println(group + " was not successfully deleted.\n");
                            }
                        }
                        break;
                    case "7":   // addUsertoGroup
                        System.out.print("Enter the name of the user you wish to add to a group: ");
                        String user = inscan.nextLine();
                        System.out.print("Enter the name of the group you wish to add " + user + " to: ");
                        group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.addUserToGroup(user, group, token);
                            if(success)
                            {
                                System.out.println("Successfully added user " + user + " to group " + group + "!\n");
                            }
                            else
                            {
                                System.out.println("User " + user + " was not successfully added to group " + group + ".\n");
                            }
                        }
                        break;
                    case "8":   // deleteUserFromGroup
                        System.out.print("Enter the name of the user you wish to remove from a group: ");
                        user = inscan.nextLine();
                        System.out.print("Enter the name of the group you wish to remove " + user + " from: ");
                        group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = gc.deleteUserFromGroup(user, group, token);
                            if(success)
                            {
                                System.out.println("Successfully removed user " + user + " from group " + group + "!\n");
                            }
                            else
                            {
                                System.out.println("User " + user + " was not successfully removed from group " + group + ".\n");
                            }
                        }
                        break;
                    case "9":   // listMembers
                        System.out.print("Enter the name of the group you wish to list the members of: ");
                        group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            List<String> members = gc.listMembers(group, token);
                            System.out.println(members);
                        }
                        break;
                    case "EXIT":
                    case "exit":
                        break;
                    case "10": // Request GroupServerKey PublicKey
                        System.out.print("Sending request to Server Owner for Public Key");
                        gc.requestPK(token);
                    case "11":
                        System.out.print("Request Group's Decryption Key file");
                        System.out.print("Enter the Group you wish to grab the their encryption keys from");
                        group = inscan.nextLine();
                        gc.requestGroupKey(token, group);
                }
            }
            else if(fc_con)
            {
                // print the file server menu
                menu3(username, fs_ip, fs_port);

                // get the user input
                input_string = inscan.nextLine();

                // switch the group server methods
                switch(input_string)
                {
                    case "1":   // disconnect
                        System.out.println("Disconnecting from the file server...\n");
                        fc.disconnect();
                        fc_con = false;
                        break;
                    case "2":   // listFiles
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            List<String> list = fc.listFiles(token);
                            if(list == null)
                            {
                                System.out.println("There are no files in this group.");
                            }
                            else
                            {
                                System.out.println(list);
                            }
                        }
                        break;
                    case "3":   // upload
                        System.out.print("Enter the location of the file you wish to upload: ");
                        String loc = inscan.nextLine();
                        System.out.print("Enter the name of your uploaded file for the server: ");
                        String file = inscan.nextLine();
                        System.out.print("Enter the name of the group you wish to add your file to: ");
                        String group = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = fc.upload(loc, file, group, token);
                            if(success)
                            {
                                System.out.println("Successfully uploaded file " + file + " from location " + loc + " to group " + group + "!");
                            }
                            else
                            {
                                System.out.println("File upload was unsuccessful.");
                            }
                        }
                        break;
                    case "4":   // download
                        System.out.print("Enter the name of the file you wish to download: ");
                        file = inscan.nextLine();
                        System.out.print("Enter the destination of the downloaded file: ");
                        loc = inscan.nextLine();
                        System.out.print("Enter the Group of the File is stored in: ");
                        String group_name = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = fc.download(file, loc, group_name, token);
                            if(success)
                            {
                                System.out.println("Successfully downloaded file " + file + " to location " + loc + "!");
                            }
                            else
                            {
                                System.out.println("File download was unsuccessful.");
                            }
                        }
                        break;
                    case "5":   // delete
                        System.out.print("Enter the name of the file you wish to delete: ");
                        file = inscan.nextLine();
                        // check to make sure token is not expired
                        if((System.currentTimeMillis() - token_creation_time) > 300000)
                        {
                            token = null;
                            System.out.println("Your token has expired. Please get a new token.");
                        }
                        else
                        {
                            success = fc.delete(file, token);
                            if(success)
                            {
                                System.out.println("Successfully deleted file " + file + "!");
                            }
                            else
                            {
                                System.out.println("File was not deleted.");
                            }
                        }
                        break;
                }
            }

        }
    }

    private static void menu1(String username)
    {
        System.out.println();
        System.out.println("\n-------------------------------------------");
        System.out.println("Welcome to the Duos Group File Share System!");
        System.out.println("--------------------------------------------");
        if(username == null)
        {
            System.out.println("You are not currently logged in.\n");
        }
        else
        {
            System.out.println("You are logged in as " + username + ".\n");
        }
        System.out.println("(1) Connect to a Group Server");
        System.out.println("(2) Connect to a File Server");
        System.out.println("Enter \"EXIT\" to quit.");
        System.out.print("> ");

    }

    private static void menu2(String username)
    {
        System.out.println();
        System.out.println("--- Group Server Menu ---");
        if(username == null)
        {
            System.out.println("You have not gotten a token.");
        }
        else
        {
            System.out.println("You are holding the token of " + username);
        }
        System.out.println("(1) Disconnect from the Group Server");
        System.out.println("(2) Get Token");
        System.out.println("(3) Create User");
        System.out.println("(4) Delete User");
        System.out.println("(5) Create Group");
        System.out.println("(6) Delete Group");
        System.out.println("(7) Add User to Group");
        System.out.println("(8) Delete User from Group");
        System.out.println("(9) List Members in Group");
        System.out.println("(10) Request Group Server Public Key");
        System.out.println("(11) Request Group's Encryption KeyList");
        System.out.println("Enter \"EXIT\" to quit.");
        System.out.print("> ");
    }

    private static void menu3(String username, String ip, String port)
    {
        System.out.println();
        System.out.println("--- File Server Menu ---");
        if(username == null)
        {
            System.out.println("You have not gotten a token.");
        }
        else
        {
            System.out.println("You are holding the token of " + username);
        }
        System.out.println("Connected to FileServer with address '" + ip + "' and port number " + port + ".");
        System.out.println("(1) Disconnect from File Server");
        System.out.println("(2) List Files in this File Server");
        System.out.println("(3) Upload a File to this File Server");
        System.out.println("(4) Download a File from this File Server");
        System.out.println("(5) Delete a File from this File Server");
        System.out.println("Enter \"EXIT\" to quit.");
        System.out.print("> ");
    }
}
