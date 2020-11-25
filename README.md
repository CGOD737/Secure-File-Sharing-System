# Secure-File-Sharing-System
Completed by Christopher Godfrey and Jarod Carl for CS1653 "Applied Cryptography and Network Security"

FileSharing Usage Information

USAGE:
 To start Group Server: java RunGroupServer -cp .;[bouncycastlejarpath] [(optional) port number]
 When the group server is first started, there are no users or groups. Since 
 there must be an administer of the system, the user is prompted via the console
 to enter a username. This name becomes the first user and is a member of the
 ADMIN group.  Also, no groups exist.  The group server will by default
 run on port 8765, but a custom port can be passed as the first command line
 argument.

 To start the File Server: java RunFileServer -cp .;[bouncycastlejarpath] [(optional) port number]
 The file server will create a shared_files inside the working directory if one 
 does not exist. The file server is now online.  The file server will by default
 run on port 4321, but a custom port can be passed as the first command line
 argument.
 
 The latest version of bouncy castle is necessary to compile and run and is recommended to be download
 and place in the src directory alongside the rest of the source code. To demonstrate the network sharing
 features, run the group server, file server, and client on different machines.

 To reset the File server completely, delete FileList.bin and the shared_files 
 directory.
 To reset the Group Server, delete UserList.bin.
 
 Note that this implementation supports server side directories.
