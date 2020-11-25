// GroupList.java created by duos group
import java.util.ArrayList;
import java.util.Hashtable;

import javax.crypto.*;
import java.security.*;


public class GroupList implements java.io.Serializable{
    public GroupList(){}
    private Hashtable<String, Group> group_list = new Hashtable<String, Group>();

    public synchronized void createGroup(String groupname, String username){
      Group newGroup = new Group(username, groupname); //the username will be the owner of the groups
      group_list.put(groupname, newGroup);
    }

    public synchronized void deleteGroup(String groupname){ //removes group from the list.
      group_list.remove(groupname);
    }

    public synchronized void addUserToGroup(String user, String group){
      group_list.get(group).addUser(user);
    }

    public synchronized void deleteUserFromGroup(String user, String group){ //gets the group from the hashtable and calls the remove group method within the group class
      group_list.get(group).removeUser(user);
    }

    public synchronized void listMembers(String user, String group){ //Prints out the list of group members
      ArrayList<String> temp = new ArrayList<String>();
      temp = group_list.get(group).getUsers();

      for (String member: temp)
        System.out.println(temp);
    }

    public synchronized boolean containsGroup(String groupname){  // returns true if the groupname is in this group_list
      return group_list.containsKey(groupname);
    }

    public synchronized ArrayList<String> listUsers(String group){
      return group_list.get(group).getUsers();
    }

    public synchronized Group getGroup(String groupname) {
      return group_list.get(groupname);
    }

    class Group implements java.io.Serializable{ //class that implements groups similar to the user class
      private String owner;
      private String name;
      private ArrayList<String> users;
      private ArrayList<SecretKey> keys;
      private int version;

      public Group(String founder, String name){
        this.owner = founder;
        users = new ArrayList<String>();
        keys = new ArrayList<SecretKey>();
        version = 0;
      }
      //gets the owner of the group
      public String getOwner(){
        return owner;
      }
      //returns the current version of the key that is stored in the arrayList
      public ArrayList<SecretKey> getKeys(){
        return keys;
      }
      public int getVersion(){
        return version;
      }
      //adds the fileKey to the keys arrayList
      public void setKey(SecretKey fkey){
        keys.add(fkey);
      }
      //returns the list of all users within the group
      public ArrayList<String> getUsers(){
        return users;
      }
      //adds user to the ArrayList of Group Users
      public void addUser(String userName){
        users.add(userName);
      }
      //removes user from the ArrayList of Group users
      public void removeUser(String userName){
        users.remove(userName);
      }
      public boolean containsUser(String username){
        return users.contains(username);
      }
    }
}
