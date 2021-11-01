// File: contracts/AuditingFinal.sol

// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;


/** 
 * @title Ballot
 * @dev Implements voting process along with vote delegation
 */
contract AuditingFinal {
   
    struct UserInfo {
        // uint weight; // weight is accumulated by delegation
        bool registered;  // if true, that person already registered
        bool signedIn;
        string  username;
        // uint vote;   // index of the voted proposal
    }


    // address public chairperson;
    address public user;
    
    // -----------------------------------START OF WORKING CODE TO SIGN IN AND REGISTER USER----------------------------------//
    mapping(address => UserInfo) public users;

    constructor(){
        user = msg.sender;
        users[user].registered = false;
        users[user].signedIn = false;
    }

    function signIn() public returns(bool Calldata){
        require(users[user].registered,"You need to register first.");
        users[user].signedIn = true ;
        return users[user].signedIn ;
    }
    
    function register(string memory _username,bool value) public{
        // require(!users[user].registered, "User is already registered and can't register more than once");
        users[user].username =  _username;
        users[user].registered = value;
        // return users[user].registered;

        }
        
    function getUsername() public view returns(string memory){
        require(users[user].signedIn, "User hasn't signed in");
        return users[user].username;
    }  
    
    // ---------------------------------------- END OF WORKING CODE TO SIGN IN AND REGISTER USER----------------------------------//
    
    //-----------------------------------START OF CODE USED TO STORE AND RETRIEVE HASH VALUES------------------------------------//
    
//             #KEY                              #
   //  UNIQUE ID FOR CLOUD -------------> hash value, file name,
   
   struct auditDetails{
       uint [] hashtags;
       string cloudDataName;
       string username;
       
   }
 mapping(string => auditDetails) public auditDatabase;
 
 
 function setAuditDatabase(string memory cloudDataID, uint[] memory _hashtags, string memory _cloudDataName, string memory _username) public{
     auditDatabase[cloudDataID].hashtags = _hashtags;
     auditDatabase[cloudDataID].cloudDataName = _cloudDataName;
     auditDatabase[_username].username = _username;
     
 }
 
 
 function getAuditDatabase (string memory cloudDataID) public  view returns (uint[] memory,string memory,string memory){

    return (auditDatabase[cloudDataID].hashtags,auditDatabase[cloudDataID].cloudDataName,auditDatabase[cloudDataID].username);
 }

   

}
