// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.4;

        // uint vote;   // index of the voted proposal
contract AuditingFinal {



    struct UserInfo {
        bool registered;  // if true, that person already registered
        bool signedIn;
        string  username;
    }
  

    // address public chairperson;
    address public user;

    constructor() public {
        user = msg.sender;
        users[user].registered = false;
        users[user].signedIn = false;
    }

    string sayHellos = "sayHello";

    // -----------------------------------START OF WORKING CODE TO SIGN IN AND REGISTER USER----------------------------------//
    mapping(address => UserInfo) public users;

    function sayHello() public view returns (string memory) {
        return "sayHello";
    }

    function sayMessage(string memory m) public pure returns (string memory) {
        return m;
    }

    function signIn() public returns (bool Calldata) {
        require(users[user].registered, "You need to register first.");
        users[user].signedIn = true;
        return users[user].signedIn;
    }

    function register(string memory _username, bool value) public {
        require(
            !users[user].registered,
            "User is already registered and can't register more than once"
        );
        users[user].username = _username;
        users[user].registered = value;

    }

    function getUsername() public view returns (string memory) {
        require(users[user].signedIn, "User hasn't signed in");
        return users[user].username;
    }

    // ---------------------------------------- END OF WORKING CODE TO SIGN IN AND REGISTER USER----------------------------------//

    //-----------------------------------START OF CODE USED TO STORE AND RETRIEVE HASH VALUES------------------------------------//

    //             #KEY                              #
    //  UNIQUE ID FOR CLOUD -------------> hash value, file name,

    struct auditDetails {
        string[] hashtags;
        string cloudDataName;
        string username;
    }
    mapping(string => auditDetails) public auditDatabase;

    function setAuditDatabase(
        string memory cloudDataID,
        string[] memory _hashtags,
        string memory _cloudDataName,
        string memory _username
    ) public {
        auditDatabase[cloudDataID].hashtags = _hashtags;
        auditDatabase[cloudDataID].cloudDataName = _cloudDataName;
        // auditDatabase[_usesrname].username = _username;
        auditDatabase[cloudDataID].username = _username;

    }

    function getAuditDatabase(string memory cloudDataID)
        public
        view
        returns (
            string[] memory,
            string memory,
            string memory
        )
    {
        return (
            auditDatabase[cloudDataID].hashtags,
            auditDatabase[cloudDataID].cloudDataName,
            auditDatabase[cloudDataID].username
        );
    }

    function getMerkleRoot(string memory cloudDataID)
        public
        view
        returns (string[] memory)
    {
        return (auditDatabase[cloudDataID].hashtags);
    }
}
