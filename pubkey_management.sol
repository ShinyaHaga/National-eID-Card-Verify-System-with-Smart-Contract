pragma solidity 0.6.0;

contract Management{
    address owner;
    mapping (bytes32 => bool) public hash_table;
    
    constructor (address _owner) public{
        owner = _owner;
    }
    
    function Add_key(bytes32 _hash) public only_owner{
        hash_table[_hash] = true;
    }
    
    function Delete_key(bytes32 _hash) public only_owner{
        hash_table[_hash] = false;
    }
    
    function Find_key(bytes32 _hash) external view returns (bool){
        return hash_table[_hash];
    }
    
    function check(bytes memory  _pubkey) public pure returns (bytes32){
        return keccak256((abi.encodePacked(_pubkey)));
    }
    
    modifier only_owner{
        require(msg.sender == owner);
        _;
    }
}