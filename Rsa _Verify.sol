pragma solidity 0.6.0;

import "main/pkcs1Sha256verify.sol";

interface Interface_Management{
    function Find_key(bytes32 _hash) external view returns (bool);
}

contract Rsa_Verify{
    
    struct Set {
        bytes32 hash;
        bytes signature;
        bytes pubkey;
    }
    Set[] set;
    
    mapping(bytes32 => Set) map;
    
    Interface_Management IM;
    constructor(address _address) public {
        IM = Interface_Management(_address);
    }
    
    function Rsa_verify(bytes32 _sha256, bytes memory _s, bytes memory _e, bytes memory _m) public{
        if(IM.Find_key(keccak256(_m)) == true){
            if(pkcs1Sha256verify.Rsa_verify(_sha256, _s, _e, _m) == 0){
                set.push(Set(_sha256, _s, _m));
            }
        }
    }
    
}