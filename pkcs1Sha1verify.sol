pragma solidity 0.6.0;

library pkcs1Sha1verify {
    
    function memcpy(uint _dest, uint _src, uint _len) pure internal {
        // Copy word-length chunks while possible
        for ( ;_len >= 32; _len -= 32) {
            assembly {
                mstore(_dest, mload(_src))
            }
            _dest += 32;
            _src += 32;
        }

        // Copy remaining bytes
        uint mask = 256 ** (32 - _len) - 1;
        assembly {
            let srcpart := and(mload(_src), not(mask))
            let destpart := and(mload(_dest), mask)
            mstore(_dest, or(destpart, srcpart))
        }
    }

    
    function join(
	bytes memory _s, bytes memory _e, bytes memory _m
    ) pure internal returns (bytes memory) {
        uint inputLen = 0x60+_s.length+_e.length+_m.length;
        
        uint slen = _s.length;
        uint elen = _e.length;
        uint mlen = _m.length;
        uint sptr;
        uint eptr;
        uint mptr;
        uint inputPtr;
        
        bytes memory input = new bytes(inputLen);
        assembly {
            sptr := add(_s,0x20)
            eptr := add(_e,0x20)
            mptr := add(_m,0x20)
            mstore(add(input,0x20),slen)
            mstore(add(input,0x40),elen)
            mstore(add(input,0x60),mlen)
            inputPtr := add(input,0x20)
        }
        memcpy(inputPtr+0x60,sptr,_s.length);        
        memcpy(inputPtr+0x60+_s.length,eptr,_e.length);        
        memcpy(inputPtr+0x60+_s.length+_e.length,mptr,_m.length);

        return input;
    }
    
    function Rsa_verify(
        bytes20 _sha1,
        bytes memory _s, bytes memory _e, bytes memory _m
    ) public view returns (uint) {
        
        uint8[15] memory sha1Prefix = [
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
        ];
        
      	require(_m.length >= sha1Prefix.length+_sha1.length+11);

        uint i;

        /// decipher
        bytes memory input = join(_s,_e,_m);
        uint inputlen = input.length;

        uint decipherlen = _m.length;
        bytes memory decipher = new bytes(decipherlen);
        assembly {
            pop(staticcall(sub(gas(), 2000), 5, add(input,0x20), inputlen, add(decipher,0x20), decipherlen))
	}
        
        /// 0x00 || 0x01 || PS || 0x00 || DigestInfo
        /// PS is padding filled with 0xff
        //  DigestInfo ::= SEQUENCE {
        //     digestAlgorithm AlgorithmIdentifier,
        //     digest OCTET STRING
        //  }
        
        uint paddingLen = decipherlen - 3 - sha1Prefix.length - 20;
        
        if (decipher[0] != 0 || uint8(decipher[1]) != 1) {
            return 1;
        }
        for (i = 2;i<2+paddingLen;i++) {
            if (decipher[i] != 0xff) {
                return 2;
            }
        }
        if (decipher[2+paddingLen] != 0) {
            return 3;
        }
        for (i = 0;i<sha1Prefix.length;i++) {
            if (uint8(decipher[3+paddingLen+i])!=sha1Prefix[i]) {
                return 4;
            }
        }
        for (i = 0;i<_sha1.length;i++) {
            if (decipher[3+paddingLen+sha1Prefix.length+i]!=_sha1[i]) {
                return 5;
            }
        }

        return 0;
    }
}