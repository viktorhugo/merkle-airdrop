// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";


contract MerkleAirdrop {
    using SafeERC20 for IERC20;

    // Some list of addresses 
    // Allow someone in the list to claim ERC-20 tokens
    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();

    address[] claimers;
    bytes32 private immutable I_MERKLE_ROOT;
    IERC20 private immutable I_AIRDROP_TOKEN;
    mapping(address => bool claimed) private sClaimed;

    event Claimed(address indexed account, uint256 amount);
    constructor(bytes32 _merkleRoot, IERC20 airdropToken) {
        I_MERKLE_ROOT = _merkleRoot;
        I_AIRDROP_TOKEN = airdropToken;
    }

    function claim(address account, uint256 amount, bytes32[] calldata merkleProof) external {
        // check if the user has already claimed
        if (sClaimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }
        // calculate using the account and amount, the hash -> leaf node
        // Use inline assembly to compute the double-hash leaf node efficiently.
        // This avoids the overhead of abi.encode (memory allocation + ABI encoding),
        // bytes.concat (copy into a new bytes array), and the Solidity keccak256 wrapper.
        //
        // Equivalent Solidity: keccak256(bytes.concat(keccak256(abi.encode(account, amount))))
        //
        // Layout in scratch space (ptr = free memory pointer):
        //   [ptr + 0x00 .. ptr + 0x1f] : account (address, padded to 32 bytes)
        //   [ptr + 0x20 .. ptr + 0x3f] : amount  (uint256, 32 bytes)
        // inner = keccak256(ptr, 0x40)  — first hash over the 64-byte packed encoding
        // leaf  = keccak256(ptr, 0x20)  — second hash over the 32-byte inner hash
        bytes32 leaf;
        assembly {
            let ptr := mload(0x40)          // load free memory pointer
            mstore(ptr, account)            // store address (zero-padded) at ptr
            mstore(add(ptr, 0x20), amount)  // store amount right after
            let inner := keccak256(ptr, 0x40)   // hash the 64-byte payload
            mstore(ptr, inner)              // overwrite ptr with the inner hash
            leaf := keccak256(ptr, 0x20)   // hash the 32-byte inner hash → leaf
        }
        // Verify the merkle proof
        bool isValidLeaf = MerkleProof.verify(merkleProof, I_MERKLE_ROOT, leaf);
        if (!isValidLeaf) {
            revert MerkleAirdrop__InvalidProof();
        }
        // add the account to the claimed users
        sClaimed[account] = true;
        emit Claimed(account, amount);
        // mint tokens to the claimer
        I_AIRDROP_TOKEN.safeTransfer(account, amount);
    }

    function isClaimed(address account) external view returns (bool) {
        return sClaimed[account];
    }

    function getMerkleRoot() external view returns (bytes32) {
        return I_MERKLE_ROOT;
    }

    function getAirdropToken() external view returns (IERC20) {
        return I_AIRDROP_TOKEN;
    }


}