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
    mapping(address => bool claimed) private s_claimed;

    event Claimed(address indexed account, uint256 amount);
    constructor(bytes32 _merkleRoot, IERC20 airdropToken) {
        I_MERKLE_ROOT = _merkleRoot;
        I_AIRDROP_TOKEN = airdropToken;
    }

    function claim(address account, uint256 amount, bytes32[] calldata merkleProof) external {
        // check if the user has already claimed
        if (s_claimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }
        // calculate using the account and amount, the hash -> leaf node
        bytes32 leaf = keccak256(
            bytes.concat(
                keccak256(abi.encode(account, amount))
            )
        );
        // Verify the merkle proof
        bool isValidLeaf = MerkleProof.verify(merkleProof, I_MERKLE_ROOT, leaf);
        if (!isValidLeaf) {
            revert MerkleAirdrop__InvalidProof();
        }
        // add the account to the claimed users
        s_claimed[account] = true;
        emit Claimed(account, amount);
        // mint tokens to the claimer
        I_AIRDROP_TOKEN.safeTransfer(account, amount);
    }

    function isClaimed(address account) external view returns (bool) {
        return s_claimed[account];
    }

    function getMerkleRoot() external view returns (bytes32) {
        return I_MERKLE_ROOT;
    }

    function getAirdropToken() external view returns (IERC20) {
        return I_AIRDROP_TOKEN;
    }
    
      
}