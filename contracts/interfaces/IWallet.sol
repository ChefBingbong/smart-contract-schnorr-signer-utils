//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.6;

interface IWallet {
    event LogReceivedEther(address indexed _from, uint256 _amount);

    event LogCall(address indexed _contract, uint256 _value, bytes _data);

    event Approval(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint160 amount,
        uint48 expiration
    );

    event Permit(
        address indexed owner,
        address indexed token,
        address indexed spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce
    );

    event WalletOpRecoveryResult(
        address indexed signer,
        bytes32 dataHash,
        bytes signature,
        address wallet,
        uint256 nonce
    );

    struct ECDSAExec {
        AllowanceOp allowanceOp;
        UserOp[] userOps;
        UserOp[] bridgeOps;
        address wallet;
        uint256 nonce;
        uint256 chainID;
        uint256 bridgeChainID;
        uint256 sigChainID;
    }

    struct UserOp {
        address to;
        uint256 amount;
        uint256 chainId;
        bytes data;
    }

    struct AllowanceOpDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct AllowanceOp {
        AllowanceOpDetails[] details;
        address spender;
        uint256 sigDeadline;
    }

    struct PackedAllowance {
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct ECDSAExecValidationDetails {
        address signer;
        bytes32 dataHash;
        bytes signature;
        address wallet;
    }

    struct Signature {
        address signer;
        bytes signatureData;
        bool dynamic;
    }

    receive() external payable;

    function nonce() external view returns (uint256);

    function owner() external view returns (address);

    function exec(
        ECDSAExec memory _walletExec,
        bytes memory _signature
    ) external;

    function execBridge(
        ECDSAExec memory _walletExec,
        bytes memory _signature,
        bytes memory _bridgeProof
    ) external;

    function execFomEoa(UserOp[] calldata userOps) external;

    function allowance(
        address user,
        address token,
        address spender
    ) external view returns (uint160 amount, uint48 expiration, uint48 nonce);

    function approve(
        address token,
        address spender,
        uint160 amount,
        uint48 expiration
    ) external;

    function transferFrom(
        address from,
        address to,
        uint160 amount,
        address token
    ) external;

    function getUserValidatedData(
        uint256 _nonce
    ) external view returns (ECDSAExecValidationDetails memory);

    function _verifySignatures(
        bytes memory signatures,
        bytes32 dataHash,
        address executor,
        uint256 requiredSignatures
    ) external view;
}
