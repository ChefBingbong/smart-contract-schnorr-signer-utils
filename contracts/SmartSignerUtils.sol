pragma solidity ^0.8.6;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Secp256k1} from "./Secp256k1.sol";
import {IWallet} from "./interfaces/IWallet.sol";

contract ECDSAWalletVerifier {
  using Secp256k1 for *;
  uint256 public constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  function publicKeyToAddress(Secp256k1.Point memory publicKey) public pure returns (address) {
    bytes32 publicKeyHash = keccak256(abi.encodePacked(publicKey.x, publicKey.y));
    return address(uint160(uint256(publicKeyHash)));
  }

  function PubDerive(uint256[2] memory pubkey, uint256 nonce) public pure returns (uint256 pubkeyX, uint256 pubkeyY) {
    (uint256 px, uint256 py) = Secp256k1.ecMul(uint256(nonce), Secp256k1.Gx, Secp256k1.Gy, Secp256k1.A, Secp256k1.PP);
    (pubkeyX, pubkeyY) = Secp256k1.ecAdd(pubkey[0], pubkey[1], px, py, Secp256k1.A, Secp256k1.PP);
  }

  function PrivDerive(uint256 secret_key, uint256 nonce) public pure returns (bytes32) {
    return bytes32(addmod(uint256(secret_key), uint256(nonce), Secp256k1.PP));
  }

  function SharedSecret(uint256 my_secret, uint256[2] memory their_public) public pure returns (uint256 xPX, uint256 xPY) {
    (xPX, xPY) = Secp256k1.ecMul(uint256(my_secret), their_public[0], their_public[1], Secp256k1.A, Secp256k1.PP);
  }

  function CreateProof(uint256 secret, uint256 message) public view returns (uint256 pubkeyX, uint256 pubkeyY, uint256 out_e, uint256 out_s) {
    (pubkeyX, pubkeyY) = Secp256k1.ecMul(secret % Secp256k1.PP, Secp256k1.Gx, Secp256k1.Gy, Secp256k1.A, Secp256k1.PP);
    uint256 k = log256(uint256(keccak256(abi.encodePacked(message, secret))) % Secp256k1.PP) * block.timestamp;
    (uint256 kgX, uint256 kgY) = Secp256k1.ecMul(k % Secp256k1.PP, Secp256k1.Gx, Secp256k1.Gy, Secp256k1.A, Secp256k1.PP);

    out_e = uint256(keccak256(abi.encodePacked(pubkeyX, pubkeyY, kgX, kgY, message)));
    out_s = mulmod(secret, out_e, NN) + k;
  }

  function VerifyProof(uint256[2] memory pubkey, uint256 message, uint256 s, uint256 e) public pure returns (bool verified) {
    (uint256 sgX, uint256 sgY) = Secp256k1.ecMul(s % Secp256k1.PP, Secp256k1.Gx, Secp256k1.Gy, Secp256k1.A, Secp256k1.PP);
    (uint256 rX, uint256 rY) = Secp256k1.ecMul(e, pubkey[0], pubkey[1], Secp256k1.A, Secp256k1.PP);
    (uint256 kgX, uint256 kgY) = Secp256k1.ecSub(sgX, sgY, rX, rY, Secp256k1.A, Secp256k1.PP);

    verified = bool(e == uint256(keccak256(abi.encodePacked(pubkey[0], pubkey[1], kgX, kgY, message))));
  }

  function sign(bytes32 msghash, bytes32 privkey) public pure returns (uint8, uint256, uint256) {
    return ecdsaRawSign(msghash, privkey);
  }

  function recover(bytes32 msghash, uint8 v, uint256 r, uint256 s) public pure returns (Secp256k1.Point memory) {
    uint256 x = r;
    uint256 xcubedaxb = addmod(
      addmod(mulmod(x, mulmod(x, x, Secp256k1.PP), Secp256k1.PP), Secp256k1.A * x, Secp256k1.PP),
      Secp256k1.B,
      Secp256k1.PP
    );
    uint256 beta = Secp256k1.expMod(xcubedaxb, (Secp256k1.PP + 1) / 4, Secp256k1.PP);
    uint256 y = ((v % 2) ^ (beta % 2) != 0) ? beta : Secp256k1.PP - beta;

    Secp256k1.Point memory G = Secp256k1.Point(Secp256k1.Gx, Secp256k1.Gy);
    Secp256k1.Point memory R = Secp256k1.Point(x, y);

    uint256 z = uint256(msghash);
    uint256 nzInv = Secp256k1.N - (z % Secp256k1.PP);

    (uint256 Gzx, uint256 Gzy, uint256 gZz) = Secp256k1.jacMul(nzInv, G.x, G.y, 1, 0, Secp256k1.PP);
    (uint256 Rzx, uint256 Rzy, uint256 xZz) = Secp256k1.jacMul(s, R.x, R.y, 1, 0, Secp256k1.PP);

    (uint256 Qx, uint256 Qy, uint256 Qz) = Secp256k1.jacAdd(Gzx, Gzy, gZz, Rzx, Rzy, xZz, Secp256k1.PP);
    (uint256 Qjx, uint256 Qjy, uint256 Qjz) = Secp256k1.jacMul(Secp256k1.invMod(x, Secp256k1.N), Qx, Qy, Qz, 0, Secp256k1.PP);

    return Secp256k1.fromJacobian(Secp256k1.Point(Qjx, Qjy), Qjz);
  }

  function deriveAddress(uint256[2] memory pubkey) public pure returns (address) {
    bytes memory pubkeyBytes = abi.encodePacked(pubkey[0], pubkey[1]);
    bytes32 pubkeyHash = keccak256(pubkeyBytes);
    return address(uint160(uint256(pubkeyHash)));
  }

  function privToPub(bytes memory privkey) internal pure returns (Secp256k1.Point memory) {
    return Secp256k1.multiply(Secp256k1.Point(Secp256k1.Gx, Secp256k1.Gy), bytesToUint(privkey));
  }

  // Function to generate the message point including the BSC operation calldata
  function generateMessagePoint(
    address sender,
    IWallet.ECDSAExec memory operation,
    uint256 nonce,
    uint256 timestamp
  ) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(sender, abi.encode(operation), nonce, timestamp));
  }

  // remember to hash private key first
  function signCrossChainTransaction(
    IWallet.ECDSAExec memory operation,
    bytes32 privateKey
  ) public view returns (uint256 pubkeyX, uint256 pubkeyY, uint256 out_e, uint256 out_s) {
    bytes32 txHash = keccak256(abi.encode(operation));
    return CreateProof(uint256(privateKey), uint256(txHash));
  }

  function deterministicGenerateK(bytes32 msghash, bytes32 priv) public pure returns (uint256) {
    bytes32 v = hex"0101010101010101010101010101010101010101010101010101010101010101";
    bytes32 k = hex"0000000000000000000000000000000000000000000000000000000000000000";

    k = hmacSha256(k, abi.encodePacked(v, bytes1(0x00), priv, msghash));
    v = hmacSha256(k, abi.encodePacked(v));
    k = hmacSha256(k, abi.encodePacked(v, bytes1(0x01), priv, msghash));
    v = hmacSha256(k, abi.encodePacked(v));

    return uint256(hmacSha256(k, abi.encodePacked(v)));
  }

  function hmacSha256(bytes32 key, bytes memory message) public pure returns (bytes32) {
    bytes32 keyHashed = key;
    if (key.length > 64) {
      keyHashed = bytes32(abi.encodePacked(key));
    }

    bytes memory keyBlock = new bytes(64);
    for (uint256 i = 0; i < 32; i++) {
      keyBlock[i] = keyHashed[i];
    }

    bytes memory ipad = new bytes(64);
    for (uint256 i = 0; i < 64; i++) {
      ipad[i] = keyBlock[i] ^ 0x36;
    }

    bytes memory opad = new bytes(64);
    for (uint256 i = 0; i < 64; i++) {
      opad[i] = keyBlock[i] ^ 0x5c;
    }

    bytes32 innerHash = sha256(abi.encodePacked(ipad, message));
    return sha256(abi.encodePacked(opad, innerHash));
  }

  function bytesToUint(bytes memory b) internal pure returns (uint256) {
    uint256 number;
    for (uint i = 0; i < b.length; i++) {
      number = number + uint256(uint8(b[i])) * (2 ** (8 * (b.length - (i + 1))));
    }
    return number;
  }

  function ecdsaRawSign(bytes32 msghash, bytes32 priv) internal pure returns (uint8, uint256, uint256) {
    uint256 z = uint256(msghash);
    uint256 k = deterministicGenerateK(msghash, priv);
    (uint256 Rx, uint256 Ry) = Secp256k1.ecMul(k, Secp256k1.Gx, Secp256k1.Gy, 0, Secp256k1.PP);

    uint256 r = Rx;
    uint256 invK = Secp256k1.invMod(k, Secp256k1.N);
    uint256 s = mulmod(invK, (z + mulmod(r, uint(priv), Secp256k1.N)), Secp256k1.N);
    uint8 v = 27 + uint8((Ry % 2) ^ (s < Secp256k1.PP / 2 ? 0 : 1));
    if (s > Secp256k1.PP / 2) s = Secp256k1.PP - s;

    return (v, r, s);
  }

  function log256(uint256 value) internal pure returns (uint256) {
    uint256 result = 0;
    unchecked {
      if (value >> 128 > 0) {
        value >>= 128;
        result += 16;
      }
      if (value >> 64 > 0) {
        value >>= 64;
        result += 8;
      }
      if (value >> 32 > 0) {
        value >>= 32;
        result += 4;
      }
      if (value >> 16 > 0) {
        value >>= 16;
        result += 2;
      }
      if (value >> 8 > 0) {
        result += 1;
      }
    }
    return result;
  }
}
