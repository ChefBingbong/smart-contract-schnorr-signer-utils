import { ethers } from "hardhat";
import { expect } from "chai";
import type {
  ECDSAWalletVerifier,
  ECDSAWalletVerifier__factory,
} from "../typechain-types";
import type { Secp256k1 } from "../typechain-types/Secp256k1";
// import BigNumber from 'bignumber.js'
import * as scep from "@noble/secp256k1";
import { keccak256 } from "ethers";
import { hexToBytes, maxUint256, zeroAddress } from "viem";

describe("ECDSAWalletVerifier", () => {
  let verifier: ECDSAWalletVerifier;
  let secp256k1: Secp256k1;
  let accounts: any[];

  before(async () => {
    accounts = await ethers.getSigners();
    const Secp256k1Factory = await ethers.getContractFactory("Secp256k1");
    secp256k1 = (await Secp256k1Factory.deploy()) as Secp256k1;

    const VerifierFactory = (await ethers.getContractFactory(
      "ECDSAWalletVerifier",
    )) as ECDSAWalletVerifier__factory;
    verifier = await VerifierFactory.deploy();
  });

  //   it("should convert public key to address correctly", async () => {
  //       const publicKey = {
  //         x: ethers.toBigInt("0x1"),
  //         y: ethers.toBigInt("0x2"),
  //       };

  //       const address = await verifier.publicKeyToAddress(publicKey);
  //       const expectedAddress = ethers.computeAddress(
  //         ethers.keccak256(ethers.de.AbiCoder.(["uint256", "uint256"], [publicKey.x, publicKey.y])).slice(26)
  //       );

  //       expect(address).to.equal(expectedAddress);
  //     });

  it("should derive public key correctly", async () => {
    const pubkey =
      scep.Point.fromPrivateKey(
        58061806736494292520208361787951596349232252952004834268315298885074801295881n,
      );
    const secretKey = ethers.toBigInt("0x1");
    const nonce = ethers.toBigInt(1);

    const expectedPubKey2 = scep.Point.fromHex(
      scep.utils.bytesToHex(
        scep.getPublicKey(
          58061806736494292520208361787951596349232252952004834268315298885074801295881n,
          false,
        ),
      ),
    );
    const [pubkeyX, pubkeyY] = await verifier.PubDerive(
      [expectedPubKey2.x, expectedPubKey2.y],
      nonce,
    );

    const expectedPrivKey = secretKey + (nonce % scep.CURVE.P);
    const expectedPubKey = scep.utils.bytesToHex(
      scep.getPublicKey(
        58061806736494292520208361787951596349232252952004834268315298885074801295881n,
        true,
      ),
    );
    //     const expectedPubKey2 = scep.utils.bytesToHex(
    //       scep.getPublicKey(
    //         58061806736494292520208361787951596349232252952004834268315298885074801295881n,
    //         false,
    //       ),
    //     );
    //     scep.utils.
    console.log(
      pubkeyX.toString(16),
      pubkeyY.toString(16),
      pubkey.x.toString(16),
      pubkey.y.toString(16),
    );
    expect(expectedPubKey).to.equal(expectedPubKey2);
    //     expect(pubkeyY).to.equal(expectedPubKey.y);
  });

  it("should derive private key correctly", async () => {
    const secretKey = ethers.toBigInt("0x1");
    const nonce = ethers.toBigInt(1);

    const derivedKey = await verifier.PrivDerive(secretKey, nonce);

    const expectedKey = secretKey + (nonce % scep.CURVE.P);
    expect(derivedKey).to.equal(expectedKey);
  });

  it("should create and verify proof correctly", async () => {
    const secret = ethers.toBigInt("0x1");
    const message = ethers.toBigInt("0x2");

    const pointPub =
      scep.Point.fromPrivateKey(
        58061806736494292520208361787951596349232252952004834268315298885074801295881n,
      );

    const schnorPrivate = await verifier.PrivDerive(
      58061806736494292520208361787951596349232252952004834268315298885074801295881n,
      keccak256(hexToBytes("0x12")),
    );
    //   console.log(pointPub);
    const aux = scep.utils.hexToBytes(
      "2ebb9c64ef99bbd299c7e1595c459f3301a1c28d50226d4c6882d584e71f6464",
    );

    await verifier.CreateProof2(
      scep.utils._bigintTo32Bytes(
        BigInt(
          58061806736494292520208361787951596349232252952004834268315298885074801295881n,
        ),
      ),
      message,
      aux,
    );

    const [pubkeyX, pubkeyY, out_e, out_s] = await verifier.CreateProof(
      schnorPrivate,
      message,
    );
    const [pubkeyX1, pubkeyY1] = await verifier.PubDerive(
      [pointPub.x, pointPub.y],
      keccak256(hexToBytes("0x12")),
    );

    const verified = await verifier.VerifyProof(
      [pubkeyX, pubkeyY],
      message,
      out_s,
      out_e,
    );

    console.log(pubkeyX1, pubkeyY1, pubkeyX, pubkeyY);
    const expectedPubKey = scep.Point.fromHex(
      scep.utils.bytesToHex(scep.schnorr.getPublicKey(BigInt(schnorPrivate))),
    );
    console.log(
      scep.utils._bigintTo32Bytes(
        BigInt(
          58061806736494292520208361787951596349232252952004834268315298885074801295881n,
        ),
      ),
    );

    expect(verified).to.be.true;
  });

  //     it("should sign and recover correctly", async () => {
  //       const msghash = ethers.keccak256(ethers.toUtf8Bytes("test message"));
  //       const privkey = ethers.keccak256(ethers.toUtf8Bytes("test private key"));

  //       const [v, r, s] = await verifier.sign(msghash, privkey);
  //       const recoveredPubKey = await verifier.recover(msghash, v, r, s);

  //       const expectedPubKey = secp256k1.privToPub(ethers.utils.arrayify(privkey));
  //       expect(recoveredPubKey.x).to.equal(expectedPubKey.x);
  //       expect(recoveredPubKey.y).to.equal(expectedPubKey.y);
  //     });
});
