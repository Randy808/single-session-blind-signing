import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/curves/utils.js";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
let { Point } = secp256k1;

const Fn = secp256k1.Point.Fn;
const G = secp256k1.Point.BASE;

// Generate keypair
const alice = secp256k1.keygen();
const alicePublicKey = Point.fromBytes(alice.publicKey);

// Generate nonce
const nonce = secp256k1.keygen();
let R = nonce.publicKey;

// Let the user tweak it
const alpha = secp256k1.keygen().secretKey;
const beta = secp256k1.keygen().secretKey;

const betaPublicKey = alicePublicKey.multiply(Fn.fromBytes(beta));
let aGbP = G.multiply(Fn.fromBytes(alpha)).add(betaPublicKey);

let R_prime = Point.fromBytes(nonce.publicKey).add(aGbP);

// Generate new challenge
let message = "hello world";
const encoder = new TextEncoder();
const messageBytes = encoder.encode(message);

let e = Fn.fromBytes(
  sha256(concatBytes(R_prime.toBytes(), alice.publicKey, messageBytes)),
);

let e_prime = Fn.create(e + Fn.fromBytes(beta));

// Give R_prime and e_prime to signer to finish blind signature
let s_prime = Fn.create(
  Fn.fromBytes(nonce.secretKey) + e_prime * Fn.fromBytes(alice.secretKey),
);

// Give to user to unblind signature
let s = Fn.create(s_prime + Fn.fromBytes(alpha));

let signatureDerivedVerificationValue = G.multiply(Fn.create(s));

let verificationValue = R_prime.add(
  Point.fromBytes(alice.publicKey).multiply(Fn.create(e)),
);

console.log(
  verificationValue.toAffine().x ===
    signatureDerivedVerificationValue.toAffine().x,
);
