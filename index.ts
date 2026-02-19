import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/curves/utils.js";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
let { Point } = secp256k1;

const Fn = secp256k1.Point.Fn;
const G = secp256k1.Point.BASE;

// Signer generates keypair
const alice = secp256k1.keygen();
const alicePublicKey = Point.fromBytes(alice.publicKey);

// Signer generates nonce
const nonce = secp256k1.keygen();
let R = nonce.publicKey;

// User tweaks committed nonce 'R' into 'R_prime'
const alpha = secp256k1.keygen().secretKey;
const beta = secp256k1.keygen().secretKey;

const betaPublicKey = alicePublicKey.multiply(Fn.fromBytes(beta));
let aGbP = G.multiply(Fn.fromBytes(alpha)).add(betaPublicKey);

let R_prime = Point.fromBytes(R).add(aGbP);

// User generates challenge 'e' (that's NOT sent to signer)
let message = "hello world";
const encoder = new TextEncoder();
const messageBytes = encoder.encode(message);

let e = Fn.fromBytes(
  sha256(concatBytes(R_prime.toBytes(), alice.publicKey, messageBytes)),
);

// User blinds challenge 'e' to get 'e_prime'
let e_prime = Fn.create(e + Fn.fromBytes(beta));

// User gives signer 'R_prime' and 'e_prime' to finish blind signature
// Signer generates blinded signature 's_prime'
let s_prime = Fn.create(
  Fn.fromBytes(nonce.secretKey) + e_prime * Fn.fromBytes(alice.secretKey),
);

// Signer gives the blinded signature 's_prime' to user
// User unblinds into 's'
let s = Fn.create(s_prime + Fn.fromBytes(alpha));

// Verifier verifies that the unblinded signature 's' is valid for message
// with the original challenge 'e' and the user-tweaked nonce 'R_prime'
let signatureDerivedVerificationValue = G.multiply(Fn.create(s));

let verificationValue = R_prime.add(
  Point.fromBytes(alice.publicKey).multiply(Fn.create(e)),
);

console.log(
  verificationValue.toAffine().x ===
    signatureDerivedVerificationValue.toAffine().x,
);
