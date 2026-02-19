# single-session-blind-signing
Reference code for generating *single session* blind signatures with Schnorr. ~~Working my way to implementing a version that's secure for parallel signing sessions.~~

Update: Nevermind the part about working my way up to parallel signing sessions. I found this [1] link and decided I'm not programming a "statistical ZK argument of knowledge with a straigh[t]-line extractor" (whatever that is) lol:
"A major deviation between our construction and the one of [FW24] is the replacement of the NIZK sent by the user to the signer with a concurrent statistical ZK argument of knowledge with a straigh[t]-line extractor that we construct in four messages (i.e., two rounds) relying on an NPRO"

[1] https://eprint.iacr.org/2025/1992

## To run
- npm install
- ts-node index.ts

Verify 'true' is printed to the console.