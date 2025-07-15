pragma circom 2.1.7;
include "circomlib/circuits/poseidon.circom";

/*  Proves knowledge of `secret` s.t. Poseidon(secret) = commitment  */
template SecretProof() {
    signal input  secret;        // private
    signal input  commitment;    // public

    component h = Poseidon(1);
    h.inputs[0] <== secret;
    h.out === commitment;
}

/* Expose the commitment as the only public signal */
component main { public [commitment] } = SecretProof();
