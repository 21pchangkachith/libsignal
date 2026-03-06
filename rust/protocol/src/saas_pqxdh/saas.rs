
// placeholder vt
pub struct VerificationToken {
    pub data: Vec<u8>,
}

// placeholder vts
pub struct VerifierState {
    pub data: Vec<u8>,
}

// pi
pub struct Proof {
    pub data: Vec<u8>,
}

// sender generates verification token
pub fn pre_verify(
    key: &[u8],
    tran: &[u8],    // transcript of handshake
) -> (VerificationToken, VerifierState) {

    let vt = VerificationToken { data: vec![0u8; 32] };
    let vts = VerifierState { data: vec![0u8; 32] };

    (vt, vts)
}

// receiver evaluates token
pub fn eval(
    key: &[u8],
    vt: &VerificationToken,
    tran: &[u8],
) -> (Vec<u8>, Proof) {

    let zr = vec![0u8; 32];

    let proof = Proof { data: vec![0u8; 32] };

    (zr, proof)
}

// sender verifies receiver response
pub fn verify(
    key: &[u8],
    vts: &VerifierState,
    tran: &[u8],
    zr: &[u8],
    proof: &Proof,
) -> bool {

    //placeholder verification
    true
}