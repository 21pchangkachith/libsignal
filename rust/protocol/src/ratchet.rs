//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// Ratchet Definition/Explanation:
// 
// A cryptographic ratchet is a mechanism used in secure messaging protocols to continually 
// update encryption keys so that each message is protected with a fresh key. The key property 
// is that the process only moves forward — once a key is used, it cannot be derived again, and 
// past keys cannot be reconstructed from future ones.
//
// A double ratchet combines a cryptographic so-called "ratchet" based on the Diffie–Hellman key 
// exchange (DH) and a ratchet based on a key derivation function (KDF), such as a hash function, 
// and is therefore called a double ratchet.
//

mod keys;
mod params;

use libsignal_core::derive_arrays;
use rand::{CryptoRng, Rng};

pub(crate) use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::CIPHERTEXT_MESSAGE_CURRENT_VERSION;
use crate::state::SessionState;
use crate::{KeyPair, Result, SessionRecord, SignalProtocolError, consts};

type InitialPQRKey = [u8; 32]; // Initial key for PQ Ratchet

fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    derive_keys_with_label(
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024",
        secret_input,
    )
}

// HKDF key derivation
fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let (root_key_bytes, chain_key_bytes, pqr_bytes) = derive_arrays(|bytes| {
        hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
            .expand(label, bytes)
            .expect("valid length")
    });

    let root_key = RootKey::new(root_key_bytes);    // Master secret for ratchet (derive chain keys)
    let chain_key = ChainKey::new(chain_key_bytes, 0);  // Starting key for message encryption/decryption chains
    let pqr_key: InitialPQRKey = pqr_bytes;

    (root_key, chain_key, pqr_key)
}

// PQ ratchet parameters
fn spqr_chain_params(self_connection: bool) -> spqr::ChainParams {
    #[allow(clippy::needless_update)]
    spqr::ChainParams {
        max_jump: if self_connection {
            u32::MAX
        } else {
            consts::MAX_FORWARD_JUMPS.try_into().expect("should be <4B")
        },
        max_ooo_keys: consts::MAX_MESSAGE_KEYS.try_into().expect("should be <4B"),
        ..Default::default()
    }
}

// ***X3DH Key Agreement for Alice***
pub(crate) fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters, // Contains Alice's ik and eph keys, Bob's ik, signed prekey, otpk, PQ prekey
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key(); // Alice's ipk

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    // Below are the DH operations for X3DH
    let our_base_private_key = parameters.our_base_key_pair().private_key;

    // Alice's private ik * Bob's signed prekey
    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    // Alice's eph key * Bob's ik
    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    // Alice's eph key * Bob's signed prekey
    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    // Optional Alice's eph key * Bob's otpk
    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    // Uses Bob's Kyber prekey to perform key encapsulation (KEM)
    // ss = shared secret from Kyber, ct = ciphertext sent to Bob
    let kyber_ciphertext = {
        let (ss, ct) = parameters.their_kyber_pre_key().encapsulate(&mut csprng)?;
        secrets.extend_from_slice(ss.as_ref());
        ct
    };

    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    // Alice generates eph sending ratchet key
    // Perform DH with Bob's ratchet key
    let sending_ratchet_key = KeyPair::generate(&mut csprng);
    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::A2B,
        // Set min_version to V0 (allow fallback to no PQR at all) while
        // there are clients that don't speak PQR.  Once all clients speak
        // PQR, we can up this to V1 to require that all subsequent sessions
        // use at least V1.
        min_version: spqr::Version::V0,
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        // Since this is an error associated with the initial creation of the state,
        // it must be a problem with the arguments provided.
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial A2B state: {e}"
        ))
    })?;

    // Create session object with receiver/sender chains
    let mut session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
        pqr_state,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    session.set_kyber_ciphertext(kyber_ciphertext); // Ciphertext to send to Bob

    Ok(session) // Alice's session ready for messaging
}

pub(crate) fn initialize_bob_session(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState> {
    // validate Alice's (ephemeral) base key
    if !parameters.their_base_key().is_canonical() {
        return Err(SignalProtocolError::InvalidMessage(
            crate::CiphertextMessageType::PreKey,
            "incoming base key is invalid",
        ));
    }

    let local_identity = parameters.our_identity_key_pair().identity_key(); // Bob's ipk

    let mut secrets = Vec::with_capacity(32 * 6);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    // DH agreement computations
    // Bob's spk * Alice's ik
    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    // Bob's ik * Alice's eph key
    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    // Bob's spk * Alice's eph key
    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    // Optional Bob's otpk * Alice's eph key
    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
    }

    // Bob's Kyber secret key recovers shared PQ secret from Alice's ciphertext
    secrets.extend_from_slice(
        &parameters
            .our_kyber_pre_key_pair()
            .secret_key
            .decapsulate(parameters.their_kyber_ciphertext())?,
    );

    let (root_key, chain_key, pqr_key) = derive_keys(&secrets);

    // PQ ratchet from Bob to Alice
    let self_session = local_identity == parameters.their_identity_key();
    let pqr_state = spqr::initial_state(spqr::Params {
        auth_key: &pqr_key,
        version: spqr::Version::V1,
        direction: spqr::Direction::B2A,
        // Set min_version to V0 (allow fallback to no PQR at all) while
        // there are clients that don't speak PQR.  Once all clients speak
        // PQR, we can up this to V1 to require that all subsequent sessions
        // use at least V1.
        min_version: spqr::Version::V0,
        chain_params: spqr_chain_params(self_session),
    })
    .map_err(|e| {
        // Since this is an error associated with the initial creation of the state,
        // it must be a problem with the arguments provided.
        SignalProtocolError::InvalidArgument(format!(
            "post-quantum ratchet: error creating initial B2A state: {e}"
        ))
    })?;

    // Bob's session object
    let session = SessionState::new(
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
        pqr_state,
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

// Wrappers
pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
