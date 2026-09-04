#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Bytes, BytesN, Env,
};

use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr};

/// Errors that can occur during proof verification.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    InvalidProofLength = 1,
    InsufficientPublicInputs = 2,
    KeyNotInitialized = 3,
}

/// Storage key for verification key components.
#[contracttype]
enum DataKey {
    VkAlphaG1,
    VkBetaG2,
    VkGammaG2,
    VkDeltaG2,
    VkIc(u32),
    VkIcCount,
    Initialized,
}

/// Generic, stateless BN254/Poseidon proof verifier (README "Smart Contract
/// Interface"). Any policy contract can plug into it.
///
/// Day 2: wired to Protocol 25 native BN254 pairing host functions via
/// `Env::crypto().bn254().pairing_check`. The verification key is stored in
/// contract instance storage and set once via `set_verification_key`.
///
/// NOTE: README's interface shows `Vec<BytesN<32>>` for public_inputs, but
/// Soroban contract functions do not support generic type parameters on
/// user-defined types.  Public inputs are instead passed as a flat `Bytes`
/// blob (N × 32 bytes, contiguous).  See docs/decisions.md.
#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    /// Store the Groth16 verification key in contract instance storage.
    ///
    /// Must be called once before any proofs can be verified.  In production
    /// this would be set during deployment or by governance.
    ///
    /// - `vk_alpha_g1`  — 64-byte serialized G1 point (alpha)
    /// - `vk_beta_g2`   — 128-byte serialized G2 point (beta)
    /// - `vk_gamma_g2`  — 128-byte serialized G2 point (gamma)
    /// - `vk_delta_g2`  — 128-byte serialized G2 point (delta)
    /// - `vk_ic`        — flat bytes of all IC points (64 bytes each, contiguous)
    /// - `vk_ic_count`  — number of IC points
    pub fn set_verification_key(
        env: Env,
        vk_alpha_g1: BytesN<64>,
        vk_beta_g2: BytesN<128>,
        vk_gamma_g2: BytesN<128>,
        vk_delta_g2: BytesN<128>,
        vk_ic: Bytes,
        vk_ic_count: u32,
    ) {
        let store = env.storage().instance();
        store.set(&DataKey::Initialized, &true);
        store.set(&DataKey::VkAlphaG1, &vk_alpha_g1);
        store.set(&DataKey::VkBetaG2, &vk_beta_g2);
        store.set(&DataKey::VkGammaG2, &vk_gamma_g2);
        store.set(&DataKey::VkDeltaG2, &vk_delta_g2);
        store.set(&DataKey::VkIcCount, &vk_ic_count);
        for i in 0..vk_ic_count {
            let offset = i * 64;
            let point_bytes: BytesN<64> = (&vk_ic.slice(offset..offset + 64))
                .try_into()
                .unwrap();
            store.set(&DataKey::VkIc(i), &point_bytes);
        }
    }

    /// Verify a Groth16 proof against the stored verification key.
    ///
    /// The proof is a serialized 256-byte Groth16 proof:
    ///   - A  (G1 point, 64 bytes)  — offset 0
    ///   - B  (G2 point, 128 bytes) — offset 64
    ///   - C  (G1 point, 64 bytes)  — offset 192
    ///
    /// Public inputs are BN254 field elements serialized as 32-byte
    /// big-endian values, packed contiguously in `public_inputs`.
    ///
    /// Uses the Groth16 pairing verification equation:
    ///   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1_T
    pub fn verify_proof(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Bytes,
    ) -> bool {
        let initialized: bool = match env.storage().instance().get(&DataKey::Initialized) {
            Some(v) => v,
            None => return false,
        };
        if !initialized {
            return false;
        }

        // --- Load verification key from storage ---
        let store = env.storage().instance();
        let alpha_g1_bytes: BytesN<64> = store.get(&DataKey::VkAlphaG1).unwrap();
        let beta_g2_bytes: BytesN<128> = store.get(&DataKey::VkBetaG2).unwrap();
        let gamma_g2_bytes: BytesN<128> = store.get(&DataKey::VkGammaG2).unwrap();
        let delta_g2_bytes: BytesN<128> = store.get(&DataKey::VkDeltaG2).unwrap();
        let ic_count: u32 = store.get(&DataKey::VkIcCount).unwrap();

        let alpha_g1 = Bn254G1Affine::from_bytes(alpha_g1_bytes);
        let beta_g2 = Bn254G2Affine::from_bytes(beta_g2_bytes);
        let gamma_g2 = Bn254G2Affine::from_bytes(gamma_g2_bytes);
        let delta_g2 = Bn254G2Affine::from_bytes(delta_g2_bytes);

        // --- Deserialize proof components from 256-byte blob ---
        let proof_arr = proof.to_array();

        let a_slice = extract_64(&env, &proof_arr, 0);
        let proof_a = Bn254G1Affine::from_bytes(a_slice);

        let b_slice = extract_128(&env, &proof_arr, 64);
        let proof_b = Bn254G2Affine::from_bytes(b_slice);

        let c_slice = extract_64(&env, &proof_arr, 192);
        let proof_c = Bn254G1Affine::from_bytes(c_slice);

        // --- Parse public inputs (flat Bytes, 32 bytes each) ---
        let input_len = public_inputs.len();
        let input_count = input_len / 32;
        if input_count == 0 || input_count + 1 > ic_count {
            return false;
        }

        // --- Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1]) ---
        let ic0_bytes: BytesN<64> = store.get(&DataKey::VkIc(0u32)).unwrap();
        let mut vk_x = Bn254G1Affine::from_bytes(ic0_bytes);

        let bn254 = env.crypto().bn254();
        for i in 0..input_count {
            let offset = i * 32;
            let input_bytes: BytesN<32> = (&public_inputs.slice(offset..offset + 32))
                .try_into()
                .unwrap();
            let input_fr = Fr::from_bytes(input_bytes);

            let ic_bytes: BytesN<64> = store.get(&DataKey::VkIc(i + 1)).unwrap();
            let ic_point = Bn254G1Affine::from_bytes(ic_bytes);
            let term = bn254.g1_mul(&ic_point, &input_fr);
            vk_x = bn254.g1_add(&vk_x, &term);
        }

        // --- Groth16 pairing check ---
        // e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1_T
        let neg_a = -proof_a;

        let mut vp1 = soroban_sdk::Vec::new(&env);
        let mut vp2 = soroban_sdk::Vec::new(&env);

        vp1.push_back(neg_a);
        vp2.push_back(proof_b);

        vp1.push_back(alpha_g1);
        vp2.push_back(beta_g2);

        vp1.push_back(vk_x);
        vp2.push_back(gamma_g2);

        vp1.push_back(proof_c);
        vp2.push_back(delta_g2);

        bn254.pairing_check(vp1, vp2)
    }
}

/// Extract a 64-byte slice from a [u8; 256] array as BytesN<64>.
fn extract_64(env: &Env, arr: &[u8; 256], offset: usize) -> BytesN<64> {
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&arr[offset..offset + 64]);
    BytesN::from_array(env, &buf)
}

/// Extract a 128-byte slice from a [u8; 256] array as BytesN<128>.
fn extract_128(env: &Env, arr: &[u8; 256], offset: usize) -> BytesN<128> {
    let mut buf = [0u8; 128];
    buf.copy_from_slice(&arr[offset..offset + 128]);
    BytesN::from_array(env, &buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::vec;

    #[test]
    fn verify_proof_returns_false_without_initialization() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VerifierContract);
        let client = VerifierContractClient::new(&env, &contract_id);

        let proof = BytesN::from_array(&env, &[0u8; 256]);
        let public_inputs = Bytes::from_array(&env, &[0u8; 32]);

        assert!(!client.verify_proof(&proof, &public_inputs));
    }

    #[test]
    fn set_vk_then_rejects_invalid_proof() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VerifierContract);
        let client = VerifierContractClient::new(&env, &contract_id);

        let alpha = BytesN::from_array(&env, &[1u8; 64]);
        let beta = BytesN::from_array(&env, &[2u8; 128]);
        let gamma = BytesN::from_array(&env, &[3u8; 128]);
        let delta = BytesN::from_array(&env, &[4u8; 128]);
        let ic_flat = Bytes::from_array(&env, &[5u8; 64]);

        client.set_verification_key(&alpha, &beta, &gamma, &delta, &ic_flat, &1u32);

        // A zeroed proof should fail pairing check.
        let proof = BytesN::from_array(&env, &[0u8; 256]);
        let public_inputs = Bytes::from_array(&env, &[0u8; 32]);

        assert!(!client.verify_proof(&proof, &public_inputs));
    }
}
