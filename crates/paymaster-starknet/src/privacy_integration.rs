#![allow(unused)]

use serde::Deserialize;
use starknet::accounts::ExecutionEncoding;
use starknet::core::crypto::{ecdsa_sign, HashFunction};
use starknet::core::types::{BlockId, BlockTag, Call, Felt, FunctionCall};
use starknet::macros::{felt, selector};
use starknet::providers::Provider;
use starknet::signers::{LocalWallet, SigningKey};

use crate::client::StarknetClient;
use crate::transaction::{Calls, EstimatedCalls, PrivateProofData};
use crate::{Error, StarknetAccount};

/// Pathfinder RPC endpoint for Privacy Integration env
const PATHFINDER_RPC: &str = "http://34.170.239.64:9545/rpc/v0_10";
/// Proving service endpoint
const PROVING_SERVICE_URL: &str = "http://136.115.124.93:3000";

/// Pool with proof validation enabled
const POOL_ADDRESS: Felt = felt!("0x2540a0877b7955ab018e0f313666a9bad629a16ce94009da62b44c9aa12a086");

/// OZ Admin account (used for estimation and gas)
const ADMIN_ADDRESS: Felt = felt!("0x048baf3ed1f0a03840186bd95063f63824d93bafd456439bfe667533437d9c91");
const ADMIN_PRIVATE_KEY: Felt = felt!("0x7021e74994902199b1fa41785e15ade56f3ba5d208818b620a3741e68845d94");

/// Account used for privacy integration tests
const USER_ADDRESS: Felt = felt!("0x048baf3ed1f0a03840186bd95063f63824d93bafd456439bfe667533437d9c91");
const USER_VIEWING_KEY: Felt = felt!("0x3021e74994902111b1fa41785e15ade7b3331263b143f9d117022fd91a136fd");

/// STRK fee token address on Privacy Integration env
const STRK_FEE_TOKEN: Felt = felt!("0x70a5da4f557b77a9c54546e4bcc900806e28793d8e3eaaa207428d2387249b7");

fn devnet_client() -> StarknetClient {
    StarknetClient::new(PATHFINDER_RPC, 30)
}

async fn devnet_account() -> StarknetAccount {
    let client = devnet_client();
    let chain_id = client.chain_id().await.unwrap();
    let signer = LocalWallet::from_signing_key(SigningKey::from_secret_scalar(ADMIN_PRIVATE_KEY));
    let mut account = StarknetAccount::new(client, signer, ADMIN_ADDRESS, chain_id, ExecutionEncoding::New);
    account.set_block_id(BlockId::Tag(BlockTag::Latest));
    account
}

// --- Proving Service Client ---

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ProveResult {
    proof: String,
    proof_facts: Vec<String>,
    l2_to_l1_messages: Vec<L2ToL1Msg>,
}

#[derive(Deserialize)]
struct L2ToL1Msg {
    from_address: String,
    #[allow(dead_code)]
    to_address: String,
    payload: Vec<String>,
}

/// Call the proving service to prove a privacy transaction.
///
/// Builds an INVOKE_TXN_V3 wrapping `execute_view(user, viewing_key, client_actions)`
/// on the pool, sends it to the proving service, and returns:
/// - `proof`: STARK proof as Vec<u64> (decoded from base64)
/// - `proof_facts`: proof metadata as Vec<Felt>
/// - `server_actions`: server actions calldata for apply_actions (from L2->L1 message)
/// Compute INVOKE V3 transaction hash for the proving invocation.
///
/// Matches the hash computation from starknet-rs RawExecutionV3::transaction_hash.
/// The sender is the pool address (not the user), matching the SDK's behavior.
fn compute_proof_invoke_hash(calldata_felts: &[Felt], chain_id: Felt) -> Felt {
    // PREFIX_INVOKE = cairo short string for "invoke"
    let prefix_invoke = Felt::from_raw([
        513_398_556_346_534_256,
        18_446_744_073_709_551_615,
        18_446_744_073_709_551_615,
        18_443_034_532_770_911_073,
    ]);

    let poseidon = HashFunction::poseidon();
    let mut hasher = poseidon.stateful();

    hasher.update(prefix_invoke);
    hasher.update(Felt::THREE); // version 3
    hasher.update(POOL_ADDRESS); // sender = pool

    // Fee hash
    let fee_hash = {
        let mut fee_hasher = poseidon.stateful();
        fee_hasher.update(Felt::ZERO); // tip = 0

        // L1_GAS: max_amount=1, max_price=0
        let mut buf = [0u8; 32];
        buf[2..8].copy_from_slice(&[b'L', b'1', b'_', b'G', b'A', b'S']);
        buf[8..16].copy_from_slice(&1u64.to_be_bytes());
        // buf[16..32] already zero (max_price=0)
        fee_hasher.update(Felt::from_bytes_be(&buf));

        // L2_GAS: max_amount=0x989680, max_price=0
        let mut buf = [0u8; 32];
        buf[2..8].copy_from_slice(&[b'L', b'2', b'_', b'G', b'A', b'S']);
        buf[8..16].copy_from_slice(&0x989680u64.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&buf));

        // L1_DATA: max_amount=1, max_price=0
        let mut buf = [0u8; 32];
        buf[1..8].copy_from_slice(&[b'L', b'1', b'_', b'D', b'A', b'T', b'A']);
        buf[8..16].copy_from_slice(&1u64.to_be_bytes());
        fee_hasher.update(Felt::from_bytes_be(&buf));

        fee_hasher.finalize()
    };
    hasher.update(fee_hash);

    // Empty paymaster_data
    hasher.update(poseidon.stateful().finalize());

    hasher.update(chain_id);
    hasher.update(Felt::ZERO); // nonce = 0

    // DA mode: L1 for both nonce and fee → 0
    hasher.update(Felt::ZERO);

    // Empty account_deployment_data
    hasher.update(poseidon.stateful().finalize());

    // Calldata hash
    let calldata_hash = {
        let mut cd_hasher = poseidon.stateful();
        for f in calldata_felts {
            cd_hasher.update(*f);
        }
        cd_hasher.finalize()
    };
    hasher.update(calldata_hash);

    hasher.finalize()
}

async fn prove_transaction(user_address: Felt, viewing_key: Felt, client_actions_calldata: &[Felt]) -> (Vec<u64>, Vec<Felt>, Vec<Felt>) {
    // Build execute_view inner calldata: [user_addr, viewing_key, ...client_actions]
    let mut execute_view_cd: Vec<Felt> = vec![user_address, viewing_key];
    execute_view_cd.extend_from_slice(client_actions_calldata);

    // Build __execute__ calldata: [1, pool, selector, data_len, ...execute_view_calldata]
    let ev_selector = selector!("execute_view");
    let mut calldata_felts: Vec<Felt> = vec![
        Felt::ONE,
        POOL_ADDRESS,
        ev_selector,
        Felt::from(execute_view_cd.len()),
    ];
    calldata_felts.extend(&execute_view_cd);

    // Get chain ID and block number from RPC
    let provider = devnet_client();
    let chain_id = provider.chain_id().await.unwrap();
    let block_number = provider.block_number().await.unwrap();
    // Use an older block to satisfy the pool's finality constraint (proof must not be too recent)
    let proof_block = block_number.saturating_sub(20);

    // Compute INVOKE V3 transaction hash and sign with user's private key
    let tx_hash = compute_proof_invoke_hash(&calldata_felts, chain_id);
    let signature = ecdsa_sign(&ADMIN_PRIVATE_KEY, &tx_hash).unwrap();

    let calldata: Vec<String> = calldata_felts.iter().map(|f| format!("{:#x}", f)).collect();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_proveTransaction",
        "params": {
            "block_id": { "block_number": proof_block },
            "transaction": {
                "type": "INVOKE",
                "version": "0x3",
                "sender_address": format!("{:#x}", POOL_ADDRESS),
                "calldata": calldata,
                "signature": [format!("{:#x}", signature.r), format!("{:#x}", signature.s)],
                "nonce": "0x0",
                "resource_bounds": {
                    "l1_gas": { "max_amount": "0x1", "max_price_per_unit": "0x0" },
                    "l2_gas": { "max_amount": "0x989680", "max_price_per_unit": "0x0" },
                    "l1_data_gas": { "max_amount": "0x1", "max_price_per_unit": "0x0" }
                },
                "tip": "0x0",
                "paymaster_data": [],
                "account_deployment_data": [],
                "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1"
            }
        }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(PROVING_SERVICE_URL)
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .expect("Failed to reach proving service");

    let json: JsonRpcResponse<ProveResult> = resp.json().await.expect("Invalid JSON response");
    if let Some(error) = json.error {
        panic!("Proving service error: {}", error);
    }

    let result = json.result.expect("No result from proving service");

    // Decode proof from base64 to Vec<u64>.
    // The starknet-rust provider serializes Vec<u64> as 4-byte LE chunks (u32 cast to u64),
    // so we must decode the raw proof bytes the same way.
    use base64::Engine;
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(&result.proof)
        .expect("Invalid base64 proof");
    let proof: Vec<u64> = proof_bytes
        .chunks(4)
        .map(|chunk| {
            let mut arr = [0u8; 4];
            arr[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(arr) as u64
        })
        .collect();

    // Convert proof_facts hex strings to Vec<Felt>
    let proof_facts: Vec<Felt> = result
        .proof_facts
        .iter()
        .map(|s| Felt::from_hex(s).expect("Invalid proof_facts hex"))
        .collect();

    // Extract server_actions from L2-to-L1 message (from_address = pool)
    let pool_message = result
        .l2_to_l1_messages
        .iter()
        .find(|m| Felt::from_hex(&m.from_address).map(|f| f == POOL_ADDRESS).unwrap_or(false))
        .expect("No L2-to-L1 message from pool");

    let server_actions: Vec<Felt> = pool_message
        .payload
        .iter()
        .map(|s| Felt::from_hex(s).expect("Invalid server_actions hex"))
        .collect();

    (proof, proof_facts, server_actions)
}

/// Expected on-chain public key derived from USER_VIEWING_KEY via STARK curve.
const EXPECTED_PUBLIC_KEY: Felt = felt!("0x57132cd4e29cca8366719e74f937f8f397e1be7c647b47ce12c73fd6b78cf30");

#[tokio::test]
async fn should_have_correct_viewing_key_set_on_chain() {
    let client = devnet_client();
    let public_key = client
        .call(
            FunctionCall {
                contract_address: POOL_ADDRESS,
                entry_point_selector: selector!("get_public_key"),
                calldata: vec![USER_ADDRESS],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
        .expect("get_public_key call failed");

    assert_eq!(public_key.len(), 1, "Expected single felt return value");
    assert_eq!(
        public_key[0], EXPECTED_PUBLIC_KEY,
        "On-chain public key does not match expected value derived from viewing key {:#x}",
        USER_VIEWING_KEY
    );
}

mod estimate_with_proof {
    use super::*;

    #[tokio::test]
    #[ignore = "Requires external proving service and clean on-chain state"]
    async fn should_estimate_fee_when_set_viewing_key() {
        // Given
        let account = devnet_account().await;

        // ClientAction::SetViewingKey (variant 0) with random=0x42
        // Span serialization: [span_len=1, variant_index=0, random]
        let client_actions = vec![Felt::from(1u64), Felt::ZERO, Felt::from(0x42u64)];

        // Prove via proving service
        let (proof, proof_facts, server_actions) =
            prove_transaction(USER_ADDRESS, USER_VIEWING_KEY, &client_actions).await;

        // Build apply_actions call with server_actions from the proof
        let apply_actions_call = Call {
            to: POOL_ADDRESS,
            selector: selector!("apply_actions"),
            calldata: server_actions,
        };
        let calls = Calls::new(vec![apply_actions_call]);
        let proof_data = PrivateProofData { proof, proof_facts };

        // When
        let result: Result<EstimatedCalls, Error> =
            calls.estimate_with_proof(&account, Some(0), &proof_data).await;

        // Then
        assert!(result.is_ok(), "Estimation failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn should_estimate_fee_when_deposit() {
        // Given
        let account = devnet_account().await;

        // ClientAction::Deposit (variant 5): token + amount
        // Span serialization: [span_len=1, variant_index=5, token, amount]
        let amount = Felt::from(1u64);
        let client_actions = vec![Felt::from(1u64), Felt::from(5u64), STRK_FEE_TOKEN, amount];

        // Prove via proving service
        let (proof, proof_facts, server_actions) =
            prove_transaction(USER_ADDRESS, USER_VIEWING_KEY, &client_actions).await;

        // Build calls: approve + apply_actions
        let approve_call = Call {
            to: STRK_FEE_TOKEN,
            selector: selector!("approve"),
            calldata: vec![POOL_ADDRESS, amount, Felt::ZERO], // u256(low, high)
        };
        let apply_actions_call = Call {
            to: POOL_ADDRESS,
            selector: selector!("apply_actions"),
            calldata: server_actions,
        };
        let calls = Calls::new(vec![approve_call, apply_actions_call]);
        let proof_data = PrivateProofData { proof, proof_facts };

        // When
        let result: Result<EstimatedCalls, Error> =
            calls.estimate_with_proof(&account, Some(0), &proof_data).await;

        // Then
        assert!(result.is_ok(), "Estimation failed: {:?}", result.err());
    }
}
