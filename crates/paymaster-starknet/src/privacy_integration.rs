#![allow(unused)]

use serde::Deserialize;
use starknet::accounts::ExecutionEncoding;
use starknet::core::types::{BlockId, BlockTag, Call, Felt};
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

/// Acc1: account with canonical viewing key (key < MAX_VIEWING_KEY)
const USER_ADDRESS: Felt = felt!("0x25405558840d3e0fe1f3b41cceaa9f2efdeca7fadf62e158daa2e309e64c3a3");
const USER_VIEWING_KEY: Felt = felt!("0x254055ba847c3e93cfb4b24e1ee07c66e6e91a6a0de81ee3fdd87a97f3d8b76");

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
async fn prove_transaction(user_address: Felt, viewing_key: Felt, client_actions_calldata: &[Felt]) -> (Vec<u64>, Vec<Felt>, Vec<Felt>) {
    // Build execute_view inner calldata: [user_addr, viewing_key, ...client_actions]
    let mut execute_view_cd: Vec<String> = vec![format!("{:#x}", user_address), format!("{:#x}", viewing_key)];
    for f in client_actions_calldata {
        execute_view_cd.push(format!("{:#x}", f));
    }

    // Build __execute__ calldata: [1, pool, selector, data_len, ...execute_view_calldata]
    let ev_selector = selector!("execute_view");
    let mut calldata: Vec<String> = vec![
        "0x1".to_string(),
        format!("{:#x}", POOL_ADDRESS),
        format!("{:#x}", ev_selector),
        format!("{:#x}", Felt::from(execute_view_cd.len())),
    ];
    calldata.extend(execute_view_cd);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "starknet_proveTransaction",
        "params": {
            "block_id": "latest",
            "transaction": {
                "type": "INVOKE",
                "version": "0x3",
                "sender_address": format!("{:#x}", POOL_ADDRESS),
                "calldata": calldata,
                "signature": ["0x0", "0x0"],
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

    // Decode proof from base64 to Vec<u64>
    use base64::Engine;
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(&result.proof)
        .expect("Invalid base64 proof");
    let proof: Vec<u64> = proof_bytes
        .chunks(8)
        .map(|chunk| {
            let mut arr = [0u8; 8];
            arr[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(arr)
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

mod estimate_with_proof {
    use super::*;

    // #[tokio::test]
    // async fn should_estimate_fee_when_set_viewing_key() {
    //     // Given
    //     let account = devnet_account().await;
    //
    //     // ClientAction::SetViewingKey (variant 0) with random=0x42
    //     // Span serialization: [span_len=1, variant_index=0, random]
    //     let client_actions = vec![Felt::from(1u64), Felt::ZERO, Felt::from(0x42u64)];
    //
    //     // Prove via proving service
    //     let (proof, proof_facts, server_actions) =
    //         prove_transaction(USER_ADDRESS, USER_VIEWING_KEY, &client_actions).await;
    //
    //     // Build apply_actions call with server_actions from the proof
    //     let apply_actions_call = Call {
    //         to: POOL_ADDRESS,
    //         selector: selector!("apply_actions"),
    //         calldata: server_actions,
    //     };
    //     let calls = Calls::new(vec![apply_actions_call]);
    //     let proof_data = PrivateProofData { proof, proof_facts };
    //
    //     // When
    //     let result: Result<EstimatedCalls, Error> =
    //         calls.estimate_with_proof(&account, Some(0), &proof_data).await;
    //
    //     // Then
    //     assert!(result.is_ok(), "Estimation failed: {:?}", result.err());
    // }

    // #[tokio::test]
    // async fn should_estimate_fee_when_deposit() {
    //     // Given
    //     let account = devnet_account().await;
    //
    //     // ClientAction::Deposit (variant 5): token + amount
    //     // Span serialization: [span_len=1, variant_index=5, token, amount]
    //     let amount = Felt::from(1u64);
    //     let client_actions = vec![Felt::from(1u64), Felt::from(5u64), STRK_FEE_TOKEN, amount];
    //
    //     // Prove via proving service
    //     let (proof, proof_facts, server_actions) =
    //         prove_transaction(USER_ADDRESS, USER_VIEWING_KEY, &client_actions).await;
    //
    //     // Build calls: approve + apply_actions
    //     let approve_call = Call {
    //         to: STRK_FEE_TOKEN,
    //         selector: selector!("approve"),
    //         calldata: vec![POOL_ADDRESS, amount, Felt::ZERO], // u256(low, high)
    //     };
    //     let apply_actions_call = Call {
    //         to: POOL_ADDRESS,
    //         selector: selector!("apply_actions"),
    //         calldata: server_actions,
    //     };
    //     let calls = Calls::new(vec![approve_call, apply_actions_call]);
    //     let proof_data = PrivateProofData { proof, proof_facts };
    //
    //     // When
    //     let result: Result<EstimatedCalls, Error> =
    //         calls.estimate_with_proof(&account, Some(0), &proof_data).await;
    //
    //     // Then
    //     assert!(result.is_ok(), "Estimation failed: {:?}", result.err());
    // }
}
