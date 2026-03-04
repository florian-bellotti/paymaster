#![allow(unused)]

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use paymaster_prices::mock::MockPriceOracle;
use paymaster_prices::{PriceConfiguration, TokenPrice};
use paymaster_relayer::lock::mock::MockLockLayer;
use paymaster_relayer::lock::{LockLayerConfiguration, RelayerLock};
use paymaster_relayer::RelayersConfiguration;
use serde::Deserialize;
use starknet::core::types::{BlockId, BlockTag, Call, Felt};
use starknet::macros::{felt, selector};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};

use crate::execution::TipPriority;
use crate::{Client, Configuration};

use paymaster_starknet::transaction::{Calls, PrivateProofData};
use paymaster_starknet::{ChainID, Configuration as StarknetConfiguration, StarknetAccountConfiguration};

/// Pathfinder RPC endpoint for Privacy Integration env
const PATHFINDER_RPC: &str = "http://34.170.239.64:9545/rpc/v0_10";
/// Proving service endpoint
const PROVING_SERVICE_URL: &str = "http://136.115.124.93:3000";

/// Pool with proof validation enabled
const POOL_ADDRESS: Felt = felt!("0x2540a0877b7955ab018e0f313666a9bad629a16ce94009da62b44c9aa12a086");

/// OZ Admin account (used for estimation, gas tank)
const ADMIN_ADDRESS: Felt = felt!("0x048baf3ed1f0a03840186bd95063f63824d93bafd456439bfe667533437d9c91");
const ADMIN_PRIVATE_KEY: Felt = felt!("0x7021e74994902199b1fa41785e15ade56f3ba5d208818b620a3741e68845d94");

/// Relayer account on Privacy Integration env
const RELAYER_ADDRESS: Felt = felt!("0x50ac57b136e4a5c99bff5bfaee3df7a67bd1ae031f2c3a8710d3c90f44a9250");
const RELAYER_PRIVATE_KEY: Felt = felt!("0x460da728cca654d756dd051490d34f5db5124351e2c10b0bb2187d28b95d6d2");

/// Acc1: account with canonical viewing key (key < MAX_VIEWING_KEY)
const USER_ADDRESS: Felt = felt!("0x25405558840d3e0fe1f3b41cceaa9f2efdeca7fadf62e158daa2e309e64c3a3");
const USER_VIEWING_KEY: Felt = felt!("0x254055ba847c3e93cfb4b24e1ee07c66e6e91a6a0de81ee3fdd87a97f3d8b76");

/// STRK fee token address on Privacy Integration env
const STRK_FEE_TOKEN: Felt = felt!("0x70a5da4f557b77a9c54546e4bcc900806e28793d8e3eaaa207428d2387249b7");
/// OZ ERC20 token on Privacy Integration env
const OZ_ERC20_TOKEN: Felt = felt!("0x7b19e89252b1ee5d7ff07a0e0e278b16b058f322053f799469b969e31b82969");

// --- Mock layers for the execution Client ---

#[derive(Debug, Clone)]
struct NoOpPriceOracle;

#[async_trait]
impl MockPriceOracle for NoOpPriceOracle {
    fn new() -> Self {
        Self
    }

    async fn fetch_token(&self, _: Felt) -> Result<TokenPrice, paymaster_prices::Error> {
        Ok(TokenPrice {
            address: Felt::ZERO,
            price_in_strk: Felt::from(1e18 as u128),
            decimals: 18,
        })
    }
}

#[derive(Debug)]
struct NoOpLockLayer;

#[async_trait]
impl MockLockLayer for NoOpLockLayer {
    fn new() -> Self {
        Self
    }

    async fn count_enabled_relayers(&self) -> usize {
        1
    }

    async fn set_enabled_relayers(&self, _: &HashSet<Felt>) {}

    async fn lock_relayer(&self) -> Result<RelayerLock, paymaster_relayer::lock::Error> {
        Ok(RelayerLock::new(RELAYER_ADDRESS, None, Duration::from_secs(5)))
    }

    async fn release_relayer(&self, _: RelayerLock) -> Result<(), paymaster_relayer::lock::Error> {
        Ok(())
    }
}

/// Build a `paymaster_execution::Client` wired to the real Privacy Integration Pathfinder RPC.
fn build_privacy_client() -> Client {
    let config = Configuration {
        starknet: StarknetConfiguration {
            chain_id: ChainID::Integration,
            endpoint: PATHFINDER_RPC.to_string(),
            timeout: 30,
            fallbacks: vec![],
        },
        estimate_account: StarknetAccountConfiguration {
            address: ADMIN_ADDRESS,
            private_key: ADMIN_PRIVATE_KEY,
        },
        gas_tank: StarknetAccountConfiguration {
            address: ADMIN_ADDRESS,
            private_key: ADMIN_PRIVATE_KEY,
        },
        max_fee_multiplier: 3.0,
        provider_fee_overhead: 0.1,
        supported_tokens: HashSet::new(),
        price: PriceConfiguration::mock::<NoOpPriceOracle>(),
        relayers: RelayersConfiguration {
            private_key: RELAYER_PRIVATE_KEY,
            addresses: vec![RELAYER_ADDRESS],
            min_relayer_balance: Felt::ZERO,
            lock: LockLayerConfiguration::mock_with_timeout::<NoOpLockLayer>(Duration::from_secs(5)),
            rebalancing: paymaster_relayer::rebalancing::OptionalRebalancingConfiguration::initialize(None),
        },
    };

    Client::new(&config)
}

/// Create a raw JSON-RPC provider for fetching block information.
fn rpc_provider() -> JsonRpcClient<HttpTransport> {
    JsonRpcClient::new(HttpTransport::new(Url::parse(PATHFINDER_RPC).unwrap()))
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

// --- Tests ---
// These tests verify the new execute-only flow (no build, no pool config).
// The wallet builds calls + proof, paymaster just estimates and executes.

// #[tokio::test]
// async fn should_estimate_set_viewing_key_through_execution_client() {
//     let execution_client = build_privacy_client();
//
//     // ClientAction::SetViewingKey (variant 0) with random=0x42
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
//     let result = execution_client
//         .estimate_with_proof(&calls, TipPriority::Custom(0), &proof_data)
//         .await;
//
//     assert!(result.is_ok(), "estimate_with_proof failed: {:?}", result.err());
//     let estimated = result.unwrap();
//     assert!(estimated.estimate().overall_fee > 0, "Overall fee should be positive");
// }

// #[tokio::test]
// async fn should_execute_set_viewing_key_through_execution_client() {
//     let execution_client = build_privacy_client();
//
//     // ClientAction::SetViewingKey (variant 0) with random=0x42
//     let client_actions = vec![Felt::from(1u64), Felt::ZERO, Felt::from(0x42u64)];
//
//     // Prove via proving service
//     let (proof, proof_facts, server_actions) =
//         prove_transaction(USER_ADDRESS, USER_VIEWING_KEY, &client_actions).await;
//
//     // Build apply_actions call
//     let apply_actions_call = Call {
//         to: POOL_ADDRESS,
//         selector: selector!("apply_actions"),
//         calldata: server_actions,
//     };
//     let calls = Calls::new(vec![apply_actions_call]);
//     let proof_data = PrivateProofData { proof, proof_facts };
//
//     // Estimate first
//     let estimated = execution_client
//         .estimate_with_proof(&calls, TipPriority::Custom(0), &proof_data)
//         .await
//         .expect("estimate_with_proof failed");
//
//     // Execute
//     let result = execution_client.execute(&estimated, Some(&proof_data)).await;
//
//     assert!(result.is_ok(), "execute failed: {:?}", result.err());
//     let tx_result = result.unwrap();
//     assert_ne!(tx_result.transaction_hash, Felt::ZERO, "Transaction hash should be non-zero");
// }
