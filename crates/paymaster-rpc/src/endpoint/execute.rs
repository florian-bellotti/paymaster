use paymaster_common::{measure_duration, metric};
use paymaster_execution::ExecutableTransaction;
use paymaster_starknet::transaction::{CalldataBuilder, Calls, ExecuteFromOutsideMessage, PrivateProofData};
use paymaster_starknet::Signature;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet::core::serde::unsigned_field_element::UfeHex;
use starknet::core::types::{Call, Felt, TypedData};
use starknet::macros::selector;

use crate::endpoint::common::{DeploymentParameters, ExecutionParameters};
use crate::endpoint::validation::check_service_is_available;
use crate::endpoint::RequestContext;
use crate::Error;

#[derive(Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub transaction: ExecutableTransactionParameters,
    pub parameters: ExecutionParameters,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutableTransactionParameters {
    Deploy {
        deployment: DeploymentParameters,
    },
    Invoke {
        invoke: ExecutableInvokeParameters,
    },
    DeployAndInvoke {
        deployment: DeploymentParameters,
        invoke: ExecutableInvokeParameters,
    },
    PrivateInvoke {
        private_invoke: ExecutablePrivateInvokeParameters,
    },
}

impl TryFrom<ExecutableTransactionParameters> for paymaster_execution::ExecutableTransactionParameters {
    type Error = Error;

    fn try_from(value: ExecutableTransactionParameters) -> Result<Self, Self::Error> {
        Ok(match value {
            ExecutableTransactionParameters::Deploy { deployment } => Self::Deploy { deployment: deployment.into() },
            ExecutableTransactionParameters::Invoke { invoke } => Self::Invoke { invoke: invoke.try_into()? },
            ExecutableTransactionParameters::DeployAndInvoke { deployment, invoke } => Self::DeployAndInvoke {
                deployment: deployment.into(),
                invoke: invoke.try_into()?,
            },
            ExecutableTransactionParameters::PrivateInvoke { .. } => {
                // PrivateInvoke is handled separately in execute_endpoint before this conversion
                unreachable!("PrivateInvoke should be handled before conversion")
            },
        })
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ExecutableInvokeParameters {
    #[serde_as(as = "UfeHex")]
    pub user_address: Felt,

    pub typed_data: TypedData,

    #[serde_as(as = "Vec<UfeHex>")]
    pub signature: Signature,
}

impl TryFrom<ExecutableInvokeParameters> for paymaster_execution::ExecutableInvokeParameters {
    type Error = Error;

    fn try_from(value: ExecutableInvokeParameters) -> Result<Self, Self::Error> {
        let result = Self::new(value.user_address, value.typed_data, value.signature)?;

        Ok(result)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ExecutablePrivateInvokeParameters {
    #[serde_as(as = "Option<UfeHex>")]
    #[serde(default)]
    pub user_address: Option<Felt>,

    #[serde(default)]
    pub typed_data: Option<TypedData>,

    #[serde_as(as = "Option<Vec<UfeHex>>")]
    #[serde(default)]
    pub signature: Option<Signature>,

    pub calls: Vec<Call>,

    pub proof: Vec<u64>,

    #[serde_as(as = "Vec<UfeHex>")]
    pub proof_facts: Vec<Felt>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecuteResponse {
    #[serde_as(as = "UfeHex")]
    pub transaction_hash: Felt,

    #[serde_as(as = "UfeHex")]
    pub tracking_id: Felt,
}

pub async fn execute_endpoint(ctx: &RequestContext<'_>, request: ExecuteRequest) -> Result<ExecuteResponse, Error> {
    check_service_is_available(ctx).await?;

    // Handle PrivateInvoke separately before converting to execution types
    if let ExecutableTransactionParameters::PrivateInvoke { private_invoke } = &request.transaction {
        let execution_params: paymaster_execution::ExecutionParameters = request.parameters.into();
        return execute_private_invoke(ctx, private_invoke, execution_params).await;
    }

    let execution_params: paymaster_execution::ExecutionParameters = request.parameters.into();
    let transaction_params: paymaster_execution::ExecutableTransactionParameters = request.transaction.try_into()?;
    ctx.transaction_filter.filter(&transaction_params)?;

    let transaction = ExecutableTransaction {
        forwarder: ctx.configuration.forwarder,
        gas_tank_address: ctx.configuration.gas_tank.address,
        parameters: execution_params,
        transaction: transaction_params,
    };

    let estimated_transaction = if transaction.parameters.fee_mode().is_sponsored() {
        let authenticated_api_key = ctx.validate_api_key().await?;
        transaction
            .estimate_sponsored_transaction(&ctx.execution, authenticated_api_key.sponsor_metadata)
            .await?
    } else {
        transaction.estimate_transaction(&ctx.execution).await?
    };

    let result = estimated_transaction.execute(&ctx.execution).await?;

    Ok(ExecuteResponse {
        transaction_hash: result.transaction_hash,
        tracking_id: Felt::ZERO,
    })
}

async fn execute_private_invoke(
    ctx: &RequestContext<'_>,
    params: &ExecutablePrivateInvokeParameters,
    execution_params: paymaster_execution::ExecutionParameters,
) -> Result<ExecuteResponse, Error> {
    // Privacy transactions must be sponsored
    if !execution_params.fee_mode().is_sponsored() {
        return Err(Error::PrivacyRequiresSponsoring);
    }

    // Validate proof data is present
    if params.proof.is_empty() || params.proof_facts.is_empty() {
        return Err(Error::PrivacyProofMissing);
    }

    let proof_data = PrivateProofData {
        proof: params.proof.clone(),
        proof_facts: params.proof_facts.clone(),
    };

    // Validate and get sponsor metadata
    let authenticated_api_key = ctx.validate_api_key().await?;

    // Build call list: optionally prepend execute_from_outside (for approve wrapping)
    let mut all_calls = vec![];
    if let (Some(typed_data), Some(signature), Some(user_address)) =
        (&params.typed_data, &params.signature, &params.user_address)
    {
        let message = ExecuteFromOutsideMessage::from_typed_data(typed_data)?;
        let execute_from_outside_call = message.to_call(*user_address, signature);
        all_calls.push(execute_from_outside_call);
    }
    all_calls.extend(params.calls.clone());

    // Wrap calls in forwarder's execute_sponsored_calls for tracking
    let forwarder_call = build_execute_sponsored_calls_call(
        ctx.configuration.forwarder,
        &all_calls,
        &authenticated_api_key.sponsor_metadata,
    );
    let calls = Calls::new(vec![forwarder_call]);

    // Estimate with proof data
    let estimated_calls = ctx
        .execution
        .estimate_with_proof(&calls, execution_params.tip(), &proof_data)
        .await?;

    // Execute with proof data
    let (result, duration) = measure_duration!(ctx.execution.execute(&estimated_calls, Some(&proof_data)).await);

    metric!(counter[privacy_execution_request] = 1);
    metric!(histogram[privacy_execution_request_duration_milliseconds] = duration.as_millis());

    match result {
        Ok(result) => Ok(ExecuteResponse {
            transaction_hash: result.transaction_hash,
            tracking_id: Felt::ZERO,
        }),
        Err(e) => {
            metric!(counter[privacy_execution_request_error] = 1, error = e.to_string());
            Err(e.into())
        },
    }
}

/// Build a call to the forwarder's `execute_sponsored_calls` entry point.
///
/// Serializes `calls` as a Cairo `Array<Call>` and appends `sponsor_metadata` as `Span<felt252>`.
fn build_execute_sponsored_calls_call(forwarder: Felt, calls: &[Call], sponsor_metadata: &[Felt]) -> Call {
    let calls_vec: Vec<Call> = calls.to_vec();
    let metadata_vec: Vec<Felt> = sponsor_metadata.to_vec();

    Call {
        to: forwarder,
        selector: selector!("execute_sponsored_calls"),
        calldata: CalldataBuilder::new().encode(&calls_vec).encode(&metadata_vec).build(),
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::endpoint::build::{build_transaction_endpoint, BuildTransactionRequest, BuildTransactionResponse, InvokeParameters, TransactionParameters};
    use crate::endpoint::common::{ExecutionParameters, FeeMode, TipPriority};
    use crate::endpoint::execute::{execute_endpoint, ExecutableInvokeParameters, ExecutableTransactionParameters, ExecuteRequest};
    use crate::endpoint::RequestContext;
    use crate::testing::TestEnvironment;
    use crate::{Error, InvokeTransaction};
    use async_trait::async_trait;
    use paymaster_prices::mock::MockPriceOracle;
    use paymaster_prices::TokenPrice;
    use paymaster_starknet::testing::transaction::an_eth_transfer;
    use paymaster_starknet::testing::TestEnvironment as StarknetTestEnvironment;
    use starknet::core::types::Felt;
    use starknet::signers::SigningKey;

    #[derive(Debug, Clone)]
    struct NoPriceOracle;

    #[async_trait]
    impl MockPriceOracle for NoPriceOracle {
        fn new() -> Self
        where
            Self: Sized,
        {
            Self
        }

        async fn fetch_token(&self, _: Felt) -> Result<TokenPrice, paymaster_prices::Error> {
            Ok(TokenPrice {
                address: Felt::ZERO,
                price_in_strk: Felt::ZERO,
                decimals: 18,
            })
        }
    }

    // TODO: enable when we can fix starknet image
    #[ignore]
    #[tokio::test]
    async fn return_error_if_not_available() {
        let test = TestEnvironment::new().await;

        let mut context = test.context().clone();

        let build_request = BuildTransactionRequest {
            transaction: TransactionParameters::Invoke {
                invoke: InvokeParameters {
                    user_address: StarknetTestEnvironment::ACCOUNT_ARGENT_1.address,
                    calls: vec![an_eth_transfer(StarknetTestEnvironment::ACCOUNT_2.address, Felt::ONE)],
                },
            },
            parameters: ExecutionParameters::V1 {
                fee_mode: FeeMode::Default {
                    gas_token: StarknetTestEnvironment::ETH,
                    tip: TipPriority::Normal,
                },
                time_bounds: None,
            },
        };

        let build_response = build_transaction_endpoint(&RequestContext::empty(&context), build_request)
            .await
            .unwrap();
        let BuildTransactionResponse::Invoke(InvokeTransaction { typed_data, .. }) = build_response else {
            unreachable!()
        };

        // set no token available
        context.price = paymaster_prices::Client::mock::<NoPriceOracle>();

        let request = ExecuteRequest {
            transaction: ExecutableTransactionParameters::Invoke {
                invoke: ExecutableInvokeParameters {
                    user_address: Felt::ZERO,
                    typed_data,
                    signature: vec![Felt::ZERO, Felt::ZERO],
                },
            },
            parameters: ExecutionParameters::V1 {
                fee_mode: FeeMode::Default {
                    gas_token: StarknetTestEnvironment::ETH,
                    tip: TipPriority::Normal,
                },
                time_bounds: None,
            },
        };

        let result = execute_endpoint(&RequestContext::empty(&context), request).await;
        assert!(matches!(result, Err(Error::ServiceNotAvailable)))
    }

    // TODO: enable when we can fix starknet image
    #[ignore]
    #[tokio::test]
    async fn execute_works_properly() {
        let test = TestEnvironment::new().await;
        let request_context = RequestContext::empty(&test.context());

        let build_request = BuildTransactionRequest {
            transaction: TransactionParameters::Invoke {
                invoke: InvokeParameters {
                    user_address: StarknetTestEnvironment::ACCOUNT_ARGENT_1.address,
                    calls: vec![an_eth_transfer(StarknetTestEnvironment::ACCOUNT_2.address, Felt::ONE)],
                },
            },
            parameters: ExecutionParameters::V1 {
                fee_mode: FeeMode::Default {
                    gas_token: StarknetTestEnvironment::ETH,
                    tip: TipPriority::Normal,
                },
                time_bounds: None,
            },
        };

        let build_response = build_transaction_endpoint(&request_context, build_request).await.unwrap();
        let BuildTransactionResponse::Invoke(InvokeTransaction { typed_data, .. }) = build_response else {
            unreachable!()
        };

        let message_hash = typed_data
            .message_hash(StarknetTestEnvironment::ACCOUNT_ARGENT_1.address)
            .unwrap();
        let signature = SigningKey::from_secret_scalar(StarknetTestEnvironment::ACCOUNT_ARGENT_1.private_key)
            .sign(&message_hash)
            .unwrap();

        let request = ExecuteRequest {
            transaction: ExecutableTransactionParameters::Invoke {
                invoke: ExecutableInvokeParameters {
                    user_address: StarknetTestEnvironment::ACCOUNT_ARGENT_1.address,
                    typed_data,
                    signature: vec![signature.r, signature.s],
                },
            },

            parameters: ExecutionParameters::V1 {
                fee_mode: FeeMode::Default {
                    gas_token: StarknetTestEnvironment::ETH,
                    tip: TipPriority::Normal,
                },
                time_bounds: None,
            },
        };

        let result = execute_endpoint(&request_context, request).await;
        assert!(result.is_ok())
    }
}
