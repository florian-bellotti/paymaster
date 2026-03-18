mod overhead;
pub use overhead::ValidationGasOverhead;

mod estimate;
pub use estimate::FeeEstimate;

use starknet::core::types::Felt;

/// Action describing a fee transfer the user must approve for private transactions.
#[derive(Debug, Clone)]
pub struct FeeAction {
    pub recipient: Felt,
    pub token: Felt,
    pub amount: Felt,
}
