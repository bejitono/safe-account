use std::sync::Arc;

use ::serde::{Deserialize, Serialize};
use aa_sdk_rs::{
    provider::{SmartAccountProvider, SmartAccountProviderTrait},
    smart_account::{SafeAccount, SmartAccount},
    types::{AccountCall, ExecuteCall, UserOperationRequest},
};
use alloy::{
    consensus::{TxEip7702, TypedTransaction},
    network::{Ethereum, EthereumWallet},
    primitives::{Address, B256, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{AccessList, Authorization, TransactionRequest},
    signers::local::PrivateKeySigner,
};
use alloy_transport_http::{Client, Http};
use thiserror::Error;
use url::Url;

const RPC_URL: &str = "https://base-sepolia.g.alchemy.com/v2/IVqOyg3PqHzBQJMqa_yZAfyonF9ne2Gx";
const DEPLOYER_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ENTRYPOINT_ADDRESS: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID: u64 = 84532;

#[tokio::main]
async fn main() {
    let signer: PrivateKeySigner =
        "82aba1f2ce3d1a0f6eca0ade8877077b7fc6fd06fb0af48ab4a53650bde69979"
            .parse()
            .unwrap();
    let user_wallet = EthereumWallet::from(signer.clone());
    let user_address: Address = signer.address();
    let user_signer = Arc::new(signer.clone());

    let deployer_pk: PrivateKeySigner = DEPLOYER_PK.parse().unwrap();
    let deployer_signer = Arc::new(deployer_pk);

    let _account_address: Address = "0x001D57AdB1461d456541354BBcD515d433299113"
        .parse()
        .unwrap();

    let rpc_url = Url::parse(RPC_URL).unwrap();
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(user_wallet)
        .on_http(rpc_url);

    let account = SafeAccount::new(
        Arc::new(provider.clone()),
        vec![user_address],
        U256::from(1),
        None, // account_address,
        CHAIN_ID,
    );

    let account_address: Address = account.get_account_address().await.unwrap();

    let _tx_hash = authorize_with_eip7702_if_needed(
        &user_signer,
        &deployer_signer,
        account_address,
        CHAIN_ID,
        &provider,
    )
    .await
    .expect("Failed to authorize EOA");

    // TODO: Poll for confirmed authorization

    let to_address: Address = "0xde3e943a1c2211cfb087dc6654af2a9728b15536"
        .parse()
        .unwrap();

    let user_op_req = UserOperationRequest::new(AccountCall::Execute(ExecuteCall::new(
        to_address,
        U256::from(100),
        Bytes::default(),
    )))
    .sender(account_address);

    let sponsored_user_op_req: UserOperationRequest =
        get_gas_paymaster_data(&account, &provider, user_op_req)
            .await
            .expect("Failed to get paymaster data");

    let smart_account_provider = SmartAccountProvider::new(provider, account);
    let result = smart_account_provider
        .send_user_operation(sponsored_user_op_req, &signer)
        .await;

    let user_op_hash: FixedBytes<32> = result.expect("Failed to send user operation");
    println!("User operation hash: {:?}", user_op_hash);

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    let mut attempts = 0;
    let max_attempts = 20;

    loop {
        interval.tick().await;
        attempts += 1;

        match smart_account_provider
            .get_user_operation_receipt(user_op_hash)
            .await
        {
            Ok(Some(receipt)) => {
                println!("Received receipt: {:?}", receipt);
                break;
            }
            Ok(None) => {
                println!("Receipt not available yet, retrying...");
            }
            Err(e) => {
                println!("Failed to get user operation receipt: {:?}", e);
                if attempts >= max_attempts {
                    println!("Exceeded max attempts ({max_attempts}), stopping retries");
                    break;
                }
            }
        }

        if attempts >= max_attempts {
            panic!("Failed to get receipt after {max_attempts} attempts");
        }
    }
}

/// 7702 Authorization

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Signer error: {0}")]
    SignerError(String),
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

async fn authorize_with_eip7702_if_needed<S, D, P>(
    user_signer: &Arc<S>,
    deployer_signer: &Arc<D>,
    delegation_address: Address,
    chain_id: u64,
    provider: &P,
) -> Result<Option<B256>, AccountError>
where
    S: alloy::signers::Signer + Send + Sync,
    D: alloy::signers::Signer + Send + Sync,
    P: Provider<Http<Client>, Ethereum> + Clone,
{
    let user_code = provider
        .get_code_at(user_signer.address())
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()))?;

    if user_code.is_empty() {
        return Ok(None);
    }

    let user_address = user_signer.address();

    let user_nonce = provider
        .get_transaction_count(user_address)
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()))?;

    let deployer_address = deployer_signer.address();
    let deployer_nonce = provider
        .get_transaction_count(deployer_address)
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()))?;

    let authorization = Authorization {
        chain_id: chain_id,
        address: delegation_address,
        nonce: user_nonce,
    };

    let signature = user_signer
        .sign_hash(&authorization.signature_hash())
        .await
        .map_err(|e| AccountError::SignerError(e.to_string()))?;

    let signed_authorization = authorization.into_signed(signature);

    let eip_7702_tx = TxEip7702 {
        chain_id: chain_id,
        nonce: deployer_nonce,
        gas_limit: 0,
        to: Address::ZERO,
        value: U256::from(0_u64),
        input: Bytes::new(),
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        access_list: AccessList::default(),
        authorization_list: vec![signed_authorization],
    };

    let tx = TypedTransaction::Eip7702(eip_7702_tx);

    let tx_request = TransactionRequest::from_transaction(tx);

    let gas_estimate = provider
        .estimate_eip1559_fees(None)
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()))?;

    let gas_limit = provider
        .estimate_gas(&tx_request)
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()))?;

    let filled_tx_request: TransactionRequest = tx_request
        .from(deployer_address)
        .gas_limit(gas_limit)
        .max_fee_per_gas(gas_estimate.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_estimate.max_priority_fee_per_gas)
        .nonce(deployer_nonce);

    let tx_envelope = provider
        .send_transaction(filled_tx_request)
        .await
        .map_err(|e| AccountError::TransactionError(e.to_string()))?;

    let tx_hash = tx_envelope.tx_hash();

    Ok(Some(*tx_hash))
}

/// Gas Sponsorship

#[derive(Serialize, Debug)]
struct AlchemyPaymasterParams {
    #[serde(rename = "policyId", default)]
    policy_id: String,
    #[serde(rename = "entryPoint", default)]
    entry_point: String,
    #[serde(rename = "dummySignature", default)]
    dummy_signature: String,
    #[serde(rename = "userOperation", default)]
    user_operation: UserOperationRequest,
}

#[derive(Deserialize, Serialize, Debug)]
struct AlchemyPaymasterResponse {
    #[serde(rename = "paymaster", default)]
    paymaster: Address,
    #[serde(rename = "paymasterData", default)]
    paymaster_data: Bytes,
    #[serde(rename = "callGasLimit", default)]
    pub call_gas_limit: U256,
    #[serde(rename = "verificationGasLimit", default)]
    pub verification_gas_limit: U256,
    #[serde(rename = "preVerificationGas", default)]
    pub pre_verification_gas: U256,
    #[serde(rename = "maxFeePerGas", default)]
    pub max_fee_per_gas: U256,
    #[serde(rename = "maxPriorityFeePerGas", default)]
    pub max_priority_fee_per_gas: U256,
    #[serde(rename = "paymasterVerificationGasLimit", default)]
    paymaster_verification_gas_limit: U256,
    #[serde(rename = "paymasterPostOpGasLimit", default)]
    paymaster_post_op_gas_limit: U256,
}

async fn get_gas_paymaster_data<
    U: Into<UserOperationRequest> + Send + Sync,
    P: Provider<Http<Client>, Ethereum>,
    S: SmartAccount<P, Http<Client>, Ethereum>,
>(
    account: &S,
    provider: &P,
    user_op: U,
) -> Result<UserOperationRequest, AccountError> {
    let user_op_req: UserOperationRequest = user_op.into();

    let nonce: U256 = account.get_nonce().await.unwrap_or(U256::from(0));
    let factory_address: Address = account.get_factory_address();
    let factory_data: Bytes = account.get_factory_data().await;

    let policy_id = "831ad866-14bf-4f4e-96e7-a5f3d083ba0a";

    let updated_user_op_req = user_op_req
        .factory(factory_address)
        .factory_data(factory_data)
        .nonce(nonce);

    let params = AlchemyPaymasterParams {
        policy_id: policy_id.to_string(),
        entry_point: ENTRYPOINT_ADDRESS.to_string(),
        dummy_signature: "0xe8fe34b166b64d118dccf44c7198648127bf8a76a48a042862321af6058026d276ca6abb4ed4b60ea265d1e57e33840d7466de75e13f072bbd3b7e64387eebfe1b".to_string(),
        user_operation: updated_user_op_req.clone(),
    };

    let result: Result<AlchemyPaymasterResponse, AccountError> = provider
        .client()
        .request("alchemy_requestGasAndPaymasterAndData", &[params])
        .await
        .map_err(|e| AccountError::ProviderError(e.to_string()));

    match result {
        Ok(resp) => {
            let final_user_op_req: UserOperationRequest = updated_user_op_req
                .paymaster(resp.paymaster)
                .paymaster_data(resp.paymaster_data)
                .call_gas_limit(resp.call_gas_limit)
                .verification_gas_limit(resp.verification_gas_limit)
                .pre_verification_gas(resp.pre_verification_gas)
                .max_fee_per_gas(resp.max_fee_per_gas)
                .max_priority_fee_per_gas(resp.max_priority_fee_per_gas)
                .paymaster_verification_gas_limit(resp.paymaster_verification_gas_limit)
                .paymaster_post_op_gas_limit(resp.paymaster_post_op_gas_limit);

            Ok(final_user_op_req)
        }
        Err(err) => Err(err),
    }
}
