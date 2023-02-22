use once_cell::sync::Lazy;
use std::str::FromStr;
use web3::{
    contract::{self, Contract, Options},
    ethabi,
    transports::Http,
    types::Address,
    Web3,
};

use serde::Deserialize;

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerificationProviderConfig {
    pub url: String,
}

/// GoodDollar Identity contract address used to verify whitelisted users
/// See more <https://github.com/GoodDollar/GoodProtocol/blob/master/releases/deployment.json>
pub static IDENTITY_CONTRACT_ADDRESS: Lazy<Address> =
    Lazy::new(|| Address::from_str("Fa8d865A962ca8456dF331D78806152d3aC5B84F").unwrap());

#[derive(Clone, Debug)]
pub struct FuseClient {
    contract: Contract<Http>,
}

impl FuseClient {
    pub fn create(web3: &Web3<Http>, address: Address) -> Result<Self, ethabi::Error> {
        let contract = Contract::from_json(
            web3.eth(),
            address,
            include_bytes!("../interfaces/Identity.json"),
        )?;

        Ok(Self { contract })
    }

    pub async fn is_whitelisted(&self, account: Address) -> contract::Result<bool> {
        self.contract
            .query("isWhitelisted", (account,), None, Options::default(), None)
            .await
    }
}
