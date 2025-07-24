mod assets;
mod attestation;
mod verify;

use ic_cdk::{init, post_upgrade, pre_upgrade};

#[init]
fn init(args: Option<assets::AssetCanisterArgs>) {
    assets::init(args);
}

#[pre_upgrade]
fn pre_upgrade() {
    assets::pre_upgrade();
}

#[post_upgrade]
fn post_upgrade(args: Option<assets::AssetCanisterArgs>) {
    assets::post_upgrade(args);
}

#[ic_cdk::update]
async fn verify(args: verify::VerifyArgs) -> String {
    verify::verify(args).await.unwrap()
}

// Workaround to avoid using the system random number generator, which is not available in the canister.
use getrandom::register_custom_getrandom;
fn custom_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
register_custom_getrandom!(custom_getrandom);
