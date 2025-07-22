use anyhow::anyhow;
use candid::{ser::IDLBuilder, utils::ArgumentEncoder};
use ic_certified_assets::{
    asset_certification::types::{certification::AssetKey, rc_bytes::RcBytes},
    types::{GetArg, GetChunkArg},
    with_state,
};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;

pub use ic_certified_assets::types::AssetCanisterArgs;

pub fn init(args: Option<AssetCanisterArgs>) {
    ic_certified_assets::init(args);
}

pub fn pre_upgrade() {
    let stable_state = ic_certified_assets::pre_upgrade();
    let value_serializer_estimate = stable_state.estimate_size();
    stable_save_with_capacity((stable_state,), value_serializer_estimate)
        .expect("failed to save stable state");
}

// this is the same as ic_cdk::storage::stable_save,
// but reserves the capacity for the value serializer
fn stable_save_with_capacity<T>(t: T, value_capacity: usize) -> Result<(), candid::Error>
where
    T: ArgumentEncoder,
{
    let mut ser = IDLBuilder::new();
    ser.try_reserve_value_serializer_capacity(value_capacity)?;
    t.encode(&mut ser)?;
    ser.serialize(ic_cdk::stable::StableWriter::default())
}

pub fn post_upgrade(args: Option<AssetCanisterArgs>) {
    let (stable_state,): (ic_certified_assets::StableState,) =
        ic_cdk::storage::stable_restore().expect("failed to restore stable state");
    ic_certified_assets::post_upgrade(stable_state, args);
}

ic_certified_assets::export_canister_methods!();

pub fn retrieve_asset_bytes(key: AssetKey) -> anyhow::Result<RcBytes> {
    let first_chunk = with_state(|s| {
        s.get(GetArg {
            key: key.clone(),
            accept_encodings: vec!["identity".to_string()],
        })
    })
    .map_err(|e| anyhow!("Failed to process asset (key: {key}): {e}"))?;

    let total_length = first_chunk.total_length.0.to_usize().unwrap();
    let mut content: Vec<u8> = Vec::with_capacity(total_length);
    content.append(&mut first_chunk.content.to_vec());

    let chunks_count = total_length / first_chunk.content.len();

    for index in 1..=chunks_count {
        let chunk = with_state(|s| {
            s.get_chunk(GetChunkArg {
                content_encoding: first_chunk.content_encoding.clone(),
                index: index.into(),
                key: key.clone(),
                sha256: first_chunk.sha256.clone(),
            })
        })
        .map_err(|e| anyhow!("Failed to process chunk (index {index}): {e}"))?;
        content.append(&mut chunk.to_vec())
    }

    Ok(ByteBuf::from(content).into())
}
