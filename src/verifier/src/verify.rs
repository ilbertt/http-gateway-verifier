use candid::{CandidType, Deserialize};

use crate::assets::retrieve_asset_bytes;

#[derive(CandidType, Deserialize)]
pub struct VerifyArgs {
    release_short_hash: String,
}

/// Steps:
/// 1. load release assets from assets state
/// 2. fetch certificate chain based on args
/// 3. fetch report based on args
/// 4. verify certificate chain
/// 5. verify report
/// 6. compare report's measurement with release assets calculation
pub fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    collect_release_assets(&args.release_short_hash)
}

fn initramfs_path(release_short_hash: &str) -> String {
    format!("/{release_short_hash}/initramfs.cpio.gz")
}

fn ovmf_path(release_short_hash: &str) -> String {
    format!("/{release_short_hash}/OVMF.fd")
}

fn vmlinuz_path(release_short_hash: &str) -> String {
    format!("/{release_short_hash}/vmlinuz")
}

fn collect_release_assets(release_short_hash: &str) -> anyhow::Result<()> {
    let initramfs_bytes = retrieve_asset_bytes(initramfs_path(release_short_hash))?;
    let ovmf_bytes = retrieve_asset_bytes(ovmf_path(release_short_hash))?;
    let vmlinuz_bytes = retrieve_asset_bytes(vmlinuz_path(release_short_hash))?;

    ic_cdk::println!(
        "initramfs len: {}, ovmf len: {}, vmlinuz len: {}",
        initramfs_bytes.len(),
        ovmf_bytes.len(),
        vmlinuz_bytes.len()
    );

    Ok(())
}
