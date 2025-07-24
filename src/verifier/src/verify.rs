use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;
use sev::firmware::guest::AttestationReport;

use crate::{
    assets::retrieve_asset_bytes,
    attestation::{
        download_certificate_authority_chain, download_report, download_vcek,
        validate_certificate_chain, verify_attestation, verify_report_data,
    },
};

#[derive(CandidType, Deserialize)]
pub struct VerifyArgs {
    gateway_host: String,
    release_hash: Option<String>,
    report_data: Option<ByteBuf>,
}

/// Steps:
/// 1. load release assets from assets state
/// 2. fetch report based on args
/// 3. fetch certificate chain based on report
/// 4. verify certificate chain
/// 5. verify report
/// 6. compare report's measurement with release assets calculation
pub async fn verify(args: VerifyArgs) -> anyhow::Result<String> {
    let report = fetch_report(&args).await?;
    ic_cdk::println!("Downloaded report: {report}");

    let ca_chain = download_certificate_authority_chain(&report).await?;
    ic_cdk::println!("Downloaded certificate authority chain");

    let vcek = download_vcek(&report).await?;
    ic_cdk::println!("Downloaded vcek");

    let mut log = String::new();

    let l = validate_certificate_chain(ca_chain, vcek.clone())?;
    ic_cdk::println!("{l}");
    log.push_str(&l);

    let l = verify_attestation(report, vcek)?;
    ic_cdk::println!("{l}");
    log.push_str(&l);

    if let Some(report_data) = args.report_data {
        let l = verify_report_data(&report, &report_data)?;
        ic_cdk::println!("{l}");
        log.push_str(&l);
    }

    if let Some(release_hash) = &args.release_hash {
        let assets = collect_release_assets(release_hash)?;
        ic_cdk::println!(
            "initramfs len: {}, ovmf len: {}, vmlinuz len: {}",
            assets.initramfs.len(),
            assets.ovmf.len(),
            assets.vmlinuz.len()
        );
        todo!("Implement measure verification")
    }

    Ok(log)
}

fn initramfs_path(release_hash: &str) -> String {
    format!("/{release_hash}/initramfs.cpio.gz")
}

fn ovmf_path(release_hash: &str) -> String {
    format!("/{release_hash}/OVMF.fd")
}

fn vmlinuz_path(release_hash: &str) -> String {
    format!("/{release_hash}/vmlinuz")
}

struct ReleaseAssets {
    initramfs: ByteBuf,
    ovmf: ByteBuf,
    vmlinuz: ByteBuf,
}

fn collect_release_assets(release_hash: &str) -> anyhow::Result<ReleaseAssets> {
    let initramfs = retrieve_asset_bytes(initramfs_path(release_hash))?;
    let ovmf = retrieve_asset_bytes(ovmf_path(release_hash))?;
    let vmlinuz = retrieve_asset_bytes(vmlinuz_path(release_hash))?;

    Ok(ReleaseAssets {
        initramfs: ByteBuf::from(initramfs.as_ref()),
        ovmf: ByteBuf::from(ovmf.as_ref()),
        vmlinuz: ByteBuf::from(vmlinuz.as_ref()),
    })
}

async fn fetch_report(args: &VerifyArgs) -> anyhow::Result<AttestationReport> {
    let mut report_data = [0u8; 64];
    if let Some(rd) = &args.report_data {
        report_data.copy_from_slice(rd.as_slice());
    }

    download_report(&args.gateway_host, &report_data).await
}
