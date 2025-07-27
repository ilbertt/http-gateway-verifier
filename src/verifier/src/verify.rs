use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

use crate::{
    assets::retrieve_asset_bytes,
    attestation::{
        MeasurementArgs, download_certificate_authority_chain, download_report, download_vcek,
        prepare_report_data, sev_snp_launch_digest, validate_certificate_chain, verify_attestation,
        verify_measurement, verify_report_data,
    },
};

#[derive(CandidType, Deserialize)]
pub struct VerifyArgs {
    /// The host of the HTTP gateway to fetch the report from.
    /// See [SEV-SNP-enabled HTTP Gateways](https://github.com/dfinity/http-gateway-release/blob/main/attestation-guide.md#sev-snp-enabled-http-gateways).
    gateway_host: String,
    /// The GitHub release hash of the assets to verify, which were previously uploaded using the [`icx-asset`](https://github.com/dfinity/sdk/blob/master/src/canisters/frontend/icx-asset/README.md) tool.
    release_hash: Option<String>,
    /// The report data to verify. Must be 64 bytes long.
    /// If not provided, a random 64 bytes will be generated.
    report_data: Option<ByteBuf>,
}

/// Steps:
/// 1. prepare report data
/// 2. fetch report with that report data
/// 3. fetch certificate chain with that report
/// 4. verify certificate chain
/// 5. verify report
/// 6. load release assets from assets state with that release hash (if provided)
/// 7. compare report's measurement with release assets calculation (if provided)
pub async fn verify(args: VerifyArgs) -> anyhow::Result<String> {
    let report_data = prepare_report_data(args.report_data.as_ref()).await?;

    let report = download_report(&args.gateway_host, &report_data).await?;
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

    let l = verify_report_data(&report, &report_data)?;
    ic_cdk::println!("{l}");
    log.push_str(&l);

    if let Some(release_hash) = &args.release_hash {
        let assets = collect_release_assets(release_hash)?;
        ic_cdk::println!(
            "initramfs len: {}, ovmf len: {}, vmlinuz len: {}",
            assets.initramfs.len(),
            assets.ovmf.len(),
            assets.vmlinuz.len()
        );

        let measurement = sev_snp_launch_digest(MeasurementArgs {
            ovmf: assets.ovmf,
            kernel: assets.vmlinuz,
            initrd: assets.initramfs,
        })?;

        let l = verify_measurement(&report, measurement)?;
        ic_cdk::println!("{l}");
        log.push_str(&l);
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
