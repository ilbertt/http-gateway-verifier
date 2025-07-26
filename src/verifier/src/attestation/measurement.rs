use serde_bytes::ByteBuf;
use sev::firmware::guest::AttestationReport;
use sev_snp_measure::{
    snp::{SnpLaunchDigest, SnpMeasurementArgs, snp_calc_launch_digest},
    vcpu_types::CpuType,
    vmsa::GuestFeatures,
};

pub struct MeasurementArgs {
    pub ovmf: ByteBuf,
    pub kernel: ByteBuf,
    pub initrd: ByteBuf,
}

pub fn sev_snp_launch_digest(args: MeasurementArgs) -> anyhow::Result<SnpLaunchDigest> {
    Ok(snp_calc_launch_digest(SnpMeasurementArgs {
        vcpus: 30,
        vcpu_type: CpuType::EpycMilan,
        ovmf_bytes: args.ovmf.into_vec(),
        guest_features: GuestFeatures::default(),
        kernel_bytes: Some(args.kernel.into_vec()),
        initrd_bytes: Some(args.initrd.into_vec()),
        append: Some("console=ttyS0,115200n8"),
        ovmf_hash_str: None,
        vmm_type: None,
    })?)
}

pub fn verify_measurement(
    report: &AttestationReport,
    launch_digest: SnpLaunchDigest,
) -> anyhow::Result<String> {
    let report_measurement: Vec<u8> = report.measurement.to_vec();
    let launch_digest: Vec<u8> = launch_digest.try_into().unwrap();
    if report_measurement == launch_digest {
        Ok("Measurements match!".to_string())
    } else {
        Err(anyhow::anyhow!(
            "Measurements do not match: report measurement: {}, launch measurement: {}",
            hex::encode(report_measurement),
            hex::encode(launch_digest)
        ))
    }
}
