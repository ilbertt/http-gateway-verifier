use anyhow::Context;
use sev::{
    certs::snp::{Certificate, Verifiable},
    firmware::{guest::AttestationReport, host::CertType},
};
use x509_parser::{
    der_parser::{Oid, oid},
    prelude::{FromDer, X509Certificate},
};

use super::{
    certificate::{check_cert_bytes, parse_common_name},
    processor::{ProcType, get_processor_model},
};

enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

// OID extensions for the VCEK, will be used to verify attestation report
impl SnpOid {
    fn oid(&self) -> Oid {
        match self {
            SnpOid::BootLoader => oid!(1.3.6.1.4.1.3704.1.3.1),
            SnpOid::Tee => oid!(1.3.6.1.4.1.3704.1.3.2),
            SnpOid::Snp => oid!(1.3.6.1.4.1.3704.1.3.3),
            SnpOid::Ucode => oid!(1.3.6.1.4.1.3704.1.3.8),
            SnpOid::HwId => oid!(1.3.6.1.4.1.3704.1.4),
            SnpOid::Fmc => oid!(1.3.6.1.4.1.3704.1.3.9),
        }
    }
}

fn verify_attestation_tcb(
    vcek: Certificate,
    att_report: AttestationReport,
    proc_model: ProcType,
    mut log: Option<&mut String>,
) -> anyhow::Result<()> {
    let vek_der = vcek.to_der().context("Could not convert VEK to der.")?;
    let (_, vek_x509) =
        X509Certificate::from_der(&vek_der).context("Could not create X509Certificate from der")?;

    // Collect extensions from VEK
    let extensions = vek_x509
        .extensions_map()
        .context("Failed getting VEK oids.")?;

    let common_name = parse_common_name(vek_x509.subject())?;

    // Compare bootloaders
    if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
        if !check_cert_bytes(cert_bl, &att_report.reported_tcb.bootloader.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB Boot Loader and Certificate Boot Loader mismatch encountered."
            ));
        }
        if let Some(log) = &mut log {
            log.push_str(
                "Reported TCB Boot Loader from certificate matches the attestation report.\n",
            );
        }
    }

    // Compare TEE information
    if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
        if !check_cert_bytes(cert_tee, &att_report.reported_tcb.tee.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB TEE and Certificate TEE mismatch encountered."
            ));
        }
        if let Some(log) = &mut log {
            log.push_str("Reported TCB TEE from certificate matches the attestation report.\n");
        }
    }

    // Compare SNP information
    if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
        if !check_cert_bytes(cert_snp, &att_report.reported_tcb.snp.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB SNP and Certificate SNP mismatch encountered."
            ));
        }
        if let Some(log) = &mut log {
            log.push_str("Reported TCB SNP from certificate matches the attestation report.\n");
        }
    }

    // Compare Microcode information
    if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
        if !check_cert_bytes(cert_ucode, &att_report.reported_tcb.microcode.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "Report TCB Microcode and Certificate Microcode mismatch encountered."
            ));
        }
        if let Some(log) = &mut log {
            log.push_str(
                "Reported TCB Microcode from certificate matches the attestation report.\n",
            );
        }
    }

    // Compare HWID information only on VCEK
    if common_name == CertType::VCEK {
        if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
            if !check_cert_bytes(cert_hwid, &*att_report.chip_id) {
                return Err(anyhow::anyhow!(
                    "Report TCB ID and Certificate ID mismatch encountered."
                ));
            }
            if let Some(log) = &mut log {
                log.push_str("Chip ID from certificate matches the attestation report.\n");
            }
        }
    }

    if proc_model == ProcType::Turin {
        if att_report.version < 3 {
            return Err(anyhow::anyhow!(
                "Turin Attestation is not supported in version 2 of the report."
            ));
        }
        if let Some(cert_fmc) = extensions.get(&SnpOid::Fmc.oid()) {
            let fmc = if let Some(fmc) = att_report.reported_tcb.fmc {
                fmc
            } else {
                return Err(anyhow::anyhow!(
                    "Attestation report TCB FMC is not present in the report. it is expecter for a {} model.",
                    proc_model
                ));
            };

            if !check_cert_bytes(cert_fmc, fmc.to_le_bytes().as_slice()) {
                return Err(anyhow::anyhow!(
                    "Report TCB FMC and Certificate FMC mismatch encountered."
                ));
            }
            if let Some(log) = &mut log {
                log.push_str("Reported TCB FMC from certificate matches the attestation report.\n");
            }
        }
    }

    Ok(())
}

fn verify_attestation_signature(
    vcek: Certificate,
    att_report: AttestationReport,
    mut log: Option<&mut String>,
) -> anyhow::Result<()> {
    (&vcek, &att_report)
        .verify()
        .context("Failed to verify attestation report signature with VEK public key.")?;
    if let Some(log) = &mut log {
        log.push_str("VEK signed the Attestation Report!\n");
    }

    Ok(())
}

pub fn verify_attestation(report: AttestationReport, vcek: Certificate) -> anyhow::Result<String> {
    let processor_model = get_processor_model(&report)?;

    let mut log = String::new();

    verify_attestation_tcb(vcek.clone(), report, processor_model, Some(&mut log))?;
    verify_attestation_signature(vcek, report, Some(&mut log))?;

    Ok(log)
}

pub fn verify_report_data(
    report: &AttestationReport,
    report_data: &[u8],
) -> anyhow::Result<String> {
    if report.report_data.as_slice() == report_data {
        Ok("Report data matches!".to_string())
    } else {
        Err(anyhow::anyhow!("Report data does not match"))
    }
}
