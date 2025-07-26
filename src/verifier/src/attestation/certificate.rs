use std::{any::type_name_of_val, io::ErrorKind};

use anyhow::anyhow;
use ic_cdk::{
    api::canister_self,
    management_canister::{
        http_request, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs,
        TransformContext, TransformFunc,
    },
};
use sev::{
    certs::snp::{ca::Chain as CaChain, Certificate, Verifiable},
    firmware::{guest::AttestationReport, host::CertType},
};
use x509_parser::{nom::AsBytes, pem::parse_x509_pem, prelude::X509Extension, x509::X509Name};

use crate::attestation::{
    endorsement::Endorsement,
    processor::{get_processor_model, ProcType},
};

/// 5kB
const MAX_CERTIFICATE_CHAIN_SIZE_BYTES: u64 = 5_000;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";

pub(super) fn parse_common_name(field: &X509Name<'_>) -> anyhow::Result<CertType> {
    if let Some(val) = field
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
    {
        match val.to_lowercase() {
            x if x.contains("ark") => Ok(CertType::ARK),
            x if x.contains("ask") | x.contains("sev") => Ok(CertType::ASK),
            x if x.contains("vcek") => Ok(CertType::VCEK),
            x if x.contains("vlek") => Ok(CertType::VLEK),
            x if x.contains("crl") => Ok(CertType::CRL),
            _ => Err(anyhow::anyhow!("Unknown certificate type encountered!")),
        }
    } else {
        Err(anyhow::anyhow!(
            "Certificate Subject Common Name is Unknown!"
        ))
    }
}

// Check the cert extension byte to value
pub(super) fn check_cert_bytes(ext: &X509Extension, val: &[u8]) -> bool {
    match ext.value[0] {
        // Integer
        0x2 => {
            if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
                panic!("Invalid octet length encountered!");
            } else if let Some(byte_value) = ext.value.last() {
                byte_value == &val[0]
            } else {
                false
            }
        }
        // Octet String
        0x4 => {
            if ext.value[1] != 0x40 {
                panic!("Invalid octet length encountered!");
            } else if ext.value[2..].len() != 0x40 {
                panic!("Invalid size of bytes encountered!");
            } else if val.len() != 0x40 {
                panic!("Invalid certificate harward id length encountered!")
            }

            &ext.value[2..] == val
        }
        // Legacy and others.
        _ => {
            // Keep around for a bit for old VCEK without x509 DER encoding.
            if ext.value.len() == 0x40 && val.len() == 0x40 {
                ext.value == val
            } else {
                panic!("Invalid type encountered!");
            }
        }
    }
}

pub fn validate_certificate_chain(ca_chain: CaChain, vek: Certificate) -> anyhow::Result<String> {
    let ark = ca_chain.ark;
    let ask = ca_chain.ask;

    let mut log = String::new();

    match (&ark, &ark).verify() {
        Ok(()) => {
            log.push_str("The AMD ARK was self-signed!\n");
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => return Err(anyhow::anyhow!("The AMD ARK is not self-signed! {e}")),
            _ => {
                return Err(anyhow::anyhow!(
                    "Failed to verify the ARK certificate: {:?}",
                    e
                ))
            }
        },
    }

    match (&ark, &ask).verify() {
        Ok(()) => {
            log.push_str("The AMD ASK was signed by the AMD ARK!\n");
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => {
                return Err(anyhow::anyhow!(
                    "The AMD ASK was not signed by the AMD ARK!"
                ))
            }
            _ => return Err(anyhow::anyhow!("Failed to verify ASK certificate: {:?}", e)),
        },
    }

    match (&ask, &vek).verify() {
        Ok(()) => {
            log.push_str("The VCEK was signed by the AMD ASK!\n");
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => {
                return Err(anyhow::anyhow!("The VCEK was not signed by the AMD ASK!",))
            }
            _ => return Err(anyhow::anyhow!("Failed to verify VEK certificate: {:?}", e)),
        },
    }

    Ok(log)
}

fn certificate_authority_chain_url(processor_model: &ProcType, endorser: &Endorsement) -> String {
    const KDS_CERT_CHAIN: &str = "cert_chain";

    format!(
        "{KDS_CERT_SITE}/{}/v1/{}/{KDS_CERT_CHAIN}",
        endorser.to_string().to_lowercase(),
        processor_model.to_kds_url()
    )
}

pub async fn download_certificate_authority_chain(
    report: &AttestationReport,
) -> anyhow::Result<CaChain> {
    let processor_model = get_processor_model(report)?;
    let url = certificate_authority_chain_url(&processor_model, &Endorsement::Vcek);

    let res = http_request(&HttpRequestArgs {
        url: url.clone(),
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        max_response_bytes: Some(MAX_CERTIFICATE_CHAIN_SIZE_BYTES),
        transform: Some(TransformContext {
            function: TransformFunc::new(
                canister_self(),
                http_outcall_certificate_authority_chain_transform_function_name(),
            ),
            context: vec![],
        }),
    })
    .await
    .map_err(|e| anyhow!("Failed to fetch certificate authority chain: url: {url}, {e}"))?;

    parse_two_pem_certs(&res.body)
}

fn parse_two_pem_certs(input: &[u8]) -> anyhow::Result<CaChain> {
    let (rem, ask) = parse_x509_pem(input)?;
    let (_, ark) = parse_x509_pem(rem)?;

    Ok(CaChain::from_der(&ark.contents, &ask.contents)?)
}

#[ic_cdk::query]
fn http_outcall_transform_certificate_authority_chain_response(
    args: TransformArgs,
) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

fn http_outcall_certificate_authority_chain_transform_function_name() -> String {
    type_name_of_val(&http_outcall_transform_certificate_authority_chain_response)
        .split("::")
        .last()
        .unwrap()
        .to_string()
}

fn vcek_url(report: &AttestationReport) -> anyhow::Result<String> {
    const KDS_VCEK: &str = "/vcek/v1";

    let processor_model = get_processor_model(report)?;

    // Get hardware id
    let hw_id: String = if report.chip_id.as_bytes() != [0; 64] {
        match processor_model {
            ProcType::Turin => {
                let shorter_bytes: &[u8] = &report.chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(report.chip_id),
        }
    } else {
        return Err(anyhow::anyhow!(
            "Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0."
        ));
    };

    // Request VCEK from KDS
    let vcek_url = match processor_model {
        ProcType::Turin => {
            let fmc = if let Some(fmc) = report.reported_tcb.fmc {
                fmc
            } else {
                return Err(anyhow::anyhow!("A Turin processor must have a fmc value"));
            };
            format!(
                "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                processor_model.to_kds_url(),
                fmc,
                report.reported_tcb.bootloader,
                report.reported_tcb.tee,
                report.reported_tcb.snp,
                report.reported_tcb.microcode
            )
        }
        _ => {
            format!(
                "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                processor_model.to_kds_url(),
                report.reported_tcb.bootloader,
                report.reported_tcb.tee,
                report.reported_tcb.snp,
                report.reported_tcb.microcode
            )
        }
    };

    Ok(vcek_url)
}

pub async fn download_vcek(report: &AttestationReport) -> anyhow::Result<Certificate> {
    let url = vcek_url(report)?;

    let res = http_request(&HttpRequestArgs {
        url: url.clone(),
        method: HttpMethod::GET,
        headers: vec![],
        body: None,
        max_response_bytes: Some(MAX_CERTIFICATE_CHAIN_SIZE_BYTES),
        transform: Some(TransformContext {
            function: TransformFunc::new(
                canister_self(),
                http_outcall_vcek_transform_function_name(),
            ),
            context: vec![],
        }),
    })
    .await
    .map_err(|e| anyhow!("Failed to fetch vcek: url: {url}, {e}"))?;

    Ok(Certificate::from_der(&res.body)?)
}

#[ic_cdk::query]
fn http_outcall_transform_vcek_response(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

fn http_outcall_vcek_transform_function_name() -> String {
    type_name_of_val(&http_outcall_transform_vcek_response)
        .split("::")
        .last()
        .unwrap()
        .to_string()
}
