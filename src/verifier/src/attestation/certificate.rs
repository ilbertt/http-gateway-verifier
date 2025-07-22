use std::io::ErrorKind;

use sev::{
    certs::snp::{Certificate, Chain, Verifiable},
    firmware::host::CertType,
};
use x509_parser::{prelude::X509Extension, x509::X509Name};

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

pub fn validate_certificate_chain(
    ark_bytes: &[u8],
    ask_bytes: &[u8],
    vcek_bytes: &[u8],
) -> anyhow::Result<String> {
    let vek_type = "vcek";
    let sign_type = "asvk";
    let ark_cert = Certificate::from_pem(ark_bytes)?;
    let ask_cert = Certificate::from_pem(ask_bytes)?;
    let vcek_cert = Certificate::from_pem(vcek_bytes)?;

    // Get a cert chain from directory
    let cert_chain: Chain = (ask_cert, ark_cert, vcek_cert).into();

    let ark = cert_chain.ca.ark;
    let ask = cert_chain.ca.ask;
    let vek = cert_chain.vek;

    let mut log = String::new();

    // Verify each signature and print result in console
    match (&ark, &ark).verify() {
        Ok(()) => {
            log.push_str("The AMD ARK was self-signed!\n");
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => return Err(anyhow::anyhow!("The AMD ARK is not self-signed!")),
            _ => {
                return Err(anyhow::anyhow!(
                    "Failed to verify the ARK cerfificate: {:?}",
                    e
                ))
            }
        },
    }

    match (&ark, &ask).verify() {
        Ok(()) => {
            log.push_str(&format!(
                "The AMD {} was signed by the AMD ARK!\n",
                sign_type.to_uppercase(),
            ));
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => {
                return Err(anyhow::anyhow!(
                    "The AMD {} was not signed by the AMD ARK!",
                    sign_type.to_uppercase()
                ))
            }
            _ => return Err(anyhow::anyhow!("Failed to verify ASK certificate: {:?}", e)),
        },
    }

    match (&ask, &vek).verify() {
        Ok(()) => {
            log.push_str(&format!(
                "The {} was signed by the AMD {}!\n",
                vek_type.to_uppercase(),
                sign_type.to_uppercase()
            ));
        }
        Err(e) => match e.kind() {
            ErrorKind::Other => {
                return Err(anyhow::anyhow!(
                    "The {} was not signed by the AMD {}!",
                    vek_type.to_uppercase(),
                    sign_type.to_uppercase(),
                ))
            }
            _ => return Err(anyhow::anyhow!("Failed to verify VEK certificate: {:?}", e)),
        },
    }

    Ok(log)
}
