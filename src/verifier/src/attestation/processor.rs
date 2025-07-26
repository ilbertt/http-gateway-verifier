use sev::firmware::guest::AttestationReport;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcType {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 4th Gen AMD EPYC Processor (Performance)
    Bergamo,

    /// 4th Gen AMD EPYC Processor (Edge)
    Siena,

    /// 5th Gen AMD EPYC Processor (Standard)
    Turin,
}

impl ProcType {
    pub(super) fn to_kds_url(&self) -> String {
        match self {
            ProcType::Genoa | ProcType::Siena | ProcType::Bergamo => &ProcType::Genoa,
            _ => self,
        }
        .to_string()
    }
}

impl std::fmt::Display for ProcType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
            ProcType::Turin => write!(f, "Turin"),
        }
    }
}

pub(super) fn get_processor_model(att_report: &AttestationReport) -> anyhow::Result<ProcType> {
    if att_report.version < 3 {
        if [0u8; 64] == *att_report.chip_id {
            return Err(anyhow::anyhow!(
                "Attestation report version is lower than 3 and Chip ID is all 0s. Make sure MASK_CHIP_ID is set to 0 or update firmware."
            ));
        } else {
            let chip_id = *att_report.chip_id;
            if chip_id[8..64] == [0; 56] {
                return Ok(ProcType::Turin);
            } else {
                return Err(anyhow::anyhow!(
                    "Attestation report could be either Milan or Genoa. Update firmware to get a new version of the report."
                ));
            }
        }
    }

    let cpu_fam = att_report
        .cpuid_fam_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_mod = att_report
        .cpuid_mod_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcType::Milan),
            0x10..=0x1F | 0xA0..0xAF => Ok(ProcType::Genoa),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcType::Turin),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow::anyhow!("Processor family not supported")),
    }
}
