use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevMode {
    Sev,
    SevEs,
    SevSnp,
    SevSnpSvsm,
}

impl SevMode {
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        match s.to_lowercase().as_str() {
            "sev" => Ok(SevMode::Sev),
            "sev-es" | "seves" => Ok(SevMode::SevEs),
            "sev-snp" | "sevsnp" => Ok(SevMode::SevSnp),
            "sev-snp-svsm" | "sevsnpsvsm" => Ok(SevMode::SevSnpSvsm),
            _ => Err("illegal SEV mode"),
        }
    }
}

impl FromStr for SevMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}

impl fmt::Display for SevMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SevMode::Sev => write!(f, "SEV"),
            SevMode::SevEs => write!(f, "SEV-ES"),
            SevMode::SevSnp => write!(f, "SEV-SNP"),
            SevMode::SevSnpSvsm => write!(f, "SEV-SNP-SVSM"),
        }
    }
}