use sev::firmware::guest::AttestationReport;

pub fn display_report(report_bytes: &[u8]) -> String {
    let attestation_report = AttestationReport::from_bytes(report_bytes).unwrap();
    format!("{attestation_report}")
}
