use std::any::type_name_of_val;

use anyhow::anyhow;
use ic_cdk::{
    api::canister_self,
    management_canister::{
        http_request, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs,
        TransformContext, TransformFunc,
    },
};
use sev::firmware::guest::AttestationReport;

/// 2kB
const MAX_REPORT_SIZE_BYTES: u64 = 2_000;

type ReportData = [u8; 64];

fn report_url(gateway_host: &str) -> String {
    format!("https://{gateway_host}/sev-snp/report")
}

pub async fn download_report(
    gateway_host: &str,
    report_data: &ReportData,
) -> anyhow::Result<AttestationReport> {
    let url = report_url(gateway_host);

    let res = http_request(&HttpRequestArgs {
        url: url.clone(),
        method: HttpMethod::POST,
        headers: vec![],
        body: Some(report_data.to_vec()), // populates the report data field
        max_response_bytes: Some(MAX_REPORT_SIZE_BYTES),
        transform: Some(TransformContext {
            function: TransformFunc::new(canister_self(), transform_function_name()),
            context: vec![],
        }),
    })
    .await
    .map_err(|e| anyhow!("Failed to fetch report: url: {url}, {e}"))?;

    let report = AttestationReport::from_bytes(&res.body)?;

    Ok(report)
}

#[ic_cdk::query]
fn http_outcall_transform_report_response(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

fn transform_function_name() -> String {
    type_name_of_val(&http_outcall_transform_report_response)
        .split("::")
        .last()
        .unwrap()
        .to_string()
}
