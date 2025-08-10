use std::any::type_name_of_val;

use anyhow::{Context, anyhow};
use ic_cdk::{
    api::canister_self,
    management_canister::{
        HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs, TransformContext,
        TransformFunc, raw_rand,
    },
};
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde_bytes::ByteBuf;
use sev::firmware::guest::AttestationReport;

use crate::outcall::{HTTP_STATUS_OK, http_request};

/// 2kB
const MAX_REPORT_SIZE_BYTES: u64 = 2_000;

const REPORT_DATA_SIZE_BYTES: usize = 64;
pub type ReportData = [u8; REPORT_DATA_SIZE_BYTES];

fn http_gateway_report_url(gateway_host: &str) -> String {
    format!("https://{gateway_host}/sev-snp/report")
}

pub async fn fetch_report(
    gateway_host: &str,
    report_data: &ReportData,
) -> anyhow::Result<AttestationReport> {
    let url = http_gateway_report_url(gateway_host);

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
        is_replicated: Some(false),
    })
    .await
    .with_context(|| format!("Failed to fetch report: url: {url}"))?;

    if res.status != HTTP_STATUS_OK {
        return Err(anyhow::anyhow!(
            "Failed to fetch report: status: {}",
            res.status
        ));
    }

    ic_cdk::println!(
        "res report: status: {} body len: {}",
        res.status,
        res.body.len()
    );

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

async fn rng_fill_report_data(buf: &mut ReportData) -> anyhow::Result<()> {
    let seed = raw_rand()
        .await
        .map_err(|e| anyhow!("Failed to generate random seed: {e}"))?;

    let mut rng = ChaCha12Rng::from_seed(seed.as_slice().try_into().unwrap());
    rng.fill_bytes(buf);

    Ok(())
}

/// Unwraps the report data from the ByteBuf if provided, otherwise generates a random report data.
pub async fn prepare_report_data(
    maybe_report_data: Option<&ByteBuf>,
) -> anyhow::Result<ReportData> {
    let mut report_data = [0u8; REPORT_DATA_SIZE_BYTES];

    match maybe_report_data {
        Some(rd) => report_data.copy_from_slice(rd),
        None => rng_fill_report_data(&mut report_data).await?,
    };

    Ok(report_data)
}
