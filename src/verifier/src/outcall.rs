use std::{borrow::Cow, cell::RefCell};

use candid::{CandidType, Decode, Encode};
use ic_cdk::management_canister::{HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult};
use ic_stable_structures::{BTreeMap, Storable, storable::Bound};
use serde::{Deserialize, Serialize};

use crate::memory::{HTTP_CACHE_MEMORY_ID, MEMORY_MANAGER, Memory};

pub const HTTP_STATUS_OK: u8 = 200;

type HttpRequestsCacheMemory = BTreeMap<HttpCacheKey, HttpCacheValue, Memory>;

thread_local! {
    static HTTP_REQUESTS_CACHE: RefCell<HttpRequestsCacheMemory> = RefCell::new(init_http_requests_cache());
}

pub async fn http_request(args: &HttpRequestArgs) -> anyhow::Result<HttpRequestResult> {
    ic_cdk::management_canister::http_request(args)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to make HTTP request: {e}"))
}

/// Makes an HTTP request using [`http_request`] and caches the result, only if the status is 200.
///
/// If the status is not 200, the request is not cached and the result is returned.
pub async fn http_request_cached(
    args: &HttpRequestArgs,
) -> anyhow::Result<HttpRequestCachedResult> {
    let key = HttpCacheKey::from(args);
    let value = HTTP_REQUESTS_CACHE.with_borrow(|cache| cache.get(&key));

    if let Some(value) = value {
        ic_cdk::println!("HTTP request cache hit for url: {}", key.url);
        return Ok(HttpRequestCachedResult::Cached(value));
    }

    let res = http_request(args).await?;

    if res.status != HTTP_STATUS_OK {
        return Ok(HttpRequestCachedResult::Fresh(res));
    }

    HTTP_REQUESTS_CACHE.with_borrow_mut(|cache| cache.insert(key, res.clone().into()));

    Ok(HttpRequestCachedResult::Fresh(res))
}

#[derive(CandidType, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpCacheKey {
    url: String,
    method: HttpMethod,
    headers: Vec<HttpHeader>,
    body: Option<Vec<u8>>,
}

impl From<&HttpRequestArgs> for HttpCacheKey {
    fn from(args: &HttpRequestArgs) -> Self {
        HttpCacheKey {
            url: args.url.clone(),
            method: args.method,
            headers: args.headers.clone(),
            body: args.body.clone(),
        }
    }
}

impl Storable for HttpCacheKey {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

#[derive(CandidType, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpCacheValue {
    pub status: candid::Nat,
    pub body: Vec<u8>,
}

impl From<HttpRequestResult> for HttpCacheValue {
    fn from(res: HttpRequestResult) -> Self {
        HttpCacheValue {
            status: res.status,
            body: res.body,
        }
    }
}

impl Storable for HttpCacheValue {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

pub enum HttpRequestCachedResult {
    Fresh(HttpRequestResult),
    Cached(HttpCacheValue),
}

impl HttpRequestCachedResult {
    pub fn status(&self) -> candid::Nat {
        match self {
            HttpRequestCachedResult::Fresh(res) => res.status.clone(),
            HttpRequestCachedResult::Cached(res) => res.status.clone(),
        }
    }

    pub fn body(&self) -> &[u8] {
        match self {
            HttpRequestCachedResult::Fresh(res) => &res.body,
            HttpRequestCachedResult::Cached(res) => &res.body,
        }
    }
}

fn init_http_requests_cache() -> HttpRequestsCacheMemory {
    HttpRequestsCacheMemory::init(get_http_requests_cache_memory())
}

fn get_http_requests_cache_memory() -> Memory {
    MEMORY_MANAGER.with_borrow(|m| m.get(HTTP_CACHE_MEMORY_ID))
}
