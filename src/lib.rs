#![allow(dead_code)]

use std::sync::Arc;

use reqwest::Method;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

const DEFAULT_API_URL: &str = "https://cohost.org/api/v1";
const PBKDF2_ROUNDS: u32 = 200_000; // lol why is this a u32 and not a usize
const PBKDF2_OUTPUT_SIZE: usize = 128;

// Thanks to iliana for this function
#[tracing::instrument(skip_all)]
fn hash_password(password: &str, salt_base64: &str) -> Result<String, base64::DecodeError> {
    let mut out = [0; PBKDF2_OUTPUT_SIZE];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha384>>(
        password.as_bytes(),
        &base64::decode_config(&salt_base64, base64::URL_SAFE_NO_PAD)?,
        PBKDF2_ROUNDS,
        &mut out,
    );
    Ok(base64::encode(&out))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Deserialize)]
struct Salt {
    /// Base64-encoded data.
    salt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    email: String,
    client_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    user_id: String,
    #[serde(flatten)]
    rest: serde_json::Value,
}

pub struct Client {
    url_base: String,
    inner: reqwest::Client,
    user_id: String,
}

impl Client {
    // `endpoint` should start with a `/`, e.g. `/login`.
    fn url(&self, endpoint: &str) -> String {
        format!("{}{endpoint}", self.url_base)
    }

    #[tracing::instrument(skip_all)]
    pub async fn login(email: &str, password: &SecretString) -> Result<Self, Error> {
        let inner = reqwest::Client::builder()
            .cookie_store(true)
            .cookie_provider(Arc::new(reqwest::cookie::Jar::default()))
            .build()
            .unwrap();
        let ret = Client {
            url_base: DEFAULT_API_URL.to_owned(),
            inner,
            user_id: "".to_owned(),
        };
        let Salt { salt } = ret
            .inner
            .request(Method::GET, ret.url("/login/salt"))
            .query(&[("email", email)])
            .header("Content-Type", "application/json")
            .send()
            .await?
            .json()
            .await?;
        tracing::debug!("Got salt");
        let client_hash = hash_password(&password.expose_secret(), &salt)?;
        let response = ret
            .inner
            .request(Method::POST, ret.url("/login"))
            .json(&LoginRequest {
                email: email.to_owned(),
                client_hash,
            })
            .header("Content-Type", "application/json")
            .send()
            .await?;
        tracing::debug!("Response: {response}", response = response.text().await?);
        // tracing::debug!(?rest, "Extra login data");
        // ret.user_id = user_id;

        Ok(ret)
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}
