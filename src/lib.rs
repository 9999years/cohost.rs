use reqwest::Method;
use reqwest::header;
use secrecy::SecretString;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

const DEFAULT_API_URL: &str = "https://cohost.org/api/v1";
const PBKDF2_ROUNDS: u32 = 200_000; // lol why is this a u32 and not a usize
const PBKDF2_OUTPUT_SIZE: usize = 128;

// Thanks to iliana for this function
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
    salt: String
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    email: String,
    client_hash: String,
}

pub struct Client {
    url_base: String,
    inner: reqwest::Client,

}

impl Client {
    // `endpoint` should start with a `/`, e.g. `/login`.
    fn url(&self, endpoint: &str) -> String {
        format!("{}{endpoint}", self.url_base)
    }

    pub async fn login(email: &str, password: &SecretString) -> Result<Self, Error> {
        let inner = reqwest::Client::new();
        let ret = Client {
            url_base: DEFAULT_API_URL.to_owned(),
            inner,
        };
        let Salt { salt } = ret.inner
            .request(Method::GET, ret.url("/login/salt"))
            .query(&[("email", email)])
            .header("Content-Type", "application/json")
            .send().await?.json().await?;
        let client_hash = hash_password(&password.expose_secret(), &salt)?;
        let login_response = ret.inner
            .request(Method::POST, ret.url("/login"))
            .json(&LoginRequest { email: email.to_owned(), client_hash })
            .header("Content-Type", "application/json")
            .send().await?;
        let cookie = login_response.headers().get(header::SET_COOKIE);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
