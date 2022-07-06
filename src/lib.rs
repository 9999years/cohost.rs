use reqwest::Method;
use secrecy::SecretString;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use pbkdf2::pbkdf2;

const DEFAULT_API_URL: &str = "https://cohost.org/api/v1";
const PBKDF2_ROUNDS: u32 = 200000;

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
            .request(Method::GET, ret.url("/login"))
            .query(&[("email", email)])
            .header("Content-Type", "application/json")
            .send().await?.json().await?;
        let decoded_salt = base64::decode(&salt)?;
        let mut hashed_password = [0u8; 128];
        pbkdf2::<()>(password.expose_secret().as_bytes(), &decoded_salt, PBKDF2_ROUNDS, &mut hashed_password);

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
