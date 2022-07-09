use secrecy::SecretString;

#[tokio::main]
async fn main() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        fmt::{self, format::FmtSpan},
        EnvFilter,
    };

    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .without_time();
    let filter_layer = EnvFilter::try_new("debug")
        .or_else(|_| EnvFilter::try_from_default_env())
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    let email = std::env::var("COHOST_EMAIL").unwrap();
    let password = SecretString::new(std::env::var("COHOST_PASSWORD").unwrap());
    let client = cohost::Client::login(&email, &password).await.unwrap();
    println!("user_id = {}", client.user_id());
}
