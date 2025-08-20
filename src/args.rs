use std::{
  collections::{HashMap, HashSet},
  fmt::Display,
  fs::File,
  io::{Error as IoError, Result as IoResult},
  ops::Deref,
  path::Path,
  str::FromStr,
  time::Duration,
};

use anyhow::Context as _;
use clap::builder::{PathBufValueParser, TypedValueParser as _, ValueParser};
use openidconnect::{ClientId, IssuerUrl, core::CoreProviderMetadata};
use serde::Deserialize;

use crate::util::OidcClient;

/// Prometheus exporter reporting ping statistics
#[derive(Debug, clap::Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
  /// Print the resulting exponential bucket list and exit.
  #[arg(long)]
  pub print_buckets: bool,

  /// Hostnames or addresses of the ping targets
  #[arg(value_name = "TARGET")]
  pub targets: Vec<String>,

  /// Interval at which packets are send to the targets.
  #[arg(short = 'i', long, default_value = "1s", value_name = "DURATION")]
  pub send_interval: humantime::Duration,

  /// Interval at which target hostnames are resolved.
  #[arg(short = 'r', long, default_value = "60s", value_name = "DURATION")]
  pub resolve_interval: humantime::Duration,

  /// Device (or VRF) to bind the raw socket to.
  #[arg(long, value_name = "DEVICE")]
  pub bind_device: Option<String>,

  /// Enable dynamically added targets via the `targets` query parameter.
  #[arg(long = "dynamic-targets")]
  pub dynamic_targets: bool,

  /// How long to keep dynamically added targets after they are last specified.
  #[arg(long, default_value = "60s", value_name = "DURATION")]
  pub dynamic_targets_hold: humantime::Duration,

  /// The maximum number of targets (permanent + dynamic). New targets over this
  /// limit are ignored.
  #[arg(long, default_value_t = 100, value_name = "COUNT")]
  pub targets_max: usize,

  #[command(flatten)]
  pub metrics: Metrics,

  #[command(flatten)]
  pub web: Web,

  /// YAML file containing authentication credentials.
  ///
  /// When specified (even if empty), only metrics requests with one of the
  /// contained credentials are accepted.
  #[arg(long, value_name = "PATH", value_parser = AuthCredentials::path_value_parser())]
  pub auth_credentials: Option<AuthCredentials>,
}

#[derive(Debug, clap::Args)]
pub struct Web {
  /// Path under which to expose metrics
  #[arg(
    long = "web.telemetry-path",
    default_value = "/metrics",
    value_name = "PATH"
  )]
  pub telemetry_path: String,

  /// Addresses on which to expose metrics and web interface.
  #[arg(
    long = "web.listen-address",
    default_value = "0.0.0.0:9143",
    value_name = "ADDRESS"
  )]
  pub listen_address: Vec<String>,

  /// Listen on systemd provided sockets instead.
  #[arg(long = "web.systemd-socket")]
  pub systemd_socket: bool,
}

#[derive(Debug, clap::Args)]
#[expect(clippy::struct_field_names)]
pub struct Metrics {
  /// Start value for the exponential bucket calculation of the RTT histogram.
  #[arg(
    long,
    default_value = "1ms",
    value_name = "DURATION",
    value_parser = humantime::Duration::from_str.try_map(greater_deref(Duration::ZERO.into())),
  )]
  pub buckets_start: humantime::Duration,

  /// Multiplier value for the exponential bucket calculation of the RTT
  /// histogram.
  #[arg(
    long,
    default_value_t = 1.5,
    value_name = "FACTOR",
    value_parser = f64::from_str.try_map(greater(1.)),
  )]
  pub buckets_factor: f64,

  /// The number of buckets for the exponential bucket calculation of the RTT
  /// histogram.
  #[arg(
    long,
    default_value_t = 20,
    value_name = "COUNT",
    value_parser = usize::from_str.try_map(greater(0)),
  )]
  pub buckets_count: usize,
}

impl Metrics {
  pub fn exponential_buckets(&self) -> prometheus::Result<Vec<f64>> {
    prometheus::exponential_buckets(
      self.buckets_start.as_secs_f64(),
      self.buckets_factor,
      self.buckets_count,
    )
  }
}

fn greater<T: Clone + Display + PartialOrd + Send + Sync + 'static>(
  check: T,
) -> impl Fn(T) -> Result<T, String> + Clone + Send + Sync + 'static {
  move |value| {
    if value > check {
      Ok(value)
    } else {
      Err(format!("must be greater than {check}"))
    }
  }
}

fn greater_deref<T: Clone + Display + Deref + Send + Sync + 'static>(
  check: T,
) -> impl Fn(T) -> Result<T, String> + Clone + Send + Sync + 'static
where
  <T as Deref>::Target: PartialOrd,
{
  move |value| {
    if *value > *check {
      Ok(value)
    } else {
      Err(format!("must be greater than {check}"))
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCredentials {
  /// Username and password pairs to accept when sent as `Basic` authorization.
  #[serde(default)]
  pub basic: HashMap<String, String>,

  /// Static values to accept when sent as `Bearer` authorization.
  #[serde(default)]
  pub bearer: HashSet<String>,

  /// OIDC parameters to validate tokens against when sent as `Bearer`
  /// authorization.
  pub oidc: Option<AuthCredentialsOidc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCredentialsOidc {
  /// The OIDC `client_id`.
  pub client_id: ClientId,

  /// The OIDC issuer address, which must provide a
  /// `.well-known/openid-configuration` file.
  pub issuer_url: IssuerUrl,

  /// Don't treat issuer discovery errors as fatal and retry the process.
  /// Until it succeeds, token validation will fail and requests will return
  /// `401 unauthorized` errors (unless accepted by another credential source).
  #[serde(default)]
  pub retry_discovery: bool,
}

impl AuthCredentials {
  pub async fn setup_oidc_client(&self) -> Option<anyhow::Result<OidcClient>> {
    self
      .oidc
      .clone()
      .map_async(AuthCredentialsOidc::setup_oidc_client)
      .await
  }

  fn from_path(path: impl AsRef<Path>) -> IoResult<Self> {
    Self::from_file(&mut File::open(path)?)
  }

  fn from_file(file: &mut File) -> IoResult<Self> {
    serde_yml::from_reader(file).map_err(IoError::other)
  }

  fn path_value_parser() -> ValueParser {
    ValueParser::new(PathBufValueParser::new().try_map(Self::from_path))
  }
}

impl AuthCredentialsOidc {
  pub async fn setup_oidc_client(self) -> anyhow::Result<OidcClient> {
    Ok(OidcClient::from_provider_metadata(
      CoreProviderMetadata::discover_async(self.issuer_url, &reqwest::Client::new())
        .await
        .context("fetch OIDC issuer configuration")?,
      self.client_id,
      None,
    ))
  }
}

pub trait MapAsync<F> {
  type Output;
  async fn map_async(self, map: F) -> Self::Output;
}

impl<T, U, F, Fu> MapAsync<F> for Option<T>
where
  T: Send,
  U: Send,
  F: FnOnce(T) -> Fu + 'static,
  Fu: Future<Output = U> + Send,
{
  type Output = Option<U>;

  async fn map_async(self, map: F) -> Self::Output {
    match self {
      Some(t) => {
        let u = map(t).await;
        Some(u)
      }
      None => None,
    }
  }
}
