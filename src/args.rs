use std::{
  collections::{HashMap, HashSet},
  fmt::Display,
  fs::File,
  io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
  ops::Deref,
  path::Path,
  str::FromStr,
  time::Duration,
};

use clap::builder::{PathBufValueParser, TypedValueParser as _, ValueParser};
use serde::Deserialize;

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

  /// Path under which to expose metrics
  #[arg(
    long = "web.telemetry-path",
    default_value = "/metrics",
    value_name = "PATH"
  )]
  pub web_telemetry_path: String,

  /// Addresses on which to expose metrics and web interface.
  #[arg(
    long = "web.listen-address",
    default_value = "0.0.0.0:9143",
    value_name = "ADDRESS"
  )]
  pub web_listen_address: Vec<String>,

  /// Listen on systemd provided sockets instead.
  #[arg(long = "web.systemd-socket")]
  pub web_systemd_socket: bool,

  /// YAML file containing authentication credentials.
  ///
  /// When specified (even if empty), only metrics requests with one of the
  /// contained credentials are accepted. asdgghqas qweq wqwqewt
  #[arg(long, value_name = "PATH", value_parser = AuthCredentials::path_value_parser())]
  pub auth_credentials: Option<AuthCredentials>,
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
pub struct AuthCredentials {
  #[serde(default)]
  pub basic: HashMap<String, String>,

  #[serde(default)]
  pub bearer: HashSet<String>,
}

impl AuthCredentials {
  fn from_path(path: impl AsRef<Path>) -> IoResult<Self> {
    Self::from_file(&mut File::open(path)?)
  }

  fn from_file(file: &mut File) -> IoResult<Self> {
    serde_yml::from_reader(file).map_err(|e| IoError::new(IoErrorKind::Other, e))
  }

  fn path_value_parser() -> ValueParser {
    ValueParser::new(PathBufValueParser::new().try_map(Self::from_path))
  }
}
