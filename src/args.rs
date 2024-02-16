use std::{fmt::Display, ops::Deref, str::FromStr, time::Duration};

use clap::builder::TypedValueParser;

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

  #[command(flatten)]
  pub metrics: Metrics,

  ///Path under which to expose metrics
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
}

#[derive(Debug, clap::Args)]
#[allow(clippy::struct_field_names)]
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

fn greater_deref<T: Clone + Display + Send + Sync + 'static>(
  check: T,
) -> impl Fn(T) -> Result<T, String> + Clone + Send + Sync + 'static
where
  T: Deref,
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
