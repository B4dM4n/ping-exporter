#![warn(
  missing_debug_implementations,
  rust_2018_idioms,
  clippy::pedantic,
  clippy::nursery
)]

mod args;

use std::{
  future::Future,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  num::Wrapping,
  pin::{pin, Pin},
  str::FromStr,
  sync::Arc,
  time::Duration,
};

use arc_swap::ArcSwap;
use hickory_resolver::{
  error::{ResolveError, ResolveErrorKind},
  TokioAsyncResolver,
};
use prometheus::{
  register_histogram_vec_with_registry, register_int_counter_vec_with_registry, Encoder,
  HistogramVec, IntCounterVec, Registry,
};
use rand::{seq::IteratorRandom, thread_rng};
use surge_ping::{Client, Config, PingIdentifier, PingSequence, Pinger, SurgeError, ICMP};
use tokio::sync::Notify;
use tracing::{debug, error, info, trace, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  setup_tracing()?;

  let args = <args::Args as clap::Parser>::parse();

  if args.print_buckets {
    println!("{:?}", args.metrics.exponential_buckets().unwrap());
    return Ok(());
  }

  let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

  let client_v4 = Client::new(&Config::default())?;
  let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())?;

  let registry = Registry::new();
  let Metrics {
    ping_duplicates,
    ping_errors,
    ping_rtt,
    ping_resolve_errors,
    send_timeout,
  } = setup_metrics(&registry, &args.metrics)?;

  let target_send_args = Arc::new(TargetSendArgs {
    send_interval: args.send_interval.into(),
    send_timeout,
    notify_exit: Notify::new(),
    client_v4,
    client_v6,
    ping_duplicates,
    ping_errors,
    ping_rtt,
  });
  let target_resolve_args = Arc::new(TargetResolveArgs {
    resolve_interval: args.resolve_interval.into(),
    notify_exit: Notify::new(),
    resolver,
    ping_resolve_errors,
  });
  let targets = args
    .targets
    .into_iter()
    .map(|hostname| {
      let target = Arc::new(Target::new(hostname));
      let join_send = tokio::spawn(target.clone().send_loop(target_send_args.clone()));
      let join_resolve = tokio::spawn(target.clone().resolve_loop(target_resolve_args.clone()));
      (target, join_send, join_resolve)
    })
    .collect::<Vec<_>>();

  let mut app = pin!(tide_app(
    args.web_telemetry_path,
    args.web_listen_address,
    registry
  ));
  let mut ctrl_c = pin!(tokio::signal::ctrl_c());

  debug!("Waiting for Ctrl-C");
  #[allow(clippy::redundant_pub_crate)]
  {
    tokio::select! {
      ret = &mut app => {
        if let Err(e) = ret {
          error!("Webserver failed: {:?}", e);
        }
      }
      _ = &mut ctrl_c => {
        debug!("Ctrl-C received");
      }
    };
  }

  target_send_args.notify_exit.notify_waiters();
  target_resolve_args.notify_exit.notify_waiters();
  for (target, join_send, join_resolve) in targets {
    if let Err(e) = join_send.await {
      warn!("The `send` task for `{}` failed: {:?}", target.hostname, e);
    }
    if let Err(e) = join_resolve.await {
      warn!(
        "The `resolve` task for `{}` failed: {:?}",
        target.hostname, e
      );
    }
  }

  Ok(())
}

fn setup_tracing() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy(),
    )
    .try_init()
    .map_err(|e| anyhow::anyhow!(e))?;

  Ok(())
}

struct Metrics {
  ping_duplicates: IntCounterVec,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
  ping_resolve_errors: IntCounterVec,
  send_timeout: Duration,
}

fn setup_metrics(registry: &Registry, args: &args::MetricsArgs) -> anyhow::Result<Metrics> {
  registry.register(Box::new(
    prometheus::process_collector::ProcessCollector::for_self(),
  ))?;

  let rtt_buckets = args.exponential_buckets()?;
  let send_timeout = Duration::from_secs_f64(*rtt_buckets.last().unwrap());
  let ping_rtt = register_histogram_vec_with_registry!(
    "ping_rtt",
    "Round Trip Time of the packets send to the targets",
    &["target", "version"],
    rtt_buckets,
    registry
  )?;
  let ping_errors = register_int_counter_vec_with_registry!(
    "ping_errors",
    "Number of packets failed to send or receive due to errors",
    &["target", "version"],
    registry
  )?;
  let ping_resolve_errors = register_int_counter_vec_with_registry!(
    "ping_resolve_errors",
    "Number of time the hostname resolve failed",
    &["target", "version"],
    registry
  )?;
  let ping_duplicates = register_int_counter_vec_with_registry!(
    "ping_duplicates",
    "Number of duplicate packages received",
    &["target", "version"],
    registry
  )?;

  Ok(Metrics {
    ping_duplicates,
    ping_errors,
    ping_rtt,
    ping_resolve_errors,
    send_timeout,
  })
}

#[tracing::instrument(ret, skip(registry))]
async fn tide_app(
  web_telemetry_path: String,
  web_listen_address: Vec<String>,
  registry: Registry,
) -> anyhow::Result<()> {
  struct Metrics {
    registry: Registry,
  }

  impl<State: Clone + Send + Sync + 'static> tide::Endpoint<State> for Metrics {
    fn call<'life0, 'async_trait>(
      &'life0 self,
      _req: tide::Request<State>,
    ) -> Pin<Box<dyn Future<Output = tide::Result> + Send + 'async_trait>>
    where
      'life0: 'async_trait,
      Self: 'async_trait,
    {
      let mut buffer = Vec::with_capacity(4096);
      let encoder = prometheus::TextEncoder::new();
      let metric_families = self.registry.gather();

      Box::pin(async move {
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(
          tide::Response::builder(tide::StatusCode::Ok)
            .content_type(prometheus::TEXT_FORMAT)
            .body(buffer.as_slice())
            .build(),
        )
      })
    }
  }

  let mut app = tide::new();
  app.at("/").get(|_req| async { Ok("") });
  app.at(&web_telemetry_path).get(Metrics { registry });
  app.listen(web_listen_address).await?;

  Ok(())
}

struct TargetSendArgs {
  send_interval: Duration,
  send_timeout: Duration,
  notify_exit: Notify,
  client_v4: Client,
  client_v6: Client,
  ping_duplicates: IntCounterVec,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
}

struct TargetResolveArgs {
  resolve_interval: Duration,
  notify_exit: Notify,
  resolver: TokioAsyncResolver,
  ping_resolve_errors: IntCounterVec,
}

#[derive(Debug)]
struct Target {
  hostname: String,
  addresses: ArcSwap<Addresses>,
}

#[derive(Debug)]
struct Addresses {
  ipv4_addr: Option<Ipv4Addr>,
  ipv6_addr: Option<Ipv6Addr>,
}

#[derive(Debug)]
enum PingResult {
  Success(Duration),
  Timeout,
  Duplicate,
  Error,
}

impl Target {
  fn new(hostname: String) -> Self {
    let addresses = ArcSwap::new(Arc::new(IpAddr::from_str(&hostname).map_or(
      Addresses {
        ipv4_addr: None,
        ipv6_addr: None,
      },
      |addr| match addr {
        IpAddr::V4(a) => Addresses {
          ipv4_addr: Some(a),
          ipv6_addr: None,
        },
        IpAddr::V6(a) => Addresses {
          ipv4_addr: None,
          ipv6_addr: Some(a),
        },
      },
    )));
    Self {
      hostname,
      addresses,
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, args), fields(hostname = self.hostname))]
  async fn send_loop(self: Arc<Self>, args: Arc<TargetSendArgs>) {
    let TargetSendArgs {
      send_interval,
      send_timeout,
      notify_exit,
      client_v4,
      client_v6,
      ping_duplicates,
      ping_errors,
      ping_rtt,
    } = args.as_ref();
    let mut interval = tokio::time::interval(*send_interval);

    let mut pinger_v4: Option<Pinger> = None;
    let mut pinger_v6: Option<Pinger> = None;
    let mut seq = Wrapping(0);

    loop {
      seq += 1;
      let seq = seq.0;

      #[allow(clippy::redundant_pub_crate)]
      {
        tokio::select! {
          _ = interval.tick() => (),
          _ = notify_exit.notified() => {
            return;
          }
        };
      }

      trace!(?seq, "loop");

      let addresses = self.addresses.load();
      if let Some(addr) = addresses.ipv4_addr {
        let pinger_v4 = match pinger_v4.as_mut() {
          Some(pinger) if pinger.host == addr => pinger,
          _ => pinger_v4
            .insert(
              client_v4
                .pinger(addr.into(), PingIdentifier(rand::random()))
                .await,
            )
            .timeout(*send_timeout),
        };

        match self.send_ipv4(seq, addr, pinger_v4).await {
          PingResult::Success(rtt) => {
            ping_rtt
              .with_label_values(&[&self.hostname, "icmp"])
              .observe(rtt.as_secs_f64());
          }
          PingResult::Timeout => {
            ping_rtt
              .with_label_values(&[&self.hostname, "icmp"])
              .observe(f64::INFINITY);
          }
          PingResult::Duplicate => {
            ping_duplicates
              .with_label_values(&[&self.hostname, "icmp"])
              .inc();
          }
          PingResult::Error => ping_errors
            .with_label_values(&[&self.hostname, "icmp"])
            .inc(),
        }
      }

      if let Some(addr) = addresses.ipv6_addr {
        let pinger_v6 = match pinger_v6.as_mut() {
          Some(pinger) if pinger.host == addr => pinger,
          _ => pinger_v6
            .insert(
              client_v6
                .pinger(addr.into(), PingIdentifier(rand::random()))
                .await,
            )
            .timeout(*send_timeout),
        };
        match self.send_ipv6(seq, addr, pinger_v6).await {
          PingResult::Success(rtt) => {
            ping_rtt
              .with_label_values(&[&self.hostname, "icmp6"])
              .observe(rtt.as_secs_f64());
          }
          PingResult::Timeout => {
            ping_rtt
              .with_label_values(&[&self.hostname, "icmp6"])
              .observe(f64::INFINITY);
          }
          PingResult::Duplicate => {
            ping_duplicates
              .with_label_values(&[&self.hostname, "icmp6"])
              .inc();
          }
          PingResult::Error => ping_errors
            .with_label_values(&[&self.hostname, "icmp6"])
            .inc(),
        }
      }
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, pinger_v4))]
  async fn send_ipv4(&self, seq: u16, addr: Ipv4Addr, pinger_v4: &mut Pinger) -> PingResult {
    match pinger_v4.ping(PingSequence(seq), &[]).await {
      Ok((_packet, rtt)) => PingResult::Success(rtt),
      Err(err) => match err {
        SurgeError::Timeout { .. } => PingResult::Timeout,
        SurgeError::IdenticalRequests { .. } => PingResult::Duplicate,
        _ => PingResult::Error,
      },
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, pinger_v6))]
  async fn send_ipv6(&self, seq: u16, addr: Ipv6Addr, pinger_v6: &mut Pinger) -> PingResult {
    match pinger_v6.ping(PingSequence(seq), &[]).await {
      Ok((_packet, rtt)) => PingResult::Success(rtt),
      Err(err) => match err {
        SurgeError::Timeout { .. } => PingResult::Timeout,
        SurgeError::IdenticalRequests { .. } => PingResult::Duplicate,
        _ => PingResult::Error,
      },
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, args), fields(hostname = self.hostname))]
  async fn resolve_loop(self: Arc<Self>, args: Arc<TargetResolveArgs>) {
    {
      let addresses = self.addresses.load();
      // stop resolving if the hostname could be parsed as an IP address
      if addresses.ipv4_addr.is_some() || addresses.ipv6_addr.is_some() {
        return;
      }
    }

    let TargetResolveArgs {
      resolve_interval,
      notify_exit,
      resolver,
      ping_resolve_errors,
    } = args.as_ref();
    let mut interval = tokio::time::interval(*resolve_interval);

    loop {
      #[allow(clippy::redundant_pub_crate)]
      {
        tokio::select! {
          _ = interval.tick() => (),
          _ = notify_exit.notified() => {
            return;
          }
        };
      }

      trace!("loop");

      let ipv4_addr = match self.resolve_ipv4(resolver).await {
        Ok(addr) => addr,
        Err(e) => {
          info!("Could not resolve IPv4 address of {}: {}", self.hostname, e);
          ping_resolve_errors
            .with_label_values(&[&self.hostname, "icmp"])
            .inc();
          None
        }
      };

      let ipv6_addr = match self.resolve_ipv6(resolver).await {
        Ok(addr) => addr,
        Err(e) => {
          info!("Could not resolve IPv6 address of {}: {}", self.hostname, e);
          ping_resolve_errors
            .with_label_values(&[&self.hostname, "icmp6"])
            .inc();
          None
        }
      };

      self.addresses.store(Arc::new(Addresses {
        ipv4_addr,
        ipv6_addr,
      }));
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, resolver))]
  async fn resolve_ipv4(
    &self,
    resolver: &TokioAsyncResolver,
  ) -> Result<Option<Ipv4Addr>, ResolveError> {
    match resolver.ipv4_lookup(&self.hostname).await {
      Ok(resp) => Ok(resp.into_iter().choose(&mut thread_rng()).map(Into::into)),
      Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),
      Err(e) => Err(e),
    }
  }

  #[tracing::instrument(level = "debug", ret, skip(self, resolver))]
  async fn resolve_ipv6(
    &self,
    resolver: &TokioAsyncResolver,
  ) -> Result<Option<Ipv6Addr>, ResolveError> {
    match resolver.ipv6_lookup(&self.hostname).await {
      Ok(resp) => Ok(resp.into_iter().choose(&mut thread_rng()).map(Into::into)),
      Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(None),
      Err(e) => Err(e),
    }
  }
}
