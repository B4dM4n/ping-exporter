#![warn(
  missing_debug_implementations,
  rust_2018_idioms,
  clippy::pedantic,
  clippy::nursery
)]

mod args;
mod util;

use std::{
  collections::{hash_map::Entry, HashMap},
  fmt,
  future::IntoFuture,
  io,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
  os::fd::{BorrowedFd, FromRawFd as _},
  pin::pin,
  str::FromStr,
  sync::Arc,
  time::{Duration, Instant},
};

use anyhow::bail;
use arc_swap::ArcSwap;
use args::AuthCredentials;
use axum::{
  extract::{ConnectInfo, Query},
  http::{header, Request, StatusCode},
  response::{IntoResponse as _, Response},
};
use hickory_resolver::{proto::ProtoErrorKind, ResolveError, ResolveErrorKind, TokioResolver};
use nix::sys::socket::{setsockopt, sockopt};
use password_auth::VerifyError;
use prometheus::{Encoder, HistogramVec, IntCounterVec, IntGauge, Registry};
use rand::{rng, seq::IteratorRandom};
use serde::Deserialize;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, Pinger, SurgeError, ICMP};
use tokio::{sync::Mutex, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, trace, warn, Instrument as _, Level};
use util::{Auth, AuthRejection};

const SECOND: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  setup_tracing()?;

  let args = <args::Args as clap::Parser>::parse();

  if args.print_buckets {
    println!("{:?}", args.metrics.exponential_buckets().unwrap());
    return Ok(());
  }

  let resolver = TokioResolver::builder_tokio()?.build();

  let client_v4 = Client::new(&Config::default())?;
  let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build())?;

  if let Some(device) = args.bind_device {
    let fd_v4 = unsafe { BorrowedFd::borrow_raw(client_v4.get_socket().get_native_sock()) };
    setsockopt(&fd_v4, sockopt::BindToDevice, &device.clone().into())?;

    let fd_v6 = unsafe { BorrowedFd::borrow_raw(client_v6.get_socket().get_native_sock()) };
    setsockopt(&fd_v6, sockopt::BindToDevice, &device.into())?;
  }

  let registry = Registry::new();
  let Metrics {
    ping_targets,
    ping_dynamic_targets,
    ping_duplicates,
    ping_errors,
    ping_rtt,
    ping_timeouts,
    ping_resolve_errors,
    send_timeout,
  } = setup_metrics(&registry, &args.metrics)?;

  let cancellation = CancellationToken::new();
  let target_send_args = Arc::new(TargetSendArgs {
    send_interval: args.send_interval.into(),
    send_timeout,
    client_v4,
    client_v6,
    ping_duplicates,
    ping_errors,
    ping_rtt,
    ping_timeouts,
  });
  let target_resolve_args = Arc::new(TargetResolveArgs {
    resolve_interval: args.resolve_interval.into(),
    resolver,
    ping_resolve_errors,
  });

  let targets = TargetMap::new(
    ping_targets,
    ping_dynamic_targets,
    args.targets_max,
    args.dynamic_targets_hold.into(),
    target_send_args.clone(),
    target_resolve_args.clone(),
    cancellation.clone(),
  );
  targets.add(args.targets, true).await;
  tokio::spawn(targets.clone().cleanup_task());

  let app = Arc::new(App::new(
    registry,
    args.dynamic_targets.then(|| targets.clone()),
    args.auth_credentials,
  ));
  let mut app = pin!(app.run(
    cancellation.child_token(),
    args.web_telemetry_path,
    args.web_listen_address,
    args.web_systemd_socket
  ));
  let mut shutdown_signal = pin!(shutdown_signal());

  debug!("Waiting for shutdown signal");
  #[allow(clippy::redundant_pub_crate)]
  {
    tokio::select! {
      _ = &mut app => {}
      () = &mut shutdown_signal => {}
    };
  }

  cancellation.cancel();
  let _ = app.await;
  let targets = std::mem::take(&mut *targets.targets.lock().await);
  for (
    hostname,
    TargetHandle {
      join_send,
      join_resolve,
      ..
    },
  ) in targets
  {
    if let Err(e) = join_send.await {
      warn!("The `send` task for `{}` failed: {:?}", hostname, e);
    }
    if let Err(e) = join_resolve.await {
      warn!("The `resolve` task for `{}` failed: {:?}", hostname, e);
    }
  }

  Ok(())
}

fn setup_tracing() -> anyhow::Result<()> {
  tracing_subscriber::fmt()
    .with_writer(std::io::stderr)
    .with_env_filter(
      tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy(),
    )
    .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
    .try_init()
    .map_err(|e| anyhow::anyhow!(e))?;

  Ok(())
}

async fn shutdown_signal() {
  use tokio::signal;

  let ctrl_c = async {
    signal::ctrl_c()
      .await
      .expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    signal::unix::signal(signal::unix::SignalKind::terminate())
      .expect("failed to install signal handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  #[allow(clippy::redundant_pub_crate)]
  {
    tokio::select! {
      () = ctrl_c => {debug!("Ctrl-C received");},
      () = terminate => {debug!("SIGTERM received");},
    }
  }
}

struct Metrics {
  ping_targets: IntGauge,
  ping_dynamic_targets: IntGauge,
  ping_duplicates: IntCounterVec,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
  ping_timeouts: IntCounterVec,
  ping_resolve_errors: IntCounterVec,
  send_timeout: Duration,
}

fn setup_metrics(registry: &Registry, args: &args::Metrics) -> anyhow::Result<Metrics> {
  registry.register(Box::new(
    prometheus::process_collector::ProcessCollector::for_self(),
  ))?;

  let ping_targets = prometheus::register_int_gauge_with_registry!(
    "ping_targets",
    "Number of currently active targets",
    registry
  )?;
  let ping_dynamic_targets = prometheus::register_int_gauge_with_registry!(
    "ping_dynamic_targets",
    "Number of currently active dynamic targets",
    registry
  )?;

  let rtt_buckets = args.exponential_buckets()?;
  let send_timeout = Duration::from_secs_f64(*rtt_buckets.last().unwrap());
  let ping_rtt = prometheus::register_histogram_vec_with_registry!(
    "ping_rtt",
    "Round Trip Time of the packets send to the targets",
    &["target", "version"],
    rtt_buckets,
    registry
  )?;
  let ping_timeouts = prometheus::register_int_counter_vec_with_registry!(
    "ping_timeouts",
    "Number of packets for which no answer was received in the maxium bucket time",
    &["target", "version"],
    registry
  )?;
  let ping_errors = prometheus::register_int_counter_vec_with_registry!(
    "ping_errors",
    "Number of packets failed to send or receive due to errors",
    &["target", "version"],
    registry
  )?;
  let ping_resolve_errors = prometheus::register_int_counter_vec_with_registry!(
    "ping_resolve_errors",
    "Number of time the hostname resolve failed",
    &["target", "version"],
    registry
  )?;
  let ping_duplicates = prometheus::register_int_counter_vec_with_registry!(
    "ping_duplicates",
    "Number of duplicate packages received",
    &["target", "version"],
    registry
  )?;

  Ok(Metrics {
    ping_targets,
    ping_dynamic_targets,
    ping_duplicates,
    ping_errors,
    ping_rtt,
    ping_timeouts,
    ping_resolve_errors,
    send_timeout,
  })
}

struct App {
  registry: Registry,
  dynamic_targets: Option<Arc<TargetMap>>,
  auth_credentials: Option<AuthCredentials>,
}

impl App {
  const fn new(
    registry: Registry,
    dynamic_targets: Option<Arc<TargetMap>>,
    auth_credentials: Option<AuthCredentials>,
  ) -> Self {
    Self {
      registry,
      dynamic_targets,
      auth_credentials,
    }
  }

  #[tracing::instrument(ret, err, skip(self, cancellation))]
  async fn run(
    self: Arc<Self>,
    cancellation: CancellationToken,
    mut web_telemetry_path: String,
    web_listen_addresses: Vec<String>,
    web_systemd_socket: bool,
  ) -> anyhow::Result<()> {
    use axum::{routing::get, Router};

    if !web_telemetry_path.starts_with('/') {
      web_telemetry_path.insert(0, '/');
    }

    let mut router = Router::new();
    if web_telemetry_path != "/" {
      router = router.route("/", get(|| async { "" }));
    }

    let router = router
      .route(
        &web_telemetry_path,
        get({
          let this = self.clone();
          move |args, auth| this.metrics_get(args, auth)
        }),
      )
      .layer(
        TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
          let client = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ConnectInfo(addr)| {
              addr.ip()
            });
          tracing::span!(
              Level::INFO,
              "request",
              %client,
              method = %request.method(),
              uri = %MaxWidth(60, request.uri()),
              version = ?request.version(),
          )
        }),
      );

    let listeners = if web_systemd_socket {
      sd_notify::listen_fds()?
        .map(|fd| unsafe { std::net::TcpListener::from_raw_fd(fd) })
        .map(tokio::net::TcpListener::from_std)
        .collect::<Result<Vec<_>, io::Error>>()?
    } else {
      futures_util::future::join_all(
        web_listen_addresses
          .into_iter()
          .map(tokio::net::TcpListener::bind),
      )
      .await
      .into_iter()
      .collect::<Result<Vec<_>, io::Error>>()?
    };
    if listeners.is_empty() {
      bail!(
        "No listening socket configured{}",
        if web_systemd_socket {
          ". Systemd service was not activated by a socket unit"
        } else {
          ""
        }
      );
    }

    sd_notify::notify(false, &[sd_notify::NotifyState::Ready])?;

    let handles = listeners
      .into_iter()
      .map(|listener| {
        let app = router.clone();
        let cancellation = cancellation.clone();

        tokio::spawn(
          async move {
            axum::serve(
              listener,
              app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .into_future()
            .await
          }
          .in_current_span(),
        )
      })
      .collect::<Vec<_>>();

    // Wait for the first task to finish
    let (res, _idx, handles) = futures_util::future::select_all(handles).await;
    // Cancel all other listener tasks and wait for them to complete
    cancellation.cancel();
    if let Err(_e) = timeout(
      Duration::from_secs(5),
      futures_util::future::join_all(handles),
    )
    .await
    {
      error!("Timeout while waiting for all lsitener tasks to finish");
    };

    // Return the potential error of the first finished task
    Ok(res??)
  }

  async fn metrics_get(
    self: Arc<Self>,
    args: Query<MetricsGetArgs>,
    auth: Result<Auth, AuthRejection>,
  ) -> Response {
    if let Some(auth_credentials) = self.auth_credentials.as_ref() {
      match auth {
        Ok(Auth::Basic(basic)) => {
          let Some(hash) = auth_credentials.basic.get(&basic.0) else {
            return (
              StatusCode::UNAUTHORIZED,
              VerifyError::PasswordInvalid.to_string(),
            )
              .into_response();
          };

          if let Err(e) = util::verify_password(basic.1.as_deref().unwrap_or_default(), hash) {
            return (StatusCode::UNAUTHORIZED, e.to_string()).into_response();
          }
        }

        Ok(Auth::Bearer(bearer)) => {
          if !auth_credentials.bearer.contains(&bearer.0) {
            return (StatusCode::UNAUTHORIZED, "Invalid access token").into_response();
          };
        }

        Err(e) => return e.into_response(),
      }
    }

    if let Some((dynamic_targets, new_targets)) = self.dynamic_targets.as_ref().zip(args.0.targets)
    {
      dynamic_targets
        .add(
          new_targets
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned),
          false,
        )
        .await;
    }

    let mut buffer = Vec::with_capacity(4096);
    let encoder = prometheus::TextEncoder::new();
    let metric_families = self.registry.gather();
    if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
      return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }

    ([(header::CONTENT_TYPE, prometheus::TEXT_FORMAT)], buffer).into_response()
  }
}

#[derive(Debug, Deserialize)]
struct MetricsGetArgs {
  targets: Option<String>,
}

struct TargetMap {
  ping_targets: IntGauge,
  ping_dynamic_targets: IntGauge,

  targets: Mutex<HashMap<String, TargetHandle>>,
  limit: usize,
  dynamic_hold_time: Duration,
  send_args: Arc<TargetSendArgs>,
  resolve_args: Arc<TargetResolveArgs>,
  cancellation: CancellationToken,
}

impl TargetMap {
  fn new(
    ping_targets: IntGauge,
    ping_dynamic_targets: IntGauge,
    limit: usize,
    dynamic_hold_time: Duration,
    send_args: Arc<TargetSendArgs>,
    resolve_args: Arc<TargetResolveArgs>,
    cancellation: CancellationToken,
  ) -> Arc<Self> {
    Arc::new(Self {
      ping_targets,
      ping_dynamic_targets,

      targets: Mutex::default(),
      limit,
      dynamic_hold_time,
      send_args,
      resolve_args,
      cancellation,
    })
  }

  #[allow(clippy::future_not_send, clippy::significant_drop_tightening)]
  #[tracing::instrument(skip(self, new_targets))]
  async fn add(&self, new_targets: impl IntoIterator<Item = String>, permanent: bool) {
    let mut targets = self.targets.lock().await;
    let now = Instant::now();

    for new in new_targets {
      let len = targets.len();
      let target = targets.entry(new).and_modify(|t| {
        if permanent && !t.permanent {
          // Remove previously dynamic target
          self.ping_dynamic_targets.dec();
        }
        t.permanent |= permanent;
        t.last_seen = now;
      });

      if let Entry::Vacant(v) = target {
        if len >= self.limit {
          continue;
        }

        self.ping_targets.inc();
        if !permanent {
          self.ping_dynamic_targets.inc();
        }

        let hostname = v.key().to_owned();
        info!(?hostname, "new target");
        let cancellation = self.cancellation.child_token();
        let target = Arc::new(Target::new(hostname, cancellation.clone()));
        let join_send = tokio::spawn(target.clone().send_loop(self.send_args.clone()));
        let join_resolve = tokio::spawn(target.resolve_loop(self.resolve_args.clone()));

        v.insert(TargetHandle {
          permanent,
          last_seen: now,
          cancellation,
          join_send,
          join_resolve,
        });
      }
    }
  }

  async fn cleanup(&self, now: Instant) {
    let mut targets = self.targets.lock().await;

    targets.retain(|hostname, target| {
      let retain =
        target.permanent || now.duration_since(target.last_seen) <= self.dynamic_hold_time;
      if !retain {
        debug!(%hostname, "drop target");
        target.cancellation.cancel();
        self.ping_dynamic_targets.dec();
      }
      retain
    });
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self))]
  async fn cleanup_task(self: Arc<Self>) {
    let mut cancelled = pin!(self.cancellation.cancelled());
    let mut interval = tokio::time::interval(SECOND.max(self.dynamic_hold_time / 2));

    #[allow(clippy::redundant_pub_crate)]
    loop {
      trace!("loop");
      tokio::select! {
        () = &mut cancelled => {
          break;
        }
        now = interval.tick() => {
          self.cleanup(now.into()).await;
        }
      }
    }
  }
}

#[derive(Debug)]
struct TargetHandle {
  permanent: bool,
  last_seen: Instant,
  cancellation: CancellationToken,
  join_send: JoinHandle<()>,
  join_resolve: JoinHandle<()>,
}

struct TargetSendArgs {
  send_interval: Duration,
  send_timeout: Duration,
  client_v4: Client,
  client_v6: Client,
  ping_duplicates: IntCounterVec,
  ping_errors: IntCounterVec,
  ping_rtt: HistogramVec,
  ping_timeouts: IntCounterVec,
}

struct TargetResolveArgs {
  resolve_interval: Duration,
  resolver: TokioResolver,
  ping_resolve_errors: IntCounterVec,
}

#[derive(Debug)]
struct Target {
  hostname: String,
  addresses: ArcSwap<Addresses>,
  cancellation: CancellationToken,
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
  fn new(hostname: String, cancellation: CancellationToken) -> Self {
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
      cancellation,
    }
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, args), fields(hostname = self.hostname))]
  async fn send_loop(self: Arc<Self>, args: Arc<TargetSendArgs>) {
    let TargetSendArgs {
      send_interval,
      send_timeout,
      client_v4,
      client_v6,
      ..
    } = args.as_ref();
    let mut interval = tokio::time::interval(*send_interval);

    let mut seq = 0_u16;
    let mut id = PingIdentifier(rand::random());

    loop {
      let (next_seq, overflow) = seq.overflowing_add(1);
      seq = next_seq;
      if overflow {
        id = PingIdentifier(rand::random());
      }

      #[allow(clippy::redundant_pub_crate)]
      {
        tokio::select! {
          _ = interval.tick() => (),
          () = self.cancellation.cancelled() => {
            break;
          }
        };
      }

      trace!(?seq, "loop");

      let addresses = self.addresses.load();
      if let Some(addr) = addresses.ipv4_addr {
        let mut pinger = client_v4.pinger(addr.into(), id).await;
        pinger.timeout(*send_timeout);

        let this = self.clone();
        let args = args.clone();
        tokio::spawn(
          async move {
            match this.send_ipv4(seq, addr, pinger).await {
              PingResult::Success(rtt) => {
                args
                  .ping_rtt
                  .with_label_values([&this.hostname, "icmp"].as_slice())
                  .observe(rtt.as_secs_f64());
              }
              PingResult::Timeout => {
                args
                  .ping_rtt
                  .with_label_values([&this.hostname, "icmp"].as_slice())
                  .observe(f64::INFINITY);
                args
                  .ping_timeouts
                  .with_label_values([&this.hostname, "icmp"].as_slice())
                  .inc();
              }
              PingResult::Duplicate => {
                args
                  .ping_duplicates
                  .with_label_values([&this.hostname, "icmp"].as_slice())
                  .inc();
              }
              PingResult::Error => args
                .ping_errors
                .with_label_values([&this.hostname, "icmp"].as_slice())
                .inc(),
            }
          }
          .in_current_span(),
        );
      }

      if let Some(addr) = addresses.ipv6_addr {
        let mut pinger = client_v6.pinger(addr.into(), id).await;
        pinger.timeout(*send_timeout);

        let this = self.clone();
        let args = args.clone();
        tokio::spawn(
          async move {
            match this.send_ipv6(seq, addr, pinger).await {
              PingResult::Success(rtt) => {
                args
                  .ping_rtt
                  .with_label_values([&this.hostname, "icmp6"].as_slice())
                  .observe(rtt.as_secs_f64());
              }
              PingResult::Timeout => {
                args
                  .ping_rtt
                  .with_label_values([&this.hostname, "icmp6"].as_slice())
                  .observe(f64::INFINITY);
                args
                  .ping_timeouts
                  .with_label_values([&this.hostname, "icmp6"].as_slice())
                  .inc();
              }
              PingResult::Duplicate => {
                args
                  .ping_duplicates
                  .with_label_values([&this.hostname, "icmp6"].as_slice())
                  .inc();
              }
              PingResult::Error => args
                .ping_errors
                .with_label_values([&this.hostname, "icmp6"].as_slice())
                .inc(),
            }
          }
          .in_current_span(),
        );
      }
    }

    let values = &[&self.hostname, "icmp"];
    let _ = args.ping_rtt.remove_label_values(values);
    let _ = args.ping_rtt.remove_label_values(values);
    let _ = args.ping_duplicates.remove_label_values(values);
    let _ = args.ping_errors.remove_label_values(values);

    let values6 = &[&self.hostname, "icmp6"];
    let _ = args.ping_rtt.remove_label_values(values6);
    let _ = args.ping_rtt.remove_label_values(values6);
    let _ = args.ping_duplicates.remove_label_values(values6);
    let _ = args.ping_errors.remove_label_values(values6);
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, pinger))]
  async fn send_ipv4(&self, seq: u16, addr: Ipv4Addr, mut pinger: Pinger) -> PingResult {
    match pinger.ping(PingSequence(seq), &[]).await {
      Ok((_packet, rtt)) => PingResult::Success(rtt),
      Err(err) => match err {
        SurgeError::Timeout { .. } => PingResult::Timeout,
        SurgeError::IdenticalRequests { .. } => PingResult::Duplicate,
        _ => PingResult::Error,
      },
    }
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, pinger_v6))]
  async fn send_ipv6(&self, seq: u16, addr: Ipv6Addr, mut pinger_v6: Pinger) -> PingResult {
    match pinger_v6.ping(PingSequence(seq), &[]).await {
      Ok((_packet, rtt)) => PingResult::Success(rtt),
      Err(err) => match err {
        SurgeError::Timeout { .. } => PingResult::Timeout,
        SurgeError::IdenticalRequests { .. } => PingResult::Duplicate,
        _ => PingResult::Error,
      },
    }
  }

  #[tracing::instrument(ret(level = Level::DEBUG), skip(self, args), fields(hostname = self.hostname))]
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
      resolver,
      ping_resolve_errors,
    } = args.as_ref();
    let mut interval = tokio::time::interval(*resolve_interval);

    loop {
      #[allow(clippy::redundant_pub_crate)]
      {
        tokio::select! {
          _ = interval.tick() => (),
          () = self.cancellation.cancelled() => {
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
            .with_label_values([&self.hostname, "icmp"].as_slice())
            .inc();
          None
        }
      };

      let ipv6_addr = match self.resolve_ipv6(resolver).await {
        Ok(addr) => addr,
        Err(e) => {
          info!("Could not resolve IPv6 address of {}: {}", self.hostname, e);
          ping_resolve_errors
            .with_label_values([&self.hostname, "icmp6"].as_slice())
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

  #[tracing::instrument(ret(level = Level::DEBUG), err(level = Level::INFO), skip(self, resolver))]
  async fn resolve_ipv4(&self, resolver: &TokioResolver) -> Result<Option<Ipv4Addr>, ResolveError> {
    match resolver.ipv4_lookup(&self.hostname).await {
      Ok(resp) => Ok(resp.into_iter().choose(&mut rng()).map(Into::into)),
      Err(e) => match e.kind() {
        ResolveErrorKind::Proto(proto_error) => match proto_error.kind() {
          ProtoErrorKind::NoRecordsFound { .. } => Ok(None),
          _ => Err(e),
        },
        _ => Err(e),
      },
    }
  }

  #[tracing::instrument(ret(level = Level::DEBUG), err(level = Level::INFO), skip(self, resolver))]
  async fn resolve_ipv6(&self, resolver: &TokioResolver) -> Result<Option<Ipv6Addr>, ResolveError> {
    match resolver.ipv6_lookup(&self.hostname).await {
      Ok(resp) => Ok(resp.into_iter().choose(&mut rng()).map(Into::into)),
      Err(e) => match e.kind() {
        ResolveErrorKind::Proto(proto_error) => match proto_error.kind() {
          ProtoErrorKind::NoRecordsFound { .. } => Ok(None),
          _ => Err(e),
        },
        _ => Err(e),
      },
    }
  }
}

struct MaxWidth<T>(usize, T);

impl<T: fmt::Display> fmt::Display for MaxWidth<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fn truncate(s: &str, max_bytes: usize) -> &str {
      if let Some((idx, _)) = s.char_indices().take_while(|(i, _)| *i < max_bytes).last() {
        &s[..idx]
      } else {
        s
      }
    }

    let mut s: String = format!("{}", self.1);
    let trunc = truncate(&s, self.0);
    if trunc.len() < s.len() {
      s.truncate(trunc.len());
      s.push('…');
    }

    f.write_str(&s)
  }
}
