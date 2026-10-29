//! Opt-in WireGuard for one outgoing screen-share UDP flow. Never installs OS routes.
mod config;
mod packet;

use boringtun::{
	noise::{Tunn, TunnResult},
	x25519::{PublicKey, StaticSecret},
};
use config::Config;
use packet::{Flow, MAX_DATAGRAM, MAX_IP};
use std::{
	io,
	net::{SocketAddr, SocketAddrV4},
	path::PathBuf,
	time::Duration,
};
use tokio::{
	net::UdpSocket,
	sync::{mpsc, oneshot},
	task::JoinHandle,
	time::{MissedTickBehavior, timeout},
};

const QUEUE: usize = 64;
const SCRATCH: usize = MAX_IP + 256;
pub const CONFIG_ENV: &str = "SEREIN_SCREEN_WIREGUARD_CONFIG";

/// Sharing and viewing use distinct instances. Only an outgoing share reads the opt-in.
pub enum MediaSocket {
	Direct(UdpSocket),
	Tunnel(Tunnel),
}

/// Common nonblocking media write boundary; a full tunnel queue drops one datagram.
pub trait Datagram {
	fn try_send(&self, data: &[u8]) -> io::Result<usize>;
}
impl Datagram for UdpSocket {
	fn try_send(&self, data: &[u8]) -> io::Result<usize> {
		self.try_send(data)
	}
}
impl Datagram for MediaSocket {
	fn try_send(&self, data: &[u8]) -> io::Result<usize> {
		match self {
			Self::Direct(socket) => socket.try_send(data),
			Self::Tunnel(tunnel) => {
				if data.len() > MAX_DATAGRAM {
					return Err(io::ErrorKind::InvalidInput.into());
				}
				tunnel
					.outgoing
					.try_send(data.to_vec().into_boxed_slice())
					.map_err(|e| {
						io::Error::from(match e {
							mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
							mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
						})
					})?;
				Ok(data.len())
			}
		}
	}
}

impl MediaSocket {
	/// Missing opt-in means direct. An invalid opt-in fails closed, including an empty path.
	pub async fn connect(remote: SocketAddr, outgoing_share: bool) -> Result<Self, &'static str> {
		let path = if outgoing_share {
			std::env::var_os(CONFIG_ENV).map(PathBuf::from)
		} else {
			None
		};
		Self::connect_with_config(remote, path).await
	}

	pub async fn connect_with_config(
		remote: SocketAddr,
		path: Option<PathBuf>,
	) -> Result<Self, &'static str> {
		if let Some(path) = path {
			let SocketAddr::V4(remote) = remote else {
				return Err("Screen-share WireGuard currently requires an IPv4 media server");
			};
			let config = tokio::task::spawn_blocking(move || Config::read(&path))
				.await
				.map_err(|_| "WireGuard configuration worker failed")??;
			return Tunnel::connect(config, remote).await.map(Self::Tunnel);
		}
		let socket = UdpSocket::bind(if remote.is_ipv4() {
			"0.0.0.0:0"
		} else {
			"[::]:0"
		})
		.await
		.map_err(|_| "Cannot bind stream UDP socket")?;
		socket
			.connect(remote)
			.await
			.map_err(|_| "Cannot connect stream UDP socket")?;
		Ok(Self::Direct(socket))
	}

	pub async fn recv(&mut self, data: &mut [u8]) -> io::Result<usize> {
		match self {
			Self::Direct(socket) => socket.recv(data).await,
			Self::Tunnel(tunnel) => {
				let packet = tunnel
					.incoming
					.recv()
					.await
					.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
				// Match UDP truncation semantics (the caller reserves MAX_PACKET + 1).
				let length = data.len().min(packet.len());
				data[..length].copy_from_slice(&packet[..length]);
				Ok(length)
			}
		}
	}

	pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
		match self {
			Self::Direct(socket) => socket.send(data).await,
			Self::Tunnel(tunnel) => {
				if data.len() > MAX_DATAGRAM {
					return Err(io::ErrorKind::InvalidInput.into());
				}
				tunnel
					.outgoing
					.send(data.to_vec().into_boxed_slice())
					.await
					.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
				Ok(data.len())
			}
		}
	}
}

pub struct Tunnel {
	outgoing: mpsc::Sender<Box<[u8]>>,
	incoming: mpsc::Receiver<Box<[u8]>>,
	worker: JoinHandle<()>,
}
impl Drop for Tunnel {
	fn drop(&mut self) {
		self.worker.abort();
	}
}

impl Tunnel {
	async fn connect(config: Config, remote: SocketAddrV4) -> Result<Self, &'static str> {
		let socket = UdpSocket::bind(if config.endpoint.is_ipv4() {
			"0.0.0.0:0"
		} else {
			"[::]:0"
		})
		.await
		.map_err(|_| "Cannot bind WireGuard socket")?;
		socket
			.connect(config.endpoint)
			.await
			.map_err(|_| "Cannot connect WireGuard endpoint")?;
		let mut random = [0; 6];
		getrandom::fill(&mut random).map_err(|_| "WireGuard random initialization failed")?;
		let flow = Flow {
			local: SocketAddrV4::new(
				config.address,
				49152 + u16::from_be_bytes([random[0], random[1]]) % 16384,
			),
			remote,
		};
		let tunnel = Tunn::new(
			StaticSecret::from(*config.private),
			PublicKey::from(config.public),
			config.preshared.as_ref().map(|key| **key),
			config.keepalive,
			u32::from_be_bytes(random[2..].try_into().unwrap()) >> 8,
			None,
		);
		let (outgoing, rx) = mpsc::channel(QUEUE);
		let (tx, incoming) = mpsc::channel(QUEUE);
		let (ready_tx, ready_rx) = oneshot::channel();
		let worker = tokio::spawn(async move {
			let _ = run(socket, tunnel, flow, rx, tx, ready_tx).await;
		});
		let result = Self {
			outgoing,
			incoming,
			worker,
		};
		// Keep the abort-on-drop guard alive while awaiting the handshake, including cancellation.
		timeout(Duration::from_secs(12), ready_rx)
			.await
			.map_err(|_| "Screen-share WireGuard handshake timed out")?
			.map_err(|_| "Screen-share WireGuard handshake failed")?;
		Ok(result)
	}
}

async fn run(
	socket: UdpSocket,
	mut tunnel: Tunn,
	flow: Flow,
	mut outgoing: mpsc::Receiver<Box<[u8]>>,
	incoming: mpsc::Sender<Box<[u8]>>,
	ready: oneshot::Sender<()>,
) -> io::Result<()> {
	let mut ready = Some(ready);
	let mut network = [0; SCRATCH];
	let mut output = [0; SCRATCH];
	let mut ip = [0; MAX_IP];
	let mut tick = tokio::time::interval(Duration::from_millis(100));
	tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
	if let TunnResult::WriteToNetwork(packet) =
		tunnel.format_handshake_initiation(&mut output, false)
	{
		socket.send(packet).await?;
	}
	loop {
		tokio::select! {
			_ = incoming.closed() => return Ok(()),
			_ = tick.tick() => {
				// Do not let media accumulate in BoringTun's queue after a send session expires.
				if tunnel.time_since_last_handshake().is_some_and(|age| age >= Duration::from_secs(180)) {
					return Err(io::ErrorKind::ConnectionAborted.into());
				}
				match tunnel.update_timers(&mut output) {
					TunnResult::WriteToNetwork(packet) => { socket.try_send(packet)?; },
					TunnResult::Err(_) => return Err(io::ErrorKind::ConnectionAborted.into()),
					_ => {},
				}
			},
			data = outgoing.recv(), if ready.is_none() => {
				let Some(data) = data else { return Ok(()); };
				let Some(n) = flow.encode(&data, &mut ip) else { continue; };
				if let TunnResult::WriteToNetwork(packet) = tunnel.encapsulate(&ip[..n], &mut output) {
					// Never wait for network capacity in the media path.
					match socket.try_send(packet) { Ok(_) => {}, Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}, Err(e) => return Err(e) }
				}
			},
			result = socket.recv(&mut network) => {
				let n = result?;
				let mut packet = &network[..n];
				// Drain BoringTun's bounded handshake/rekey queue. Initial media is held
				// until handshake and expired sessions terminate instead of queuing media.
				for _ in 0..=256 {
					match tunnel.decapsulate(None, packet, &mut output) {
						TunnResult::WriteToNetwork(bytes) => { socket.try_send(bytes)?; },
						TunnResult::WriteToTunnelV4(bytes, _) => {
							if let Some(data) = flow.decode(bytes) { let _ = incoming.try_send(data.to_vec().into_boxed_slice()); }
							break;
						},
						_ => break,
					}
					packet = &[];
				}
				if tunnel.time_since_last_handshake().is_some() && let Some(tx) = ready.take() {
					let _ = tx.send(());
				}
			}
		}
	}
}

#[cfg(test)]
mod tests;
