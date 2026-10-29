use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
	io::Read,
	net::{IpAddr, Ipv4Addr, SocketAddr},
	path::Path,
};
use zeroize::Zeroizing;

pub(crate) const MAX_CONFIG: usize = 16 * 1024;
pub(crate) struct Config {
	pub private: Zeroizing<[u8; 32]>,
	pub public: [u8; 32],
	pub preshared: Option<Zeroizing<[u8; 32]>>,
	pub address: Ipv4Addr,
	pub endpoint: SocketAddr,
	pub keepalive: Option<u16>,
}

fn key(value: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
	let mut result = Zeroizing::new([0; 32]);
	if STANDARD.decode_slice(value, &mut *result).ok() != Some(32) {
		return Err("Invalid WireGuard key");
	}
	Ok(result)
}

impl Config {
	pub fn read(path: &Path) -> Result<Self, &'static str> {
		let mut options = std::fs::OpenOptions::new();
		options.read(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			// Reject symlinks and avoid hanging a blocking worker on a substituted FIFO.
			options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
		}
		let file = options
			.open(path)
			.map_err(|_| "Cannot open screen-share WireGuard configuration")?;
		let metadata = file
			.metadata()
			.map_err(|_| "Cannot inspect WireGuard configuration")?;
		if !metadata.is_file() || metadata.len() > MAX_CONFIG as u64 {
			return Err("WireGuard configuration must be a regular file of at most 16 KiB");
		}
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			if metadata.permissions().mode() & 0o077 != 0 {
				return Err("WireGuard configuration must be private (chmod 600)");
			}
		}
		let mut bytes = Zeroizing::new(Vec::new());
		file.take((MAX_CONFIG + 1) as u64)
			.read_to_end(&mut bytes)
			.map_err(|_| "Cannot read WireGuard configuration")?;
		let text =
			std::str::from_utf8(&bytes).map_err(|_| "Invalid WireGuard configuration encoding")?;
		Self::parse(text)
	}

	fn parse(text: &str) -> Result<Self, &'static str> {
		if text.len() > MAX_CONFIG {
			return Err("WireGuard configuration exceeds 16 KiB");
		}
		let mut section = "";
		let mut interface = false;
		let mut peer = false;
		let mut seen = std::collections::HashSet::new();
		let (mut private, mut public, mut preshared, mut address, mut endpoint, mut keepalive) =
			(None, None, None, None, None, None);
		let mut allowed = false;
		for raw in text.lines() {
			let line = raw.split('#').next().unwrap_or("").trim();
			if line.is_empty() {
				continue;
			}
			if line.starts_with('[') {
				match line {
					"[Interface]" if !interface && !peer => {
						interface = true;
						section = "interface";
					}
					"[Peer]" if interface && !peer => {
						peer = true;
						section = "peer";
					}
					_ => return Err("WireGuard requires one Interface and one Peer"),
				}
				continue;
			}
			let (name, value) = line
				.split_once('=')
				.ok_or("Invalid WireGuard configuration entry")?;
			let (name, value) = (name.trim(), value.trim());
			if !seen.insert((section, name)) {
				return Err("Duplicate WireGuard configuration entry");
			}
			match (section, name) {
				("interface", "PrivateKey") => private = Some(key(value)?),
				("peer", "PublicKey") => public = Some(*key(value)?),
				("peer", "PresharedKey") => preshared = Some(key(value)?),
				("interface", "Address") => {
					for cidr in value.split(',') {
						let (ip, prefix) = cidr
							.trim()
							.split_once('/')
							.ok_or("Invalid WireGuard interface address")?;
						let ip: IpAddr = ip
							.parse()
							.map_err(|_| "Invalid WireGuard interface address")?;
						let prefix: u8 = prefix
							.parse()
							.map_err(|_| "Invalid WireGuard address prefix")?;
						match ip {
							IpAddr::V4(ip)
								if prefix == 32
									&& address.is_none() && !ip.is_unspecified()
									&& !ip.is_multicast() && !ip.is_loopback() =>
							{
								address = Some(ip)
							}
							IpAddr::V6(_) if prefix == 128 => {}
							_ => return Err("WireGuard requires one IPv4 /32 address"),
						}
					}
				}
				("peer", "AllowedIPs") => {
					for cidr in value.split(',').map(str::trim) {
						match cidr {
							"0.0.0.0/0" => allowed = true,
							"::/0" => {}
							_ => return Err("Screen tunnel requires default AllowedIPs"),
						}
					}
				}
				("peer", "Endpoint") => {
					let value: SocketAddr = value
						.parse()
						.map_err(|_| "WireGuard endpoint must be a numeric IP and port")?;
					if value.port() == 0 || value.ip().is_unspecified() || value.ip().is_multicast()
					{
						return Err("Invalid WireGuard endpoint");
					}
					endpoint = Some(value);
				}
				("peer", "PersistentKeepalive") => {
					let seconds: u16 = value.parse().map_err(|_| "Invalid WireGuard keepalive")?;
					keepalive = (seconds != 0).then_some(seconds);
				}
				// DNS never changes system resolution. Hook commands are deliberately unsupported.
				("interface", "DNS") => {}
				_ => return Err("Unsupported WireGuard configuration entry"),
			}
		}
		if !peer || !allowed {
			return Err("Missing WireGuard peer or IPv4 AllowedIPs");
		}
		Ok(Self {
			private: private.ok_or("Missing WireGuard private key")?,
			public: public.ok_or("Missing WireGuard peer key")?,
			preshared,
			address: address.ok_or("Missing WireGuard IPv4 address")?,
			endpoint: endpoint.ok_or("Missing WireGuard endpoint")?,
			keepalive,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	fn fixture() -> String {
		format!(
			"[Interface]\nPrivateKey = {}\nAddress = 10.2.0.2/32, 2a07:b944::2:2/128\nDNS = 10.2.0.1\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:51820\nPersistentKeepalive = 25\n",
			STANDARD.encode([1; 32]),
			STANDARD.encode([2; 32])
		)
	}
	#[test]
	fn proton_config_is_bounded_and_never_executes_hooks_or_accepts_ambiguous_peers() {
		let text = fixture();
		assert_eq!(
			Config::parse(&text).unwrap().address,
			Ipv4Addr::new(10, 2, 0, 2)
		);
		for invalid in [
			format!("{text}\n[Peer]\n"),
			text.replace("DNS = 10.2.0.1", "PostUp = command"),
			text.replace("PrivateKey =", "PrivateKey = broken\nPrivateKey ="),
			"x".repeat(MAX_CONFIG + 1),
			text.replace("0.0.0.0/0", "192.0.2.0/24"),
		] {
			assert!(Config::parse(&invalid).is_err());
		}
		let error = Config::parse(&text.replace(&STANDARD.encode([1; 32]), "PRIVATE-SECRET"))
			.err()
			.unwrap();
		assert!(!error.contains("PRIVATE-SECRET"));
	}

	#[cfg(unix)]
	#[test]
	fn external_config_requires_private_regular_bounded_file() {
		use std::{
			io::Write,
			os::unix::fs::{OpenOptionsExt, PermissionsExt},
		};
		let mut random = [0; 8];
		getrandom::fill(&mut random).unwrap();
		let path = std::env::temp_dir().join(format!(
			"serein-synthetic-wg-{:x}.conf",
			u64::from_ne_bytes(random)
		));
		struct Remove(std::path::PathBuf);
		impl Drop for Remove {
			fn drop(&mut self) {
				let _ = std::fs::remove_file(&self.0);
			}
		}
		let _remove = Remove(path.clone());
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&path)
			.unwrap();
		file.write_all(fixture().as_bytes()).unwrap();
		assert!(Config::read(&path).is_ok());
		file.set_permissions(std::fs::Permissions::from_mode(0o644))
			.unwrap();
		assert!(Config::read(&path).is_err());
		file.set_permissions(std::fs::Permissions::from_mode(0o600))
			.unwrap();
		file.set_len((MAX_CONFIG + 1) as u64).unwrap();
		assert!(Config::read(&path).is_err());
		assert!(Config::read(&std::env::temp_dir()).is_err());
	}
}
