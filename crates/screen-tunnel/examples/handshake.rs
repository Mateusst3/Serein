//! Tests the selected VPN peer only. No Discord connection or inner IP traffic.
#[tokio::main]
async fn main() {
	let Some(path) = std::env::args_os().nth(1) else {
		eprintln!("Usage: cargo run -p screen-tunnel --example handshake -- /path/to/config.conf");
		std::process::exit(2);
	};
	match screen_tunnel::MediaSocket::connect_with_config(
		"192.0.2.1:9".parse().unwrap(),
		Some(path.into()),
	)
	.await
	{
		Ok(_socket) => {
			println!("WireGuard peer authenticated. No Discord or inner IP traffic sent.")
		}
		Err(error) => {
			eprintln!("{error}");
			std::process::exit(1);
		}
	}
}
