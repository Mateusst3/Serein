use super::*;
use zeroize::Zeroizing;

#[tokio::test]
async fn authenticated_loopback_tunnel_delivers_only_its_udp_flow_and_stops_with_owner() {
	let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let client_key = StaticSecret::from([1; 32]);
	let server_key = StaticSecret::from([2; 32]);
	let config = Config {
		private: Zeroizing::new(client_key.to_bytes()),
		public: PublicKey::from(&server_key).to_bytes(),
		preshared: None,
		address: "10.2.0.2".parse().unwrap(),
		endpoint: server.local_addr().unwrap(),
		keepalive: Some(25),
	};
	let target: SocketAddrV4 = "192.0.2.10:50000".parse().unwrap();
	let peer = tokio::spawn(async move {
		let mut tunnel = Tunn::new(
			server_key,
			PublicKey::from(&client_key),
			None,
			None,
			1,
			None,
		);
		let mut wire = [0; SCRATCH];
		let mut output = [0; SCRATCH];
		let mut ip = [0; MAX_IP];
		loop {
			let (n, client) = server.recv_from(&mut wire).await.unwrap();
			assert!(
				!wire[..n]
					.windows(b"synthetic-screen-frame".len())
					.any(|p| p == b"synthetic-screen-frame")
			);
			match tunnel.decapsulate(None, &wire[..n], &mut output) {
				TunnResult::WriteToNetwork(packet) => {
					server.send_to(packet, client).await.unwrap();
				}
				TunnResult::WriteToTunnelV4(packet, _) if !packet.is_empty() => {
					let local = SocketAddrV4::new(
						std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
						u16::from_be_bytes([packet[20], packet[21]]),
					);
					let flow = Flow {
						local: target,
						remote: local,
					};
					assert_eq!(
						flow.decode(packet),
						Some(b"synthetic-screen-frame".as_slice())
					);
					// Authenticated WireGuard packets from a different inner flow are still rejected.
					let wrong = Flow {
						local: SocketAddrV4::new(*target.ip(), target.port() + 1),
						remote: local,
					};
					let n = wrong.encode(b"other-flow", &mut ip).unwrap();
					if let TunnResult::WriteToNetwork(packet) =
						tunnel.encapsulate(&ip[..n], &mut output)
					{
						server.send_to(packet, client).await.unwrap();
					}
					let n = flow.encode(b"stream-feedback", &mut ip).unwrap();
					if let TunnResult::WriteToNetwork(packet) =
						tunnel.encapsulate(&ip[..n], &mut output)
					{
						server.send_to(packet, client).await.unwrap();
					}
					return;
				}
				_ => {}
			}
		}
	});
	let mut client = timeout(Duration::from_secs(3), Tunnel::connect(config, target))
		.await
		.unwrap()
		.unwrap();
	client
		.outgoing
		.send(b"synthetic-screen-frame".to_vec().into_boxed_slice())
		.await
		.unwrap();
	let received = timeout(Duration::from_secs(3), client.incoming.recv())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(&*received, b"stream-feedback");
	peer.await.unwrap();
	let abort = client.worker.abort_handle();
	drop(client);
	// Await task termination rather than sleeping or depending on scheduler timing.
	timeout(Duration::from_secs(3), async {
		while !abort.is_finished() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

#[tokio::test]
async fn configured_failure_has_no_direct_fallback_and_queue_has_a_byte_ceiling() {
	let direct = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let result = MediaSocket::connect_with_config(
		direct.local_addr().unwrap(),
		Some(PathBuf::from(
			"/nonexistent/serein-synthetic-wireguard.conf",
		)),
	)
	.await;
	assert!(result.is_err());
	assert_eq!(
		direct.try_recv(&mut [0; 128]).unwrap_err().kind(),
		io::ErrorKind::WouldBlock
	);
	let (outgoing, _rx) = mpsc::channel(QUEUE);
	let (_tx, incoming) = mpsc::channel(QUEUE);
	let socket = MediaSocket::Tunnel(Tunnel {
		outgoing,
		incoming,
		worker: tokio::spawn(std::future::pending()),
	});
	for _ in 0..QUEUE {
		assert_eq!(socket.try_send(&[0; MAX_DATAGRAM]).unwrap(), MAX_DATAGRAM);
	}
	assert_eq!(
		socket.try_send(&[0]).unwrap_err().kind(),
		io::ErrorKind::WouldBlock
	);
	assert_eq!(
		socket.try_send(&[0; MAX_DATAGRAM + 1]).unwrap_err().kind(),
		io::ErrorKind::InvalidInput
	);
}
