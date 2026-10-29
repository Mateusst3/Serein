//! A single IPv4/UDP flow, not a general IP stack. No fragments, forwarding or DNS.
use std::net::{Ipv4Addr, SocketAddrV4};

pub(crate) const MAX_DATAGRAM: usize = 4096;
pub(crate) const MAX_IP: usize = MAX_DATAGRAM + 28;

pub(crate) struct Flow {
	pub local: SocketAddrV4,
	pub remote: SocketAddrV4,
}

fn checksum(bytes: &[u8], mut sum: u32) -> u16 {
	for chunk in bytes.chunks(2) {
		sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
	}
	while sum >> 16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	!(sum as u16)
}

fn pseudo(source: Ipv4Addr, destination: Ipv4Addr, length: u16) -> u32 {
	let mut sum = u32::from(length) + 17;
	for ip in [source, destination] {
		let bytes = ip.octets();
		sum += u32::from(u16::from_be_bytes([bytes[0], bytes[1]]))
			+ u32::from(u16::from_be_bytes([bytes[2], bytes[3]]));
	}
	sum
}

impl Flow {
	pub fn encode(&self, data: &[u8], out: &mut [u8; MAX_IP]) -> Option<usize> {
		if data.len() > MAX_DATAGRAM {
			return None;
		}
		let length = 28 + data.len();
		out[..28].fill(0);
		out[0] = 0x45;
		out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
		out[6] = 0x40; // Do not fragment the inner packet.
		out[8] = 64;
		out[9] = 17;
		out[12..16].copy_from_slice(&self.local.ip().octets());
		out[16..20].copy_from_slice(&self.remote.ip().octets());
		let ip_checksum = checksum(&out[..20], 0);
		out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
		out[20..22].copy_from_slice(&self.local.port().to_be_bytes());
		out[22..24].copy_from_slice(&self.remote.port().to_be_bytes());
		out[24..26].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
		out[28..length].copy_from_slice(data);
		let udp_checksum = checksum(
			&out[20..length],
			pseudo(*self.local.ip(), *self.remote.ip(), (data.len() + 8) as u16),
		);
		out[26..28].copy_from_slice(
			&if udp_checksum == 0 {
				u16::MAX
			} else {
				udp_checksum
			}
			.to_be_bytes(),
		);
		Some(length)
	}

	pub fn decode<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
		if !(28..=MAX_IP).contains(&packet.len())
			|| packet[0] != 0x45
			|| packet[9] != 17
			|| usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
			|| u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff != 0
			|| checksum(&packet[..20], 0) != 0
			|| packet[12..16] != self.remote.ip().octets()
			|| packet[16..20] != self.local.ip().octets()
			|| packet[20..22] != self.remote.port().to_be_bytes()
			|| packet[22..24] != self.local.port().to_be_bytes()
			|| usize::from(u16::from_be_bytes([packet[24], packet[25]])) != packet.len() - 20
		{
			return None;
		}
		if packet[26..28] != [0, 0]
			&& checksum(
				&packet[20..],
				pseudo(
					*self.remote.ip(),
					*self.local.ip(),
					(packet.len() - 20) as u16,
				),
			) != 0
		{
			return None;
		}
		Some(&packet[28..])
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn flow_rejects_spoofing_fragments_lengths_and_corruption() {
		let sender = Flow {
			local: "10.2.0.2:50000".parse().unwrap(),
			remote: "192.0.2.1:50001".parse().unwrap(),
		};
		let receiver = Flow {
			local: sender.remote,
			remote: sender.local,
		};
		let mut packet = [0; MAX_IP];
		let n = sender.encode(b"odd payload", &mut packet).unwrap();
		assert_eq!(
			receiver.decode(&packet[..n]),
			Some(b"odd payload".as_slice())
		);
		assert!(sender.decode(&packet[..n]).is_none());
		for index in [0, 2, 6, 9, 12, 16, 20, 22, 24, 28] {
			packet[index] ^= 1;
			assert!(receiver.decode(&packet[..n]).is_none(), "byte {index}");
			packet[index] ^= 1;
		}
		assert!(receiver.decode(&packet[..n - 1]).is_none());
		assert!(receiver.decode(&packet[..n + 1]).is_none());
		assert!(sender.encode(&[0; MAX_DATAGRAM + 1], &mut packet).is_none());
	}
}
