use colored::*;
use pcap::Device;
use etherparse::{SlicedPacket, NetSlice, TransportSlice};
use std::net::IpAddr;

mod handle;
use handle::create_handle;

mod ip;
use ip::get_all_local_addrs;

fn main() {
    let default_device = Device::lookup().expect("No default device found").unwrap();
    let mut cap = create_handle(&default_device);
    let local_addrs = get_all_local_addrs();

    let mut incoming_total: u64 = 0;
    let mut outgoing_total: u64 = 0;

    println!("{}", "Wi-Fi/Ethernet traffic monitor".yellow());
    println!("{}", "Press Ctrl+C to quit".green());
    println!("=========================================================");
    println!("Monitoring {} traffic", default_device.name.as_str().yellow());

    loop {
        if let Ok(pkt) = cap.next_packet() {
            let size = pkt.header.len as u64;

            if let Ok(sliced) = SlicedPacket::from_ethernet(pkt.data) {
                if let Some(net_slice) = sliced.net {
                    match net_slice {
                        NetSlice::Ipv4(ip4) => {
                            let src = IpAddr::V4(ip4.header().source_addr());
                            let dst = IpAddr::V4(ip4.header().destination_addr());

                            if local_addrs.contains(&src) {
                                outgoing_total += size;
                                println!("{}: Outgoing {}: {} bytes (total {})", default_device.name.as_str().blue(),
                                         "IPv4".yellow(),
                                         size.to_string().green(),
                                         outgoing_total.to_string().green());
                            } else if local_addrs.contains(&dst) {
                                incoming_total += size;
                                println!("{}: Incoming {}: {} bytes (total {})", default_device.name.as_str().blue(),
                                         "IPv4".yellow(),
                                         size.to_string().green(),
                                         incoming_total.to_string().green());
                            }
                        }
                        NetSlice::Ipv6(ip6) => {
                            let src = IpAddr::V6(ip6.header().source_addr());
                            let dst = IpAddr::V6(ip6.header().destination_addr());

                            if local_addrs.contains(&src) {
                                outgoing_total += size;
                                println!("{}: Outgoing {}: {} bytes (total {})", default_device.name.as_str().blue(),
                                         "IPv6".yellow(),
                                         size.to_string().green(),
                                         outgoing_total.to_string().green());
                            } else if local_addrs.contains(&dst) {
                                incoming_total += size;
                                println!("{}: Incoming {}: {} bytes (total {})", default_device.name.as_str().blue(),
                                         "IPv6".yellow(),
                                         size.to_string().green(),
                                         incoming_total.to_string().green());
                            }
                        }
                        _ => {
                            // Here: IP packets that are not important
                        }
                    }
                }

                // Transport layer (e.g., TCP)
                if let Some(transport) = sliced.transport {
                    match transport {
                        TransportSlice::Tcp(tcp_header) => {
                            println!("TCP port {} → {}", tcp_header.source_port().to_string().yellow(),
                                     tcp_header.destination_port().to_string().yellow());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
