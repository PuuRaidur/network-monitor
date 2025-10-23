use pcap::Device;
use std::net::IpAddr;

pub fn get_all_local_addrs() -> Vec<IpAddr> {
    Device::list()
        .unwrap()
        .into_iter()
        .flat_map(|d| d.addresses)
        .map(|a| a.addr)
        .collect()
}