basic wi-fi/ethernet traffic monitor. no pre-fixed refresh rate

$ cargo build

$ sudo setcap cap_net_raw,cap_net_admin=eip target/debug/network-monitor

$ ./target/debug/network-monitor
