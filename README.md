basic wi-fi/ethernet traffic monitor. no pre-fixed refresh rate. it refreshes at raw cpu cycles

$ cargo build

$ sudo setcap cap_net_raw,cap_net_admin=eip target/debug/network-monitor

$ ./target/debug/network-monitor
