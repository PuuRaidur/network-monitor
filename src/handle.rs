use pcap::{Device, Capture, Active};
use colored::*;

pub fn create_handle(default_device: &Device) -> Capture<Active> {
    match Capture::from_device(default_device.name.as_str()) {
        Ok(dev) => match dev.promisc(true).immediate_mode(true).open() {
            Ok(handle) => {
                println!("Opened handle on {}", default_device.name.as_str().blue());
                handle
            }
            Err(e) => panic!("Error opening handle on {}: {}", default_device.name.as_str().blue(), e.to_string().red()),
        },
        Err(e) => panic!("Error accessing device {}: {}", default_device.name.as_str().blue(), e.to_string().red()),
    }
}