/*
use minimuxer::rsd::{handshake, RSDManager};
use rusty_libimobiledevice::idevice::get_first_device;
use simplelog::{Config, LevelFilter, SimpleLogger};

fn main() {
    SimpleLogger::init(LevelFilter::Debug, Config::default()).unwrap();
    let device = get_first_device().unwrap();
    let mut manager = RSDManager::new(&device).unwrap();
    handshake(&mut manager);
}
*/
