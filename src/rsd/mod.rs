//mod http2;
mod net;
mod xpc;

use h2::frame::StreamId;
//use http2::HTTP2XPC;
use log::{debug, error};
use net::ServiceClientInterface;
use rand::random;
use rusty_libimobiledevice::{
    error::{LockdowndError, ServiceError},
    idevice::Device,
    service::ServiceClient,
};
use serde::Deserialize;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{PcapMode, PcapWriter},
    socket::tcp::{Socket, SocketBuffer},
    time::Instant,
    wire::{HardwareAddress, Ipv6Address, Ipv6Cidr},
};
use std::str::FromStr;
use std::{collections::HashMap, fs::File};
use xpc::{XPCMessage, XPCWrapperFlags};

#[derive(Deserialize, Debug)]
struct RSDClientParameters {
    pub netmask: String,
    pub address: String,
    pub mtu: u32,
}
#[derive(Deserialize, Debug)]
struct RSDHandshakeResult {
    #[serde(rename = "clientParameters")]
    pub client_info: RSDClientParameters,
    #[serde(rename = "serverAddress")]
    pub server_address: String,
    #[serde(rename = "type")]
    pub response_type: String,
    #[serde(rename = "serverRSDPort")]
    pub rsd_port: u16,
}

pub struct RSDManager<'a> {
    pub interface: Interface,
    pub sockets: SocketSet<'a>,
    pub device: PcapWriter<ServiceClientInterface<'a>, File>, //ServiceClientInterface<'a>,
    pub addr: Ipv6Address,
    rsd_port: u16,
}
#[derive(Debug)]
pub enum NewRSDManagerError {
    ServiceError(ServiceError),
    LockdowndError(LockdowndError),
    HandshakeFailed,
}

impl<'a> RSDManager<'a> {
    pub fn new(device: &Device) -> Result<RSDManager, NewRSDManagerError> {
        let mut lockdown_client = match device.new_lockdownd_client("sidestore-rsd") {
            Ok(l) => l,
            Err(e) => {
                error!("Unable to create lockdown client: {:?}", e);
                return Err(NewRSDManagerError::LockdowndError(e));
            }
        };
        let service = match lockdown_client
            .start_service("com.apple.internal.devicecompute.CoreDeviceProxy", false)
        {
            Ok(s) => s,
            Err(e) => {
                error!("Unable to start service: {:?}", e);
                return Err(NewRSDManagerError::LockdowndError(e));
            }
        };
        let client = match ServiceClient::new(&device, service) {
            Ok(c) => c,
            Err(e) => {
                error!("Unable to convert service client: {:?}", e);
                return Err(NewRSDManagerError::ServiceError(e));
            }
        };

        match client.send(b"CDTunnel\x00,{\"mtu\":1500,\"type\":\"clientHandshakeRequest\"}".into())
        {
            Ok(_) => {}
            Err(e) => {
                error!("Unable to send handshake packet: {:?}", e);
                return Err(NewRSDManagerError::ServiceError(e));
            }
        }
        let response = match client.receive(10) {
            Ok(r) => r,
            Err(e) => {
                error!("Unable to receive handshake result: {:?}", e);
                return Err(NewRSDManagerError::ServiceError(e));
            }
        };

        if &response[..9] != b"CDTunnel\x00" {
            debug!("Invalid handshake1 response: {:?}", response);
            error!("Handshake step 1 failed");
            return Err(NewRSDManagerError::HandshakeFailed);
        }
        let response =
            match client.receive(u8::from_le_bytes(response[9..10].try_into().unwrap()).into()) {
                Ok(r) => r,
                Err(e) => {
                    error!("Unable to receive handshake result: {:?}", e);
                    return Err(NewRSDManagerError::ServiceError(e));
                }
            };
        let response_value: RSDHandshakeResult =
            match serde_json::from_str(&String::from_utf8_lossy(&response)) {
                Ok(r) => r,
                Err(e) => {
                    error!("Unable to parse handshake result: {:?}", e);
                    return Err(NewRSDManagerError::HandshakeFailed);
                }
            };

        let netmask: u8 = Ipv6Address::from_str(&response_value.client_info.netmask)
            .unwrap()
            .to_bits()
            .count_ones()
            .try_into()
            .unwrap();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random();
        let mut device = ServiceClientInterface::new(client, response_value.client_info.mtu);
        let mut intf = Interface::new(config, &mut device, Instant::now());
        intf.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(
                    Ipv6Cidr::new(
                        Ipv6Address::from_str(&response_value.client_info.address).unwrap(),
                        netmask,
                    )
                    .into(),
                )
                .unwrap()
        });
        
        Ok(RSDManager {
            device: PcapWriter::new(
                device,
                File::create_new("pack.pcap").unwrap(),
                PcapMode::Both,
            ),
            interface: intf,
            sockets: SocketSet::new(Vec::new()),
            addr: Ipv6Address::from_str(&response_value.server_address).unwrap(),
            rsd_port: response_value.rsd_port,
        })
    }
    pub fn poll(&mut self) {
        self.interface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
    }

    pub fn connect(&mut self, port: u16) -> SocketHandle {
        let sock = Socket::new(
            SocketBuffer::new(vec![0; 65535]),
            SocketBuffer::new(vec![0; 65535]),
        );

        let tcp_handle = self.sockets.add(sock);
        let socket = self.sockets.get_mut::<Socket>(tcp_handle);
        socket
            .connect(
                self.interface.context(),
                (self.addr, port),
                49152 + random::<u16>() % 16384,
            )
            .unwrap();
        tcp_handle
    }

    pub fn connect_rsd(&mut self) -> SocketHandle {
        self.connect(self.rsd_port)
    }
}

/*
pub fn handshake(manager: &mut RSDManager) {
    let rsd = manager.connect_rsd();
    let sid1 = StreamId::from(1);
    let sid3 = StreamId::from(3);
    let mut http2 = HTTP2XPC::new();
    http2.establish();
    // Through idk why they called that, I'm going to mark them
    // ClientServer
    http2.new_stream(sid1, false);
    // ServerClient
    http2.new_stream(sid3, false);

    http2.streams.get_mut(&sid1).unwrap().send_xpc(
        XPCWrapperFlags::AlwaysSet as u32,
        XPCMessage::Root(Box::new(XPCMessage::Dictionary(HashMap::new()))),
        Some(0),
    );
    http2.streams.get_mut(&sid1).unwrap().send_xpc(
        XPCWrapperFlags::AlwaysSet as u32 | 0x200,
        XPCMessage::Nothing,
        Some(0),
    );
    http2.streams.get_mut(&sid3).unwrap().send_xpc(
        XPCWrapperFlags::AlwaysSet as u32 | XPCWrapperFlags::InitHandshake as u32,
        XPCMessage::Nothing,
        Some(0),
    );
    let mut last_log = String::new();
    while http2.active {
        manager.poll();

        let socket = manager.sockets.get_mut::<Socket>(rsd);
        http2.deal_socket(socket);

        let log = format!("{:?}", http2.streams);
        if log != last_log {
            println!("{}", log);
            last_log = log;
        }
    }
}
*/
