use rusty_libimobiledevice::service::ServiceClient;
use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};

pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer[..])
    }
}

pub struct TxToken<'a> {
    client: &'a ServiceClient<'a>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        match self.client.send(buffer) {
            Ok(_) => {}
            Err(err) => panic!("{}", err),
        }
        result
    }
}

pub struct ServiceClientInterface<'a> {
    pub client: ServiceClient<'a>,
    mtu: u32,
}

impl<'a> ServiceClientInterface<'a> {
    pub fn new(client: ServiceClient<'a>, mtu: u32) -> ServiceClientInterface<'a> {
        /*
        let fd = client.get_connection().get_fd();
        unsafe {
            let flags = fcntl(fd, F_GETFL, 0);
            if flags == -1 {
                panic!("fcntl() failed");
            }
            fcntl(fd, F_SETFL, flags|O_NONBLOCK);
        }*/
        ServiceClientInterface {
            client: client,
            mtu: mtu,
        }
    }
}

impl<'a> Device for ServiceClientInterface<'a> {
    type RxToken<'b>
        = RxToken
    where
        Self: 'b;
    type TxToken<'b>
        = TxToken<'b>
    where
        Self: 'b;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut data = Vec::new();
        loop {
            // Receive byte by byte
            match self.client.receive_with_timeout(1, 50) {
                Ok(mut v) => {
                    data.append(&mut v);
                }
                Err(_) => {
                    break;
                }
            }
        }
        if data.len() > 0 {
            Some((
                RxToken { buffer: data },
                TxToken {
                    client: &self.client,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            client: &self.client,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu.try_into().unwrap();
        caps.medium = Medium::Ip;
        caps
    }
}
