use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    mem::swap,
};

use bytes::{BufMut, Bytes, BytesMut};
use h2::frame::{GoAway, Head, Kind, Reset, Settings, StreamId, WindowUpdate, HEADER_LEN};
use log::debug;
use smoltcp::socket::tcp::Socket;

use super::xpc::{TryDecodeXPCError, XPCMessage};

// idk where the number from but both pymobiledevice3 and my ipad prefer this
const WINDOW_SIZE: u32 = 983041;

fn get_send(stream: &mut HTTP2XPCStream, window_left: usize) -> Bytes {
    let data = stream.send_buf.get_mut(0).unwrap();
    let data_len = data.len();
    let send_size = min(data_len, window_left);
    if send_size == data_len {
        stream.send_buf.pop_front().unwrap()
    } else {
        data.split_to(send_size)
    }
}

#[derive(Debug)]
pub enum ReceivedContent {
    XPC(VecDeque<XPCMessage>),
    File(Bytes),
}

#[derive(Debug)]
pub struct HTTP2XPCStream {
    pub stream_id: StreamId,
    /// Received content
    pub received: ReceivedContent,
    /// Active or not
    pub active: bool,
    /// How many bytes left in remote's window
    window_left: Option<u32>,
    /// Buffer of contents received
    read_buf: BytesMut,
    /// Buffer of contents to be sent
    send_buf: VecDeque<Bytes>,
    /// Last msg_id we sent
    last_msg_id: u64,
}
impl HTTP2XPCStream {
    pub fn new(stream_id: StreamId, is_file_stream: bool) -> HTTP2XPCStream {
        HTTP2XPCStream {
            stream_id,
            active: false,
            window_left: None,
            read_buf: BytesMut::with_capacity(1048576),
            send_buf: VecDeque::new(),
            last_msg_id: 0,
            received: if is_file_stream {
                ReceivedContent::File(Bytes::new())
            } else {
                ReceivedContent::XPC(VecDeque::new())
            },
        }
    }

    /*
    pub fn establish(&mut self) {
        Head::new(Kind::Headers, 0x4, self.stream_id).encode(0, &mut self.send_buf);
        //WindowUpdate::new(self.stream_id, WINDOW_SIZE).encode(&mut self.send_buf);
    }*/

    fn handle_xpc(&mut self) {
        let mut buf = self.read_buf.clone().into();
        match XPCMessage::try_from(&mut buf) {
            Ok(v) => {
                if let ReceivedContent::XPC(vd) = &mut self.received {
                    vd.push_back(v);
                } else {
                    unreachable!();
                }
                // XPCMessage::try_from will remove bytes processed from the buffer
                self.read_buf = buf.into();
            }
            Err(e) => {
                match e {
                    TryDecodeXPCError::NeedMoreBytes(_) => {
                        // Need more bytes so just copy received bytes into read_buf
                        // Which has done in HTTP2XPC
                    }
                    e => {
                        debug!("Unexpected error {:?} when processing XPC", e);
                        self.read_buf.clear();
                    }
                }
            }
        };
    }

    fn swap_into_file(&mut self) {
        let mut buf = BytesMut::new();
        swap(&mut self.read_buf, &mut buf);
        self.received = ReceivedContent::File(buf.into());
    }

    /*
    fn process_wait_send(&mut self) {
        /*if self.window_left == 0 {
            //debug!("*** {:?} left is 0", self.stream_id);
        }*/
        let data_to_send: Vec<u8> = self
            .wait_send_buf
            .drain(
                ..min(
                    self.wait_send_buf.len(),
                    min(self.global_window_left as usize, self.window_left as usize),
                ),
            )
            .collect();
        let data_size = data_to_send.len();
        if data_size > 0 {
            self.window_left -= data_size as u32;
            self.global_window_left -= data_size as u32;
            Head::new(Kind::Data, 0, self.stream_id).encode(data_size, &mut self.send_buf);
            self.send_buf.put(data_to_send.as_slice());
        }
    }

    pub fn increase_window_size(&mut self, size: u32) {
        self.window_left += size;
        self.process_wait_send();
    }*/

    pub fn send_xpc(&mut self, flag: u32, data: XPCMessage, msg_id: Option<u64>) {
        let message_id = match msg_id {
            Some(id) => {
                self.last_msg_id = id;
                id
            }
            None => {
                self.last_msg_id += 1;
                self.last_msg_id
            }
        };
        let wrapper = XPCMessage::Wrapper(flag, message_id, Box::new(data));
        let data: Vec<u8> = wrapper.into();
        self.send_buf.push_back(data.into());
    }
}

pub struct HTTP2XPC {
    // We have only 3 streams so duplicated StreamId should be affordable
    pub streams: HashMap<StreamId, HTTP2XPCStream>,
    pub active: bool,
    pub send_buf: BytesMut,
    read_buf: BytesMut,
    global_window_left: Option<u32>,
}

impl HTTP2XPC {
    pub fn new() -> HTTP2XPC {
        HTTP2XPC {
            streams: HashMap::new(),
            active: false,
            send_buf: BytesMut::with_capacity(1048576),
            read_buf: BytesMut::with_capacity(1048576),
            global_window_left: None,
        }
    }

    pub fn establish(&mut self) {
        self.send_buf.put(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
        let mut settings = Settings::default();
        settings.set_max_concurrent_streams(Some(100));
        settings.set_initial_window_size(Some(1048576));
        /*
        settings.set_header_table_size(Some(0));
        settings.set_enable_push(false);
        settings.set_max_header_list_size(Some(0));
        */
        settings.encode(&mut self.send_buf);
        WindowUpdate::new(StreamId::ZERO, WINDOW_SIZE).encode(&mut self.send_buf);
        self.active = true;
    }

    pub fn handle_data(&mut self, data: &[u8]) -> usize {
        let data_len = data.len();
        self.read_buf.extend_from_slice(data);
        //match self.read_buf.get
    }

    pub fn process_data(&mut self) -> usize {
        let payload_size = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        if data.len() < (HEADER_LEN + payload_size) {
            // no enough bytes, wait
            return 0;
        }
        let head = Head::parse(data);
        match head.kind() {
            Kind::Settings => {
                let settings =
                    Settings::load(head, &data[HEADER_LEN..HEADER_LEN + payload_size]).unwrap();
                debug!("{:?}", settings);
                if !settings.is_ack() {
                    Settings::ack().encode(&mut self.send_buf);
                    if let Some(s) = settings.initial_window_size() {
                        if self.global_window_left == None {
                            self.global_window_left = Some(s);
                        } else {
                            debug!(
                                "initial_window_size received after WindowUpdate or more than once"
                            );
                            self.global_window_left = Some(self.global_window_left.unwrap() + s);
                        }
                        for stream in self.streams.values_mut() {
                            if stream.window_left == None {
                                stream.window_left = Some(s);
                            } else {
                                stream.window_left = Some(stream.window_left.unwrap() + s);
                            }
                        }
                    }
                }
            }
            Kind::WindowUpdate => {
                let wu =
                    WindowUpdate::load(head, &data[HEADER_LEN..HEADER_LEN + payload_size]).unwrap();
                if wu.stream_id() == StreamId::ZERO {
                    if self.global_window_left == None {
                        debug!("WindowUpdate received before initial_window_size");
                        self.global_window_left = Some(wu.size_increment());
                    } else {
                        self.global_window_left =
                            Some(self.global_window_left.unwrap() + wu.size_increment());
                    }
                } else {
                    if let Some(s) = self.streams.get_mut(&wu.stream_id()) {
                        if s.window_left == None {
                            debug!("WindowUpdate received before initial_window_size");
                            s.window_left = Some(wu.size_increment());
                        } else {
                            s.window_left = Some(s.window_left.unwrap() + wu.size_increment());
                        }
                    }
                };
            }
            Kind::Data => {
                debug!("Data flag={:#x}", head.flag());
                let payload = &data[HEADER_LEN..HEADER_LEN + payload_size];
                WindowUpdate::new(StreamId::ZERO, payload.len() as u32).encode(&mut self.send_buf);
                match self.streams.get_mut(&head.stream_id()) {
                    Some(s) => {
                        WindowUpdate::new(head.stream_id(), payload.len() as u32)
                            .encode(&mut self.send_buf);
                        s.read_buf.extend(payload);
                        if let ReceivedContent::XPC(_) = s.received {
                            s.handle_xpc();
                        }
                    }
                    None => debug!(
                        "Trying send data to non-exist stream {:?}",
                        head.stream_id()
                    ),
                }
            }
            Kind::Reset => {
                match Reset::load(head, &data[HEADER_LEN..HEADER_LEN + payload_size]) {
                    Ok(reset) => {
                        if let Some(s) = self.streams.get_mut(&reset.stream_id()) {
                            s.active = false;
                            if let ReceivedContent::File(_) = s.received {
                                s.swap_into_file();
                            }
                        } else {
                            debug!("Trying to reset non-exist stream {:?}", reset.stream_id())
                        }
                    }
                    Err(e) => debug!("Invalid reset: {:?}", e),
                };
            }
            Kind::GoAway => {
                debug!(
                    "GoAway: {:?}",
                    GoAway::load(&data[HEADER_LEN..HEADER_LEN + payload_size])
                );
                self.active = false;
            }
            Kind::Headers => {
                if let Some(s) = self.streams.get_mut(&head.stream_id()) {
                    s.active = true;
                } else {
                    debug!("Trying to open non-exist stream {:?}", head.stream_id())
                }
            }
            kind => debug!("Unhandled {:?}", kind),
        };
        HEADER_LEN + payload_size
    }

    pub fn prepare_send(&mut self) {
        for stream in self.streams.values_mut() {
            if stream.active {
                let window_left = min(
                    stream.window_left.unwrap_or(0),
                    self.global_window_left.unwrap_or(0),
                ) as usize;
                while window_left > 0 && stream.send_buf.len() > 0 {
                    let data = get_send(stream, window_left);
                    Head::new(Kind::Data, 0, stream.stream_id)
                        .encode(data.len(), &mut self.send_buf);
                    self.send_buf.extend(data);
                }
                /*
                stream.window_left.unwrap_or(0) > 0 && stream.send_buf.len() > 0 {
                let send_size = min(
                    stream.send_buf.len(),
                    min(

                    ) as usize,
                );
                if send_size == 0 {
                    continue;
                }
                let send_data = stream.send_buf.split_to(send_size);
                Head::new(Kind::Data, 0, stream.stream_id).encode(send_size, &mut self.send_buf);
                self.send_buf.extend(send_data);
                */
            }
        }
    }

    pub fn new_stream(&mut self, stream_id: StreamId, is_file_stream: bool) {
        Head::new(Kind::Headers, 0x4, stream_id).encode(0, &mut self.send_buf);
        self.streams
            .insert(stream_id, HTTP2XPCStream::new(stream_id, is_file_stream));
    }

    pub fn deal_socket(&mut self, socket: &mut Socket) {
        if !self.active {
            return;
        }
        if !socket.is_open() {
            self.active = false;
            return;
        }
        if socket.can_recv() {
            socket.recv(|data| (self.handle_data(&data), ())).unwrap();
        }

        if socket.can_send() {
            self.prepare_send();
            if self.send_buf.len() > 0 {
                socket
                    .send_slice(self.send_buf.to_vec().as_slice())
                    .unwrap();
                self.send_buf.clear();
            }
        }
    }
}
