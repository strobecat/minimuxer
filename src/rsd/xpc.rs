// xpc package ref:
// https://github.com/duo-labs/apple-t2-xpc/blob/344c494141131df4ce166f96dda941c14a4799e0/xpc_types.py
// xpc wrapper ref:
// https://github.com/doronz88/pymobiledevice3/blob/1c6445ad3911ff967f3c31fd8f0fe26df46bbe24/pymobiledevice3/remote/xpc_message.py
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use std::{collections::HashMap, fmt::Display, result, vec};
use log::warn;

fn pad_to_four(n: usize) -> usize {
    let reminder = n % 4;
    if reminder == 0 {
        n
    } else {
        n + (4 - (n % 4))
    }
}

fn pad_data(mut data: BytesMut) -> BytesMut {
    data.resize(pad_to_four(data.len()).try_into().unwrap(), 0x00);
    data
}

// As you know, string in C has a NULL terminator
fn pad_string(mut string: BytesMut) -> BytesMut {
    string.put_u8(b'\x00');
    pad_data(string)
}

const XPC_ROOT_MAGIC: u32 = 0x42133742;
const XPC_PROTO_VER: u32 = 0x00000005;
const XPC_WRAPPER_MAGIC: u32 = 0x29b00b92;

#[repr(u32)]
pub enum XPCMessageDataType {
    Null = 0x00001000,
    Bool = 0x00002000,
    Int64 = 0x00003000,
    Uint64 = 0x00004000,
    Double = 0x00005000,
    Pointer = 0x00006000,
    Date = 0x00007000,
    Data = 0x00008000,
    String = 0x00009000,
    Uuid = 0x0000a000,
    Fd = 0x0000b000,
    Shmem = 0x0000c000,
    MachSend = 0x0000d000,
    Array = 0x0000e000,
    Dictionary = 0x0000f000,
    Error = 0x00010000,
    Connection = 0x00011000,
    Endpoint = 0x00012000,
    Serializer = 0x00013000,
    Pipe = 0x00014000,
    MachRecv = 0x00015000,
    Bundle = 0x00016000,
    Service = 0x00017000,
    ServiceInstance = 0x00018000,
    Activity = 0x00019000,
    FileTransfer = 0x0001a000,
    Unimplemented = 0xffffffff,
}
impl From<u32> for XPCMessageDataType {
    fn from(value: u32) -> Self {
        match value {
            0x00001000 => Self::Null,
            0x00002000 => Self::Bool,
            0x00003000 => Self::Int64,
            0x00004000 => Self::Uint64,
            0x00005000 => Self::Double,
            0x00006000 => Self::Pointer,
            0x00007000 => Self::Date,
            0x00008000 => Self::Data,
            0x00009000 => Self::String,
            0x0000a000 => Self::Uuid,
            0x0000b000 => Self::Fd,
            0x0000c000 => Self::Shmem,
            0x0000d000 => Self::MachSend,
            0x0000e000 => Self::Array,
            0x0000f000 => Self::Dictionary,
            0x00010000 => Self::Error,
            0x00011000 => Self::Connection,
            0x00012000 => Self::Endpoint,
            0x00013000 => Self::Serializer,
            0x00014000 => Self::Pipe,
            0x00015000 => Self::MachRecv,
            0x00016000 => Self::Bundle,
            0x00017000 => Self::Service,
            0x00018000 => Self::ServiceInstance,
            0x00019000 => Self::Activity,
            0x0001a000 => Self::FileTransfer,
            _ => Self::Unimplemented,
        }
    }
}
impl From<XPCMessageDataType> for [u8; 4] {
    fn from(value: XPCMessageDataType) -> Self {
        if let XPCMessageDataType::Unimplemented = value {
            unreachable!();
        }
        (value as u32).to_le_bytes()
    }
}
impl From<XPCMessageDataType> for Bytes {
    fn from(value: XPCMessageDataType) -> Self {
        let arr: [u8; 4] = value.into();
        Bytes::from_owner(arr)
    }
}

#[repr(u32)]
pub enum XPCWrapperFlags {
    AlwaysSet = 0x00000001,
    Ping = 0x00000002,
    DataPresent = 0x00000100,
    WantingReply = 0x00010000,
    Reply = 0x00020000,
    FileTxStreamRequest = 0x00100000,
    FileTxStreamResponse = 0x00200000,
    InitHandshake = 0x00400000,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XPCMessage {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    // Pointer,
    Date(u64),
    Data(Bytes),
    String(Bytes),
    Uuid([u8; 16]),
    Fd,
    Shmem(u32),
    // MachSend,
    Array(Vec<XPCMessage>),
    Dictionary(HashMap<Bytes, XPCMessage>),
    Error(HashMap<Bytes, XPCMessage>),
    Connection,
    Endpoint,
    // Serializer,
    // Pipe,
    // MachRecv,
    // Bundle,
    // Service,
    // ServiceInstance,
    // Activity,
    FileTransfer(u64, u64),
    // Special type, means empty payload, could be root of wrapper
    Nothing,
    // Following aren't data types but data wrappers
    //   body
    Root(Box<XPCMessage>),
    //    flags  msg_id          root
    Wrapper(u32, u64, Box<XPCMessage>),
}
impl From<XPCMessage> for Bytes {
    fn from(value: XPCMessage) -> Self {
        if value == XPCMessage::Nothing {
            return Bytes::new();
        }
        let mut result = BytesMut::new();

        fn encode_dict(val: HashMap<Bytes, XPCMessage>, result: &mut BytesMut) {
            //let mut result = BytesMut::new();
            let mut items = BytesMut::new();
            let val_len = val.len() as u32;
            for (key, value) in val {
                items.extend(pad_string(key.into()));
                items.extend::<Bytes>(value.into());
            }
            result.put_u32_le(items.len() as u32 + 4);
            result.put_u32_le(val_len);
            result.extend(items);
        }
        match value {
            XPCMessage::Null => result.put_u32_le(XPCMessageDataType::Null as u32),
            XPCMessage::Bool(val) => {
                result.put_u32_le(XPCMessageDataType::Bool as u32);
                result.put_u32_le(val.into());
            },
            XPCMessage::Int64(val) => {
                result.put_u32_le(XPCMessageDataType::Int64 as u32);
                result.put_i64_le(val);
            }
            XPCMessage::Uint64(val) => {
                result.put_u32_le(XPCMessageDataType::Uint64 as u32);
                result.put_u64_le(val);
            }
            XPCMessage::Double(val) => {
                result.put_u32_le(XPCMessageDataType::Double as u32);
                result.put_f64(val);
            }
            XPCMessage::Date(val) => {
                result.put_u32_le(XPCMessageDataType::Date as u32);
                result.put_u64_le(val);
            }
            XPCMessage::Data(val) => {
                result.put_u32_le(XPCMessageDataType::Data as u32);
                result.put_u32_le(val.len() as u32);
                result.extend(pad_data(val.into()));
            }
            XPCMessage::String(val) => {
                let mut string: BytesMut = val.into();
                let string_len = string.len();
                result.put_u32_le(XPCMessageDataType::String as u32);
                result.put_u32_le(string_len as u32 + 1);
                string.put_u8(b'\x00');
                result.extend(pad_data(string));
            }
            XPCMessage::Uuid(val) => {
                result.put_u32_le(XPCMessageDataType::Uuid as u32);
                result.extend_from_slice(&val[..]);
            }
            XPCMessage::Fd => {
                result.put_u32_le(XPCMessageDataType::Fd as u32);
            }
            XPCMessage::Shmem(val) => {
                result.put_u32_le(XPCMessageDataType::Shmem as u32);
                result.put_u32_le(val);
                result.put_u32_le(0);
            }
            XPCMessage::Array(val) => {
                result.put_u32_le(XPCMessageDataType::Array as u32);
                let mut elements = BytesMut::new();
                let val_len = val.len() as u32;
                for element in val {
                    elements.extend::<Bytes>(element.into());
                }
                result.put_u32_le(elements.len() as u32 + 4);
                result.put_u32_le(val_len);
                result.extend(elements);
            }
            XPCMessage::Dictionary(val) => {
                result.put_u32_le(XPCMessageDataType::Dictionary as u32);
                encode_dict(val, &mut result);
            }
            XPCMessage::Error(val) => {
                result.put_u32_le(XPCMessageDataType::Error as u32);
                encode_dict(val, &mut result);
            }
            XPCMessage::Connection => {
                result.put_u32_le(XPCMessageDataType::Connection as u32);
            }
            XPCMessage::Endpoint => {
                result.put_u32_le(XPCMessageDataType::Endpoint as u32);
            }
            XPCMessage::FileTransfer(id, size) => {
                result.put_u32_le(XPCMessageDataType::FileTransfer as u32);
                let mut temp_dict = HashMap::new();
                temp_dict.insert(Bytes::from_owner(b"s"), XPCMessage::Uint64(size));
                result.put_u64_le(id);
                encode_dict(temp_dict, &mut result);
            }
            XPCMessage::Nothing => unreachable!(),
            XPCMessage::Root(val) => {
                result.put_u32_le(XPC_ROOT_MAGIC);
                result.put_u32_le(XPC_PROTO_VER);
                if !matches!(*val, XPCMessage::Dictionary(_)) {
                    warn!("Trying encode Root, but child is not a Dictionary")
                }
                let val_bytes: Bytes = (*val).into();
                result.extend(val_bytes);
            }
            XPCMessage::Wrapper(flag, msg_id, root) => {
                result.put_u32_le(XPC_WRAPPER_MAGIC);
                result.put_u32_le(flag);
                if !matches!(*root, XPCMessage::Root(_)) {
                    warn!("Trying encode Wrapper, but child is not a Root")
                }
                let payload: Bytes = (*root).into();
                let payload_len = payload.len() as u64;
                result.put_u64_le(payload_len);
                result.put_u64_le(msg_id);
                result.extend(payload);
            }
        };
        result.into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TryDecodeXPCError {
    NeedMoreBytes(usize),
    UnexpectedData,
    CorruptedData,
    UnimplementedType,
}
impl Display for TryDecodeXPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedMoreBytes(n) => f.write_fmt(format_args!("Expect {} more bytes", n)),
            Self::UnexpectedData => f.write_str("Unexpected data"),
            Self::CorruptedData => f.write_str("Corrupted data"),
            Self::UnimplementedType => f.write_str("Unimplemented XPC data type"),
        }
    }
}
impl From<TryGetError> for TryDecodeXPCError {
    fn from(value: TryGetError) -> Self {
        TryDecodeXPCError::NeedMoreBytes(value.requested - value.available)
    }
}

impl TryFrom<&mut BytesMut> for XPCMessage {
    type Error = TryDecodeXPCError;

    fn try_from(value: &mut BytesMut) -> Result<XPCMessage, TryDecodeXPCError> {
        fn decode_dict(value: &mut BytesMut) -> Result<XPCMessage, TryDecodeXPCError> {
            let size = value.try_get_u32_le()? as usize;
            let left_size = value.len();
            if left_size < size {
                return Err(TryDecodeXPCError::NeedMoreBytes(size - left_size));
            }
            let mut body = value.split_to(size);
            let entries = match body.try_get_u32_le() {
                Ok(v) => v,
                Err(_) => {
                    return Err(TryDecodeXPCError::CorruptedData);
                }
            };

            let mut result = HashMap::with_capacity(entries as usize);
            for _ in 0..entries {
                let mut key = BytesMut::new();
                loop {
                    let chr: u8 = body
                        .try_get_u8()
                        .map_err(|_| TryDecodeXPCError::CorruptedData)?;
                    if chr == b'\x00' {
                        break;
                    }
                    key.put_u8(chr);
                }
                let str_len = key.len(); // includes a NULL terminator
                body.advance(pad_to_four(str_len + 1) - str_len - 1);

                let obj = match XPCMessage::try_from(&mut body) {
                    Ok(v) => v,
                    Err(_) => {
                        return Err(TryDecodeXPCError::CorruptedData);
                    }
                };
                result.insert(key.into(), obj);
            }
            Ok(XPCMessage::Dictionary(result))
        }

        let magic = match value.try_get_u32_le() {
            Ok(v) => v,
            Err(e) => {
                if e.available == 0 {
                    return Ok(XPCMessage::Nothing);
                } else {
                    return Err(e.into());
                }
            }
        };
        if magic == XPC_ROOT_MAGIC {
            if value.try_get_u32_le()? != XPC_PROTO_VER {
                return Err(TryDecodeXPCError::UnimplementedType);
            }
            return match XPCMessage::try_from(value) {
                Ok(b) => Ok(XPCMessage::Root(Box::new(b))),
                Err(e) => Err(e),
            };
        }
        if magic == XPC_WRAPPER_MAGIC {
            let flag = value.try_get_u32_le()?;
            let size = value.try_get_u64_le()? as usize + 8 as usize;
            let left_size = value.len();
            if left_size < size {
                return Err(TryDecodeXPCError::NeedMoreBytes(size - left_size));
            }
            let mut message = value.split_to(size as usize);
            let msg_id = message
                .try_get_u64_le()
                .map_err(|_| TryDecodeXPCError::CorruptedData)?;
            return match XPCMessage::try_from(&mut message) {
                Ok(p) => Ok(XPCMessage::Wrapper(flag, msg_id, Box::new(p))),
                Err(_) => Err(TryDecodeXPCError::CorruptedData),
            };
        }
        match XPCMessageDataType::from(magic) {
            XPCMessageDataType::Null => Ok(Self::Null),
            XPCMessageDataType::Bool => match value.try_get_u32_le()? {
                1 => Ok(Self::Bool(true)),
                0 => Ok(Self::Bool(false)),
                _ => Err(TryDecodeXPCError::UnexpectedData),
            },
            XPCMessageDataType::Int64 => Ok(XPCMessage::Int64(value.try_get_i64_le()?)),
            XPCMessageDataType::Uint64 => Ok(XPCMessage::Uint64(value.try_get_u64_le()?)),
            XPCMessageDataType::Double => Ok(XPCMessage::Double(value.try_get_f64()?)),
            XPCMessageDataType::Date => Ok(XPCMessage::Date(value.try_get_u64_le()?)),
            XPCMessageDataType::Data => {
                let size = value.try_get_u32_le()? as usize;
                let left_size = value.len();
                if left_size < size {
                    return Err(TryDecodeXPCError::NeedMoreBytes(size - left_size));
                }
                let result = Ok(XPCMessage::Data(value.split_to(size)));
                value.advance(pad_to_four(size) - size);
                result
            }
            XPCMessageDataType::String => {
                let length = value.try_get_u32_le()? as usize;
                let left_size = value.len();
                if left_size < length {
                    return Err(TryDecodeXPCError::NeedMoreBytes(length - left_size));
                }
                let mut string: BytesMut = value.split_to(pad_to_four(length)).into();
                while let Some(element) = string.last() {
                    if element != &b'\x00' {
                        break;
                    }
                    string.truncate(string.len() - 1);
                }
                Ok(XPCMessage::String(string.into()))
            }
            XPCMessageDataType::Uuid => {
                let mut uuid = [0u8; 16];
                value.try_copy_to_slice(&mut uuid)?;
                Ok(XPCMessage::Uuid(uuid))
            }
            XPCMessageDataType::Fd => Ok(XPCMessage::Fd),
            XPCMessageDataType::Shmem => {
                let size = value.try_get_u32_le()?;
                value.advance(4);
                Ok(XPCMessage::Shmem(size))
            }
            XPCMessageDataType::Array => {
                let size = value.try_get_u32_le()? as usize;
                let left_size = value.len();
                if left_size < size {
                    return Err(TryDecodeXPCError::NeedMoreBytes(size - left_size));
                }
                let mut body = value.split_to(size);
                let entries = match body.try_get_u32_le() {
                    Ok(v) => v,
                    Err(_) => {
                        return Err(TryDecodeXPCError::CorruptedData);
                    }
                };
                let mut result = Vec::with_capacity(entries as usize);
                for _ in 0..entries {
                    let obj = match XPCMessage::try_from(&mut body) {
                        Ok(v) => v,
                        Err(_) => {
                            return Err(TryDecodeXPCError::CorruptedData);
                        }
                    };
                    result.push(obj);
                }
                Ok(XPCMessage::Array(result))
            }
            XPCMessageDataType::Dictionary => decode_dict(value),
            XPCMessageDataType::Error => decode_dict(value),
            XPCMessageDataType::Connection => Ok(XPCMessage::Connection),
            XPCMessageDataType::Endpoint => Ok(XPCMessage::Endpoint),
            XPCMessageDataType::FileTransfer => {
                let msg_id = value.try_get_u64_le()?;
                let body = match XPCMessage::try_from(value) {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(e);
                    }
                };
                if let XPCMessage::Dictionary(map) = body {
                    let size_body = match map.get(&Bytes::from_static(b"s")) {
                        Some(v) => v,
                        None => {
                            return Err(TryDecodeXPCError::CorruptedData);
                        }
                    };
                    if let XPCMessage::Uint64(size) = size_body {
                        return Ok(XPCMessage::FileTransfer(msg_id, *size));
                    } else {
                        return Err(TryDecodeXPCError::CorruptedData);
                    }
                }
                Err(TryDecodeXPCError::UnexpectedData)
            }
            _ => Err(TryDecodeXPCError::UnimplementedType),
        }
    }
}
/*
impl TryFrom<&[u8]> for XPCMessage {
    type Error = TryDecodeXPCError;

    fn try_from(value: &[u8]) -> Result<Self, TryDecodeXPCError> {
        XPCMessage::try_from(&mut Bytes::copy_from_slice(value))
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: &[u8; 292] = b"\x92\x0b\xb0)\x01\x01\x00\x00\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B7\x13B\x05\x00\x00\x00\x00\xf0\x00\x00\xfc\x00\x00\x00\x07\x00\x00\x00array\x00\x00\x00\x00\xe0\x00\x004\x00\x00\x00\x04\x00\x00\x00\x00P\x00\x00?\xf3333333\x00P\x00\x00@\x0b333333\x00\x90\x00\x00\x02\x00\x00\x00a\x00\x00\x00\x00\x90\x00\x00\x02\x00\x00\x00b\x00\x00\x00dict\x00\x00\x00\x00\x00\xf0\x00\x00(\x00\x00\x00\x02\x00\x00\x00\xe5\xa5\xbd\x00\x00\x80\x00\x00\x03\x00\x00\x00\xe5\x9d\x8f\x00good\x00\x00\x00\x00\x00\x80\x00\x00\x03\x00\x00\x00bad\x00bool\x00\x00\x00\x00\x00\xe0\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00\x00 \x00\x00\x01\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00float\x00\x00\x00\x00P\x00\x00@\t!\xfbTREPuuid\x00\x00\x00\x00\x00\xa0\x00\x00\x95NO\x87\xd0\x08I;\x9d\xe7\xc3\x8f2\x1d\xf7vui64\x00\x00\x00\x00\x00@\x00\x00\xff\xff\xff\xff\xff\xff\xff\xffsi64\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80";

    /*
    extern crate test;
    use test::{Bencher, black_box};
    // 1,925.30 ns/iter (+/- 89.31) on AMD EPYC 7K62
    #[bench]
    fn bench_example(bencher: &mut Bencher) {
        let data = Bytes::from(&EXAMPLE[..]);
        bencher.iter(|| {
            let mut data1 = data.clone();
            let _ = black_box({
                XPCMessage::try_from(&mut data1);
            });
        });
    }*/

    #[test]
    fn test_example() {
        let expected = XPCMessage::Wrapper(
            0x101,
            0,
            Box::new(XPCMessage::Root(Box::new(XPCMessage::Dictionary(
                HashMap::from([
                    (
                        b"array"[..].into(),
                        XPCMessage::Array(vec![
                            XPCMessage::Double(1.2),
                            XPCMessage::Double(3.4),
                            XPCMessage::String(b"a"[..].into()),
                            XPCMessage::String(b"b"[..].into()),
                        ]),
                    ),
                    (
                        b"dict"[..].into(),
                        XPCMessage::Dictionary(HashMap::from([
                            (
                                "好".as_bytes().into(),
                                XPCMessage::Data("坏".as_bytes().into()),
                            ),
                            (b"good"[..].into(), XPCMessage::Data(b"bad"[..].into())),
                        ])),
                    ),
                    (
                        b"bool"[..].into(),
                        XPCMessage::Array(vec![XPCMessage::Bool(true), XPCMessage::Bool(false)]),
                    ),
                    (b"float"[..].into(), XPCMessage::Double(3.141592654)),
                    (
                        b"uuid"[..].into(),
                        XPCMessage::Uuid(*b"\x95NO\x87\xd0\x08I;\x9d\xe7\xc3\x8f2\x1d\xf7v"),
                    ),
                    (b"ui64"[..].into(), XPCMessage::Uint64(18446744073709551615)),
                    (b"si64"[..].into(), XPCMessage::Int64(-9223372036854775808)),
                ]),
            )))),
        );
        assert_eq!(XPCMessage::try_from(&mut Bytes::from_static(EXAMPLE)).unwrap(), expected);
    }

    macro_rules! test_entry {
        ($expect:expr, $encoded:literal) => {{
            assert_eq!($expect, XPCMessage::try_from(&mut Bytes::from_static($encoded)).unwrap());
            assert_eq!(Into::<Bytes>::into($expect), Bytes::from_static($encoded));
        }};
    }

    #[test]
    fn test_array() {
        test_entry!(
            XPCMessage::Array(vec![XPCMessage::Double(1.2), XPCMessage::Double(3.4), XPCMessage::String(b"a"[..].into()), XPCMessage::String(b"bcd"[..].into())]),
            b"\x00\xe0\x00\x004\x00\x00\x00\x04\x00\x00\x00\x00P\x00\x00?\xf3333333\x00P\x00\x00@\x0b333333\x00\x90\x00\x00\x02\x00\x00\x00a\x00\x00\x00\x00\x90\x00\x00\x04\x00\x00\x00bcd\x00"
        );
    }

    #[test]
    fn test_dictionary() {
        let expected = XPCMessage::Dictionary(HashMap::from([
            (b"true"[..].into(), XPCMessage::Bool(false)),
            (b"1"[..].into(), XPCMessage::Int64(0)),
        ]));
        let encoded1 = Bytes::from_static(b"\x00\xf0\x00\x00$\x00\x00\x00\x02\x00\x00\x00true\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x001\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let encoded2 = Bytes::from_static(b"\x00\xf0\x00\x00$\x00\x00\x00\x02\x00\x00\x001\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00true\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00");
        assert_eq!(expected, XPCMessage::try_from(&mut encoded1.clone()).unwrap());
        assert_eq!(expected, XPCMessage::try_from(&mut encoded2.clone()).unwrap());
        let encoded3: Bytes = expected.into();
        assert!(encoded3 == encoded1 || encoded3 == encoded2);
    }

    #[test]
    fn test_bool() {
        test_entry!(
            XPCMessage::Array(vec![XPCMessage::Bool(true), XPCMessage::Bool(false)]),
            b"\x00\xe0\x00\x00\x14\x00\x00\x00\x02\x00\x00\x00\x00 \x00\x00\x01\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00"
        )
    }

    #[test]
    fn test_string() {
        test_entry!(
            XPCMessage::Array(vec![XPCMessage::String(b"a"[..].into()), XPCMessage::String(b"bcd"[..].into()), XPCMessage::String(b"efgh"[..].into())]),
            b"\x00\xe0\x00\x00,\x00\x00\x00\x03\x00\x00\x00\x00\x90\x00\x00\x02\x00\x00\x00a\x00\x00\x00\x00\x90\x00\x00\x04\x00\x00\x00bcd\x00\x00\x90\x00\x00\x05\x00\x00\x00efgh\x00\x00\x00\x00"
        )
    }

    #[test]
    fn test_data() {
        test_entry!(
            XPCMessage::Data(b"\xab\xcd\x12\x34"[..].into()),
            b"\x00\x80\x00\x00\x04\x00\x00\x00\xab\xcd\x124"
        )
    }

    #[test]
    fn test_double() {
        test_entry!(
            XPCMessage::Double(3.141592654),
            b"\x00P\x00\x00@\t!\xfbTREP"
        )
    }

    #[test]
    fn test_uuid() {
        test_entry!(
            XPCMessage::Uuid(*b"\x15 %\xea_\x04M\x07\x81J\xd9\xac\x11V^\x90"),
            b"\x00\xa0\x00\x00\x15 %\xea_\x04M\x07\x81J\xd9\xac\x11V^\x90"
        )
    }

    #[test]
    fn test_null() {
        test_entry!(XPCMessage::Null, b"\x00\x10\x00\x00");
    }

    #[test]
    fn test_uint64() {
        test_entry!(
            XPCMessage::Array(vec![XPCMessage::Uint64(0), XPCMessage::Uint64(18446744073709551615)]),
            b"\x00\xe0\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
        )
    }

    #[test]
    fn test_int64() {
        test_entry!(
            XPCMessage::Array(vec![XPCMessage::Int64(-9223372036854775808), XPCMessage::Int64(9223372036854775807)]),
            b"\x00\xe0\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x000\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f"
        )
    }

    #[test]
    fn test_wrapper_root() {
        test_entry!(
            XPCMessage::Wrapper(0x1, 0, Box::new(XPCMessage::Root(Box::new(XPCMessage::Dictionary(HashMap::new()))))),
            b"\x92\x0b\xb0)\x01\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B7\x13B\x05\x00\x00\x00\x00\xf0\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
        );
        test_entry!(
            XPCMessage::Wrapper(0x400001, 0, Box::new(XPCMessage::Nothing)),
            b"\x92\x0b\xb0)\x01\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );
    }
    /* Not tested:
    Date(u64),
    Fd,
    Shmem(u32),
    Error(HashMap<Vec<u8>, XPCMessage>),
    Connection,
    Endpoint,
    FileTransfer(u64, u64),
    */
}
