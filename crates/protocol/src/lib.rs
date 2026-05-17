pub const MAGIC: [u8; 2] = *b"MY";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 10;
pub const MAX_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientMsgKind {
    Hello = 1,
    OpLogRequest = 2,
    OpPush = 3,
    BlobPut = 4,
    BlobGet = 5,
    SnapshotPut = 6,
    PairingOpen = 7,
    PairingGrant = 8,
    Ping = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerMsgKind {
    HelloChallenge = 1,
    HelloAck = 2,
    OpLog = 3,
    OpBroadcast = 4,
    BlobAck = 5,
    Blob = 6,
    BlobMissing = 7,
    Snapshot = 8,
    PairingEvent = 9,
    Pong = 10,
    Error = 255,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpKind {
    FileCreate = 1,
    FileUpdate = 2,
    FileRename = 3,
    FileDelete = 4,
    FileCopy = 5,
}

impl TryFrom<u8> for OpKind {
    type Error = OpKindError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::FileCreate),
            2 => Ok(Self::FileUpdate),
            3 => Ok(Self::FileRename),
            4 => Ok(Self::FileDelete),
            5 => Ok(Self::FileCopy),
            _ => Err(OpKindError::Unsupported(value)),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpKindError {
    #[error("unsupported op kind {0}")]
    Unsupported(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is shorter than the header")]
    ShortHeader,
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unsupported frame version {0}")]
    UnsupportedVersion(u8),
    #[error("payload length exceeds limit")]
    PayloadTooLarge,
    #[error("frame payload is incomplete")]
    IncompletePayload,
}

impl Frame {
    #[must_use]
    pub fn new(kind: u8, flags: u16, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags,
            payload,
        }
    }

    /// Encodes the frame into the public Mylonite wire format.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::PayloadTooLarge`] when the payload cannot fit in
    /// the protocol length field or exceeds the configured frame limit.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge);
        }

        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a complete public Mylonite wire-format frame.
    ///
    /// # Errors
    ///
    /// Returns a [`FrameError`] when the header is malformed, the version is not
    /// supported, the announced payload is too large, or the payload is incomplete.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::ShortHeader);
        }
        if bytes[0..2] != MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        if bytes[2] != VERSION {
            return Err(FrameError::UnsupportedVersion(bytes[2]));
        }

        let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        if len > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge);
        }
        let expected_len =
            HEADER_LEN + usize::try_from(len).map_err(|_| FrameError::PayloadTooLarge)?;
        if bytes.len() < expected_len {
            return Err(FrameError::IncompletePayload);
        }

        Ok(Self {
            kind: bytes[3],
            flags: u16::from_be_bytes([bytes[4], bytes[5]]),
            payload: bytes[HEADER_LEN..expected_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientMsgKind, Frame, FrameError, HEADER_LEN, MAX_PAYLOAD_LEN, OpKind};

    #[test]
    fn frame_round_trips() {
        let frame = Frame::new(ClientMsgKind::Ping as u8, 7, b"hello".to_vec());
        let encoded = frame.encode().expect("valid frame");
        let decoded = Frame::decode(&encoded).expect("encoded frame decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn websocket_sync_kind_numbers_are_stable() {
        assert_eq!(ClientMsgKind::Hello as u8, 1);
        assert_eq!(ClientMsgKind::OpPush as u8, 3);
        assert_eq!(ClientMsgKind::Ping as u8, 9);
        assert_eq!(super::ServerMsgKind::HelloAck as u8, 2);
        assert_eq!(super::ServerMsgKind::OpBroadcast as u8, 4);
        assert_eq!(super::ServerMsgKind::Pong as u8, 10);
    }

    #[test]
    fn sync_op_kind_numbers_are_stable() {
        assert_eq!(OpKind::FileCreate as u8, 1);
        assert_eq!(OpKind::FileUpdate as u8, 2);
        assert_eq!(OpKind::FileRename as u8, 3);
        assert_eq!(OpKind::FileDelete as u8, 4);
        assert_eq!(OpKind::FileCopy as u8, 5);
        assert_eq!(OpKind::try_from(6), Err(super::OpKindError::Unsupported(6)));
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut encoded = Frame::new(ClientMsgKind::Ping as u8, 0, Vec::new())
            .encode()
            .expect("valid frame");
        encoded[0] = b'N';

        assert_eq!(Frame::decode(&encoded), Err(FrameError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_invalid_version() {
        let mut encoded = Frame::new(ClientMsgKind::Ping as u8, 0, Vec::new())
            .encode()
            .expect("valid frame");
        encoded[2] = 2;

        assert_eq!(
            Frame::decode(&encoded),
            Err(FrameError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn decode_rejects_incomplete_payload() {
        let encoded = Frame::new(ClientMsgKind::Ping as u8, 0, b"hello".to_vec())
            .encode()
            .expect("valid frame");

        assert_eq!(
            Frame::decode(&encoded[..HEADER_LEN + 2]),
            Err(FrameError::IncompletePayload)
        );
    }

    #[test]
    fn decode_rejects_oversized_payload() {
        let mut encoded = Frame::new(ClientMsgKind::Ping as u8, 0, Vec::new())
            .encode()
            .expect("valid frame");
        encoded[6..10].copy_from_slice(&(MAX_PAYLOAD_LEN + 1).to_be_bytes());

        assert_eq!(Frame::decode(&encoded), Err(FrameError::PayloadTooLarge));
    }
}
