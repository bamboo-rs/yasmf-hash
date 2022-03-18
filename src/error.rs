use snafu::Snafu;

#[derive(Debug, Clone, Snafu, Serialize, Eq, PartialEq)]
#[repr(C)]
pub enum Error {
    EncodeError,
    EncodeWriteError,
    DecodeVaru64Error,
    DecodeError,
}
