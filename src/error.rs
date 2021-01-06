use snafu::Snafu;

#[derive(Debug, Clone,Snafu, Serialize)]
#[repr(C)]
pub enum Error {
    EncodeError,
    EncodeWriteError,
    DecodeVaru64Error,
    DecodeError,

}
