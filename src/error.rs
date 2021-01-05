#[derive(Debug, Clone, Serialize)]
#[repr(C)]
pub enum Error {
    EncodeError,
    EncodeWriteError,
    DecodeVaru64Error,
    DecodeError,

}
