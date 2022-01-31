#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Read error: {0}")]
    ReadError(#[from] ReadError),

    #[error("The page entry's first_address didn't match the address of its first function")]
    InvalidPageEntryFirstAddress,

    #[error("Invalid page kind")]
    InvalidPageKind,

    #[error("Unexpected sentinel page")]
    UnexpectedSentinelPage,
}

/// This error indicates that the data slice was not large enough to
/// read the respective item.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    #[error("Could not read CompactUnwindInfoHeader")]
    Header,

    #[error("Could not read global opcodes")]
    GlobalOpcodes,

    #[error("Could not read pages")]
    Pages,

    #[error("Could not read RegularPage")]
    RegularPage,

    #[error("Could not read RegularPage functions")]
    RegularPageFunctions,

    #[error("Could not read CompressedPage")]
    CompressedPage,

    #[error("Could not read CompressedPage functions")]
    CompressedPageFunctions,

    #[error("Could not read local opcodes")]
    LocalOpcodes,

    #[error("Could not read page kind")]
    PageKind,
}
