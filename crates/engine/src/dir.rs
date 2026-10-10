#![forbid(unsafe_code)]

/// Byte-read progress and distinct stream termination outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// Number of bytes copied into the caller's output.
    Data(usize),
    /// No bytes are available yet; the read direction remains open.
    Waiting,
    /// Clean end of the read direction after buffered bytes drain.
    Eof,
    Reset,
    Truncated,
    Cancelled,
}
