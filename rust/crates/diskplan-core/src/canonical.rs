use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 4] = b"DPCB";
const VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Activity {
    Absent = 0,
    Unknown = 1,
    Inactive = 2,
    Active = 3,
}

impl TryFrom<u8> for Activity {
    type Error = CanonicalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Absent),
            1 => Ok(Self::Unknown),
            2 => Ok(Self::Inactive),
            3 => Ok(Self::Active),
            _ => Err(CanonicalError::UnknownVariant {
                field: "activity",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Coverage {
    Unknown = 0,
    Complete = 1,
    Partial = 2,
    Unreadable = 3,
    Failed = 4,
}

impl TryFrom<u8> for Coverage {
    type Error = CanonicalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Complete),
            2 => Ok(Self::Partial),
            3 => Ok(Self::Unreadable),
            4 => Ok(Self::Failed),
            _ => Err(CanonicalError::UnknownVariant {
                field: "coverage",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceBinding {
    pub candidate_id: String,
    pub raw_path: Vec<u8>,
    pub logical_bytes: u64,
    pub observed_at: Option<Timestamp>,
    pub activity: Activity,
    pub coverage: Coverage,
    pub labels: Vec<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CanonicalError {
    #[error("input ended while decoding {field}")]
    Truncated { field: &'static str },
    #[error("invalid canonical magic")]
    InvalidMagic,
    #[error("unsupported canonical version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown {field} variant {value}")]
    UnknownVariant { field: &'static str, value: u8 },
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 { field: &'static str },
    #[error("non-canonical label ordering")]
    NonCanonicalLabels,
    #[error("timestamp nanoseconds out of range")]
    InvalidNanoseconds,
    #[error("input is not the canonical encoding of its decoded value")]
    NonCanonicalEncoding,
    #[error("trailing bytes after canonical record")]
    TrailingBytes,
    #[error("field {field} is too long")]
    FieldTooLong { field: &'static str },
}

fn encode_evidence(value: &EvidenceBinding) -> Result<Vec<u8>, CanonicalError> {
    if value
        .observed_at
        .as_ref()
        .is_some_and(|timestamp| timestamp.nanos >= 1_000_000_000)
    {
        return Err(CanonicalError::InvalidNanoseconds);
    }

    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    put_string(&mut output, &value.candidate_id, "candidate_id")?;
    put_bytes(&mut output, &value.raw_path, "raw_path")?;
    output.extend_from_slice(&value.logical_bytes.to_be_bytes());
    match &value.observed_at {
        None => output.push(0),
        Some(timestamp) => {
            output.push(1);
            output.extend_from_slice(&timestamp.seconds.to_be_bytes());
            output.extend_from_slice(&timestamp.nanos.to_be_bytes());
        }
    }
    output.push(value.activity as u8);
    output.push(value.coverage as u8);
    let mut labels: Vec<&str> = value.labels.iter().map(String::as_str).collect();
    labels.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    labels.dedup();
    put_u32(&mut output, labels.len(), "labels")?;
    for label in labels {
        put_string(&mut output, label, "label")?;
    }
    Ok(output)
}

pub fn verify_evidence(bytes: &[u8]) -> Result<EvidenceBinding, CanonicalError> {
    let binding = decode_evidence_record(bytes)?;
    if encode_evidence(&binding)? != bytes {
        return Err(CanonicalError::NonCanonicalEncoding);
    }
    Ok(binding)
}

fn decode_evidence_record(bytes: &[u8]) -> Result<EvidenceBinding, CanonicalError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4, "magic")? != MAGIC {
        return Err(CanonicalError::InvalidMagic);
    }
    let version = decoder.u16("version")?;
    if version != VERSION {
        return Err(CanonicalError::UnsupportedVersion(version));
    }
    let candidate_id = decoder.string("candidate_id")?;
    let raw_path = decoder.bytes("raw_path")?.to_vec();
    let logical_bytes = decoder.u64("logical_bytes")?;
    let observed_at = match decoder.u8("observed_at variant")? {
        0 => None,
        1 => {
            let timestamp = Timestamp {
                seconds: decoder.i64("observed_at seconds")?,
                nanos: decoder.u32("observed_at nanos")?,
            };
            if timestamp.nanos >= 1_000_000_000 {
                return Err(CanonicalError::InvalidNanoseconds);
            }
            Some(timestamp)
        }
        value => {
            return Err(CanonicalError::UnknownVariant {
                field: "observed_at",
                value,
            });
        }
    };
    let activity = Activity::try_from(decoder.u8("activity")?)?;
    let coverage = Coverage::try_from(decoder.u8("coverage")?)?;
    let label_count = decoder.u32("labels")? as usize;
    if label_count > decoder.remaining_len() / 4 {
        return Err(CanonicalError::Truncated { field: "labels" });
    }
    let mut labels = Vec::with_capacity(label_count);
    for _ in 0..label_count {
        labels.push(decoder.string("label")?);
    }
    if !labels
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
    {
        return Err(CanonicalError::NonCanonicalLabels);
    }
    if !decoder.is_empty() {
        return Err(CanonicalError::TrailingBytes);
    }
    Ok(EvidenceBinding {
        candidate_id,
        raw_path,
        logical_bytes,
        observed_at,
        activity,
        coverage,
        labels,
    })
}

pub fn evidence_digest(canonical_bytes: &[u8]) -> Result<[u8; 32], CanonicalError> {
    verify_evidence(canonical_bytes)?;
    let mut hasher = Sha256::new();
    hasher.update(b"diskplan/evidence/v1\0");
    hasher.update(canonical_bytes);
    Ok(hasher.finalize().into())
}

fn put_u32(output: &mut Vec<u8>, value: usize, field: &'static str) -> Result<(), CanonicalError> {
    let value = u32::try_from(value).map_err(|_| CanonicalError::FieldTooLong { field })?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    field: &'static str,
) -> Result<(), CanonicalError> {
    put_u32(output, bytes.len(), field)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_string(
    output: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), CanonicalError> {
    put_bytes(output, value.as_bytes(), field)
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8], CanonicalError> {
        if self.remaining.len() < count {
            return Err(CanonicalError::Truncated { field });
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn remaining_len(&self) -> usize {
        self.remaining.len()
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, CanonicalError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, CanonicalError> {
        Ok(u16::from_be_bytes(
            self.take(2, field)?.try_into().expect("exact length"),
        ))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, CanonicalError> {
        Ok(u32::from_be_bytes(
            self.take(4, field)?.try_into().expect("exact length"),
        ))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, CanonicalError> {
        Ok(u64::from_be_bytes(
            self.take(8, field)?.try_into().expect("exact length"),
        ))
    }

    fn i64(&mut self, field: &'static str) -> Result<i64, CanonicalError> {
        Ok(i64::from_be_bytes(
            self.take(8, field)?.try_into().expect("exact length"),
        ))
    }

    fn bytes(&mut self, field: &'static str) -> Result<&'a [u8], CanonicalError> {
        let length = self.u32(field)? as usize;
        self.take(length, field)
    }

    fn string(&mut self, field: &'static str) -> Result<String, CanonicalError> {
        String::from_utf8(self.bytes(field)?.to_vec())
            .map_err(|_| CanonicalError::InvalidUtf8 { field })
    }
}
