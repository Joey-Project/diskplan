#![forbid(unsafe_code)]

use prost::Message;

pub mod diskplan {
    pub mod v1 {
        include!("generated/diskplan.v1.rs");
    }
}

pub mod runtime;
pub mod sealed;

/// A protobuf envelope admitted from its original frame bytes. The decoded
/// value is never exposed without first proving byte-identical re-encoding,
/// which rejects unknown fields at the envelope or any nested message level.
#[derive(Clone, Debug)]
pub struct CanonicalEnvelopeReceipt {
    envelope: diskplan::v1::Envelope,
}

impl CanonicalEnvelopeReceipt {
    pub fn envelope(&self) -> &diskplan::v1::Envelope {
        &self.envelope
    }
}

pub fn decode_canonical_envelope(
    raw: &[u8],
) -> Result<CanonicalEnvelopeReceipt, runtime::RuntimeProjectionError> {
    let envelope = diskplan::v1::Envelope::decode(raw)
        .map_err(|error| runtime::RuntimeProjectionError::Protobuf(error.to_string()))?;
    if envelope.encode_to_vec() != raw {
        return Err(runtime::RuntimeProjectionError::InvalidManifest(
            "envelope or nested message is not canonical protobuf",
        ));
    }
    Ok(CanonicalEnvelopeReceipt { envelope })
}
