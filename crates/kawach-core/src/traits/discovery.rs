//! [`DiscoverySource`]: scanning half of the discovery pillar.

use async_trait::async_trait;

use crate::error::Result;
use crate::model::{Finding, ScanStats};
use crate::refs::SourceId;
use crate::scope::Scope;

/// Where findings go as they are produced.
///
/// Streaming rather than `Vec<Finding>` for a security reason, not a performance one:
/// a batching scanner holds candidate *values* alive until it returns. Streaming lets
/// each candidate be fingerprinted and dropped immediately, which keeps the number of
/// live plaintext buffers at any instant to O(1) instead of O(findings).
pub trait FindingSink: Send {
    /// Accept one finding.
    ///
    /// # Errors
    /// Persistence failures. A sink error aborts the scan: silently dropping findings
    /// would make an incomplete report indistinguishable from a clean one.
    fn emit(&mut self, finding: Finding) -> Result<()>;
}

/// A sink that collects into a `Vec`, for tests and small scans.
#[derive(Debug, Default)]
pub struct VecSink {
    /// Everything emitted so far.
    pub findings: Vec<Finding>,
}

impl FindingSink for VecSink {
    fn emit(&mut self, finding: Finding) -> Result<()> {
        self.findings.push(finding);
        Ok(())
    }
}

/// A place secrets might be hiding.
///
/// Note the absence of a `CommitToken` anywhere: discovery is read-only by
/// construction. A `DiscoverySource` has no way to mutate anything it scans.
#[async_trait]
pub trait DiscoverySource: Send + Sync {
    /// This source's configured identifier.
    fn id(&self) -> &SourceId;

    /// Scan, emitting findings as they are produced.
    ///
    /// Implementations must fingerprint and drop each candidate value before moving to
    /// the next, and must never place a value in a [`Finding`] — which the type system
    /// prevents anyway, since `Finding` has no field for one.
    ///
    /// # Errors
    /// I/O or API failures, and any error propagated from the sink.
    async fn scan(&self, scope: &Scope, sink: &mut dyn FindingSink) -> Result<ScanStats>;
}
