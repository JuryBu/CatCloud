//! Diagnostics, sanitized logs, AI onboarding guides, Agent manuals, and GitHub Issue drafts.

pub(in crate::commands) mod issue_docs;
pub(in crate::commands) mod report;

pub use issue_docs::*;
pub use report::*;
