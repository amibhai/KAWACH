//! The ghost model used to machine-check the state machine's safety properties.
//!
//! "Ghost state" in the verification sense: variables that do not exist at runtime but
//! that track what would be true of the world if the state machine were driving a real
//! rotation. Pairing each [`RotationState`] with a [`Ghost`] turns the properties in
//! DESIGN.md §6.5 into assertions that can be checked at every node of an exhaustive
//! exploration of the reachable space.
//!
//! The state machine is small and finite, so we do not sample it — we explore all of
//! it. See `tests/model_check.rs`.
//!
//! ## Nondeterministic failure outcomes
//!
//! A failure event does not tell us whether the effect happened. `ProvisionFailed` may
//! mean "nothing was created" or "a credential was created and then the connection
//! dropped". Modelling only the convenient branch would be checking a machine we do
//! not have, so [`Ghost::successors`] returns *every* world consistent with the event,
//! and the checker explores all of them.

use crate::state::{Observation, PublishedSide, RotationEvent};

/// The modelled state of the world alongside a [`RotationState`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ghost {
    /// Has a new credential been created in the home system?
    pub new_exists: bool,
    /// Does the home system accept the new credential?
    pub new_live: bool,
    /// Does it accept the old credential?
    pub old_live: bool,
    /// Which value consumers currently read.
    pub published: PublishedSide,
    /// Has the new credential been proven to work at some point in this trace?
    pub verified: bool,
}

impl Ghost {
    /// The world at the start of a rotation: one credential, live and published.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            new_exists: false,
            new_live: false,
            old_live: true,
            published: PublishedSide::Old,
            verified: false,
        }
    }

    /// **S2** — consumers have something that works.
    ///
    /// At least one credential is both live in the home system and published in the
    /// backend. This is the machine-checked form of "no dropped connections", and it
    /// is what forces compensation to be a mirror rather than an undo.
    #[must_use]
    pub fn consumers_have_a_working_credential(self) -> bool {
        match self.published {
            PublishedSide::Old => self.old_live,
            PublishedSide::New => self.new_live,
            // Cannot be reached in the model; a real backend reporting this escalates.
            PublishedSide::Unknown => false,
        }
    }

    /// What an `observe()` call would return in this world.
    ///
    /// Used to generate reconciliation events consistent with reality, rather than
    /// arbitrary ones — recovery is only sound if the observation is truthful.
    #[must_use]
    pub fn observation(self) -> Observation {
        Observation { new_live: self.new_live, old_live: self.old_live, published: self.published }
    }

    /// Every world that could result from `event`.
    ///
    /// Success events are deterministic. Failure events are not: the effect may or may
    /// not have landed before the failure was reported, and both branches are explored.
    #[must_use]
    pub fn successors(self, event: RotationEvent) -> Vec<Self> {
        use RotationEvent as E;

        match event {
            E::ProvisionOk => vec![Self { new_exists: true, new_live: true, ..self }],

            // Did the provision land before the failure? Unknown. Explore both.
            E::ProvisionFailed => vec![self, Self { new_exists: true, new_live: true, ..self }],

            E::VerifyOk => vec![Self { verified: true, ..self }],

            E::PublishOk => vec![Self { published: PublishedSide::New, ..self }],

            // A lost acknowledgement looks exactly like a failed write.
            E::PublishFailed => vec![self, Self { published: PublishedSide::New, ..self }],

            E::RevokeOk => vec![Self { old_live: false, ..self }],
            E::RevokeFailed => vec![self, Self { old_live: false, ..self }],

            E::RestoreOk => vec![Self { published: PublishedSide::Old, ..self }],
            E::RestoreFailed => vec![self, Self { published: PublishedSide::Old, ..self }],

            E::RevokeNewOk => vec![Self { new_live: false, new_exists: false, ..self }],
            E::RevokeNewFailed => vec![self, Self { new_live: false, new_exists: false, ..self }],

            // Everything else — starts, drains, aborts, reconciliation — observes or
            // sequences, and changes nothing about the world.
            _ => vec![self],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_initial_world_is_available() {
        assert!(Ghost::initial().consumers_have_a_working_credential());
    }

    #[test]
    fn publishing_a_credential_that_is_not_live_is_an_unavailable_world() {
        // Not reachable through the state machine — that is exactly what the model
        // checker proves. Asserted here so the property itself is known to have teeth.
        let broken = Ghost { published: PublishedSide::New, new_live: false, ..Ghost::initial() };
        assert!(!broken.consumers_have_a_working_credential());
    }

    #[test]
    fn failure_events_are_modelled_nondeterministically() {
        let g = Ghost::initial();
        assert_eq!(g.successors(RotationEvent::ProvisionFailed).len(), 2);
        assert_eq!(g.successors(RotationEvent::PublishFailed).len(), 2);
        assert_eq!(g.successors(RotationEvent::ProvisionOk).len(), 1);
    }

    #[test]
    fn observation_reports_the_world_faithfully() {
        let g = Ghost { new_live: true, old_live: false, published: PublishedSide::New, ..Ghost::initial() };
        let o = g.observation();
        assert!(o.new_live && !o.old_live);
        assert_eq!(o.published, PublishedSide::New);
    }
}
