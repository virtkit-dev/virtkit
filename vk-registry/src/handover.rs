//! Handing the registry from one process to the next when its hub updates it, so that no
//! connection is refused: the listeners serve through a [`Gate`] the hand-over closes, which
//! holds new connections in the backlog and asks those open to end once their request is
//! answered.

use vk_peer::handoff::Gate;

/// The listeners a registry serves through, to hand over: one per process.
#[derive(Default)]
pub struct Handover {
    pub gate: Gate,
}
