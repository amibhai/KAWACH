//! Exhaustive bounded model check of the rotation state machine (DESIGN.md §6.5).
//!
//! The machine is finite and small, so we do not sample it — we explore **all** of it.
//! Every reachable `(state, world)` pair is visited and every safety property is
//! asserted at every node. A contributor who adds an unsafe transition gets a failing
//! build with a counterexample trace, rather than a code review that might catch it.
//!
//! The final test in this file points the same checker at a *deliberately broken*
//! transition function and asserts that it fails. A model checker that cannot fail is
//! not evidence of anything.

use std::collections::{HashMap, HashSet, VecDeque};

use kawach_rotation::safety::Ghost;
use kawach_rotation::state::{next, PublishedSide, RotationEvent, RotationState};

/// A node in the reachable space: where the protocol is, and what is true of the world.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Node {
    state: RotationState,
    ghost: Ghost,
}

/// A safety property: a name and a predicate over a node.
struct Property {
    id: &'static str,
    statement: &'static str,
    holds: fn(&Node) -> bool,
}

const PROPERTIES: &[Property] = &[
    Property {
        id: "S1",
        statement: "a rotation completes only if the new credential was verified",
        holds: |n| n.state != RotationState::Completed || n.ghost.verified,
    },
    Property {
        id: "S2",
        statement: "consumers always have at least one credential that is live and published",
        holds: |n| n.ghost.consumers_have_a_working_credential(),
    },
    Property {
        id: "S3a",
        statement: "a completed rotation leaves the old credential revoked",
        holds: |n| n.state != RotationState::Completed || !n.ghost.old_live,
    },
    Property {
        id: "S3b",
        statement: "a rolled-back rotation leaves the new credential revoked",
        holds: |n| n.state != RotationState::RolledBack || !n.ghost.new_live,
    },
    Property {
        id: "S5",
        statement: "an unverified credential is never published to consumers",
        holds: |n| n.ghost.published != PublishedSide::New || n.ghost.verified,
    },
];

/// What an exploration found.
struct Exploration {
    nodes: HashSet<Node>,
    edges: Vec<(Node, RotationEvent, Node)>,
    /// Parent links, for reconstructing a counterexample trace.
    parents: HashMap<Node, (Node, RotationEvent)>,
}

impl Exploration {
    /// The shortest event sequence from the initial node to `target`.
    fn trace_to(&self, target: Node) -> Vec<RotationEvent> {
        let mut trace = Vec::new();
        let mut cursor = target;
        while let Some(&(parent, event)) = self.parents.get(&cursor) {
            trace.push(event);
            cursor = parent;
        }
        trace.reverse();
        trace
    }

    fn render_trace(&self, target: Node) -> String {
        let mut out = String::from("\n    Pending");
        let mut state = RotationState::START;
        for event in self.trace_to(target) {
            // Re-derive the state so the trace reads as a sequence of transitions.
            if let Ok(to) = next(state, event) {
                out.push_str(&format!("\n      --{event}--> {to}"));
                state = to;
            }
        }
        out
    }
}

/// Breadth-first exploration of the full reachable `(state, world)` space.
///
/// `transition` is a parameter so the same checker can be pointed at a deliberately
/// broken machine in the meta-test below.
fn explore(
    transition: impl Fn(RotationState, RotationEvent) -> Option<RotationState>,
) -> Exploration {
    let start = Node { state: RotationState::START, ghost: Ghost::initial() };

    let mut nodes = HashSet::new();
    let mut edges = Vec::new();
    let mut parents: HashMap<Node, (Node, RotationEvent)> = HashMap::new();
    let mut queue = VecDeque::new();

    nodes.insert(start);
    queue.push_back(start);

    while let Some(node) = queue.pop_front() {
        // Every plain event, plus the one reconciliation event that a truthful
        // `observe()` would produce in this world. Reconciliation must be driven by
        // reality, not by arbitrary input, or we would be checking a machine that
        // recovers from observations no honest backend could return.
        let events = RotationEvent::ALL_PLAIN
            .into_iter()
            .chain(std::iter::once(RotationEvent::Reconciled(node.ghost.observation())));

        for event in events {
            let Some(to) = transition(node.state, event) else {
                continue; // the state rejects this event, which is the intended behaviour
            };
            for ghost in node.ghost.successors(event) {
                let successor = Node { state: to, ghost };
                edges.push((node, event, successor));
                if nodes.insert(successor) {
                    parents.insert(successor, (node, event));
                    queue.push_back(successor);
                }
            }
        }
    }

    Exploration { nodes, edges, parents }
}

fn explore_real() -> Exploration {
    explore(|state, event| next(state, event).ok())
}

#[test]
fn every_reachable_state_satisfies_every_safety_property() {
    let exploration = explore_real();

    for node in &exploration.nodes {
        for property in PROPERTIES {
            assert!(
                (property.holds)(node),
                "\n\n  SAFETY VIOLATION [{}]: {}\n  at state {} with world {:?}\n  counterexample trace:{}\n",
                property.id,
                property.statement,
                node.state,
                node.ghost,
                exploration.render_trace(*node),
            );
        }
    }

    // An exploration that visited almost nothing would satisfy everything above
    // vacuously, so assert the coverage is real rather than trusting a magic number.

    // (a) every protocol state was visited
    let states: HashSet<RotationState> = exploration.nodes.iter().map(|n| n.state).collect();
    assert_eq!(states.len(), RotationState::ALL.len(), "not every state was explored");

    // (b) the world model adds real distinctions — some state is reachable with more
    //     than one world, which is what makes pairing state with ghost meaningful
    let mut worlds_per_state: HashMap<RotationState, HashSet<Ghost>> = HashMap::new();
    for node in &exploration.nodes {
        worlds_per_state.entry(node.state).or_default().insert(node.ghost);
    }
    assert!(
        worlds_per_state.values().any(|w| w.len() > 1),
        "every state has exactly one world — the ghost model is not doing any work"
    );

    // (c) the nondeterministic failure branches were actually taken. `ProvisionFailed`
    //     must be explored both as "nothing was created" and as "a credential was
    //     created and then the call failed"; if only one branch were reachable we would
    //     be checking a machine with easier failure modes than the real one.
    let post_provision_failure: HashSet<bool> = exploration
        .edges
        .iter()
        .filter(|(_, event, _)| *event == RotationEvent::ProvisionFailed)
        .map(|(_, _, to)| to.ghost.new_exists)
        .collect();
    assert_eq!(
        post_provision_failure.len(),
        2,
        "both outcomes of a failed provision must be explored, found {post_provision_failure:?}"
    );
}

#[test]
fn s4_every_state_is_reachable() {
    let exploration = explore_real();
    let reached: HashSet<RotationState> = exploration.nodes.iter().map(|n| n.state).collect();

    for state in RotationState::ALL {
        assert!(reached.contains(&state), "{state} is unreachable — dead code in the state machine");
    }
}

#[test]
fn s4_every_reachable_state_can_still_reach_a_terminal_state() {
    let exploration = explore_real();

    // Backward reachability from the terminal nodes over the explored edge set.
    let mut reverse: HashMap<Node, Vec<Node>> = HashMap::new();
    for (from, _, to) in &exploration.edges {
        reverse.entry(*to).or_default().push(*from);
    }

    let mut co_reachable: HashSet<Node> = HashSet::new();
    let mut queue: VecDeque<Node> = exploration
        .nodes
        .iter()
        .copied()
        .filter(|n| n.state.is_terminal())
        .inspect(|n| {
            co_reachable.insert(*n);
        })
        .collect();

    while let Some(node) = queue.pop_front() {
        for &predecessor in reverse.get(&node).into_iter().flatten() {
            if co_reachable.insert(predecessor) {
                queue.push_back(predecessor);
            }
        }
    }

    for node in &exploration.nodes {
        assert!(
            co_reachable.contains(node),
            "livelock: {} with world {:?} cannot reach any terminal state{}",
            node.state,
            node.ghost,
            exploration.render_trace(*node),
        );
    }
}

#[test]
fn revocation_of_the_old_credential_never_precedes_publication_of_the_new_one() {
    // S1 restated as a stronger operational property: at the moment the old credential
    // stops being live, the new one must already be what consumers read. Otherwise the
    // revoke would strand every consumer that had not yet migrated.
    let exploration = explore_real();
    for node in &exploration.nodes {
        if !node.ghost.old_live {
            assert_eq!(
                node.ghost.published,
                PublishedSide::New,
                "the old credential was revoked while consumers still read it{}",
                exploration.render_trace(*node),
            );
            assert!(node.ghost.new_live, "revoked the old credential with no live replacement");
        }
    }
}

#[test]
fn compensation_after_publication_always_drains_before_revoking() {
    // The specific bug this state machine exists to prevent: rolling back by revoking
    // the new credential while consumers are still using it. `RevokingNew` must never
    // be reached in a world where the new value is still what consumers read.
    let exploration = explore_real();
    for node in exploration.nodes.iter().filter(|n| n.state == RotationState::RevokingNew) {
        assert_eq!(
            node.ghost.published,
            PublishedSide::Old,
            "reached RevokingNew while the new value was still published{}",
            exploration.render_trace(*node),
        );
    }
}

#[test]
fn the_model_checker_actually_fails_on_an_unsafe_machine() {
    // A model checker that cannot fail proves nothing. Point it at a machine with the
    // single most dangerous plausible bug — revoking the old credential when
    // verification *fails* — and assert it is caught.
    let broken = |state: RotationState, event: RotationEvent| -> Option<RotationState> {
        if state == RotationState::Verifying && event == RotationEvent::VerifyFailed {
            return Some(RotationState::Revoking); // "just clean up the old one"
        }
        next(state, event).ok()
    };

    let exploration = explore(broken);
    let violations: Vec<_> = exploration
        .nodes
        .iter()
        .flat_map(|node| {
            PROPERTIES.iter().filter(move |p| !(p.holds)(node)).map(move |p| (p.id, *node))
        })
        .collect();

    assert!(
        !violations.is_empty(),
        "the checker passed a machine that revokes the old credential on verification failure"
    );
    let violated: HashSet<&str> = violations.iter().map(|(id, _)| *id).collect();
    // Completing without verification (S1) and stranding consumers (S2) are both
    // consequences of that one bad edge.
    assert!(violated.contains("S1"), "expected S1 to catch the unverified completion");
    assert!(violated.contains("S2"), "expected S2 to catch the stranded consumers");
}

#[test]
fn the_state_machine_rejects_more_than_it_accepts() {
    // A machine that accepted everything would satisfy nothing meaningfully. Confirm
    // the transition relation is sparse: most (state, event) pairs are refusals.
    let total = RotationState::ALL.len() * RotationEvent::ALL_PLAIN.len();
    let accepted = RotationState::ALL
        .into_iter()
        .flat_map(|s| RotationEvent::ALL_PLAIN.into_iter().map(move |e| (s, e)))
        .filter(|(s, e)| next(*s, *e).is_ok())
        .count();

    assert!(
        accepted * 4 < total,
        "transition relation is suspiciously permissive: {accepted} of {total} pairs accepted"
    );
}
