//! The playbooks an agent follows, as a table. Each row says when its playbook applies
//! to what the ledger holds, and carries the playbook's file from `playbooks/`. The
//! next playbook is one row here and one file there.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use ledger_core::{EvidenceId, EvidenceKind, Ledger};

use crate::runner::FINGERPRINT;
use crate::tools::{Rejection, reject};

struct Playbook {
    /// The name agents ask for it by.
    id: &'static str,
    title: &'static str,
    /// Whether it applies to what the ledger holds now.
    applies: fn(&Ledger) -> bool,
    /// Why it applies, in one line.
    why: &'static str,
    text: &'static str,
}

static PLAYBOOKS: [Playbook; 2] = [
    Playbook {
        id: "capture-a-session",
        title: "1. Capture a session",
        applies: holds_no_session,
        why: "the ledger holds no browser session, and every other web playbook reads one",
        text: include_str!("../../../playbooks/web/1-capture-a-session.md"),
    },
    Playbook {
        id: "fingerprint-the-stack",
        title: "2. Fingerprint the stack",
        applies: holds_an_unread_session,
        why: "the ledger holds a session that no fingerprint run has read",
        text: include_str!("../../../playbooks/web/2-fingerprint-the-stack.md"),
    },
];

fn holds_no_session(ledger: &Ledger) -> bool {
    ledger.evidence_of(EvidenceKind::Session).next().is_none()
}

fn holds_an_unread_session(ledger: &Ledger) -> bool {
    let fingerprinted = |facts| {
        let run = ledger.derivation_of(facts);
        run.filter(|(tool, _)| tool.id == FINGERPRINT.id)
    };
    let read: BTreeSet<&EvidenceId> = (ledger.evidence_of(EvidenceKind::TechnologyFacts))
        .filter_map(fingerprinted)
        .flat_map(|(_, inputs)| inputs)
        .collect();
    ledger
        .evidence_of(EvidenceKind::Session)
        .any(|session| !read.contains(session))
}

/// The playbooks that apply to what `ledger` holds, one line each, or the text of
/// the one called `id`.
///
/// # Errors
/// No playbook is called `id`.
pub fn answer(ledger: &Ledger, id: Option<&str>) -> Result<String, Rejection> {
    if let Some(id) = id {
        let found = PLAYBOOKS.iter().find(|playbook| playbook.id == id);
        return found
            .map(|playbook| playbook.text.to_owned())
            .ok_or_else(|| {
                let ids: Vec<&str> = PLAYBOOKS.iter().map(|playbook| playbook.id).collect();
                reject(
                    "playbook_unknown",
                    id,
                    format!("No playbook has this id. There are: {}.", ids.join(", ")),
                    "Call ask about=playbooks without a subject to list the ones that apply.",
                )
            });
    }
    let mut out = String::new();
    for playbook in PLAYBOOKS
        .iter()
        .filter(|playbook| (playbook.applies)(ledger))
    {
        let _ = writeln!(out, "{}  {}: {}", playbook.id, playbook.title, playbook.why);
    }
    out.push_str(if out.is_empty() {
        "none applies to what this ledger holds"
    } else {
        "read one with ask about=playbooks subject=<id>"
    });
    Ok(out)
}
