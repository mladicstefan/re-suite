//! Reads memory from a running process and writes it, with what the person saw
//! on screen at that moment, as a file the ledger takes as `live_snapshot` evidence.
//!
//! Only a person at a terminal can take a capture: the tool asks them to type the
//! process's name before it reads anything. The server and its agents cannot.

use std::collections::BTreeMap;
use std::io::{BufRead as _, IsTerminal as _};
use std::path::PathBuf;

use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use ledger_core::{Capture, Observed};

#[derive(Parser)]
#[command(
    about = "Capture memory of a running process, with what you see on screen at that moment"
)]
struct Args {
    /// The process to read. It is only read, never stopped or changed.
    #[arg(long)]
    pid: u32,
    /// Where to read, as a debugger shows it: `0x7ffd1234`, or a decimal number.
    #[arg(long, value_parser = address)]
    address: u64,
    /// How many bytes to read.
    #[arg(long)]
    len: usize,
    /// What you see right now, under the name a layout will give the field: `hp=73`,
    /// or `armor=20.5..21.5` for a value the screen rounds. Give one for each value.
    #[arg(long, required = true, value_parser = seen)]
    seen: Vec<(String, Observed)>,
    /// The file to write. It must not exist yet.
    out: PathBuf,
}

fn address(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("`{text}` is not an address: write 0x7ffd1234 or a decimal number"))
}

fn seen(text: &str) -> Result<(String, Observed), String> {
    let wrong = || format!("`{text}` is not `name=73` or `name=20.5..21.5`");
    let (name, value) = text.split_once('=').ok_or_else(wrong)?;
    let number = |part: &str| part.parse::<f64>().ok().filter(|n| n.is_finite());
    let (min, max) = match value.split_once("..") {
        Some((min, max)) => (number(min), number(max)),
        None => (number(value), number(value)),
    };
    match (name, min, max) {
        (name, Some(min), Some(max)) if !name.is_empty() && min <= max => {
            Ok((name.to_owned(), Observed { min, max }))
        }
        _ => Err(wrong()),
    }
}

/// Takes the capture once `answer` gives the process's name, and returns what to tell the person.
/// `answer` is `None` when nobody is at a terminal to be asked.
fn capture(
    args: &Args,
    answer: Option<impl FnOnce(&str) -> std::io::Result<String>>,
) -> anyhow::Result<String> {
    let Args {
        pid, address, len, ..
    } = *args;
    ensure!(
        (1..=Capture::MAX_MEMORY).contains(&len),
        "a capture is 1 to {} bytes: one object or region, not a whole process",
        Capture::MAX_MEMORY
    );
    ensure!(
        !args.out.exists(),
        "{} exists already; a capture is never overwritten",
        args.out.display()
    );
    let process = ledger_os::process_name(pid).with_context(|| format!("process {pid}"))?;
    let Some(answer) = answer else {
        bail!(
            "a live capture is taken by a person at a terminal, and this is not one; nothing was read"
        );
    };
    let question = format!(
        "About to read {len} bytes at {address:#x} from process {pid} (`{process}`). It is only read.\n\
         Type the process's name to go ahead: "
    );
    ensure!(
        answer(&question)?.trim() == process,
        "that is not the process's name; nothing was read"
    );
    let memory = ledger_os::read_memory(pid, address, len)
        .with_context(|| format!("reading {len} bytes at {address:#x} from process {pid}"))?;
    let observed: BTreeMap<String, Observed> = args.seen.iter().cloned().collect();
    let seen: Vec<String> = (observed.iter())
        .map(|(name, seen)| format!("{name} {seen}"))
        .collect();
    let capture = Capture {
        process,
        pid,
        address,
        observed,
    };
    // Memory can hold secrets, so the file is the owner's alone, and whole or absent.
    ledger_os::write_once(&args.out, &capture.encode(&memory)?)
        .with_context(|| format!("writing {}", args.out.display()))?;
    Ok(format!(
        "wrote {}: {len} bytes of `{}` at {address:#x}; seen: {}\n\
         give it to the agent as `live_snapshot` evidence",
        args.out.display(),
        capture.process,
        seen.join(", ")
    ))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ask = |question: &str| {
        eprint!("{question}");
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    };
    let at_terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    println!("{}", capture(&args, at_terminal.then_some(ask))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Never = fn(&str) -> std::io::Result<String>;

    #[test]
    fn what_was_seen_is_a_number_or_a_range() {
        let range = |min, max| Observed { min, max };
        assert_eq!(seen("hp=73"), Ok(("hp".to_owned(), range(73.0, 73.0))));
        assert_eq!(
            seen("armor=20.5..21.5"),
            Ok(("armor".to_owned(), range(20.5, 21.5)))
        );
        assert_eq!(seen("x=-2..-1"), Ok(("x".to_owned(), range(-2.0, -1.0))));
        for wrong in [
            "hp", "=73", "hp=", "hp=full", "hp=5..1", "hp=1..", "hp=inf", "hp=nan",
        ] {
            assert!(seen(wrong).is_err(), "{wrong}");
        }
        assert_eq!(address("0x7ffd1234"), Ok(0x7ffd_1234));
        assert_eq!(address("4096"), Ok(4096));
        assert!(address("player").is_err());
    }

    #[test]
    fn a_capture_needs_a_person_who_names_the_process() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // The process read is this test itself, at a buffer it holds.
        let known = std::hint::black_box(73u32.to_le_bytes());
        let args = |out: &str| Args {
            pid: std::process::id(),
            address: known.as_ptr().addr() as u64,
            len: known.len(),
            seen: vec![(
                "hp".to_owned(),
                Observed {
                    min: 73.0,
                    max: 73.0,
                },
            )],
            out: dir.path().join(out),
        };
        let refusal = |result: anyhow::Result<String>| result.unwrap_or_else(|e| e.to_string());
        let name = ledger_os::process_name(std::process::id())?;

        let nobody = refusal(capture(&args("a.capture"), None::<Never>));
        assert!(nobody.contains("a person at a terminal"), "{nobody}");
        let wrong = refusal(capture(
            &args("a.capture"),
            Some(|_: &str| Ok("yes\n".to_owned())),
        ));
        assert_eq!(wrong, "that is not the process's name; nothing was read");
        assert!(!dir.path().join("a.capture").exists());

        let mut asked = String::new();
        let told = capture(
            &args("a.capture"),
            Some(|question: &str| {
                asked = question.to_owned();
                Ok(format!("{name}\n"))
            }),
        )?;
        assert!(
            asked.contains(&format!("read 4 bytes at {:#x}", known.as_ptr().addr())),
            "{asked}"
        );
        assert!(told.contains("seen: hp 73"), "{told}");
        let stored = std::fs::read(dir.path().join("a.capture"))?;
        let (header, memory) = Capture::split(&stored).map_err(anyhow::Error::msg)?;
        assert_eq!((header.process, memory), (name.clone(), &known[..]));

        // Never over a file that is there, and never more than one region.
        let again = refusal(capture(
            &args("a.capture"),
            Some(|_: &str| Ok(name.clone())),
        ));
        assert!(again.contains("exists already"), "{again}");
        let huge = Args {
            len: Capture::MAX_MEMORY + 1,
            ..args("b.capture")
        };
        assert!(refusal(capture(&huge, None::<Never>)).contains("a capture is 1 to"));
        Ok(())
    }
}
