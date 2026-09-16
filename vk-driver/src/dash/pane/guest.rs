//! The guest pane: what the selected environment's guest makes of **itself**.
//!
//! The other half of the question the pane beside it answers. The host knows what a VM is
//! taking from it; only the guest knows how that is being spent inside — which of its
//! processors are busy, how much of its memory is cache, whether it is stalling on memory or
//! on disk, and which of its own processes is doing it. Those are the figures
//! `vk atop --view` draws, and they are drawn here by the same two functions, so the panel
//! and the pane can never drift apart or disagree about a sample.
//!
//! Getting them costs the guest a sampler of its own, so the recording behind this pane runs
//! only while the pane is up — see [`crate::dash::guest`]. That is also why a heading says
//! how old the newest sample is once it has stopped being new: a pane that quietly kept
//! showing a figure from a minute ago would be read as a guest that is idle.
//!
//! Nothing here makes the guest's text safe, because nothing here needs to: every line
//! reaches [`crate::dash::render::Painter`], which gives a cell only to characters that
//! occupy one.

use crate::atop_view::{self, Table};
use crate::dash::poll::Guest;
use crate::dash::render::{Line, Style, span};
use crate::dash::state::App;

/// The narrowest column the process table is worth drawing in. Its heading alone is a pid, a
/// state, three figures and a command, which is about forty-five columns before a command
/// has anywhere to go.
const TABLE: usize = 60;

/// How many samples may go missing before the heading says so, as a multiple of the interval
/// they are being recorded at.
const STALE: u32 = 3;

/// What the selected environment's guest says about itself, in the room the pane has.
pub(crate) fn lines(app: &App, width: usize, rows: usize) -> Vec<Line> {
    if rows == 0 {
        return Vec::new();
    }
    let Some(env) = app.selected_env() else {
        return vec![note("nothing selected")];
    };
    let mut out = vec![heading(app)];
    if !env.is_running() {
        out.push(note("not running, so it has nothing to say about itself"));
        return out;
    }
    match &app.guest {
        // Nothing yet either way: the guest was asked a moment ago, or is still writing the
        // first sample of the recording it was asked for.
        None | Some(Guest::Starting) => out.push(note("asking the guest for its own figures…")),
        // A VM that records itself lays its log down only once its guest has written to the
        // share, so a pane opened early waits for it rather than calling it missing.
        Some(Guest::Waiting(why)) => out.push(note(&format!(
            "waiting for the guest's own recording — {why}"
        ))),
        // Said in the words it failed with: they already name what went wrong, and one of
        // them asks the question a reader of this pane most often needs answering.
        Some(Guest::Failed(why)) => out.push(note(why)),
        Some(Guest::Sample(sample)) => {
            for line in atop_view::system_panel(sample, width) {
                out.push(vec![span(line, Style::Plain)]);
            }
            // The table is dropped rather than squeezed on a narrow column: cut to half its
            // width it is a list of pids with no figures beside them, and the system lines
            // above are the half that still reads.
            let room = rows.saturating_sub(out.len()).saturating_sub(1);
            if width >= TABLE && room > 1 {
                out.push(Line::new());
                for line in atop_view::process_table(Table::default(), sample, room, width) {
                    out.push(vec![span(line, Style::Plain)]);
                }
            }
        }
    }
    out
}

/// Whose figures these are, and — once the guest has gone quiet — how old they are.
fn heading(app: &App) -> Line {
    let mut line = vec![
        span("guest figures", Style::Bold),
        span("  what it sees inside itself", Style::Dim),
    ];
    if let Some(secs) = stale_for(app) {
        line.push(span(format!("  last sample {secs}s ago"), Style::Warn));
    }
    line
}

/// How long it has been since the newest sample, where that is long enough to be worth
/// saying. Measured against this host's clock, never the guest's: a guest whose clock is
/// wrong is exactly the guest a reader opens this pane about.
fn stale_for(app: &App) -> Option<u64> {
    let waited = app.guest_at?.elapsed();
    (waited > app.interval.saturating_mul(STALE)).then_some(waited.as_secs())
}

/// A pane with nothing to draw says why, where the figures would have been.
fn note(said: &str) -> Line {
    vec![span(said, Style::Dim)]
}

/// A guest's own sample, for the tests here and in the renderer that draws this pane.
#[cfg(test)]
pub(crate) mod fixture {
    // A fixture that did not parse is a test that cannot report; the panic lints this module
    // gates on exist to keep a live terminal intact, which no test has.
    #![allow(clippy::expect_used)]

    /// One sample as a guest writes one: a busy processor of two, memory with cache in it,
    /// pressure, a disk, an interface, and a process running `command`.
    pub(crate) fn sample(command: &str) -> crate::atoplog::Sample {
        let h = |label: &str| format!("{label} guest 1000 1970/01/01 00:16:40 30");
        let text = format!(
            "RESET\n\
             {} 100 2 20 80 0 700 4 0 6 2 0 0 100 0 0\n\
             {} 100 0 10 70 0 350 2 0 3 1 0 0 100 0 0\n\
             {} 4096 250000 150000 20000 500 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 0 0 250\n\
             {} y 0.5 0.2 0.1 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 1.5 0.4 0.2 4000 0.0 0.0 0.0 0\n\
             {} vda 200 10 800 5 800 -1 0 1 2.50\n\
             {} eth0 100 20000 90 9000 10000 1\n\
             {} 412 (sh) S 0 0 412 1 0 900 ({command}) 1 1 0 0 0 0 0 0 0 0 0 y 0 0 - N ()\n\
             {} 412 (sh) S 100 90 10 5 25 0 0 1 0 412 y 900 (do_wait) 0 -3 -3\n\
             {} 412 (sh) S 4096 20000 40000 700 0 0 900 2 2400 1100 132 0 412 y 0 0 -3 -3 -3 -3\n\
             SEP\n",
            h("CPU"),
            h("cpu"),
            h("MEM"),
            h("PSI"),
            h("DSK"),
            h("NET"),
            h("PRG"),
            h("PRC"),
            h("PRM"),
        );
        crate::atoplog::parse(&text)
            .samples
            .pop()
            .expect("one sample")
    }
}

#[cfg(test)]
mod tests {
    // An assertion is how a test reports; the panic lints this module gates on exist to
    // keep a live terminal intact, which no test has.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::fixture::sample;
    use super::*;
    use crate::dash::envs::fixture::{row, vm};
    use crate::dash::poll::Event;
    use crate::dev::list::Status;
    use crate::term::Press;
    use std::time::{Duration, Instant};

    /// A dashboard with one running environment selected and the guest pane showing.
    fn app() -> App {
        let mut app = App::new(Duration::from_secs(3), false);
        app.on_event(Event::Envs(crate::dash::envs::join(
            vec![row("virtkit-4171942f2d70bae7", "/state/a", Status::Running)],
            vec![vm("/state/a", 4242)],
        )));
        app.key(Press::Char('3'));
        app
    }

    /// Everything this pane can be showing, in the order a reader meets them.
    fn states() -> Vec<Option<Guest>> {
        vec![
            None,
            Some(Guest::Starting),
            Some(Guest::Failed(
                "the guest sampler ended before its first sample (exit 127) — is this VM's \
                 vk-agent older than `vk atop`?"
                    .to_string(),
            )),
            Some(Guest::Sample(Box::new(sample("sh -c make test")))),
        ]
    }

    /// The pane draws at every width, and never wider than the column it was given — a line
    /// one column too long wraps, and a wrap scrolls the whole dashboard.
    #[test]
    fn the_pane_fits_every_column_it_is_given() {
        for width in [0usize, 20, 48, 60, 80, 200] {
            for rows in [0usize, 1, 3, 16] {
                for guest in states() {
                    let figures = matches!(guest, Some(Guest::Sample(_)));
                    let mut app = app();
                    app.guest = guest;
                    let drawn = lines(&app, width, rows);
                    assert!(rows > 0 || drawn.is_empty(), "no room, and it drew anyway");
                    // The figures are cut to the column as they are built. The heading and
                    // the notes are sentences, and fitting those is the painter's job.
                    for line in drawn.iter().skip(1).filter(|_| figures) {
                        let columns: usize = line
                            .iter()
                            .map(|run| run.text().chars().count())
                            .sum::<usize>();
                        assert!(columns <= width, "{width}x{rows} drew {columns} columns");
                    }
                    // A table's heading is no use without room for its columns.
                    let table = drawn
                        .iter()
                        .any(|line| line.iter().any(|run| run.text().contains("command")));
                    assert!(
                        !table || width >= TABLE,
                        "{width} columns is too narrow for a process table"
                    );
                }
            }
        }
    }

    /// Each state says what is going on in words, since the only other thing this pane could
    /// say is nothing at all — which reads as a broken dashboard.
    #[test]
    fn every_state_says_what_it_is() {
        let said = |app: &App| {
            lines(app, 100, 20)
                .iter()
                .flat_map(|line| line.iter().map(|run| run.text().to_string()))
                .collect::<Vec<_>>()
                .join("")
        };

        let mut app = app();
        assert!(said(&app).contains("asking the guest"), "{}", said(&app));

        app.guest = Some(Guest::Failed("is this VM's vk-agent older".to_string()));
        assert!(
            said(&app).contains("is this VM's vk-agent older"),
            "the reason was not passed on"
        );

        app.guest = Some(Guest::Sample(Box::new(sample("sh -c make test"))));
        let drawn = said(&app);
        assert!(drawn.contains("what it sees inside itself"), "{drawn}");
        assert!(drawn.contains("cpu "), "{drawn}");
        assert!(drawn.contains("mem "), "{drawn}");
        assert!(drawn.contains("psi "), "{drawn}");
        assert!(drawn.contains("sh -c make test"), "{drawn}");

        // An environment that is down has nothing to say about itself, which is a fact and
        // not a pane that failed to read something.
        let mut stopped = App::new(Duration::from_secs(3), false);
        stopped.on_event(Event::Envs(crate::dash::envs::join(
            vec![row("wab-qa-d3a92b42d7d0a15f", "/state/b", Status::Stopped)],
            Vec::new(),
        )));
        stopped.key(Press::Char('3'));
        assert!(said(&stopped).contains("not running"), "{}", said(&stopped));

        // And with nothing selected at all there is nothing for it to be about.
        let nothing = App::new(Duration::from_secs(3), false);
        assert!(said(&nothing).contains("nothing selected"));
    }

    /// A sample that has stopped being new says so. A pane that went on showing a figure
    /// from a minute ago reads as a guest that is idle.
    #[test]
    fn a_sample_that_has_stopped_arriving_says_how_old_it_is() {
        let mut app = app();
        app.on_event(Event::Guest {
            epoch: app.sample_epoch(),
            guest: Guest::Sample(Box::new(sample("sh -c make test"))),
        });
        let fresh = lines(&app, 100, 20);
        assert!(
            !fresh[0]
                .iter()
                .any(|run| run.text().contains("last sample")),
            "a sample that has just arrived was called old"
        );

        // Four intervals on, with nothing since.
        let now = Instant::now();
        app.guest_at = now.checked_sub(Duration::from_secs(12)).or(Some(now));
        let stale = lines(&app, 100, 20);
        assert!(
            stale[0]
                .iter()
                .any(|run| run.text().contains("last sample 12s ago")),
            "{:?}",
            stale[0]
        );
    }

    /// The log is written where a guest can reach it, so a command line can hold an escape
    /// sequence — which reaching the terminal would drive it rather than name a process.
    #[test]
    fn guest_text_cannot_drive_the_terminal() {
        let mut app = app();
        app.guest = Some(Guest::Sample(Box::new(sample("sh -c \x1b[2Jecho\rx"))));
        let drawn: String = lines(&app, 100, 20)
            .iter()
            .flat_map(|line| line.iter().map(|run| run.text().to_string()))
            .collect();
        assert!(!drawn.contains('\x1b'), "{drawn:?}");
        assert!(!drawn.contains('\r'), "{drawn:?}");
        assert!(drawn.contains("sh -c .[2Jecho.x"), "{drawn:?}");
    }
}
