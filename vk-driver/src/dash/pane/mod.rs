//! The panes the dashboard is made of.
//!
//! Each pane is a pure function of [`crate::dash::state::App`] and its available space,
//! returning [`crate::dash::render::Line`]s without file, process or terminal I/O.
//! [`crate::dash::render::Painter`] fits the lines and writes the escape sequences.

pub(crate) mod console;
pub(crate) mod detail;
pub(crate) mod list;
pub(crate) mod overlay;
pub(crate) mod usage;
