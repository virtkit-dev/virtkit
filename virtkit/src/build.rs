//! `virtkit build` — a from-scratch Dockerfile builder (no docker, no buildkit).
//!
//! Parsing frontend: [`parser`] (Dockerfile → instructions, lexing mirrors buildkit's
//! parser), [`interp`] (`$VAR`/`${VAR}` interpolation against ARG/ENV), and [`plan`]
//! (group instructions into stages, resolve cross-stage deps, toposort). The executor
//! backends and the build driver that consume this frontend are added in the following
//! commits.

// Nothing reaches the frontend until the build driver + subcommand land next; allow the
// not-yet-wired items until then.
#![allow(dead_code)]

mod interp;
mod parser;
mod plan;
