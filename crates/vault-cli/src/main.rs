//! fvlt — scripting/test front-end over vault-core (no UI).
//!
//!   fvlt lock   <folder> [--password-stdin] [--secure-delete]
//!   fvlt unlock <file>   [--password-stdin] [--master-stdin]
//!   fvlt inspect <file>
//!   fvlt verify  <file>
//!
//! Hand-rolled arg parsing (no clap) to keep the binary tiny.

fn main() {
    // TODO(phase-1): wire subcommands to vault-core.
    eprintln!("fvlt: not yet implemented — see docs/PLAN.md phase 1");
    std::process::exit(2);
}
