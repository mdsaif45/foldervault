// The Rust side is tiny — the UI lives in ui/unlock.slint. This just launches it.
slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let w = Unlock::new()?;
    w.run()
}
