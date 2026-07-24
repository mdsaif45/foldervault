// egui "unlock dialog" — compare this to foldervault's ui.rs (~1200 lines of
// raw Win32). Here the whole UI is one function that re-runs every frame.
use eframe::egui;

struct App { pw: String, reveal: bool, fails: u32 }

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        // dark theme + gold accent, set once
        let gold = egui::Color32::from_rgb(0xE1, 0xB9, 0x4A);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🔒").size(24.0).color(gold));
                ui.vertical(|ui| {
                    ui.heading("Photos");
                    ui.label(egui::RichText::new("Locked folder · 2.4 GB").weak());
                });
            });
            ui.add_space(14.0);

            // password field + eye toggle — a built-in widget, one line each
            ui.horizontal(|ui| {
                let field = egui::TextEdit::singleline(&mut self.pw)
                    .password(!self.reveal)
                    .desired_width(240.0)
                    .hint_text("Password");
                ui.add(field);
                if ui.button(if self.reveal { "🙈" } else { "👁" }).clicked() {
                    self.reveal = !self.reveal;
                }
            });
            ui.add_space(6.0);

            // attempt dots + label
            ui.horizontal(|ui| {
                for i in 0..3 {
                    let c = if i < self.fails { egui::Color32::from_rgb(0xE2,0x4B,0x4A) }
                            else { egui::Color32::DARK_GRAY };
                    ui.label(egui::RichText::new("●").color(c));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("{} attempts remaining", 3-self.fails))
                        .color(egui::Color32::from_rgb(0xD8,0x9A,0x3E)));
                });
            });
            ui.add_space(14.0);

            ui.horizontal(|ui| {
                if ui.link("Use master password").clicked() {}
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let b = egui::Button::new(egui::RichText::new("Unlock").color(egui::Color32::BLACK))
                        .fill(gold);
                    if ui.add(b).clicked() { self.fails = (self.fails+1).min(3); }
                });
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 240.0]),
        ..Default::default()
    };
    eframe::run_native("Unlock", opts,
        Box::new(|cc| { cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App { pw: "secret".into(), reveal: false, fails: 1 })) }))
}
