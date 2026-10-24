// SPDX-FileCopyrightText: 2026 Ethereum Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0

// App theming.
//
// The app theme is authored as JSON (the source of truth) at the path named by
// `theme` in app-config.toml and compiled to Rust by the Foundation CLI. Use
// `foundation theme` to edit it visually.
//
// The app theme carries ethereum.org's palette (resources/theme.json) and
// otherwise inherits the built-in theme.

slint_keyos_platform::settings::use_api!(
    slint_keyos_platform::settings,
    slint_keyos_platform::server
);

use {
    foundation_themes::ColorScheme,
    slint_keyos_platform::{gui_server_api::ControlCenterColor, slint::ComponentHandle},
    std::rc::Rc,
};

foundation_themes::include_theme!(app_theme);

/// Paints the collapsed control-center bar while this app is in front.
pub type SetBarColor = Rc<dyn Fn(Option<ControlCenterColor>)>;

pub fn init(ui: &crate::AppWindow, set_bar: SetBarColor) {
    apply_system_theme(ui, &set_bar, SettingsApi::default().get_system_theme());

    let ui_weak = ui.as_weak();
    let mut updates = slint_keyos_platform::subscribe_scalar::<settings_permissions::SettingsPermissions, _>(
        settings_permissions::settings::messages::SubscribeSystemTheme,
    );
    slint_keyos_platform::spawn_local(async move {
        while let Some(system_theme) = updates.next().await {
            let Some(ui) = ui_weak.upgrade() else {
                break;
            };
            apply_system_theme(&ui, &set_bar, system_theme);
        }
    })
    .detach();
}

fn apply_system_theme(
    ui: &crate::AppWindow,
    set_bar: &SetBarColor,
    system_theme: settings_permissions::settings::global::SystemTheme,
) {
    let scheme = match system_theme {
        settings_permissions::settings::global::SystemTheme::Dark => ColorScheme::Dark,
        settings_permissions::settings::global::SystemTheme::Light => ColorScheme::Light,
    };

    // Apply the app theme to every component binding (palette, button styles,
    // sizes, named text-role font sizes).
    foundation_themes::apply_theme!(ui, app_theme::theme(), scheme);

    // The bar takes the colour the page tint starts with, just below it
    // (ui/components/layout.slint, Wash), so the two read as one surface.
    let bar = ui.global::<crate::Wash>().get_bar();
    set_bar(Some(ControlCenterColor::new(bar.red(), bar.green(), bar.blue())));
}
