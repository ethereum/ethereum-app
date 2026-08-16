/// dc34-console's power manager blocks on connecting to a server with this exact name
/// before it starts feeding the hardware watchdog, so the "vault slot" app in the image
/// must register it — the WDT reboots the device otherwise.
#[cfg(feature = "board-baosec")]
pub use dc34_api::SERVER_NAME_VAULT2 as SERVER_NAME_ETH_SIGNER;
/// hosted mode has no dc34-console (and the emulation swarm's vault2 owns "_Vault2_")
#[cfg(feature = "hosted-baosec")]
pub const SERVER_NAME_ETH_SIGNER: &str = "_EthSigner_";

/// Opcodes handled by the main event loop.
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum MainOp {
    /// Keyboard events, routed to us by the graphics server (filtered while modals are up)
    KeyPress = 0,
    /// Sent by MenuMatic when the menu closes
    MenuDone,
    /// Repaint the status screen (sent by the actions thread when a flow completes)
    Redraw,
    Quit,
    /// Hard-coded into dc34-console: the wake-from-screen-off keypress is about to arrive
    /// and should be swallowed instead of acted on
    ConsoleSkipKey = 1026,
}

/// Opcodes handled by the actions thread, which owns all blocking modal flows.
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive, Debug, Copy, Clone, PartialEq)]
pub enum ActionOp {
    /// First-boot seed discovery: offer creation if no seeds exist, else selection
    Startup = 0,
    SelectSeed,
    CreateSeed,
    ImportSeed,
    /// Dummy activate/deactivate cycle so the status screen under the menu gets redrawn
    MenuClose,
    Quit,
}
