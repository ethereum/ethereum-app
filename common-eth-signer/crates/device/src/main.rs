//! Interactive device binary.
//!
//! Usage: `device <eth-sign-request-hex> <bip39-entropy-hex>`
//!
//! By default it confirms via the console UI (works on a headless host). Build
//! with `--features slint` to confirm via the Slint GUI (needs a display).

use device::run_scenario;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <eth-sign-request-hex> <bip39-entropy-hex>",
            args.first().map(String::as_str).unwrap_or("device")
        );
        std::process::exit(2);
    }

    #[cfg(feature = "slint")]
    let mut ui = signer_displaying::SlintUi;
    #[cfg(not(feature = "slint"))]
    let mut ui = signer_displaying::ConsoleUi;

    match run_scenario(&args[1], &args[2], &mut ui) {
        Ok(signature) => println!("eth-signature: 0x{}", hex::encode(signature)),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
