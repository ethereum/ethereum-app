mod actions;
mod api;
mod storage;
mod ur;

use std::fmt::Write as _;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use api::*;
use blitstr2::GlyphStyle;
#[cfg(feature = "board-baosec")]
use dc34_api::PowerManagerOp;
use num_traits::*;
use ux_api::menu::*;
use ux_api::minigfx::*;
use ux_api::service::api::Gid;
use ux_api::service::gfx::Gfx;
use xous::{Message, send_message};

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("dc34-eth-signer PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_ETH_SIGNER, None).expect("can't register server");
    let conn = xous::connect(sid).unwrap();

    let gfx = Gfx::new(&xns).unwrap();
    let tt = ticktimer_server::Ticktimer::new().unwrap();

    // seed selected for use by the signing flow; shared with the actions thread
    let selected_seed = Arc::new(Mutex::new(None::<String>));
    // true while the actions thread has a modal flow in progress
    let action_active = Arc::new(AtomicBool::new(false));

    draw_status(&gfx, "starting...");

    let actions_sid = xous::create_server().unwrap();
    let actions_conn = xous::connect(actions_sid).unwrap();
    actions::spawn_actions(conn, actions_sid, selected_seed.clone(), action_active.clone());

    let menu_sid = xous::create_server().unwrap();
    let menu_mgr = build_menu(conn, actions_conn, menu_sid);

    // dc34-console arms a hardware watchdog at boot and only feeds it after this app sends
    // Boot; send it before the (potentially very slow, first-boot) PDDB mount or the WDT
    // reboots the device mid-init. (No console in hosted mode, so board builds only.)
    #[cfg(feature = "board-baosec")]
    let power_server = {
        let power_server = xns.request_connection_blocking(dc34_api::POWER_MANAGER_SERVER).unwrap();
        send_message(
            power_server,
            Message::new_blocking_scalar(PowerManagerOp::Boot.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .ok();
        log::info!("boot: power manager Boot sent");
        power_server
    };

    // let the system settle before attempting the mount; first boot disk init is slow
    tt.sleep_ms(1000).ok();
    let pddb = pddb::Pddb::new();
    let mut mounted = false;
    for _ in 0..4 {
        let (ok, _count) = pddb.try_mount();
        if ok {
            mounted = true;
            break;
        }
        tt.sleep_ms(1000).ok();
    }

    // register with the graphics server (not the keyboard driver): it withholds keys from
    // us automatically while a modal is on screen
    gfx.register_listener(SERVER_NAME_ETH_SIGNER, MainOp::KeyPress.to_u32().unwrap() as usize);
    log::info!("boot: key listener registered");

    #[cfg(feature = "board-baosec")]
    ensure_swap_encryption(&xns, power_server);
    log::info!("boot: swap encryption ensured");

    if mounted {
        send_message(actions_conn, Message::new_scalar(ActionOp::Startup.to_usize().unwrap(), 0, 0, 0, 0))
            .ok();
    } else {
        log::error!("PDDB did not mount; seed storage unavailable");
        draw_status(&gfx, "storage unavailable");
    }

    let mut menu_active = false;
    let mut skip_next_key = false;
    loop {
        let msg = xous::receive_message(sid).unwrap();
        let opcode: Option<MainOp> = FromPrimitive::from_usize(msg.body.id());
        match opcode {
            Some(MainOp::KeyPress) => xous::msg_scalar_unpack!(msg, k1, _k2, _k3, _k4, {
                let k = char::from_u32(k1 as u32).unwrap_or('\u{0000}');
                if skip_next_key {
                    // this keypress only woke the screen from power-off; don't act on it
                    skip_next_key = false;
                } else if menu_active {
                    menu_mgr.key_press(k);
                } else if k == '∴' {
                    menu_mgr.redraw();
                    menu_active = true;
                } else if k == '🔥' {
                    // center button: shortcut straight into request scanning
                    send_message(
                        actions_conn,
                        Message::new_scalar(ActionOp::ScanRequest.to_usize().unwrap(), 0, 0, 0, 0),
                    )
                    .ok();
                } else {
                    log::trace!("ignoring key {:?}", k);
                }
            }),
            Some(MainOp::ConsoleSkipKey) => skip_next_key = true,
            Some(MainOp::MenuDone) => {
                menu_active = false;
                draw_status(&gfx, &status_line(&selected_seed));
            }
            Some(MainOp::Redraw) => {
                if !menu_active && !action_active.load(Ordering::SeqCst) {
                    draw_status(&gfx, &status_line(&selected_seed));
                }
            }
            Some(MainOp::Quit) => {
                log::warn!("quit requested; ignoring (server must stay resident)");
            }
            None => log::error!("got unknown message: {:?}", msg),
        }
    }
}

/// First-boot bring-up of swap encryption (the app itself runs from swap). This can take a
/// while, so the watchdog is fed for every progress tick reported by the keystore.
#[cfg(feature = "board-baosec")]
fn ensure_swap_encryption(xns: &xous_names::XousNames, power_server: xous::CID) {
    let keystore = keystore::Keystore::new(xns);
    const THROW_AWAY_SERVER: &str = "_eth-signer swap status_";
    const THROW_AWAY_OP: usize = 42;
    let status_server = xns.register_name(THROW_AWAY_SERVER, None).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(200)); // settle the system a little

    let rand = xous::create_server_id().unwrap().to_array();
    let token = [rand[0], rand[1], rand[2]];
    keystore.ensure_swap_encryption(THROW_AWAY_SERVER, THROW_AWAY_OP, token).unwrap();
    let modals = modals::Modals::new(xns).unwrap();
    let mut in_progress = false;
    let mut msg_opt = None;
    loop {
        xous::reply_and_receive_next(status_server, &mut msg_opt).unwrap();
        let msg = msg_opt.as_mut().unwrap();
        if msg.body.id() == THROW_AWAY_OP {
            if let Some(scalar) = msg.body.scalar_message() {
                // feed the WDT so we don't time out during the encryption pass
                xous::try_send_message(
                    power_server,
                    Message::new_scalar(PowerManagerOp::FeedWdt.to_usize().unwrap(), 0, 0, 0, 0),
                )
                .ok();

                if token == [scalar.arg2 as u32, scalar.arg3 as u32, scalar.arg4 as u32] {
                    let progress = scalar.arg1 as u32;
                    if progress == 100 {
                        break;
                    }
                    if !in_progress {
                        modals.start_progress("Encrypting apps...", progress, 100, 0).ok();
                        in_progress = true;
                    } else {
                        modals.update_progress(progress).ok();
                    }
                }
            }
        }
    }
    if in_progress {
        modals.finish_progress().ok();
    }
}

fn build_menu(main_conn: xous::CID, actions_conn: xous::CID, menu_sid: xous::SID) -> MenuMatic {
    let mut items = Vec::<MenuItem>::new();
    for (name, op) in [
        ("Scan request", ActionOp::ScanRequest),
        ("Select seed", ActionOp::SelectSeed),
        ("New seed", ActionOp::CreateSeed),
        ("Import seed", ActionOp::ImportSeed),
        ("Accounts", ActionOp::AccountMenu),
        ("Close Menu", ActionOp::MenuClose),
    ] {
        items.push(MenuItem {
            name: String::from(name),
            action_conn: Some(actions_conn),
            action_opcode: op.to_u32().unwrap(),
            action_payload: MenuPayload::Scalar([0, 0, 0, 0]),
            close_on_select: true,
        });
    }
    menu_matic(items, "ETH Signer", Some(menu_sid), main_conn, MainOp::MenuDone.to_usize().unwrap())
        .expect("couldn't create MenuMatic manager")
}

fn status_line(selected_seed: &Arc<Mutex<Option<String>>>) -> String {
    match selected_seed.lock().unwrap().as_deref() {
        Some(seed) => format!("Seed: {}", seed),
        None => String::from("no seed selected"),
    }
}

fn draw_status(gfx: &Gfx, status: &str) {
    gfx.clear().ok();
    let mut title = TextView::new(
        Gid::dummy(),
        TextBounds::CenteredTop(Rectangle::new(Point::new(0, 8), Point::new(127, 40))),
    );
    title.draw_border = false;
    title.style = GlyphStyle::Bold;
    write!(title, "ETH Signer").ok();
    gfx.draw_textview(&mut title).ok();

    let mut sub = TextView::new(
        Gid::dummy(),
        TextBounds::CenteredTop(Rectangle::new(Point::new(0, 56), Point::new(127, 120))),
    );
    sub.draw_border = false;
    sub.style = GlyphStyle::Regular;
    write!(sub, "{}", status).ok();
    gfx.draw_textview(&mut sub).ok();
    gfx.flush().ok();
}
