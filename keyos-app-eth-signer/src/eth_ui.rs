// SPDX-FileCopyrightText: 2026 Ethereum Foundation
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ethereum presentation helpers behind the Slint `Eth` global: hex values cut
//! into reading groups, MetaMask Jazzicon identicons, QR codes, chain names and
//! the exact wei/gwei renderings of an amount. Slint cannot slice strings or
//! draw pixels, so every page asks these instead of formatting on its own.

use {
    crate::{AppWindow, Eth, HexLine, ShortAddress},
    slint_keyos_platform::slint::{
        Color, ComponentHandle, Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel,
    },
    std::{cell::RefCell, collections::HashMap, rc::Rc},
};

pub fn init(ui: &AppWindow) {
    let eth = ui.global::<Eth>();

    eth.on_hex_lines(|value, per_line| {
        let lines = hex_lines(&value, per_line.max(1) as usize)
            .into_iter()
            .map(|groups| HexLine {
                groups: ModelRc::new(VecModel::from(
                    groups.into_iter().map(SharedString::from).collect::<Vec<_>>(),
                )),
            })
            .collect::<Vec<_>>();
        ModelRc::new(VecModel::from(lines))
    });

    // Rows re-evaluate their bindings as the list scrolls; an icon is drawn
    // once per address and size.
    let icons: Rc<RefCell<HashMap<(SharedString, u32), Image>>> = Default::default();
    eth.on_jazzicon(move |address, size| {
        let px = (size.round() as u32).clamp(8, 256);
        icons
            .borrow_mut()
            .entry((address.clone(), px))
            .or_insert_with(|| jazzicon_image(&address, px).unwrap_or_default())
            .clone()
    });

    eth.on_qr(|data| {
        // The platform renderer panics on empty input.
        if data.is_empty() {
            return Image::default();
        }
        slint_keyos_platform::qrcode::render(
            data.as_bytes(),
            Color::from_rgb_u8(0, 0, 0),
            Color::from_rgb_u8(255, 255, 255),
        )
    });

    eth.on_short_address(|address| {
        let (head, tail) = short_address(&address);
        ShortAddress { head: head.into(), tail: tail.into() }
    });

    eth.on_network_name(|chain_id| {
        chain_id.trim().parse::<u64>().ok().and_then(network_name).unwrap_or_default().into()
    });
}

// ----- hex groups ------------------------------------------------------------

/// A hex value as lines of four-character groups, `per_line` groups a line.
/// The `0x` prefix is dropped: pages draw it themselves, muted.
pub fn hex_lines(value: &str, per_line: usize) -> Vec<Vec<String>> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    let chars: Vec<char> = digits.chars().collect();
    let groups: Vec<String> = chars.chunks(4).map(|c| c.iter().collect()).collect();
    groups.chunks(per_line).map(|line| line.to_vec()).collect()
}

/// `0x` plus six digits, and the last six: enough to tell accounts apart in a
/// list. The full value is always one tap away.
pub fn short_address(address: &str) -> (String, String) {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() < 16 {
        return (address.to_string(), String::new());
    }
    (chars[..8].iter().collect(), chars[chars.len() - 6..].iter().collect())
}

// ----- chains ------------------------------------------------------------------

/// Names for the chain ids a Passport user is likely to sign for, from
/// chainlist.org. Anything else shows its bare id.
pub fn network_name(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        1 => "Ethereum Mainnet",
        10 => "OP Mainnet",
        56 => "BNB Smart Chain",
        100 => "Gnosis",
        130 => "Unichain",
        137 => "Polygon",
        146 => "Sonic",
        324 => "zkSync Era",
        480 => "World Chain",
        1101 => "Polygon zkEVM",
        5000 => "Mantle",
        8453 => "Base",
        17000 => "Holesky",
        42161 => "Arbitrum One",
        42220 => "Celo",
        43114 => "Avalanche C-Chain",
        59144 => "Linea",
        81457 => "Blast",
        534352 => "Scroll",
        560048 => "Hoodi",
        7777777 => "Zora",
        11155111 => "Sepolia",
        _ => return None,
    })
}

// ----- amounts -------------------------------------------------------------------

/// The decimal number of a "1.5 ETH" string from the decoder.
pub fn ether_number(formatted: &str) -> Option<&str> {
    let number = formatted.trim().strip_suffix("ETH")?.trim();
    let mut parts = number.splitn(2, '.');
    let whole = parts.next()?;
    let frac = parts.next().unwrap_or("");
    let ok = !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.bytes().all(|b| b.is_ascii_digit())
        && frac.len() <= 18;
    ok.then_some(number)
}

/// Exact wei for a decimal ETH number, digit by digit: no float ever touches
/// the value.
pub fn ether_to_wei(number: &str) -> String {
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    let digits = format!("{whole}{frac:0<18}");
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
}

/// Gwei for a wei integer string, with any fraction kept exact.
pub fn wei_to_gwei(wei: &str) -> String {
    let padded = format!("{wei:0>10}");
    let (whole, frac) = padded.split_at(padded.len() - 9);
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { whole.to_string() } else { format!("{whole}.{frac}") }
}

/// Thousands grouped with spaces (the integer part only), so a long figure
/// can be read at a glance in the monospace face.
pub fn group_digits(number: &str) -> String {
    let (whole, frac) = number.split_once('.').map_or((number, None), |(w, f)| (w, Some(f)));
    let mut grouped = String::new();
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i) % 3 == 0 {
            grouped.push(' ');
        }
        grouped.push(c);
    }
    match frac {
        Some(frac) => format!("{grouped}.{frac}"),
        None => grouped,
    }
}

// ----- Jazzicon ------------------------------------------------------------------
//
// MetaMask's identicon, as @metamask/jazzicon draws it: a Mersenne Twister
// seeded from the address picks a hue shift for a ten-colour palette, a
// background, and three squares, each translated and rotated, clipped to a
// circle. Colour arithmetic follows the `color` 0.11 package it depends on,
// whose HSL values are rounded to integers before the hue turns, so the same
// address gets the same icon here as in the user's wallet.

const JAZZ_COLORS: [u32; 10] =
    [0x01888C, 0xFC7500, 0x034F5D, 0xF73F01, 0xFC1960, 0xC7144C, 0xF3C100, 0x1598F2, 0x2465E1, 0xF19E02];
const SHAPE_COUNT: usize = 4;
const WOBBLE: f64 = 30.0;

struct Mt19937 {
    mt: [u32; 624],
    index: usize,
}

impl Mt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            let prev = mt[i - 1] ^ (mt[i - 1] >> 30);
            mt[i] = 1812433253u32.wrapping_mul(prev).wrapping_add(i as u32);
        }
        Self { mt, index: 624 }
    }

    fn next_u32(&mut self) -> u32 {
        const UPPER: u32 = 0x8000_0000;
        const LOWER: u32 = 0x7fff_ffff;
        const MATRIX_A: u32 = 0x9908_b0df;
        if self.index >= 624 {
            for k in 0..624 {
                let y = (self.mt[k] & UPPER) | (self.mt[(k + 1) % 624] & LOWER);
                let mag = if y & 1 == 1 { MATRIX_A } else { 0 };
                self.mt[k] = self.mt[(k + 397) % 624] ^ (y >> 1) ^ mag;
            }
            self.index = 0;
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^ (y >> 18)
    }

    /// `random()` of the mersenne-twister package: [0, 1) at 32-bit resolution.
    fn random(&mut self) -> f64 {
        self.next_u32() as f64 * (1.0 / 4294967296.0)
    }
}

/// JavaScript's Math.round.
fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

fn rgb_to_hsl(rgb: [u8; 3]) -> [f64; 3] {
    let [r, g, b] = rgb.map(|c| c as f64 / 255.0);
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let delta = max - min;
    let mut h = if max == min {
        0.0
    } else if r == max {
        (g - b) / delta
    } else if g == max {
        2.0 + (b - r) / delta
    } else {
        4.0 + (r - g) / delta
    };
    h = (h * 60.0).min(360.0);
    if h < 0.0 {
        h += 360.0;
    }
    let l = (min + max) / 2.0;
    let s = if max == min {
        0.0
    } else if l <= 0.5 {
        delta / (max + min)
    } else {
        delta / (2.0 - max - min)
    };
    [js_round(h), js_round(s * 100.0), js_round(l * 100.0)]
}

fn hsl_to_rgb(hsl: [f64; 3]) -> [u8; 3] {
    let (h, s, l) = (hsl[0] / 360.0, hsl[1] / 100.0, hsl[2] / 100.0);
    if s == 0.0 {
        let v = js_round(l * 255.0) as u8;
        return [v, v, v];
    }
    let t2 = if l < 0.5 { l * (1.0 + s) } else { l + s - l * s };
    let t1 = 2.0 * l - t2;
    let mut rgb = [0u8; 3];
    for (i, out) in rgb.iter_mut().enumerate() {
        let mut t3 = h + 1.0 / 3.0 * -(i as f64 - 1.0);
        if t3 < 0.0 {
            t3 += 1.0;
        }
        if t3 > 1.0 {
            t3 -= 1.0;
        }
        let v = if 6.0 * t3 < 1.0 {
            t1 + (t2 - t1) * 6.0 * t3
        } else if 2.0 * t3 < 1.0 {
            t2
        } else if 3.0 * t3 < 2.0 {
            t1 + (t2 - t1) * (2.0 / 3.0 - t3) * 6.0
        } else {
            t1
        };
        *out = js_round(v * 255.0) as u8;
    }
    rgb
}

fn rotate_hue(rgb: [u8; 3], degrees: f64) -> [u8; 3] {
    let mut hsl = rgb_to_hsl(rgb);
    let mut hue = (hsl[0] + degrees) % 360.0;
    if hue < 0.0 {
        hue += 360.0;
    }
    // color's setValues caps and rounds the turned hue before converting back.
    hsl[0] = js_round(hue.clamp(0.0, 360.0));
    hsl_to_rgb(hsl)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JazzShape {
    pub tx: f64,
    pub ty: f64,
    /// Degrees about the centre, rounded to one decimal as the SVG attribute is.
    pub rotation: f64,
    pub color: [u8; 3],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Jazzicon {
    pub background: [u8; 3],
    pub shapes: Vec<JazzShape>,
}

/// MetaMask's seed: the first four bytes of the address, as a number.
fn jazz_seed(address: &str) -> Option<u32> {
    let digits = address.strip_prefix("0x").or_else(|| address.strip_prefix("0X"))?;
    u32::from_str_radix(digits.get(..8)?, 16).ok()
}

pub fn jazzicon(address: &str, diameter: f64) -> Option<Jazzicon> {
    let mut rng = Mt19937::new(jazz_seed(address)?);
    let amount = rng.random() * 30.0 - WOBBLE / 2.0;
    let mut remaining: Vec<[u8; 3]> = JAZZ_COLORS
        .iter()
        .map(|&c| rotate_hue([(c >> 16) as u8, (c >> 8) as u8, c as u8], amount))
        .collect();
    let mut gen_color = |rng: &mut Mt19937| {
        rng.random();
        let idx = (remaining.len() as f64 * rng.random()).floor() as usize;
        remaining.remove(idx)
    };

    let background = gen_color(&mut rng);
    let total = (SHAPE_COUNT - 1) as f64;
    let shapes = (0..SHAPE_COUNT - 1)
        .map(|i| {
            let first_rot = rng.random();
            let angle = std::f64::consts::PI * 2.0 * first_rot;
            let velocity = diameter / total * rng.random() + (i as f64 * diameter / total);
            let second_rot = rng.random();
            let rotation = ((first_rot * 360.0 + second_rot * 180.0) * 10.0).round() / 10.0;
            JazzShape {
                tx: angle.cos() * velocity,
                ty: angle.sin() * velocity,
                rotation,
                color: gen_color(&mut rng),
            }
        })
        .collect();
    Some(Jazzicon { background, shapes })
}

/// RGBA pixels of the icon, `size` pixels across, 4x4 supersampled so the
/// square edges and the circle are smooth at list sizes.
pub fn jazzicon_pixels(address: &str, size: u32) -> Option<Vec<[u8; 4]>> {
    const SS: u32 = 4;
    let d = size as f64;
    let icon = jazzicon(address, d)?;
    let c = d / 2.0;
    // Inverse transform of each square: undo the translation, then the
    // rotation about the centre; inside when the result lands in [0, d)^2.
    let inverse: Vec<(f64, f64, f64, f64, [u8; 3])> = icon
        .shapes
        .iter()
        .map(|s| {
            let r = -s.rotation.to_radians();
            (s.tx, s.ty, r.cos(), r.sin(), s.color)
        })
        .collect();

    let mut out = Vec::with_capacity((size * size) as usize);
    for py in 0..size {
        for px in 0..size {
            let (mut r, mut g, mut b, mut hits) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = px as f64 + (sx as f64 + 0.5) / SS as f64;
                    let y = py as f64 + (sy as f64 + 0.5) / SS as f64;
                    if (x - c).powi(2) + (y - c).powi(2) > c * c {
                        continue;
                    }
                    let mut color = icon.background;
                    for &(tx, ty, cos, sin, shape_color) in &inverse {
                        let (qx, qy) = (x - tx - c, y - ty - c);
                        let ux = qx * cos - qy * sin + c;
                        let uy = qx * sin + qy * cos + c;
                        if (0.0..d).contains(&ux) && (0.0..d).contains(&uy) {
                            color = shape_color;
                        }
                    }
                    r += color[0] as u32;
                    g += color[1] as u32;
                    b += color[2] as u32;
                    hits += 1;
                }
            }
            out.push(if hits == 0 {
                [0, 0, 0, 0]
            } else {
                // Premultiplied by coverage, as Slint expects for RGBA8.
                let alpha = hits * 255 / (SS * SS);
                [
                    (r / hits * alpha / 255) as u8,
                    (g / hits * alpha / 255) as u8,
                    (b / hits * alpha / 255) as u8,
                    alpha as u8,
                ]
            });
        }
    }
    Some(out)
}

fn jazzicon_image(address: &str, size: u32) -> Option<Image> {
    let pixels = jazzicon_pixels(address, size)?;
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(size, size);
    for (dst, src) in buffer.make_mut_slice().iter_mut().zip(pixels) {
        *dst = Rgba8Pixel { r: src[0], g: src[1], b: src[2], a: src[3] };
    }
    Some(Image::from_rgba8_premultiplied(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_lines_are_two_rows_of_five() {
        let lines = hex_lines("0x4007f96a7F1096c3F34F2D5bab258C4e9Ca6D0c9", 5);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], ["4007", "f96a", "7F10", "96c3", "F34F"]);
        assert_eq!(lines[1], ["2D5b", "ab25", "8C4e", "9Ca6", "D0c9"]);
    }

    #[test]
    fn digest_lines_are_four_rows_of_four() {
        let digest = format!("0x{}", "ab".repeat(32));
        let lines = hex_lines(&digest, 4);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|l| l.len() == 4 && l.iter().all(|g| g == "abab")));
    }

    #[test]
    fn short_address_keeps_head_and_tail() {
        let (head, tail) = short_address("0x4007f96a7F1096c3F34F2D5bab258C4e9Ca6D0c9");
        assert_eq!((head.as_str(), tail.as_str()), ("0x4007f9", "a6D0c9"));
    }

    #[test]
    fn amounts_convert_exactly() {
        assert_eq!(ether_number("0.25 ETH"), Some("0.25"));
        assert_eq!(ether_number("12 ETH"), Some("12"));
        assert_eq!(ether_number("ALL CHAINS"), None);
        assert_eq!(ether_to_wei("0.25"), "250000000000000000");
        assert_eq!(ether_to_wei("0"), "0");
        assert_eq!(ether_to_wei("0.000000000000000001"), "1");
        assert_eq!(ether_to_wei("1234.5"), "1234500000000000000000");
        assert_eq!(wei_to_gwei("412000000000000"), "412000");
        assert_eq!(wei_to_gwei("1500000001"), "1.500000001");
        assert_eq!(wei_to_gwei("7"), "0.000000007");
        assert_eq!(group_digits("250000000000000000"), "250 000 000 000 000 000");
        assert_eq!(group_digits("412000"), "412 000");
        assert_eq!(group_digits("1234.56789"), "1 234.56789");
        assert_eq!(group_digits("12"), "12");
    }

    #[test]
    fn known_networks() {
        assert_eq!(network_name(1), Some("Ethereum Mainnet"));
        assert_eq!(network_name(11155111), Some("Sepolia"));
        assert_eq!(network_name(999_999_999), None);
    }

    #[test]
    fn mersenne_twister_matches_reference() {
        // First outputs of MT19937 seeded with 5489, the reference default.
        let mut mt = Mt19937::new(5489);
        assert_eq!(mt.next_u32(), 3499211612);
        assert_eq!(mt.next_u32(), 581869302);
        assert_eq!(mt.next_u32(), 3890346734);
    }

    /// Captured from @metamask/jazzicon 2.0.0 (color 0.11.4, mersenne-twister
    /// 1.1.0) under Node, drawing at diameter 100.
    #[test]
    fn jazzicon_matches_metamask() {
        fn rgb(hex: u32) -> [u8; 3] {
            [(hex >> 16) as u8, (hex >> 8) as u8, hex as u8]
        }
        let cases: [(&str, u32, [(f64, f64, f64, u32); 3]); 3] = [
            ("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", 0xC81477, [
                (-2.5556158521297045, 8.063881321515783, 204.4, 0x2392E1),
                (36.18089408122237, -31.77026171937678, 424.9, 0xFB1895),
                (-96.5139388652027, -24.46017458395903, 366.6, 0x018E72),
            ]),
            ("0x4007f96a7F1096c3F34F2D5bab258C4e9Ca6D0c9", 0xF94701, [
                (-0.0706339013181617, -0.3921595059823485, 404.7, 0xC81447),
                (-29.092425301547646, 26.26453573234586, 307.7, 0x034D5E),
                (-47.36231846201072, 59.722883808137404, 150.2, 0x01858E),
            ]),
            ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", 0xC81471, [
                (-3.5741614683507765, 3.9533012712000732, 171.4, 0xFB188D),
                (57.74563700869359, -31.92859991508948, 425.7, 0xF90E01),
                (-1.867365502748861, 71.8236750648264, 108.3, 0xFA4300),
            ]),
        ];
        for (address, background, shapes) in cases {
            let icon = jazzicon(address, 100.0).unwrap();
            assert_eq!(icon.background, rgb(background), "{address} background");
            for (got, (tx, ty, rotation, color)) in icon.shapes.iter().zip(shapes) {
                assert!((got.tx - tx).abs() < 1e-9, "{address} tx {} vs {tx}", got.tx);
                assert!((got.ty - ty).abs() < 1e-9, "{address} ty {} vs {ty}", got.ty);
                assert_eq!(got.rotation, rotation, "{address} rotation");
                assert_eq!(got.color, rgb(color), "{address} fill");
            }
        }
    }

    #[test]
    fn jazzicon_is_deterministic_and_round() {
        let address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let a = jazzicon_pixels(address, 32).unwrap();
        let b = jazzicon_pixels(address, 32).unwrap();
        assert_eq!(a, b);
        // Corners fall outside the circle, the centre inside it.
        assert_eq!(a[0][3], 0);
        assert_eq!(a[16 * 32 + 16][3], 255);
        assert!(jazzicon("not an address", 32.0).is_none());
    }
}
