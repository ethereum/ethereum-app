//! Minimal BC-UR (Uniform Resources) receiver for ERC-4527 QR transport.
//!
//! Decodes single-part URs (`ur:type/<bytewords>`) and multi-part URs
//! (`ur:type/K-N/<bytewords>`) built from *pure* fountain fragments, i.e. parts
//! 1..=N. Mixed fountain parts (seqNum > seqLen) are ignored: the companion
//! ur-bridge tool re-transmits messages as pure parts only, stepped manually,
//! because the device camera is too slow for animated fountain streams.

/// The 256 bytewords, 4 letters each; the minimal encoding uses the first and
/// last letter of each word (both are unique per word).
const BYTEWORDS: &str = "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

/// Caps to keep a malicious QR from ballooning memory.
const MAX_MESSAGE_LEN: usize = 8192;
const MAX_SEQ_LEN: usize = 256;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Decode minimal-style bytewords and verify the trailing CRC32.
fn bytewords_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 || s.len() < 10 {
        return Err("bad bytewords length");
    }
    // build the (first letter, last letter) -> byte table
    let mut table = [-1i16; 26 * 26];
    let bw = BYTEWORDS.as_bytes();
    for i in 0..256 {
        let a = (bw[i * 4] - b'a') as usize;
        let b = (bw[i * 4 + 3] - b'a') as usize;
        table[a * 26 + b] = i as i16;
    }
    let sb = s.as_bytes();
    let mut data = Vec::with_capacity(s.len() / 2);
    for pair in sb.chunks_exact(2) {
        if !pair[0].is_ascii_lowercase() || !pair[1].is_ascii_lowercase() {
            return Err("bad bytewords character");
        }
        let idx = (pair[0] - b'a') as usize * 26 + (pair[1] - b'a') as usize;
        match table[idx] {
            -1 => return Err("unknown byteword"),
            v => data.push(v as u8),
        }
    }
    let body_len = data.len() - 4;
    let expected = u32::from_be_bytes(data[body_len..].try_into().unwrap());
    if crc32(&data[..body_len]) != expected {
        return Err("bytewords checksum mismatch");
    }
    data.truncate(body_len);
    Ok(data)
}

/// Tiny CBOR reader: returns (major type, argument value) and advances the cursor.
fn cbor_header(data: &[u8], pos: &mut usize) -> Result<(u8, u64), &'static str> {
    let b = *data.get(*pos).ok_or("cbor truncated")?;
    *pos += 1;
    let major = b >> 5;
    let info = b & 0x1f;
    let value = match info {
        0..=23 => info as u64,
        24..=27 => {
            let n = 1usize << (info - 24);
            let bytes = data.get(*pos..*pos + n).ok_or("cbor truncated")?;
            *pos += n;
            let mut v = 0u64;
            for &x in bytes {
                v = (v << 8) | x as u64;
            }
            v
        }
        _ => return Err("unsupported cbor header"),
    };
    Ok((major, value))
}

/// Parsed fountain part: [seqNum, seqLen, messageLen, checksum, data].
struct Part {
    seq_num: usize,
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    data: Vec<u8>,
}

fn parse_part(cbor: &[u8]) -> Result<Part, &'static str> {
    let mut pos = 0;
    let (major, count) = cbor_header(cbor, &mut pos)?;
    if major != 4 || count != 5 {
        return Err("bad part structure");
    }
    let mut uints = [0u64; 4];
    for u in uints.iter_mut() {
        let (major, v) = cbor_header(cbor, &mut pos)?;
        if major != 0 {
            return Err("bad part field");
        }
        *u = v;
    }
    let (major, len) = cbor_header(cbor, &mut pos)?;
    if major != 2 {
        return Err("bad part data");
    }
    let data = cbor.get(pos..pos + len as usize).ok_or("cbor truncated")?.to_vec();
    Ok(Part {
        seq_num: uints[0] as usize,
        seq_len: uints[1] as usize,
        message_len: uints[2] as usize,
        checksum: uints[3] as u32,
        data,
    })
}

pub enum UrEvent {
    /// Accepted a new pure part; not complete yet.
    Part {
        received: usize,
        total: usize,
    },
    /// This pure part was already scanned; the sender needs to advance.
    Duplicate {
        part: usize,
        received: usize,
        total: usize,
    },
    /// Mixed fountain part; nothing we can use, keep scanning.
    Ignored,
    /// The full message has been reassembled and its CRC verified.
    Complete {
        ur_type: String,
        message: Vec<u8>,
    },
    Error(&'static str),
}

#[derive(Default)]
pub struct UrDecoder {
    ur_type: Option<String>,
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl UrDecoder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn in_progress(&self) -> bool {
        self.received > 0
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.received, self.seq_len)
    }

    pub fn receive(&mut self, text: &str) -> UrEvent {
        match self.receive_inner(text) {
            Ok(ev) => ev,
            Err(e) => UrEvent::Error(e),
        }
    }

    fn receive_inner(&mut self, text: &str) -> Result<UrEvent, &'static str> {
        let lower = text.trim().to_ascii_lowercase();
        let rest = lower.strip_prefix("ur:").ok_or("not a UR code")?;
        let segments: Vec<&str> = rest.split('/').collect();
        let (ur_type, seq, body) = match segments.as_slice() {
            [t, b] => (*t, None, *b),
            [t, s, b] => (*t, Some(*s), *b),
            _ => return Err("malformed UR"),
        };
        match &self.ur_type {
            Some(t) if t != ur_type => return Err("mismatched UR type"),
            Some(_) => {}
            None => self.ur_type = Some(ur_type.to_string()),
        }

        let payload = bytewords_decode(body)?;
        let Some(seq) = seq else {
            // single-part UR: payload is the message itself
            if self.in_progress() {
                return Err("expected another part");
            }
            return Ok(UrEvent::Complete { ur_type: ur_type.to_string(), message: payload });
        };
        // sanity-check the "K-N" sequence label, but trust the CBOR header contents
        if !seq.split_once('-').is_some_and(|(k, n)| k.parse::<usize>().is_ok() && n.parse::<usize>().is_ok())
        {
            return Err("malformed sequence");
        }

        let part = parse_part(&payload)?;
        if part.seq_len == 0
            || part.seq_len > MAX_SEQ_LEN
            || part.message_len == 0
            || part.message_len > MAX_MESSAGE_LEN
            || part.message_len > part.seq_len * part.data.len()
        {
            return Err("implausible part header");
        }
        if self.seq_len == 0 {
            self.seq_len = part.seq_len;
            self.message_len = part.message_len;
            self.checksum = part.checksum;
            self.fragments = vec![None; part.seq_len];
        } else if part.seq_len != self.seq_len
            || part.message_len != self.message_len
            || part.checksum != self.checksum
        {
            return Err("part from a different message");
        }

        if part.seq_num == 0 || part.seq_num > self.seq_len {
            // mixed fountain part (or nonsense); the bridge tool only sends pure parts
            return Ok(UrEvent::Ignored);
        }
        let slot = &mut self.fragments[part.seq_num - 1];
        if slot.is_some() {
            return Ok(UrEvent::Duplicate {
                part: part.seq_num,
                received: self.received,
                total: self.seq_len,
            });
        }
        *slot = Some(part.data);
        self.received += 1;

        if self.received < self.seq_len {
            return Ok(UrEvent::Part { received: self.received, total: self.seq_len });
        }
        // all pure parts present: reassemble and verify
        let mut message = Vec::with_capacity(self.seq_len * self.fragments[0].as_ref().unwrap().len());
        for fragment in self.fragments.iter() {
            message.extend_from_slice(fragment.as_ref().unwrap());
        }
        message.truncate(self.message_len);
        if crc32(&message) != self.checksum {
            return Err("message checksum mismatch");
        }
        Ok(UrEvent::Complete { ur_type: self.ur_type.clone().unwrap(), message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // vectors from tools/test-vectors.json (generated by tools/gen_vectors.py,
    // whose UR layer is validated against the bc-ur reference test suite)
    const SINGLE: &str = "UR:ETH-SIGN-REQUEST/OSADTPDAGDFWFWFWFWFWFWFWFWFWFWFWFWFWFWFWFWAOGRFDIHJZJZJLDWCXFWJLIDCLAXAXAAADAHTAADDYOYADLECSDWYKCSFNYKAEYKAEWKAEWKAMGHMKHDWSZCCNDNFZEOVEKIMHAEFSFPWPEEWPPLTNMWATJTFEKSHSJNJOJZIHCXHGHSJZJZIHJYHDRPGOOE";
    const PARTS: [&str; 3] = [
        "UR:ETH-SIGN-REQUEST/1-3/LPADAXCSHECYHDRPGOOEHDCXOSADTPDAGDFWFWFWFWFWFWFWFWFWFWFWFWFWFWFWFWAOGRFDIHJZJZJLDWCXFWJLRPCAMODS",
        "UR:ETH-SIGN-REQUEST/2-3/LPAOAXCSHECYHDRPGOOEHDCXIDCLAXAXAAADAHTAADDYOYADLECSDWYKCSFNYKAEYKAEWKAEWKAMGHMKHDWSZCCNRNBTZOSK",
        "UR:ETH-SIGN-REQUEST/3-3/LPAXAXCSHECYHDRPGOOEHDCXDNFZEOVEKIMHAEFSFPWPEEWPPLTNMWATJTFEKSHSJNJOJZIHCXHGHSJZJZIHJYAEWTDWZCON",
    ];
    const EXPECTED_PREFIX: [u8; 8] = [0xa7, 0x01, 0xd8, 0x25, 0x50, 0x42, 0x42, 0x42];
    const EXPECTED_LEN: usize = 95;

    #[test]
    fn crc32_reference() {
        assert_eq!(crc32(b"Wolf"), 0x598c84dc);
        assert_eq!(crc32(b"Hello, world!"), 0xebe6c6e6);
    }

    #[test]
    fn bytewords_reference() {
        assert_eq!(bytewords_decode("aeadaolazmjendeoti").unwrap(), vec![0, 1, 2, 128, 255]);
        assert!(bytewords_decode("aeadaolazojendeowf").is_err()); // bad checksum
    }

    #[test]
    fn single_part() {
        let mut d = UrDecoder::new();
        match d.receive(SINGLE) {
            UrEvent::Complete { ur_type, message } => {
                assert_eq!(ur_type, "eth-sign-request");
                assert_eq!(message.len(), EXPECTED_LEN);
                assert_eq!(&message[..8], &EXPECTED_PREFIX);
            }
            _ => panic!("expected completion"),
        }
    }

    #[test]
    fn multi_part_out_of_order_with_duplicates() {
        let mut d = UrDecoder::new();
        assert!(matches!(d.receive(PARTS[1]), UrEvent::Part { received: 1, total: 3 }));
        assert!(matches!(d.receive(PARTS[1]), UrEvent::Duplicate { part: 2, received: 1, total: 3 }));
        assert!(matches!(d.receive(PARTS[0]), UrEvent::Part { received: 2, total: 3 }));
        match d.receive(PARTS[2]) {
            UrEvent::Complete { ur_type, message } => {
                assert_eq!(ur_type, "eth-sign-request");
                assert_eq!(message.len(), EXPECTED_LEN);
                assert_eq!(&message[..8], &EXPECTED_PREFIX);
            }
            _ => panic!("expected completion"),
        }
    }

    #[test]
    fn rejects_foreign_and_corrupt() {
        let mut d = UrDecoder::new();
        assert!(matches!(d.receive("otpauth://x"), UrEvent::Error(_)));
        assert!(matches!(d.receive(PARTS[0]), UrEvent::Part { .. }));
        // a part of a different UR type must be rejected once locked in
        assert!(matches!(d.receive(SINGLE.replace("ETH-SIGN-REQUEST", "BYTES").as_str()), UrEvent::Error(_)));
        // corrupt bytewords
        let corrupt = format!("{}AA", &PARTS[1][..PARTS[1].len() - 2]);
        assert!(matches!(d.receive(&corrupt), UrEvent::Error(_)));
    }
}
