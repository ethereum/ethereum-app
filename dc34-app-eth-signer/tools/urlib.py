"""Minimal BC-UR (Uniform Resources) implementation for generating test vectors.

Implements bytewords (minimal style), CRC32 framing, Xoshiro256** PRNG, the
alias-method random sampler, and the fountain-code part chooser exactly as the
BlockchainCommons bc-ur reference implementation, so that multi-part URs
generated here are bit-identical with what standard wallets produce.

Run this file directly to execute the self-tests against vectors extracted
from bc-ur's test suite.
"""

import hashlib
import zlib

BYTEWORDS = (
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzz"
    "calmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordown"
    "drawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflap"
    "flewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhang"
    "hardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoin"
    "joltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegs"
    "liarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknail"
    "navyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose"
    "puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilk"
    "skewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinugly"
    "undouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhen"
    "whizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom"
)
WORDS = [BYTEWORDS[i * 4:i * 4 + 4] for i in range(256)]
MINIMAL = [w[0] + w[3] for w in WORDS]
MINIMAL_MAP = {m: i for i, m in enumerate(MINIMAL)}

MASK64 = (1 << 64) - 1


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def bytewords_encode_minimal(payload: bytes) -> str:
    data = payload + crc32(payload).to_bytes(4, "big")
    return "".join(MINIMAL[b] for b in data)


def bytewords_decode_minimal(s: str) -> bytes:
    if len(s) % 2 != 0 or len(s) < 10:
        raise ValueError("invalid bytewords length")
    data = bytes(MINIMAL_MAP[s[i:i + 2]] for i in range(0, len(s), 2))
    body, checksum = data[:-4], data[-4:]
    if crc32(body).to_bytes(4, "big") != checksum:
        raise ValueError("bytewords checksum mismatch")
    return body


class Xoshiro256:
    """xoshiro256** seeded with SHA-256 of the seed material (bc-ur convention)."""

    def __init__(self, seed: bytes):
        digest = hashlib.sha256(seed).digest()
        self.s = [int.from_bytes(digest[i * 8:i * 8 + 8], "big") for i in range(4)]

    @staticmethod
    def _rotl(x, k):
        return ((x << k) | (x >> (64 - k))) & MASK64

    def next(self) -> int:
        s = self.s
        result = (self._rotl((s[1] * 5) & MASK64, 7) * 9) & MASK64
        t = (s[1] << 17) & MASK64
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = self._rotl(s[3], 45)
        return result

    def next_double(self) -> float:
        return self.next() / float(1 << 64)

    def next_int(self, low: int, high: int) -> int:
        return int(self.next_double() * (high - low + 1)) + low

    def next_byte(self) -> int:
        return self.next_int(0, 255)

    def next_data(self, count: int) -> bytes:
        return bytes(self.next_byte() for _ in range(count))


class RandomSampler:
    """Walker/Vose alias method, replicating bc-ur's reversed index order."""

    def __init__(self, probs):
        n = len(probs)
        total = float(sum(probs))
        P = [p * n / total for p in probs]
        S, L = [], []
        for i in range(n - 1, -1, -1):
            (S if P[i] < 1 else L).append(i)
        probs_out = [0.0] * n
        aliases = [0] * n
        while S and L:
            a = S.pop()
            g = L.pop()
            probs_out[a] = P[a]
            aliases[a] = g
            P[g] += P[a] - 1
            (S if P[g] < 1 else L).append(g)
        while L:
            probs_out[L.pop()] = 1
        while S:
            probs_out[S.pop()] = 1
        self.probs = probs_out
        self.aliases = aliases

    def next(self, rng_double) -> int:
        r1 = rng_double()
        r2 = rng_double()
        i = int(len(self.probs) * r1)
        return i if r2 < self.probs[i] else self.aliases[i]


def shuffled(items, rng: Xoshiro256):
    remaining = list(items)
    result = []
    while remaining:
        index = rng.next_int(0, len(remaining) - 1)
        result.append(remaining.pop(index))
    return result


def choose_degree(seq_len: int, rng: Xoshiro256) -> int:
    sampler = RandomSampler([1.0 / i for i in range(1, seq_len + 1)])
    return sampler.next(rng.next_double) + 1


def choose_fragments(seq_num: int, seq_len: int, checksum: int):
    """Set of fragment indexes mixed into part seq_num (1-based)."""
    if seq_num <= seq_len:
        return {seq_num - 1}
    seed = seq_num.to_bytes(4, "big") + checksum.to_bytes(4, "big")
    rng = Xoshiro256(seed)
    degree = choose_degree(seq_len, rng)
    return set(shuffled(range(seq_len), rng)[:degree])


# --- minimal CBOR helpers (just what UR framing needs) ---

def cbor_uint(n: int) -> bytes:
    if n < 24:
        return bytes([n])
    for size, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < (1 << (8 * size)):
            return bytes([marker]) + n.to_bytes(size, "big")
    raise ValueError("uint too large")


def cbor_bytes(b: bytes) -> bytes:
    header = cbor_uint(len(b))
    return bytes([0x40 | header[0]]) + header[1:] + b


def find_nominal_fragment_length(message_len, min_len, max_len):
    for fragment_count in range(1, message_len // min_len + 1):
        fragment_len = -(-message_len // fragment_count)  # ceil div
        if fragment_len <= max_len:
            return fragment_len
    raise ValueError("no valid fragment length")


def partition_message(message: bytes, fragment_len: int):
    fragments = []
    for i in range(0, len(message), fragment_len):
        frag = message[i:i + fragment_len]
        fragments.append(frag + b"\0" * (fragment_len - len(frag)))
    return fragments


def fountain_part_cbor(seq_num, seq_len, message_len, checksum, data: bytes) -> bytes:
    return (
        b"\x85"
        + cbor_uint(seq_num)
        + cbor_uint(seq_len)
        + cbor_uint(message_len)
        + b"\x1a" + checksum.to_bytes(4, "big")
        + cbor_bytes(data)
    )


def ur_encode(ur_type: str, message_cbor: bytes, max_fragment_len=None):
    """Return a list of UR part strings. Single element if it fits in one part."""
    if max_fragment_len is None or len(message_cbor) <= max_fragment_len:
        return ["ur:%s/%s" % (ur_type, bytewords_encode_minimal(message_cbor))]
    fragment_len = find_nominal_fragment_length(len(message_cbor), 10, max_fragment_len)
    fragments = partition_message(message_cbor, fragment_len)
    checksum = crc32(message_cbor)
    seq_len = len(fragments)
    parts = []
    for seq_num in range(1, seq_len + 1):  # pure parts only
        part = fountain_part_cbor(seq_num, seq_len, len(message_cbor), checksum, fragments[seq_num - 1])
        parts.append("ur:%s/%d-%d/%s" % (ur_type, seq_num, seq_len, bytewords_encode_minimal(part)))
    return parts


def fountain_part_for(ur_type, message_cbor, fragments, seq_num):
    """Any fountain part (including mixed ones beyond seq_len), for testing."""
    checksum = crc32(message_cbor)
    seq_len = len(fragments)
    indexes = choose_fragments(seq_num, seq_len, checksum)
    mixed = bytearray(len(fragments[0]))
    for i in indexes:
        for j, b in enumerate(fragments[i]):
            mixed[j] ^= b
    part = fountain_part_cbor(seq_num, seq_len, len(message_cbor), checksum, bytes(mixed))
    return "ur:%s/%d-%d/%s" % (ur_type, seq_num, seq_len, bytewords_encode_minimal(part))


# --- self tests against bc-ur reference vectors ---

def self_test():
    assert crc32(b"Hello, world!") == 0xEBE6C6E6
    assert crc32(b"Wolf") == 0x598C84DC

    assert bytewords_encode_minimal(bytes([0, 1, 2, 128, 255])) == "aeadaolazmjendeoti"
    assert bytewords_decode_minimal("aeadaolazmjendeoti") == bytes([0, 1, 2, 128, 255])

    rng = Xoshiro256(b"Wolf")
    numbers = [rng.next() % 100 for _ in range(100)]
    assert numbers[:12] == [42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74], numbers[:12]

    rng = Xoshiro256(b"Wolf")
    sampler = RandomSampler([1, 2, 4, 8])
    samples = [sampler.next(rng.next_double) for _ in range(500)]
    assert samples[:16] == [3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2], samples[:16]

    rng = Xoshiro256(b"Wolf")
    shuffles = [shuffled(list(range(1, 11)), rng) for _ in range(3)]
    assert shuffles[0] == [6, 4, 9, 3, 10, 5, 7, 8, 1, 2], shuffles[0]
    assert shuffles[1] == [10, 8, 6, 5, 1, 2, 3, 9, 7, 4]

    # choose_fragments over make_message(1024) per reference
    message = Xoshiro256(b"Wolf").next_data(1024)
    checksum = crc32(message)
    fragment_len = find_nominal_fragment_length(len(message), 10, 100)
    fragments = partition_message(message, fragment_len)
    expected = [
        {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {9},
        {2, 5, 6, 8, 9, 10}, {8}, {1, 5}, {1}, {0, 2, 4, 5, 8, 10}, {5}, {2}, {2},
    ]
    for seq_num in range(1, 21):
        assert choose_fragments(seq_num, len(fragments), checksum) == expected[seq_num - 1], seq_num

    # single-part UR of make_message_ur(50)
    msg50 = Xoshiro256(b"Wolf").next_data(50)
    parts = ur_encode("bytes", cbor_bytes(msg50))
    assert parts == [
        "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch"
    ], parts

    # multi-part UR of make_message_ur(256), max fragment 30, parts 1..15 incl. mixed
    msg256 = Xoshiro256(b"Wolf").next_data(256)
    message_cbor = cbor_bytes(msg256)
    fragment_len = find_nominal_fragment_length(len(message_cbor), 10, 30)
    fragments = partition_message(message_cbor, fragment_len)
    expected_parts = [
        "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
        "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
        "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
        "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
        "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
        "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
        "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
        "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
        "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
        "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
        "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
        "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
        "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
        "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
        "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
    ]
    for seq_num in range(1, 16):
        got = fountain_part_for("bytes", message_cbor, fragments, seq_num)
        assert got == expected_parts[seq_num - 1], (seq_num, got)

    print("urlib self-test: all reference vectors PASS")


if __name__ == "__main__":
    self_test()
