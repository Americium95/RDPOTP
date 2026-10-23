"""FastPath input parser and output helpers (MS-RDPBCGR).  Pure stdlib.

Reverse-engineered against the FreeRDP sources in this directory and then
validated byte-for-byte on a live mstsc capture (341 bytes, 6 PDUs,
63 events, zero bytes left over).

Wire format
-----------
A FastPath input PDU is *not* TPKT framed:

    byte 0   action:2 | numEvents:4 | secFlags:2
    byte 1   length (high bit clear)  -> 1-byte length, PDU is `length` long
    byte 1.. length (high bit set)    -> 2-byte big-endian length, 3-byte header
    payload  numEvents FastPath input events, packed back to back

`length` counts the action byte and the length bytes themselves, so the next
PDU starts at offset `length`.  action == 3 means the PDU is really a
slow-path TPKT (first byte 0x03) and belongs to the TPKT framer, not here.

FastPath input event header:

    eventFlags:5 | eventCode:3     ->  code = hdr >> 5,  flags = hdr & 0x1F

Event codes and their payload sizes (header byte included):

    0 SCANCODE   keyCode:1                                   ->  2
    1 MOUSE      pointerFlags:2  xPos:2  yPos:2              ->  7
    2 MOUSEX     pointerFlags:2  xPos:2  yPos:2              ->  7
    3 SYNC       (no payload; toggle flags ride in eventFlags) ->  1
    4 UNICODE    unicodeCode:2                               ->  3
    5 MOUSEREL   pointerFlags:2  xDelta:2  yDelta:2          ->  7
    6 QOE        timestamp:4                                 ->  5

All multi-byte fields are little-endian.

Sources: fr_fastpath.c:684-975 (event parsers and the numEvents loop),
lib_fastpath.h:46-94 (action / eventCode enums), xrdp_rdp.c:1262-1333.
"""

import struct

# --- event codes -----------------------------------------------------------
CODE_SCANCODE = 0
CODE_MOUSE = 1
CODE_MOUSEX = 2
CODE_SYNC = 3
CODE_UNICODE = 4
CODE_MOUSEREL = 5
CODE_QOE = 6

# TS_SURFCMD_SET_SURFACE_BITS, MS-RDPBCGR 2.2.9.2.1.
SURFCMD_SET_SURFACE_BITS = 0x0001


def build_surface_bits_updates(left, top, width, height, bpp, codec_id, data,
                               max_packet=16000):
    """Build Fast-Path Surface Bits output PDUs, fragmenting large updates."""
    if not (0 <= left <= 0xFFFF and 0 <= top <= 0xFFFF):
        raise ValueError("surface origin out of range")
    if not (1 <= width <= 0xFFFF and 1 <= height <= 0xFFFF):
        raise ValueError("surface dimensions out of range")
    if not (1 <= max_packet <= 16380):
        raise ValueError("max_packet out of range")
    command = (struct.pack("<HHHHH", SURFCMD_SET_SURFACE_BITS,
                           left, top, left + width, top + height) +
               struct.pack("<BBBBHHI", bpp, 0, 0, codec_id, width, height,
                           len(data)) + data)
    chunks = [command[i:i + max_packet]
              for i in range(0, len(command), max_packet)]
    packets = []
    for index, chunk in enumerate(chunks):
        fragment = 0 if len(chunks) == 1 else (2 if index == 0 else
                    1 if index == len(chunks) - 1 else 3)
        update = bytes((0x04 | (fragment << 4),)) + struct.pack("<H", len(chunk)) + chunk
        total = 1 + (1 if 1 + len(update) <= 127 else 2) + len(update)
        if total <= 127:
            length = bytes((total,))
        elif total <= 16383:
            length = bytes((0x80 | (total >> 8), total & 0xFF))
        else:
            raise ValueError("fast-path packet exceeds protocol limit")
        packets.append(b"\x00" + length + update)
    return packets


def build_surface_bits_batch(updates, max_packet=4096):
    """Pack complete Surface Bits updates into progressive Fast-Path PDUs.

    A tile remains an independent, complete RDP update, but multiple tile
    updates share one Fast-Path network packet. Oversized single tiles are
    emitted alone (fragmented only when required by the protocol limit).
    """
    if not (1 <= max_packet <= 16000):
        raise ValueError("max_packet out of range")

    def encode_packet(update_stream):
        total = 1 + (1 if 1 + len(update_stream) <= 127 else 2) + len(update_stream)
        if total <= 127:
            length = bytes((total,))
        elif total <= 16383:
            length = bytes((0x80 | (total >> 8), total & 0xFF))
        else:
            raise ValueError("fast-path packet exceeds protocol limit")
        return b"\x00" + length + update_stream

    packets = []
    stream = bytearray()
    for item in updates:
        command = (struct.pack("<HHHHH", SURFCMD_SET_SURFACE_BITS,
                               item["left"], item["top"],
                               item["left"] + item["width"],
                               item["top"] + item["height"]) +
                   struct.pack("<BBBBHHI", item["bpp"], 0, 0,
                               item["codec_id"], item["width"],
                               item["height"], len(item["data"])) + item["data"])
        update = bytes((0x04,)) + struct.pack("<H", len(command)) + command
        if stream and len(stream) + len(update) > max_packet:
            packets.append(encode_packet(bytes(stream)))
            stream.clear()
        if len(update) > max_packet:
            if stream:
                packets.append(encode_packet(bytes(stream)))
                stream.clear()
            packets.extend(build_surface_bits_updates(
                item["left"], item["top"], item["width"], item["height"],
                item["bpp"], item["codec_id"], item["data"],
                max_packet=max_packet))
            continue
        stream.extend(update)
    if stream:
        packets.append(encode_packet(bytes(stream)))
    return packets

CODE_NAME = {
    CODE_SCANCODE: "SCANCODE",
    CODE_MOUSE: "MOUSE",
    CODE_MOUSEX: "MOUSEX",
    CODE_SYNC: "SYNC",
    CODE_UNICODE: "UNICODE",
    CODE_MOUSEREL: "MOUSEREL",
    CODE_QOE: "QOE",
}

# header byte + payload
_EVENT_SIZE = {
    CODE_SCANCODE: 2,
    CODE_MOUSE: 7,
    CODE_MOUSEX: 7,
    CODE_SYNC: 1,
    CODE_UNICODE: 3,
    CODE_MOUSEREL: 7,
    CODE_QOE: 5,
}

# --- fast-path keyboard eventFlags (2.2.8.1.2.2.1) --------------------------
KBD_RELEASE = 0x01
KBD_EXTENDED = 0x02
KBD_EXTENDED1 = 0x04
KBD_UNICODE = 0x10

# --- fast-path sync eventFlags (2.2.8.1.2.2.5) ------------------------------
SYNC_SCROLL_LOCK = 0x01
SYNC_NUM_LOCK = 0x02
SYNC_CAPS_LOCK = 0x04
SYNC_KANA_LOCK = 0x08

# --- TS_POINTER_EVENT pointerFlags ------------------------------------------
PTR_WHEEL_NEGATIVE = 0x0100
PTR_WHEEL_ROTATION_MASK = 0x01FF
PTR_VERTICAL_WHEEL = 0x0200
PTR_HORIZONTAL_WHEEL = 0x0400
PTR_MOVE = 0x0800
PTR_DOWN = 0x8000
PTR_BUTTON1 = 0x1000          # left
PTR_BUTTON2 = 0x2000          # right
PTR_BUTTON3 = 0x4000          # middle / wheel click
PTRX_BUTTON1 = 0x0001         # extended: button 4
PTRX_BUTTON2 = 0x0002         # extended: button 5

BUTTON_NAME = {
    PTR_BUTTON1: "left",
    PTR_BUTTON2: "right",
    PTR_BUTTON3: "middle",
}

# Set-1 (XT) scan codes, for readable logs only.
SCAN_NAME = {
    0x01: "Esc", 0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5",
    0x07: "6", 0x08: "7", 0x09: "8", 0x0A: "9", 0x0B: "0", 0x0C: "-",
    0x0D: "=", 0x0E: "Backspace", 0x0F: "Tab", 0x10: "Q", 0x11: "W",
    0x12: "E", 0x13: "R", 0x14: "T", 0x15: "Y", 0x16: "U", 0x17: "I",
    0x18: "O", 0x19: "P", 0x1A: "[", 0x1B: "]", 0x1C: "Enter",
    0x1D: "Ctrl", 0x1E: "A", 0x1F: "S", 0x20: "D", 0x21: "F", 0x22: "G",
    0x23: "H", 0x24: "J", 0x25: "K", 0x26: "L", 0x27: ";", 0x28: "'",
    0x29: "`", 0x2A: "Shift", 0x2B: "\\", 0x2C: "Z", 0x2D: "X", 0x2E: "C",
    0x2F: "V", 0x30: "B", 0x31: "N", 0x32: "M", 0x33: ",", 0x34: ".",
    0x35: "/", 0x36: "RShift", 0x37: "Num*", 0x38: "Alt", 0x39: "Space",
    0x3A: "CapsLock", 0x3B: "F1", 0x3C: "F2", 0x3D: "F3", 0x3E: "F4",
    0x3F: "F5", 0x40: "F6", 0x41: "F7", 0x42: "F8", 0x43: "F9",
    0x44: "F10", 0x45: "NumLock", 0x46: "ScrollLock", 0x47: "Home",
    0x48: "Up", 0x49: "PgUp", 0x4A: "Num-", 0x4B: "Left", 0x4C: "Center",
    0x4D: "Right", 0x4E: "Num+", 0x4F: "End", 0x50: "Down", 0x51: "PgDn",
    0x52: "Insert", 0x53: "Delete", 0x57: "F11", 0x58: "F12",
    0x72: "Hangul", 0xF2: "Hangul",
}


def scan_name(scancode, flags=0):
    """Human readable name for a set-1 scancode."""
    name = SCAN_NAME.get(scancode)
    if name is None:
        name = "0x%02X" % scancode
    if flags & KBD_EXTENDED and scancode in (0x1D, 0x38):
        name = "R" + name
    elif flags & KBD_EXTENDED and scancode in (0x47, 0x48, 0x49, 0x4B, 0x4D,
                                               0x4F, 0x50, 0x51, 0x52, 0x53):
        name = name  # keypad keys already named
    return name


class MalformedInput(Exception):
    """The stream did not look like a FastPath input PDU."""


def parse_pdu(buf, offset=0):
    """Parse one FastPath input PDU starting at buf[offset].

    Returns (events, total_length).  total_length is the number of bytes the
    PDU occupies in the stream, so the next PDU starts at offset+total_length.
    Raises MalformedInput when the header is unusable.
    """
    end = len(buf)
    if end - offset < 2:
        raise MalformedInput("short header")

    b0 = buf[offset]
    action = b0 & 0x03
    num_events = (b0 >> 2) & 0x0F
    sec_flags = (b0 >> 6) & 0x03

    if action == 3:
        # Not a FastPath input PDU -- a slow-path TPKT slipped in here.
        raise MalformedInput("slow-path TPKT (action=3) is not FastPath")

    b1 = buf[offset + 1]
    if b1 & 0x80:
        if end - offset < 3:
            raise MalformedInput("short 2-byte length")
        length = ((b1 & 0x7F) << 8) | buf[offset + 2]
        header_len = 3
    else:
        length = b1
        header_len = 2

    if length < header_len:
        raise MalformedInput("length %d shorter than header %d" % (length, header_len))
    if end - offset < length:
        raise MalformedInput("truncated: need %d have %d" % (length, end - offset))

    pos = offset + header_len
    stop = offset + length
    events = []

    # numEvents == 0 means "the count is in the next byte" (MS-RDPBCGR
    # 2.2.8.1.2; see the optional-numEvents path in xrdp_sec.c:1462-1472 and
    # fr_fastpath.c:957-961).
    if num_events == 0:
        if pos >= stop:
            raise MalformedInput("numEvents==0 but no count byte")
        num_events = buf[pos]
        pos += 1

    for _ in range(num_events):
        if pos >= stop:
            raise MalformedInput("truncated event header")
        hdr = buf[pos]
        code = hdr >> 5
        flags = hdr & 0x1F
        size = _EVENT_SIZE.get(code)
        if size is None:
            raise MalformedInput("unknown event code %d at %d" % (code, pos))
        if pos + size > stop:
            raise MalformedInput("event %s needs %d bytes, %d left"
                                 % (CODE_NAME.get(code, code), size, stop - pos))
        payload = bytes(buf[pos + 1:pos + size])
        events.append(_decode(code, flags, payload))
        pos += size

    return events, length


def _decode(code, flags, payload):
    """Turn one raw event into a dict."""
    ev = {"code": code, "type": CODE_NAME.get(code, str(code)), "flags": flags}

    if code == CODE_SCANCODE:
        sc = payload[0] if payload else 0
        ev.update(scancode=sc, name=scan_name(sc, flags),
                  released=bool(flags & KBD_RELEASE),
                  extended=bool(flags & KBD_EXTENDED),
                  extended1=bool(flags & KBD_EXTENDED1))

    elif code in (CODE_MOUSE, CODE_MOUSEX):
        pf = payload[0] | (payload[1] << 8)
        x = payload[2] | (payload[3] << 8)
        y = payload[4] | (payload[5] << 8)
        button = 0
        for bit, nm in BUTTON_NAME.items():
            if pf & bit:
                button = bit
                break
        wheel = 0
        if pf & PTR_VERTICAL_WHEEL or pf & PTR_HORIZONTAL_WHEEL:
            wheel = pf & PTR_WHEEL_ROTATION_MASK
            if wheel & PTR_WHEEL_NEGATIVE:
                wheel -= 0x200
        ev.update(x=x, y=y, pointer_flags=pf, button=button,
                  button_name=BUTTON_NAME.get(button, ""),
                  down=bool(pf & PTR_DOWN), moved=bool(pf & PTR_MOVE),
                  wheel=wheel,
                  horizontal=bool(pf & PTR_HORIZONTAL_WHEEL))

    elif code == CODE_SYNC:
        ev.update(caps_lock=bool(flags & SYNC_CAPS_LOCK),
                  num_lock=bool(flags & SYNC_NUM_LOCK),
                  scroll_lock=bool(flags & SYNC_SCROLL_LOCK),
                  kana_lock=bool(flags & SYNC_KANA_LOCK))

    elif code == CODE_UNICODE:
        u = payload[0] | (payload[1] << 8) if len(payload) >= 2 else 0
        ev.update(unicode=chr(u) if u else "", code_point=u,
                  released=bool(flags & KBD_RELEASE))

    elif code == CODE_MOUSEREL:
        pf = payload[0] | (payload[1] << 8)
        dx = payload[2] | (payload[3] << 8)
        dy = payload[4] | (payload[5] << 8)
        ev.update(dx=dx, dy=dy, pointer_flags=pf, down=bool(pf & PTR_DOWN))

    elif code == CODE_QOE:
        ts = int.from_bytes(payload, "little")
        ev.update(timestamp=ts)

    return ev


def parse_stream(buf):
    """Parse every complete FastPath PDU in buf.

    Returns (events, consumed).  Consumed bytes must be dropped by the caller;
    any remainder is a PDU split across TCP segments and stays buffered.
    """
    events = []
    pos = 0
    while pos < len(buf):
        try:
            evs, length = parse_pdu(buf, pos)
        except MalformedInput:
            break
        events.extend(evs)
        pos += length
    return events, pos


# --- slow-path (TPKT-framed) client PDU parsing ------------------------------
# mstsc also sends whole TPKT frames mid-session (e.g. periodic data PDUs,
# possibly TS_INPUT_PDU).  These used to be fed to the FastPath parser, which
# poisoned inbuf and permanently killed all input.  A frame looks like:
#
#   03 00 <len u16be> | 02 f0 80 | <MCS 6B> | <BER len> | userData
#   MCS = opcode(0x64/0x68) initiator(2) channelId(2) seg=0x70
#   userData = ShareControlHeader(6) + ShareDataHeader(12) + body
#
# pduType2 sits at userData[14]; 0x1C is TS_INPUT_PDU (SPEC.md 12).
PDUTYPE2_INPUT = 0x1C

INPUT_SYNC = 0x0000
INPUT_SCANCODE = 0x0004
INPUT_UNICODE = 0x0005
INPUT_MOUSE = 0x8000
INPUT_MOUSEX = 0x8001

# KBDFLAGS (slow-path) -> fast-path eventFlags
_KBD_RELEASE_S = 0x8000
_KBD_EXTENDED_S = 0x0100
_KBD_EXTENDED1_S = 0x0200

MAX_TPKT = 16384


def parse_slowpath(buf, offset=0):
    """Parse one TPKT-framed slow-path client PDU.

    Returns (status, events, consumed):
      "incomplete" -> need more bytes (consumed = total frame size expected)
      "invalid"    -> garbage; drop `consumed` bytes to resynchronise
      "ok"         -> frame consumed; events parsed (may be empty)

    Never raises: the caller must always be able to advance the buffer.
    """
    have = len(buf) - offset
    if have < 4:
        return "incomplete", [], 4
    if buf[offset] != 3:
        return "invalid", [], 1
    if buf[offset + 1] != 0:
        # FastPath action==3 is reserved and never sent by mstsc; treat the
        # stray 0x03 as one garbage byte rather than waiting forever.
        return "invalid", [], 1
    tpkt_len = (buf[offset + 2] << 8) | buf[offset + 3]
    if tpkt_len < 14 or tpkt_len > MAX_TPKT:
        return "invalid", [], 4
    if have < tpkt_len:
        return "incomplete", [], tpkt_len
    frame = bytes(buf[offset:offset + tpkt_len])
    if frame[4:7] != b"\x02\xf0\x80" or frame[7] not in (0x64, 0x68):
        return "invalid", [], tpkt_len
    # MCS: opcode(1) initiator(2) channelId(2) seg(1) then a BER length
    b = frame[13]
    if b & 0x80 == 0:
        pos = 14
    elif b == 0x81:
        pos = 15
    elif b == 0x82:
        pos = 16
    else:
        return "invalid", [], tpkt_len
    user = frame[pos:]
    if len(user) < 18:
        return "invalid", [], tpkt_len
    pdu_type2 = user[14]
    if pdu_type2 != PDUTYPE2_INPUT:
        return "ok", [], tpkt_len
    total = user[0] | (user[1] << 8)
    end = total if 18 <= total <= len(user) else len(user)
    payload = user[18:end]
    if len(payload) < 4:
        return "ok", [], tpkt_len
    n_events = payload[0] | (payload[1] << 8)
    p = 4
    events = []
    for _ in range(n_events):
        if p + 6 > len(payload):
            break
        mtype = payload[p + 4] | (payload[p + 5] << 8)
        p += 6
        if mtype == INPUT_SYNC:
            if p + 2 > len(payload):
                break
            flags = payload[p] | (payload[p + 1] << 8)
            p += 2
            events.append(_decode(CODE_SYNC, flags & 0x0F, b""))
        elif mtype == INPUT_SCANCODE:
            if p + 4 > len(payload):
                break
            kf = payload[p] | (payload[p + 1] << 8)
            code = payload[p + 2] | (payload[p + 3] << 8)
            p += 4
            fpf = ((0x01 if kf & _KBD_RELEASE_S else 0) |
                   (0x02 if kf & _KBD_EXTENDED_S else 0) |
                   (0x04 if kf & _KBD_EXTENDED1_S else 0))
            events.append(_decode(CODE_SCANCODE, fpf, bytes([code & 0xFF])))
        elif mtype == INPUT_UNICODE:
            if p + 4 > len(payload):
                break
            kf = payload[p] | (payload[p + 1] << 8)
            u = payload[p + 2] | (payload[p + 3] << 8)
            p += 4
            fpf = 0x01 if kf & _KBD_RELEASE_S else 0
            events.append(_decode(CODE_UNICODE, fpf,
                                  bytes([u & 0xFF, u >> 8])))
        elif mtype in (INPUT_MOUSE, INPUT_MOUSEX):
            need = 6 if mtype == INPUT_MOUSE else 8
            if p + need > len(payload):
                break
            data = bytes(payload[p:p + 6])
            p += need
            code = CODE_MOUSE if mtype == INPUT_MOUSE else CODE_MOUSEX
            events.append(_decode(code, 0, data))
        else:
            # Unknown event type: its length is unknowable, so stop here
            # but keep the events parsed so far (frame is still consumed).
            break
    return "ok", events, tpkt_len


class InputState:
    """Tracks the client's pointer / buttons / keys and fires callbacks.

    The server keeps one of these per connection so that "input" is not just
    bytes thrown away: mouse position, held buttons, lock keys and the set of
    currently-down scancodes are all observable, and callers can register
    hooks to act on them.
    """

    def __init__(self):
        self.x = 0
        self.y = 0
        self.buttons = set()        # names: "left"/"right"/"middle"
        self.wheel = 0              # accumulated vertical wheel delta
        self.horizontal_wheel = 0
        self.keys_down = set()      # scancodes currently held
        self.caps_lock = False
        self.num_lock = False
        self.scroll_lock = False
        self.events = 0             # total events seen
        self.last_key = None        # last decoded key event dict
        self.last_mouse = None      # last decoded mouse event dict
        self.dirty = False          # set by hooks when a repaint is wanted
        self.history = []           # recent events, newest last
        self.max_history = 64
        # hooks -- assign callables to react to input
        self.on_key = None          # fn(event_dict)
        self.on_mouse = None        # fn(event_dict)
        self.on_text = None         # fn(char)

    def dispatch(self, events):
        for ev in events:
            self.events += 1
            if len(self.history) >= self.max_history:
                del self.history[:len(self.history) - self.max_history + 1]
            self.history.append(ev)

            code = ev["code"]
            if code == CODE_SCANCODE:
                self._key(ev)
            elif code in (CODE_MOUSE, CODE_MOUSEX):
                self._mouse(ev)
            elif code == CODE_MOUSEREL:
                self.x = max(0, self.x + ev["dx"])
                self.y = max(0, self.y + ev["dy"])
                self.last_mouse = ev
                if self.on_mouse:
                    self.on_mouse(ev)
            elif code == CODE_SYNC:
                self.caps_lock = ev["caps_lock"]
                self.num_lock = ev["num_lock"]
                self.scroll_lock = ev["scroll_lock"]
            elif code == CODE_UNICODE:
                self.last_key = ev
                if not ev["released"] and self.on_text:
                    self.on_text(ev["unicode"])

    def _key(self, ev):
        sc = ev["scancode"]
        if ev["released"]:
            self.keys_down.discard(sc)
        else:
            self.keys_down.add(sc)
        self.last_key = ev
        if self.on_key:
            self.on_key(ev)

    def _mouse(self, ev):
        self.x, self.y = ev["x"], ev["y"]
        name = ev["button_name"]
        if name:
            if ev["down"]:
                self.buttons.add(name)
            else:
                self.buttons.discard(name)
        if ev["wheel"]:
            if ev["horizontal"]:
                self.horizontal_wheel += ev["wheel"]
            else:
                self.wheel += ev["wheel"]
        self.last_mouse = ev
        if self.on_mouse:
            self.on_mouse(ev)

    def describe(self, ev):
        """One-line human readable rendering of an event, for logging."""
        code = ev["code"]
        if code == CODE_SCANCODE:
            return "key %-8s %s%s" % (ev["name"],
                                      "up  " if ev["released"] else "down",
                                      " ext" if ev["extended"] else "")
        if code in (CODE_MOUSE, CODE_MOUSEX):
            parts = ["mouse (%4d,%4d)" % (ev["x"], ev["y"])]
            if ev["moved"]:
                parts.append("move")
            if ev["button_name"]:
                parts.append("%s %s" % (ev["button_name"], "down" if ev["down"] else "up"))
            if ev["wheel"]:
                parts.append("wheel %s%d" % ("+" if ev["wheel"] > 0 else "", ev["wheel"]))
            return " ".join(parts)
        if code == CODE_MOUSEREL:
            return "mouserel (%+d,%+d)" % (ev["dx"], ev["dy"])
        if code == CODE_SYNC:
            locks = [n for n in ("caps_lock", "num_lock", "scroll_lock", "kana_lock")
                     if ev[n]]
            return "sync %s" % (",".join(locks) or "none")
        if code == CODE_UNICODE:
            return "unicode %r%s" % (ev["unicode"], " up" if ev["released"] else " down")
        if code == CODE_QOE:
            return "qoe t=%d" % ev["timestamp"]
        return ev["type"]
