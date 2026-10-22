import struct

from contract import (
    CAPSTYPE_SURFACE_COMMANDS,
    CAPSTYPE_LARGE_POINTER,
    CAPSTYPE_MULTIFRAGMENTUPDATE,
    CAPSTYPE_BITMAPCACHE_HOSTSUPPORT,
    CAPSTYPE_BITMAP,
    CAPSTYPE_GENERAL,
    CAPSTYPE_INPUT,
    CAPSTYPE_ORDER,
    CAPSTYPE_POINTER,
    CTRLACTION_COOPERATE,
    CTRLACTION_GRANTED_CONTROL,
    ERROR_ALERT,
    PDUTYPE_DATAPDU,
    PDUTYPE_DEMANDACTIVEPDU,
    PDUTYPE_DEACTIVATEALLPDU,
    PDUTYPE2_CONTROL,
    PDUTYPE2_FONTMAP,
    PDUTYPE2_INPUT,
    PDUTYPE2_SYNCHRONIZE,
    PDU_SOURCE,
    SHARE_ID_TYPED,
    ST_NO_TRANSITION,
    STATUS_VALID_CLIENT,
    SYNCMSGTYPE_SYNC,
)

PDUTYPE2_LICENSING = 0x01
INPUT_FLAG_SCANCODES = 0x0001
INPUT_FLAG_MOUSEX = 0x0004
INPUT_FLAG_UNICODE = 0x0010
FASTPATH_INPUT_PROBE = 0x0F
EVENTTYPE_SYNC = 0x0000
EVENTTYPE_SCANCODE = 0x0004
EVENTTYPE_UNICODE = 0x0005
EVENTTYPE_MOUSE = 0x8000
EVENTTYPE_MOUSEX = 0x8001


def share_data(pdu_type2: int, body: bytes, stream_id: int = 1, share_id: int = SHARE_ID_TYPED) -> bytes:
    # TS_SHARECONTROLHEADER: pduType MUST carry PDU_VERSION (0x10) in high 12 bits
    pdu_type = TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU
    # TS_SHAREDATAHEADER is exactly 12 bytes
    data_header = (
        struct.pack("<I", share_id)     # shareID
        + struct.pack("<B", 0)         # pad1OctetA
        + struct.pack("<B", stream_id)  # streamID
        + struct.pack("<H", len(body))  # uncompressedLength
        + struct.pack("<B", pdu_type2)  # pduType2
        + struct.pack("<B", 0)          # compressedType
        + struct.pack("<H", 0)          # compressedLength
    )
    assert len(data_header) == 12, len(data_header)
    total = 6 + len(data_header) + len(body)
    header = struct.pack("<HHH", total, pdu_type, PDU_SOURCE)
    return header + data_header + body


def build_synchronize() -> bytes:
    return share_data(
        PDUTYPE2_SYNCHRONIZE, struct.pack("<HH", SYNCMSGTYPE_SYNC, 0)
    )


def build_control_cooperate() -> bytes:
    return share_data(
        PDUTYPE2_CONTROL, struct.pack("<HHI", CTRLACTION_COOPERATE, 0, 0)
    )


def build_control_granted(grant_id: int = 0, control_id: int = 0) -> bytes:
    return share_data(
        PDUTYPE2_CONTROL,
        struct.pack("<HHI", CTRLACTION_GRANTED_CONTROL, grant_id, control_id),
    )


def build_font_map() -> bytes:
    """TS_FONT_MAP_PDU body, byte-identical to xrdp's xrdp_rdp_send_fontmap().

    xrdp emits 8 bytes:
        numberEntries    = 0
        totalNumEntries  = 0
        mapFlags         = 0x0003  (FONTLIST_FIRST | FONTLIST_LAST)
        entrySize        = 0x0004
    An empty map (zero entries) is what mstsc expects; declaring entries
    without emitting their bytes leaves the client parsing past the PDU end.
    """
    body = struct.pack("<HHHH", 0, 0, 0x0003, 0x0004)
    return share_data(PDUTYPE2_FONTMAP, body)


def build_license_error_valid_client() -> bytes:
    sec = struct.pack("<HH", 0x0280, 0x0010)
    preamble = struct.pack("<BBH", ERROR_ALERT, 0x03, 16)
    message = struct.pack("<IIHH", STATUS_VALID_CLIENT, ST_NO_TRANSITION, 4, 0)
    return sec + preamble + message


TS_PROTOCOL_VERSION = 0x0010


def _cap(type_id: int, body: bytes) -> bytes:
    return struct.pack("<HH", type_id, 4 + len(body)) + body


def _cap_general() -> bytes:
    body = (
        struct.pack("<H", 1)            # osMajorType WINDOWS
        + struct.pack("<H", 3)          # osMinorType WINDOWSNT
        + struct.pack("<H", 0x0200)     # protocolVersion (MUST)
        + struct.pack("<H", 0)          # pad2octetsA
        + struct.pack("<H", 0)          # compressionTypes (MUST be 0)
        + struct.pack("<H", 0x0401)     # extraFlags FASTPATH|NO_BITMAP_COMPRESSION_HDR
        + struct.pack("<H", 0)          # updateCapabilityFlag (MUST be 0)
        + struct.pack("<H", 0)          # remoteUnshareFlag (MUST be 0)
        + struct.pack("<H", 0)          # compressionLevel (MUST be 0)
        + struct.pack("<B", 1)          # refreshRectSupport
        + struct.pack("<B", 1)          # suppressOutputSupport
    )
    return _cap(CAPSTYPE_GENERAL, body)


def _cap_bitmap(width: int, height: int, bpp: int = 32) -> bytes:
    body = (
        struct.pack("<H", bpp)          # preferredBitsPerPixel
        + struct.pack("<H", 1)          # receive1BitPerPixel
        + struct.pack("<H", 1)          # receive4BitsPerPixel
        + struct.pack("<H", 1)          # receive8BitsPerPixel
        + struct.pack("<H", width)      # desktopWidth
        + struct.pack("<H", height)     # desktopHeight
        + struct.pack("<H", 0)          # pad2octets
        + struct.pack("<H", 1)          # desktopResizeFlag
        + struct.pack("<H", 1)          # bitmapCompressionFlag (MUST be 1)
        + struct.pack("<B", 0)          # highColorFlags
        + struct.pack("<B", 0)          # drawingFlags
        + struct.pack("<H", 1)          # multipleRectangleSupport (MUST be 1)
        + struct.pack("<H", 0)          # pad2octetsB
    )
    return _cap(CAPSTYPE_BITMAP, body)


def _cap_order() -> bytes:
    body = (
        b"\x00" * 16                    # terminalDescriptor
        + struct.pack("<I", 0)          # pad4octetsA (4 bytes)
        + struct.pack("<H", 1)          # desktopSaveXGranularity
        + struct.pack("<H", 20)         # desktopSaveYGranularity
        + struct.pack("<H", 0)          # pad2octetsA
        + struct.pack("<H", 1)          # maximumOrderLevel
        + struct.pack("<H", 0)          # numberFonts
        + struct.pack("<H", 0x0002)     # orderFlags NEGOTIATEORDERSUPPORT
        + b"\x00" * 32                  # orderSupport
        + struct.pack("<H", 0)          # textFlags
        + struct.pack("<H", 0)          # orderSupportExFlags
        + struct.pack("<I", 0)          # pad4octetsB
        + struct.pack("<I", 230400)     # desktopSaveSize
        + struct.pack("<H", 0)          # pad2octetsC
        + struct.pack("<H", 0)          # pad2octetsD
        + struct.pack("<H", 0)          # textANSICodePage
        + struct.pack("<H", 0)          # pad2octetsE
    )
    return _cap(CAPSTYPE_ORDER, body)


def _cap_pointer() -> bytes:
    return _cap(CAPSTYPE_POINTER, struct.pack("<HHH", 1, 25, 25))


def _cap_input() -> bytes:
    flags = 0x0001 | 0x0004 | 0x0010 | 0x0020
    body = (
        struct.pack("<H", flags)        # inputFlags
        + struct.pack("<H", 0)          # pad2octetsA
        + struct.pack("<I", 0)          # keyboardLayout
        + struct.pack("<I", 0)          # keyboardType
        + struct.pack("<I", 0)          # keyboardSubType
        + struct.pack("<I", 0)          # keyboardFunctionKey
        + b"\x00" * 64                  # imeFileName
    )
    return _cap(CAPSTYPE_INPUT, body)


def build_demand_active(width: int, height: int, bpp: int = 32) -> bytes:
    cap_list = [
        _cap_general(),
        _cap_bitmap(width, height, bpp),
        _cap_order(),
        _cap_pointer(),
        _cap_input(),
    ]
    caps = b"".join(cap_list)
    num_caps = len(cap_list)
    source = b"RDP\x00"
    # lengthCombinedCapabilities = numberCapabilities(2) + pad2Octets(2) + sum(capset lengths)
    lcc = 4 + len(caps)
    body = (
        struct.pack("<IHH", SHARE_ID_TYPED, len(source), lcc)
        + source
        + struct.pack("<HH", num_caps, 0)
        + caps
        + struct.pack("<I", 0)
    )
    # TS_SHARECONTROLHEADER: pduType MUST include PDU_VERSION (0x10) in high 12 bits
    header = struct.pack(
        "<HHH", 6 + len(body), TS_PROTOCOL_VERSION | PDUTYPE_DEMANDACTIVEPDU, PDU_SOURCE
    )
    return header + body


def parse_confirm_active(user_data: bytes) -> dict:
    """Parse a client Confirm Active PDU.

    Layout (offsets from start of userData):
      0  TS_SHARECONTROLHEADER totalLength/pduType/pduSource
      6  shareID (4)
      10 originatorID (2)          <- only in Confirm Active
      12 lengthSourceDescriptor (2)
      14 lengthCombinedCapabilities (2)
      16 sourceDescriptor
      .. numberCapabilities (2), pad2Octets (2), capabilitySets, sessionId(4)
    """
    width = height = bpp = 0
    if len(user_data) < 20:
        return {"desktop_width": width, "desktop_height": height, "bpp": bpp}
    lsd = struct.unpack_from("<H", user_data, 12)[0]
    lcc = struct.unpack_from("<H", user_data, 14)[0]
    offset = 16 + lsd + 4
    end = min(offset + lcc, len(user_data))
    while offset + 4 <= end:
        cap_type, cap_length = struct.unpack_from("<HH", user_data, offset)
        if cap_length < 4:
            break
        # TS_BITMAP_CAPABILITYSET: type(0) len(2) bpp(4) r1(6) r4(8) r8(10) w(12) h(14)
        if cap_type == CAPSTYPE_BITMAP and cap_length >= 16 and offset + 16 <= len(user_data):
            bpp = struct.unpack_from("<H", user_data, offset + 4)[0]
            width = struct.unpack_from("<H", user_data, offset + 12)[0]
            height = struct.unpack_from("<H", user_data, offset + 14)[0]
            break
        offset += cap_length
    return {"desktop_width": width, "desktop_height": height, "bpp": bpp}


def classify_user_data(user_data: bytes) -> dict:
    if not user_data or len(user_data) < 18:
        return {"pdu_type": None, "pdu_type2": None, "body": user_data}
    if (user_data[0] >> 2) == FASTPATH_INPUT_PROBE:
        return {"pdu_type": None, "pdu_type2": None, "body": user_data}
    pdu_type = struct.unpack_from("<H", user_data, 2)[0] & 0x000F
    if pdu_type == PDUTYPE_DATAPDU:
        return {
            "pdu_type": pdu_type,
            "pdu_type2": user_data[14],
            "body": user_data[18:],
        }
    return {"pdu_type": pdu_type, "pdu_type2": None, "body": user_data[6:]}


def parse_input(user_data: bytes) -> list:
    if not user_data or len(user_data) < 22:
        return []
    if (user_data[0] >> 2) == FASTPATH_INPUT_PROBE:
        return []
    pdu_type = struct.unpack_from("<H", user_data, 2)[0] & 0x000F
    if pdu_type != PDUTYPE_DATAPDU or user_data[14] != PDUTYPE2_INPUT:
        return []
    number_events = struct.unpack_from("<H", user_data, 18)[0]
    events = []
    offset = 22
    for _ in range(number_events):
        if offset + 6 > len(user_data):
            break
        message_type = struct.unpack_from("<H", user_data, offset + 4)[0]
        offset += 6
        if message_type == EVENTTYPE_SCANCODE:
            if offset + 4 > len(user_data):
                break
            flags, code = struct.unpack_from("<HH", user_data, offset)
            events.append(
                {"type": "scancode", "flags": flags, "x": None, "y": None, "code": code}
            )
            offset += 4
        elif message_type == EVENTTYPE_UNICODE:
            if offset + 4 > len(user_data):
                break
            flags, code = struct.unpack_from("<HH", user_data, offset)
            events.append(
                {"type": "unicode", "flags": flags, "x": None, "y": None, "code": code}
            )
            offset += 4
        elif message_type == EVENTTYPE_MOUSE:
            if offset + 6 > len(user_data):
                break
            flags, x, y = struct.unpack_from("<HHH", user_data, offset)
            events.append(
                {"type": "mouse", "flags": flags, "x": x, "y": y, "code": None}
            )
            offset += 6
        elif message_type == EVENTTYPE_MOUSEX:
            if offset + 8 > len(user_data):
                break
            flags, x, y = struct.unpack_from("<HHH", user_data, offset)
            events.append(
                {"type": "mousex", "flags": flags, "x": x, "y": y, "code": None}
            )
            offset += 8
        elif message_type == EVENTTYPE_SYNC:
            offset += 2
            events.append(
                {"type": "sync", "flags": 0, "x": None, "y": None, "code": None}
            )
        else:
            break
    return events
