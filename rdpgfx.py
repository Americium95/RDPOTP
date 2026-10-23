"""Isolated helpers for RDPGFX AVC420 framing and encoding.

This module does not negotiate or install the graphics path; callers must only
use it after the client has accepted the RDPGFX capabilities.
"""

from __future__ import annotations

import struct
from fractions import Fraction
from typing import Iterable


DVC_MAX_PDU = 1600
DVC_CMD_DATA_FIRST = 0x02
DVC_CMD_DATA = 0x03
DVC_CMD_CREATE = 0x01
DVC_CMD_CAPABILITIES = 0x05
GFX_CHANNEL_NAME = "Microsoft::Windows::RDS::Graphics"
GFX_CAPS_ADVERTISE = 0x0012
GFX_CAPS_CONFIRM = 0x0013
GFX_CREATE_SURFACE = 0x0009
GFX_RESET_GRAPHICS = 0x000E
GFX_START_FRAME = 0x000B
GFX_END_FRAME = 0x000C
GFX_MAP_SURFACE_TO_OUTPUT = 0x000F
GFX_CAPVERSION_81 = 0x00080105
GFX_CAPVERSION_8 = 0x00080004
GFX_CAPVERSION_10 = 0x000A0002
GFX_CAPVERSION_101 = 0x000A0100
GFX_CAPVERSION_102 = 0x000A0200
GFX_CAPVERSION_103 = 0x000A0301
GFX_CAPVERSION_104 = 0x000A0400
GFX_CAPVERSION_105 = 0x000A0502
GFX_CAPVERSION_106 = 0x000A0600
GFX_CAPVERSION_107 = 0x000A0701
GFX_CAP_AVC420_ENABLED = 0x00000010
GFX_CAP_AVC_DISABLED = 0x00000020
RDPGFX_CMD_WIRE_TO_SURFACE_1 = 0x0001
RDPGFX_CODEC_UNCOMPRESSED = 0x0000
RDPGFX_CODEC_CLEARCODEC = 0x0008
RDPGFX_CODEC_AVC420 = 0x000B
RDPGFX_PIXELFORMAT_XRGB_8888 = 0x20


def _uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def _wire_width(value: int) -> tuple[int, int]:
    """Return the DVC width code and byte width for a nonnegative integer."""
    _uint(value, 32, "DVC value")
    if value <= 0xFF:
        return 0, 1
    if value <= 0xFFFF:
        return 1, 2
    return 2, 4


def _dvc_header(command: int, channel_id: int, *, message_length: int | None = None) -> bytes:
    channel_code, channel_width = _wire_width(channel_id)
    header = bytearray()
    if message_length is None:
        header.append((command << 4) | channel_code)  # Sp is reserved and zero.
    else:
        length_code, length_width = _wire_width(message_length)
        header.append((command << 4) | (length_code << 2) | channel_code)
    header.extend(channel_id.to_bytes(channel_width, "little"))
    if message_length is not None:
        header.extend(message_length.to_bytes(length_width, "little"))
    return bytes(header)


def build_dvc_capabilities_request(version: int = 1) -> bytes:
    """Build the server's uncompressed DRDYNVC capabilities request."""
    _uint(version, 16, "version")
    if version < 1:
        raise ValueError("DRDYNVC version must be positive")
    return bytes(((DVC_CMD_CAPABILITIES << 4), 0)) + struct.pack("<H", version)


def build_dvc_create_request(channel_id: int, name: str = GFX_CHANNEL_NAME) -> bytes:
    """Build a server-initiated DVC channel create request."""
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("DVC channel name must be a nonempty string without NUL")
    try:
        encoded_name = name.encode("ascii") + b"\x00"
    except UnicodeEncodeError as exc:
        raise ValueError("DVC channel names use ANSI/ASCII bytes") from exc
    return _dvc_header(DVC_CMD_CREATE, channel_id) + encoded_name


def parse_dvc_pdu(data: bytes) -> dict:
    """Parse the subset of DRDYNVC PDUs used by the GFX channel."""
    data = bytes(data)
    if not data:
        raise ValueError("empty DVC PDU")
    header = data[0]
    command = header >> 4
    sp = (header >> 2) & 0x03
    channel_code = header & 0x03
    widths = (1, 2, 4)
    if channel_code == 3:
        raise ValueError("invalid DVC ChannelId width")
    offset = 1
    if command == DVC_CMD_CAPABILITIES:
        if len(data) != 4 or data[1] != 0:
            raise ValueError("malformed DVC capabilities PDU")
        return {"command": "capabilities", "version": struct.unpack_from("<H", data, 2)[0]}
    if command == DVC_CMD_CREATE:
        width = widths[channel_code]
        if len(data) < offset + width:
            raise ValueError("truncated DVC create PDU")
        channel_id = int.from_bytes(data[offset:offset + width], "little")
        offset += width
        tail = data[offset:]
        if len(tail) == 4:
            return {"command": "create_response", "priority": sp,
                    "channel_id": channel_id,
                    "status": struct.unpack("<I", tail)[0]}
        if not tail or tail[-1] != 0 or b"\x00" in tail[:-1]:
            raise ValueError("malformed DVC create request name")
        try:
            name = tail[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid DVC channel name") from exc
        return {"command": "create_request", "priority": sp,
                "channel_id": channel_id, "name": name}
    if command in (DVC_CMD_DATA_FIRST, DVC_CMD_DATA):
        length = None
        if command == DVC_CMD_DATA_FIRST:
            length_code = (header >> 2) & 0x03
            if length_code == 3:
                raise ValueError("invalid DVC message Length width")
            offset += widths[channel_code]
            length_width = widths[length_code]
            if len(data) < offset + length_width:
                raise ValueError("truncated DVC data-first PDU")
            # ChannelId precedes Length in the DVC_DATA_FIRST structure.
            channel_id = int.from_bytes(data[1:1 + widths[channel_code]], "little")
            length = int.from_bytes(data[offset:offset + length_width], "little")
            offset += length_width
        else:
            width = widths[channel_code]
            if len(data) < offset + width:
                raise ValueError("truncated DVC data PDU")
            channel_id = int.from_bytes(data[offset:offset + width], "little")
            offset += width
        return {"command": "data_first" if command == DVC_CMD_DATA_FIRST else "data",
                "channel_id": channel_id, "length": length, "data": data[offset:]}
    if command == 0x04:
        width = widths[channel_code]
        if len(data) != 1 + width:
            raise ValueError("malformed DVC close PDU")
        return {"command": "close", "channel_id": int.from_bytes(
            data[1:1 + width], "little")}
    return {"command": "unknown", "cmd": command, "data": data[1:]}


def build_dvc_create_response(channel_id: int, status: int = 0) -> bytes:
    """Build a DVC create response (mainly useful to protocol tests)."""
    _uint(status, 32, "status")
    return _dvc_header(DVC_CMD_CREATE, channel_id) + struct.pack("<I", status)


def _gfx_pdu(command: int, payload: bytes = b"") -> bytes:
    _uint(command, 16, "command")
    length = 8 + len(payload)
    if length > 0xFFFFFFFF:
        raise ValueError("RDPGFX PDU exceeds its length field")
    return struct.pack("<HHI", command, 0, length) + payload


def parse_gfx_pdu(data: bytes) -> tuple[int, bytes, int]:
    """Validate and return (command, payload, total length) for one GFX PDU."""
    data = bytes(data)
    if len(data) < 8:
        raise ValueError("truncated RDPGFX header")
    command, flags, length = struct.unpack_from("<HHI", data)
    if flags != 0 or length < 8 or length > len(data):
        raise ValueError("invalid RDPGFX header length or flags")
    return command, data[8:length], length


def select_avc420_capset(capsets: Iterable[tuple[int, int, bytes]]) -> tuple[int, int, bytes] | None:
    """Choose an explicitly AVC420-capable capset that this server supports.

    The v8.1 AVC420 flag is explicit. For v10+ capability sets, AVC is usable
    unless AVC_DISABLED is set. Only the documented fixed four-byte flags
    structures are selected, and the highest offered compatible version is
    chosen to match MSTSC's advertised graphics pipeline revision.
    """
    v10_versions = {GFX_CAPVERSION_10, GFX_CAPVERSION_101, GFX_CAPVERSION_102,
                    GFX_CAPVERSION_103, GFX_CAPVERSION_104, GFX_CAPVERSION_105,
                    GFX_CAPVERSION_106, GFX_CAPVERSION_107}
    candidates = []
    for version, data_length, caps_data in capsets:
        caps_data = bytes(caps_data)
        if data_length != 4 or len(caps_data) != 4:
            continue
        flags = struct.unpack("<I", caps_data)[0]
        if version == GFX_CAPVERSION_81 and flags & GFX_CAP_AVC420_ENABLED:
            candidates.append((version, flags, caps_data))
        elif version in v10_versions and not flags & GFX_CAP_AVC_DISABLED:
            candidates.append((version, flags, caps_data))
    if not candidates:
        return None
    selected = max(candidates, key=lambda item: item[0])
    return selected


def parse_gfx_caps_advertise(payload: bytes) -> list[tuple[int, int, bytes]]:
    """Parse the capabilities array in a client CAPS_ADVERTISE PDU."""
    payload = bytes(payload)
    if len(payload) < 2:
        raise ValueError("truncated RDPGFX CAPS_ADVERTISE")
    count = struct.unpack_from("<H", payload)[0]
    offset = 2
    capsets = []
    for _ in range(count):
        if len(payload) - offset < 8:
            raise ValueError("truncated RDPGFX capability-set header")
        version, data_length = struct.unpack_from("<II", payload, offset)
        offset += 8
        if data_length > len(payload) - offset:
            raise ValueError("truncated RDPGFX capability-set data")
        cap_data = payload[offset:offset + data_length]
        offset += data_length
        capsets.append((version, data_length, cap_data))
    if offset != len(payload):
        raise ValueError("trailing bytes in RDPGFX CAPS_ADVERTISE")
    return capsets


def select_graphics_capset(capsets: Iterable[tuple[int, int, bytes]]) -> tuple[int, bytes, bool] | None:
    """Select a conservative v8/v8.1 capset and enable AVC420 explicitly.

    AVC420 is available through the v8.1 flag or through a v10+ capset with
    AVC_DISABLED clear. The most recent compatible version is preferred.
    """
    capsets = tuple((version, length, bytes(data))
                    for version, length, data in capsets)
    avc = select_avc420_capset(capsets)
    if avc is not None:
        return avc[0], avc[2], True
    for version, length, data in capsets:
        if version == GFX_CAPVERSION_8 and length == 4 and len(data) == 4:
            return version, data, False
    for version, length, data in capsets:
        if version == GFX_CAPVERSION_81 and length == 4 and len(data) == 4:
            return version, data, False
    return None


def build_gfx_caps_confirm(version: int, flags_data: bytes) -> bytes:
    """Build CAPS_CONFIRM with the exact selected version-specific flags."""
    _uint(version, 32, "version")
    flags_data = bytes(flags_data)
    if len(flags_data) != 4:
        raise ValueError("selected capability data must be four flag bytes")
    return _gfx_pdu(GFX_CAPS_CONFIRM,
                    struct.pack("<II", version, len(flags_data)) + flags_data)


def build_gfx_reset_graphics(width: int, height: int) -> bytes:
    """Build the mandatory 340-byte single-monitor RESET_GRAPHICS PDU."""
    _uint(width, 32, "width")
    _uint(height, 32, "height")
    if not 1 <= width <= 32766 or not 1 <= height <= 32766:
        raise ValueError("graphics dimensions must be between 1 and 32766")
    monitor = struct.pack("<IIIII", 0, 0, width - 1, height - 1, 1)
    body = struct.pack("<III", width, height, 1) + monitor
    return _gfx_pdu(GFX_RESET_GRAPHICS, body + bytes(340 - 8 - len(body)))


def build_gfx_create_surface(surface_id: int, width: int, height: int,
                             pixel_format: int = RDPGFX_PIXELFORMAT_XRGB_8888) -> bytes:
    for value, name in ((surface_id, "surface_id"), (width, "width"),
                        (height, "height")):
        _uint(value, 16, name)
    _uint(pixel_format, 8, "pixel_format")
    if not width or not height:
        raise ValueError("surface dimensions must be positive")
    return _gfx_pdu(GFX_CREATE_SURFACE,
                    struct.pack("<HHHB", surface_id, width, height, pixel_format))


def build_gfx_map_surface_to_output(surface_id: int, origin_x: int = 0,
                                    origin_y: int = 0) -> bytes:
    _uint(surface_id, 16, "surface_id")
    _uint(origin_x, 32, "origin_x")
    _uint(origin_y, 32, "origin_y")
    return _gfx_pdu(GFX_MAP_SURFACE_TO_OUTPUT,
                    struct.pack("<HHII", surface_id, 0, origin_x, origin_y))


def build_gfx_frame_start(frame_id: int, timestamp: int = 0) -> bytes:
    _uint(frame_id, 32, "frame_id")
    _uint(timestamp, 32, "timestamp")
    return _gfx_pdu(GFX_START_FRAME, struct.pack("<II", timestamp, frame_id))


def build_gfx_frame_end(frame_id: int) -> bytes:
    _uint(frame_id, 32, "frame_id")
    return _gfx_pdu(GFX_END_FRAME, struct.pack("<I", frame_id))


def fragment_dvc_message(channel_id: int, message: bytes, *, max_pdu: int = DVC_MAX_PDU) -> list[bytes]:
    """Frame one logical message as DYNVC_DATA or DATA_FIRST plus DATA PDUs.

    ``max_pdu`` includes each DVC header and is capped at the protocol's
    1,600-byte maximum. The returned packets are DVC payloads, before MCS.
    """
    _uint(channel_id, 32, "channel_id")
    message = bytes(message)
    if not message:
        raise ValueError("DVC messages must not be empty")
    if len(message) > 0xFFFFFFFF:
        raise ValueError("DVC message exceeds the 32-bit length field")
    _uint(max_pdu, 16, "max_pdu")
    if max_pdu < 4 or max_pdu > DVC_MAX_PDU:
        raise ValueError("max_pdu must be between 4 and 1600")

    data_header = _dvc_header(DVC_CMD_DATA, channel_id)
    # MS-RDPEDYC sends messages up to 1,590 bytes as one DATA PDU.
    if len(message) <= 1590 and len(data_header) + len(message) <= max_pdu:
        return [data_header + message]

    first_header = _dvc_header(DVC_CMD_DATA_FIRST, channel_id, message_length=len(message))
    first_room = max_pdu - len(first_header)
    next_room = max_pdu - len(data_header)
    if first_room <= 0 or next_room <= 0:
        raise ValueError("max_pdu is too small for DVC headers")
    packets = [first_header + message[:first_room]]
    offset = first_room
    while offset < len(message):
        packets.append(data_header + message[offset:offset + next_room])
        offset += next_room
    return packets


def _rect16(rect: tuple[int, int, int, int]) -> bytes:
    if len(rect) != 4:
        raise ValueError("rect must be (left, top, right, bottom)")
    left, top, right, bottom = rect
    for value, name in zip(rect, ("left", "top", "right", "bottom")):
        _uint(value, 16, name)
    if right <= left or bottom <= top:
        raise ValueError("rectangle must have positive width and height")
    return struct.pack("<HHHH", left, top, right, bottom)


def build_avc420_metadata(rects: Iterable[tuple[int, int, int, int]], *, qp: int = 23,
                          quality: int = 100, progressive: bool = False) -> bytes:
    """Build an RFX_AVC420_METABLOCK for its region mask and quality values."""
    rects = tuple(rects)
    if not rects:
        raise ValueError("AVC420 metadata requires at least one region rectangle")
    if len(rects) > 0xFFFFFFFF:
        raise ValueError("too many AVC420 region rectangles")
    _uint(qp, 6, "qp")
    _uint(quality, 8, "quality")
    if quality > 100:
        raise ValueError("quality must be between 0 and 100")
    qp_val = qp | (0x80 if progressive else 0)
    return (struct.pack("<I", len(rects)) + b"".join(_rect16(rect) for rect in rects) +
            bytes((qp_val, quality)) * len(rects))


def _annex_b(data: bytes) -> bool:
    return data.startswith(b"\x00\x00\x01") or data.startswith(b"\x00\x00\x00\x01")


def build_wire_to_surface_avc420(surface_id: int, dest_rect: tuple[int, int, int, int],
                                 bitstream: bytes, *, qp: int = 23,
                                 quality: int = 100) -> bytes:
    """Build an RDPGFX_WIRE_TO_SURFACE_PDU_1 with AVC420 bitmap data."""
    _uint(surface_id, 16, "surface_id")
    bitstream = bytes(bitstream)
    if not bitstream or not _annex_b(bitstream):
        raise ValueError("AVC420 bitstream must be nonempty Annex-B H.264")
    rect_bytes = _rect16(dest_rect)
    left, top, right, bottom = struct.unpack("<HHHH", rect_bytes)
    metadata = build_avc420_metadata(((0, 0, right - left, bottom - top),), qp=qp,
                                     quality=quality)
    bitmap = metadata + bitstream
    body = (struct.pack("<HHB", surface_id, RDPGFX_CODEC_AVC420,
                        RDPGFX_PIXELFORMAT_XRGB_8888) + rect_bytes +
            struct.pack("<I", len(bitmap)) + bitmap)
    pdu_length = 8 + len(body)
    if pdu_length > 0xFFFFFFFF:
        raise ValueError("RDPGFX PDU exceeds its 32-bit length field")
    return struct.pack("<HHI", RDPGFX_CMD_WIRE_TO_SURFACE_1, 0, pdu_length) + body


def build_clearcodec_bitmap_stream(width: int, height: int, rgb: bytes,
                                   sequence: int) -> bytes:
    """Encode a full 24-bit RGB frame as a ClearCodec raw-pixel subcodec stream."""
    _uint(width, 16, "width")
    _uint(height, 16, "height")
    _uint(sequence, 8, "sequence")
    rgb = bytes(rgb)
    expected = width * height * 3
    if not width or not height or len(rgb) != expected:
        raise ValueError("RGB frame length must match positive dimensions")

    # CLEARCODEC_SUBCODEC: origin, size, byte count, raw subcodec, BGR pixels.
    bgr = bytearray(expected)
    bgr[0::3] = rgb[2::3]
    bgr[1::3] = rgb[1::3]
    bgr[2::3] = rgb[0::3]
    subcodec = struct.pack("<HHHHIB", 0, 0, width, height, expected, 0) + bgr
    composite = struct.pack("<III", 0, 0, len(subcodec)) + subcodec
    return bytes((0, sequence)) + composite


def build_wire_to_surface_clearcodec(surface_id: int,
                                     dest_rect: tuple[int, int, int, int],
                                     bitmap_stream: bytes) -> bytes:
    """Build WIRE_TO_SURFACE_PDU_1 carrying a ClearCodec bitmap stream."""
    _uint(surface_id, 16, "surface_id")
    rect_bytes = _rect16(dest_rect)
    bitmap_stream = bytes(bitmap_stream)
    if not bitmap_stream:
        raise ValueError("ClearCodec bitmap stream must not be empty")
    body = (struct.pack("<HHB", surface_id, RDPGFX_CODEC_CLEARCODEC,
                        RDPGFX_PIXELFORMAT_XRGB_8888) + rect_bytes +
            struct.pack("<I", len(bitmap_stream)) + bitmap_stream)
    pdu_length = 8 + len(body)
    return struct.pack("<HHI", RDPGFX_CMD_WIRE_TO_SURFACE_1, 0, pdu_length) + body


def wrap_server_gfx_message(gfx_pdu: bytes) -> bytes:
    """Wrap one server-to-client graphics PDU in uncompressed RDP_SEGMENTED_DATA."""
    gfx_pdu = bytes(gfx_pdu)
    if len(gfx_pdu) < 8:
        raise ValueError("graphics PDU is shorter than its header")
    declared = struct.unpack_from("<I", gfx_pdu, 4)[0]
    if declared != len(gfx_pdu):
        raise ValueError("graphics PDU length does not match its header")
    # SINGLE descriptor followed by RDP8 bulk data (compression type 4),
    # with PACKET_COMPRESSED clear because the graphics PDU is not compressed.
    return b"\xE0\x04" + gfx_pdu


class H264FrameEncoder:
    """Low-latency PyAV/libx264 encoder producing one Annex-B frame per call."""

    def __init__(self, width: int, height: int, *, fps: int = 30, qp: int = 23,
                 gop_size: int = 30):
        for value, name in ((width, "width"), (height, "height"), (fps, "fps"),
                            (gop_size, "gop_size")):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        _uint(qp, 6, "qp")
        if width > 65535 or height > 65535:
            raise ValueError("frame dimensions exceed RDPGFX RECT16 bounds")

        import av

        self.width = width
        self.height = height
        self.encoded_width = (width + 15) & ~15
        self.encoded_height = (height + 15) & ~15
        self.qp = qp
        self._av = av
        self._np = __import__("numpy")
        self._context = av.CodecContext.create("libx264", "w")
        self._context.width = self.encoded_width
        self._context.height = self.encoded_height
        self._context.pix_fmt = "yuv420p"
        self._context.time_base = Fraction(1, fps)
        self._context.framerate = Fraction(fps, 1)
        self._context.gop_size = gop_size
        self._context.max_b_frames = 0
        self._context.options = {
            "preset": "ultrafast",
            "tune": "zerolatency",
            "qp": str(qp),
            "x264-params": "annexb=1:repeat-headers=1",
        }
        self._context.open()
        self._closed = False
        self._frame_index = 0

    def encode(self, rgb: bytes) -> bytes:
        """Encode one tightly packed RGB24 frame, padding to AVC macroblocks."""
        if self._closed:
            raise ValueError("encoder is closed")
        rgb = bytes(rgb)
        expected = self.width * self.height * 3
        if len(rgb) != expected:
            raise ValueError(f"RGB frame must contain exactly {expected} bytes")
        np = self._np
        source = np.frombuffer(rgb, dtype=np.uint8).reshape((self.height, self.width, 3))
        padded = np.zeros((self.encoded_height, self.encoded_width, 3), dtype=np.uint8)
        padded[:self.height, :self.width] = source
        frame = self._av.VideoFrame.from_ndarray(padded, format="rgb24")
        frame.pts = self._frame_index
        self._frame_index += 1
        packets = self._context.encode(frame)
        data = b"".join(bytes(packet) for packet in packets)
        if not data:
            raise RuntimeError("low-latency encoder did not emit a frame")
        if not _annex_b(data):
            raise RuntimeError("encoder did not produce an Annex-B H.264 byte stream")
        return data

    def close(self) -> None:
        """Flush the codec and prevent further frame submissions."""
        if not self._closed:
            self._context.encode(None)
            self._closed = True

    def __enter__(self) -> "H264FrameEncoder":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

def encode_avc420_frame(rgb: bytes, width: int, height: int, *, qp: int = 23,
                        quality: int = 100, fps: int = 30) -> bytes:
    """Convenience one-shot encoder for a single AVC420 frame."""
    with H264FrameEncoder(width, height, fps=fps, qp=qp) as encoder:
        bitstream = encoder.encode(rgb)
    return build_avc420_metadata(((0, 0, width, height),), qp=qp, quality=quality) + bitstream
