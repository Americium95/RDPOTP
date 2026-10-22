"""Small, transport-independent MS-RDPEA (rdpsnd) packet helpers.

The caller owns channel negotiation, socket writes, and audio capture.  Functions
here produce or consume the bytes carried as static virtual-channel data.
"""

from dataclasses import dataclass
import struct
import time


SNDC_CLOSE = 0x01
SNDC_WAVE = 0x02
SNDC_WAVECONFIRM = 0x05
SNDC_TRAINING = 0x06
SNDC_FORMATS = 0x07
SNDC_QUALITYMODE = 0x0C
SNDC_WAVE2 = 0x0D
WAVE_FORMAT_PCM = 0x0001

CHANNEL_FLAG_FIRST = 0x00000001
CHANNEL_FLAG_LAST = 0x00000002
CHANNEL_FLAG_SHOW_PROTOCOL = 0x00000010
CHANNEL_FLAG_SUSPEND = 0x00000020
CHANNEL_FLAG_RESUME = 0x00000040
CHANNEL_FLAG_COMPRESSED = 0x00200000

_RDPSND_HEADER = struct.Struct("<BBH")
_FORMATS_FIXED = struct.Struct("<IIIHHBHB")
_WAVE_FORMAT = struct.Struct("<HHIIHHH")
_CHANNEL_HEADER = struct.Struct("<II")
_WAVE2_FIXED = struct.Struct("<HHB3sI")


@dataclass(frozen=True)
class AudioFormat:
    format_tag: int
    channels: int
    samples_per_sec: int
    avg_bytes_per_sec: int
    block_align: int
    bits_per_sample: int
    extra_data: bytes = b""

    @classmethod
    def pcm(cls, sample_rate=48000, channels=2, bits_per_sample=16):
        if sample_rate <= 0 or channels <= 0 or bits_per_sample <= 0:
            raise ValueError("PCM parameters must be positive")
        if bits_per_sample % 8:
            raise ValueError("PCM bits_per_sample must be byte aligned")
        align = channels * (bits_per_sample // 8)
        return cls(WAVE_FORMAT_PCM, channels, sample_rate,
                   sample_rate * align, align, bits_per_sample)

    def pack(self):
        extra = bytes(self.extra_data)
        if len(extra) > 0xFFFF:
            raise ValueError("WAVEFORMATEX extra data too large")
        return _WAVE_FORMAT.pack(
            self.format_tag, self.channels, self.samples_per_sec,
            self.avg_bytes_per_sec, self.block_align, self.bits_per_sample,
            len(extra),
        ) + extra


def _pdu(msg_type, body):
    body = bytes(body)
    if len(body) > 0xFFFF:
        raise ValueError("RDPSND PDU body too large")
    return _RDPSND_HEADER.pack(msg_type, 0, len(body)) + body


def parse_pdu(data):
    """Parse one complete RDPSND PDU; reject truncated or trailing bytes."""
    data = bytes(data)
    if len(data) < _RDPSND_HEADER.size:
        raise ValueError("incomplete RDPSND header")
    msg_type, pad, body_size = _RDPSND_HEADER.unpack_from(data)
    end = _RDPSND_HEADER.size + body_size
    if len(data) < end:
        raise ValueError("incomplete RDPSND body")
    if len(data) != end:
        raise ValueError("trailing bytes after RDPSND PDU")
    return {"msg_type": msg_type, "pad": pad, "body": data[4:end]}


def build_server_formats(formats=None, *, version=6, initial_block=0):
    """Build the server SNDC_FORMATS PDU (use PCM formats in preference order)."""
    if formats is None:
        formats = (AudioFormat.pcm(48000, 2), AudioFormat.pcm(44100, 2),
                   AudioFormat.pcm(16000, 1))
    formats = tuple(formats)
    if not formats or len(formats) > 0xFFFF:
        raise ValueError("at least one and at most 65535 formats are required")
    if not 0 <= version <= 0xFFFF or not 0 <= initial_block <= 0xFF:
        raise ValueError("version or initial block out of range")
    # Flags, volume, pitch, datagram port, format count, last block, version, pad.
    fixed = _FORMATS_FIXED.pack(0, 0, 0, 0, len(formats), initial_block,
                                version, 0)
    return _pdu(SNDC_FORMATS, fixed + b"".join(fmt.pack() for fmt in formats))


def _parse_wave_formats(body, count, offset):
    formats = []
    for _ in range(count):
        if len(body) - offset < _WAVE_FORMAT.size:
            raise ValueError("truncated AUDIO_FORMAT")
        tag, channels, rate, avg, align, bits, extra_len = \
            _WAVE_FORMAT.unpack_from(body, offset)
        offset += _WAVE_FORMAT.size
        if len(body) - offset < extra_len:
            raise ValueError("truncated AUDIO_FORMAT extra data")
        extra = body[offset:offset + extra_len]
        offset += extra_len
        formats.append(AudioFormat(tag, channels, rate, avg, align, bits, extra))
    if offset != len(body):
        raise ValueError("unexpected bytes after AUDIO_FORMAT array")
    return formats


def parse_client_formats(packet, *, server_formats=None):
    """Parse a client SNDC_FORMATS reply and return capabilities and formats.

    If ``server_formats`` is supplied, enforce MS-RDPEA's required subset rule.
    """
    pdu = parse_pdu(packet)
    if pdu["msg_type"] != SNDC_FORMATS:
        raise ValueError("expected SNDC_FORMATS")
    body = pdu["body"]
    if len(body) < _FORMATS_FIXED.size:
        raise ValueError("truncated client formats fixed fields")
    flags, volume, pitch, port, count, last_block, version, pad = \
        _FORMATS_FIXED.unpack_from(body)
    formats = _parse_wave_formats(body, count, _FORMATS_FIXED.size)
    if server_formats is not None:
        allowed = {fmt.pack() for fmt in server_formats}
        if any(fmt.pack() not in allowed for fmt in formats):
            raise ValueError("client selected a format not offered by server")
    return {
        "flags": flags, "volume": volume, "pitch": pitch,
        "datagram_port": port, "last_block_confirmed": last_block,
        "version": version, "pad": pad, "formats": formats,
    }


def select_pcm_format(client_reply, *, preferred=(48000, 44100, 16000)):
    """Return (client format index, AudioFormat) for a supported PCM reply."""
    formats = client_reply.get("formats", ())
    pcm = [(i, f) for i, f in enumerate(formats)
           if f.format_tag == WAVE_FORMAT_PCM and f.channels in (1, 2)
           and f.bits_per_sample in (8, 16) and f.samples_per_sec > 0
           and f.block_align == f.channels * (f.bits_per_sample // 8)]
    for rate in preferred:
        for index, fmt in pcm:
            if fmt.samples_per_sec == rate:
                return index, fmt
    if pcm:
        return pcm[0]
    return None


def build_wave2(pcm, *, format_no=0, block_no=0, timestamp=None,
                audio_timestamp=None):
    """Build SNDC_WAVE2 containing one PCM sample/chunk and its metadata."""
    pcm = bytes(pcm)
    if not 0 <= format_no <= 0xFFFF or not 0 <= block_no <= 0xFF:
        raise ValueError("format or block number out of range")
    if timestamp is None:
        timestamp = int(time.monotonic() * 1000) & 0xFFFF
    if audio_timestamp is None:
        audio_timestamp = int(time.monotonic() * 1000) & 0xFFFFFFFF
    if not 0 <= timestamp <= 0xFFFF or not 0 <= audio_timestamp <= 0xFFFFFFFF:
        raise ValueError("timestamp out of range")
    body = _WAVE2_FIXED.pack(timestamp, format_no, block_no, b"\x00\x00\x00",
                             audio_timestamp) + pcm
    return _pdu(SNDC_WAVE2, body)


def build_training(*, timestamp=0, pack_size=0):
    """Build a virtual-channel training request with no optional test data."""
    return _pdu(SNDC_TRAINING, struct.pack("<HH", timestamp, pack_size))


def parse_training(packet):
    """Parse a four-byte Training or Training Confirm body."""
    pdu = parse_pdu(packet)
    if pdu["msg_type"] != SNDC_TRAINING or len(pdu["body"]) != 4:
        raise ValueError("expected four-byte SNDC_TRAINING body")
    return dict(zip(("timestamp", "pack_size"), struct.unpack("<HH", pdu["body"])))


def parse_wave_confirm(packet):
    """Read the client's confirmation for a previously sent audio block."""
    pdu = parse_pdu(packet)
    # MS-RDPEA's confirm structure has timestamp, block number, and one pad
    # byte (four bytes total). Accept the older three-byte fixture form too.
    if pdu["msg_type"] != SNDC_WAVECONFIRM or len(pdu["body"]) not in (3, 4):
        raise ValueError("expected three- or four-byte SNDC_WAVECONFIRM body")
    timestamp, block_no = struct.unpack_from("<HB", pdu["body"])
    return {"timestamp": timestamp, "block_no": block_no}


def wrap_virtual_channel(data, *, chunk_size=1600, show_protocol=False):
    """Wrap data in one or more MS-RDPBCGR CHANNEL_PDU_HEADER chunks.

    Returned byte strings each contain the 8-byte channel header plus payload;
    the caller sends each over the negotiated MCS static channel ID.
    """
    data = bytes(data)
    if not 1 <= chunk_size <= 0xFFFF:
        raise ValueError("chunk_size must be between 1 and 65535")
    if len(data) > 0xFFFFFFFF:
        raise ValueError("virtual-channel message too large")
    base_flags = CHANNEL_FLAG_SHOW_PROTOCOL if show_protocol else 0
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
    if not chunks:
        chunks = [b""]
    wrapped = []
    for i, chunk in enumerate(chunks):
        flags = base_flags
        if i == 0:
            flags |= CHANNEL_FLAG_FIRST
        if i == len(chunks) - 1:
            flags |= CHANNEL_FLAG_LAST
        wrapped.append(_CHANNEL_HEADER.pack(len(data), flags) + chunk)
    return wrapped


def parse_virtual_channel(packet):
    """Parse a single static-channel chunk (reassembly is left to the caller)."""
    packet = bytes(packet)
    if len(packet) < _CHANNEL_HEADER.size:
        raise ValueError("incomplete CHANNEL_PDU_HEADER")
    total, flags = _CHANNEL_HEADER.unpack_from(packet)
    return {"total_length": total, "flags": flags, "data": packet[8:]}
