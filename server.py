import os
import socket
import struct
import threading
import logging
import time
import ssl
import json
import pathlib
import math
import subprocess
import contract
import framing
import gcc
import pdu
import bitmap
import fastpath
import ssl_setup
import hangul_input
import rdpsnd
import rdpgfx
import portal
import settings

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log"),
    filemode="w",
)


def _map_pointer_to_desktop(x, y, input_width, input_height,
                            desktop_width, desktop_height):
    """Map pointer coordinates through the actual centered RDP viewport."""
    input_width = max(1, int(input_width))
    input_height = max(1, int(input_height))
    desktop_width = max(1, int(desktop_width))
    desktop_height = max(1, int(desktop_height))
    outside = (x < 0 or y < 0 or x >= input_width or y >= input_height)
    scale = min(input_width / desktop_width,
                input_height / desktop_height)
    shown_width = desktop_width * scale
    shown_height = desktop_height * scale
    offset_x = (input_width - shown_width) / 2
    offset_y = (input_height - shown_height) / 2
    outside = (outside or x < offset_x or y < offset_y or
               x >= offset_x + shown_width or
               y >= offset_y + shown_height)
    if outside:
        # Some phone clients report taps in the bottom gesture/navigation
        # area just beyond the fitted desktop. Route those taps to the center
        # of the page, where the OTP input is placed, instead of its bottom edge.
        return desktop_width // 2, desktop_height // 2, True
    mapped_x = round((x - offset_x) / scale)
    mapped_y = round((y - offset_y) / scale)
    return (max(0, min(desktop_width - 1, mapped_x)),
            max(0, min(desktop_height - 1, mapped_y)), outside)


SEND_POINTER = False
SKIP_IMAGE = False
MAX_TILES = 0
# Pace bitmap bursts so MSTSC's receive callback is not flooded by a whole
# desktop worth of tiles at once. Both values can be overridden for testing.
BAND_DELAY = max(0.0, settings.get("server", "band_delay", 0, float, "RDP_BAND_DELAY"))
MAX_FRAME_RATE = max(0.0, settings.get("server", "max_fps", 30, float, "RDP_MAX_FPS"))
BITMAP_TILE_WIDTH = 128
BITMAP_TILE_HEIGHT = 60  # 15,360 raw 16-bpp bytes keeps one tile under 16 KB.
# Keep graphics batches large enough to avoid a receive callback per small
# tile, while remaining well below the TPKT/bitmap-update safety ceiling.
BITMAP_UPDATE_CHUNK_BYTES = settings.get(
    "server", "bitmap_chunk_bytes", 4096, int, "RDP_BITMAP_CHUNK_BYTES")
if not 1024 <= BITMAP_UPDATE_CHUNK_BYTES <= 16000:
    raise ValueError("bitmap_chunk_bytes must be between 1024 and 16000")
BITMAP_COMPRESSION_MODE = settings.get(
    "server", "bitmap_compression", "max", str,
    "RDP_BITMAP_COMPRESSION").strip().lower()
if BITMAP_COMPRESSION_MODE == "on":
    BITMAP_COMPRESSION_MODE = "standard"
if BITMAP_COMPRESSION_MODE not in ("max", "standard", "off"):
    raise ValueError("bitmap_compression must be max, standard/on, or off")
NSCODEC_SURFACE_UPDATES = settings.get(
    "server", "nscodec_surface_updates", False, bool,
    "RDP_NSCODEC_SURFACE_UPDATES")
GRAPHICS_CODEC = settings.get(
    "server", "graphics_codec", "auto", str,
    "RDP_GRAPHICS_CODEC").strip().lower()
if GRAPHICS_CODEC not in ("auto", "h264", "bitmap"):
    raise ValueError("graphics_codec must be auto, h264, or bitmap")
RENDER_SCALE = settings.get("server", "render_scale", 1.0, float,
                            "RDP_RENDER_SCALE")
if not 0.25 <= RENDER_SCALE <= 1.0:
    raise ValueError("render_scale must be between 0.25 and 1.0")
SERVER_USER_ID = 1004          # MCS user id assigned to client
SERVER_INITIATOR = SERVER_USER_ID - contract.MCS_BASE_CHANNEL_ID  # 3


def _extract_rgb_region(frame, frame_width, left, top, width, height):
    """Copy one tightly-packed RGB rectangle from a tightly-packed frame."""
    row_bytes = frame_width * 3
    tile_row_bytes = width * 3
    result = bytearray(tile_row_bytes * height)
    for row in range(height):
        start = (top + row) * row_bytes + left * 3
        dest = row * tile_row_bytes
        result[dest:dest + tile_row_bytes] = frame[start:start + tile_row_bytes]
    return bytes(result)


def _tile_origins(width, height, tile_width, tile_height, center_first=False):
    """Return tile origins in paint order, optionally prioritizing the center.

    The OTP form is centered in the RDP canvas. On a slow link, sending its
    tiles first makes the usable form appear before the full background.
    """
    origins = [(left, top)
               for top in range(0, height, tile_height)
               for left in range(0, width, tile_width)]
    if center_first:
        center_x, center_y = width / 2.0, height / 2.0
        origins.sort(key=lambda p: (
            (p[0] + min(tile_width, width - p[0]) / 2.0 - center_x) ** 2 +
            (p[1] + min(tile_height, height - p[1]) / 2.0 - center_y) ** 2
        ))
    return origins

# This branch starts at the phone-OTP portal. RDP_HTML/RDP_HTML_DEFAULT can still
# override it for diagnostics.
DEFAULT_HTML = os.environ.get("RDP_HTML_DEFAULT") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "pin_portal.html")
OTP_TTL_SECONDS = settings.get("otp", "ttl_seconds", 60, int, "RDP_OTP_TTL_SECONDS")
OTP_MAX_ATTEMPTS = settings.get("otp", "max_attempts", 3, int, "RDP_OTP_MAX_ATTEMPTS")
if not 5 <= OTP_TTL_SECONDS <= 600:
    raise ValueError("RDP_OTP_TTL_SECONDS must be between 5 and 600")
OTP_RATE_LIMITER = portal.OtpRateLimiter(
    max_issues=settings.get("otp", "max_sends", 5, int, "RDP_OTP_MAX_SENDS"),
    window_seconds=settings.get("otp", "send_window_seconds", 600, float, "RDP_OTP_SEND_WINDOW_SECONDS"))
ROUTING_TICKETS = portal.RoutingTickets(
    ttl_seconds=settings.get("routing_ticket", "ttl_seconds", 900, float, "RDP_ROUTING_TICKET_TTL"),
    max_uses=settings.get("routing_ticket", "max_uses", 16, int, "RDP_ROUTING_TICKET_MAX_USES"),
    bind_source=settings.get("routing_ticket", "bind_source", False, bool, "RDP_ROUTING_TICKET_BIND_SOURCE"))
NATIVE_RDP_HOST = settings.get("server", "native_host", "127.0.0.1", str, "RDP_REDIRECT_HOST")
NATIVE_RDP_PORT = settings.get("server", "native_port", 3389, int, "RDP_REDIRECT_PORT")
# How long the portal connection is drained after the redirection PDU was
# sent, waiting for the client to hang up on its own.
REDIRECT_DRAIN_SECONDS = settings.get("server", "redirect_drain_seconds", 15.0, float, "RDP_REDIRECT_DRAIN_SECONDS")
DISABLE_HYBRID_EX = settings.get("server", "disable_hybrid_ex", False, bool, "RDP_DISABLE_HYBRID_EX")


def _send_otp_notification(code):
    """Send an OTP through the configured batch file without logging it."""
    notify_url = settings.get("notify", "url", "", str, "RDP_NOTIFY_URL").strip()
    if not notify_url:
        logging.warning("OTP notification URL is not configured")
        return False
    batch = os.environ.get("RDP_NOTIFY_BAT") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "send_notify.bat")
    batch = os.path.abspath(batch)
    if not os.path.isfile(batch):
        logging.warning("OTP notifier batch file is unavailable")
        return False
    message = ("RDP one-time code: %s. Expires in %d seconds." %
               (code, OTP_TTL_SECONDS)).encode("ascii")
    env = os.environ.copy()
    env["RDP_OTP_STDIN"] = "1"
    env["RDP_NOTIFY_URL"] = notify_url
    try:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", batch], input=message,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(batch), env=env, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logging.warning("OTP notification failed (%s)", type(exc).__name__)
        return False
    if result.returncode != 0:
        logging.warning("OTP notification batch returned a failure status")
        return False
    return True


class _NativeRelayDiagnostics:
    """Bounded observer for X.224 negotiation and first TLS record headers."""
    def __init__(self):
        self.cr = bytearray()
        self.cr_total = None
        self.cr_done = False
        self.cc = bytearray()
        self.cc_total = None
        self.cc_done = False
        self.tls = {"client": bytearray(), "native": bytearray()}
        self.tls_remaining = {"client": 0, "native": 0}
        self.tls_record_count = {"client": 0, "native": 0}

    def observe(self, direction, data):
        if direction == "client" and not self.cr_done:
            self.cr.extend(data[:max(0, 19 - len(self.cr))])
            if self.cr_total is None and len(self.cr) >= 4:
                self.cr_total = int.from_bytes(self.cr[2:4], "big") if self.cr[:2] == b"\x03\x00" else 0
            if self.cr_total and len(self.cr) >= self.cr_total:
                p = self.cr
                requested = None
                if len(p) >= 19 and p[5] == 0xE0:
                    off = 4 + 1 + p[4] - 8
                    if off >= 11 and p[off:off + 2] == b"\x01\x00":
                        requested = int.from_bytes(p[off + 4:off + 8], "little")
                if requested is not None:
                    logging.info("native RDP relay CR requestedProtocols=%d", requested)
                self.cr_done = True
                self.cr.clear()
            elif self.cr_total == 0:
                self.cr_done = True
                self.cr.clear()

        tls_data = data if direction != "native" or self.cc_done else b""
        if direction == "native" and not self.cc_done:
            old_len = len(self.cc)
            self.cc.extend(data[:max(0, 19 - old_len)])
            if self.cc_total is None and len(self.cc) >= 4:
                self.cc_total = int.from_bytes(self.cc[2:4], "big") if self.cc[:2] == b"\x03\x00" else 0
            if self.cc_total and len(self.cc) >= self.cc_total:
                p = self.cc
                selected = None
                if (len(p) >= 19 and p[5] == 0xD0 and p[11] == 0x02
                        and int.from_bytes(p[13:15], "little") == 8):
                    selected = int.from_bytes(p[15:19], "little")
                if selected is not None:
                    logging.info("native RDP relay X.224 CC selectedProtocol=%d flags=%d",
                                 selected, p[12])
                else:
                    code = p[5] if len(p) > 5 else None
                    neg_type = p[11] if len(p) > 11 else None
                    neg_length = int.from_bytes(p[13:15], "little") if len(p) >= 15 else None
                    detail = ""
                    if neg_type == 3 and len(p) >= 19 and neg_length == 8:
                        detail = " failureCode=%d" % int.from_bytes(p[15:19], "little")
                    elif neg_type == 2 and len(p) >= 19 and neg_length == 8:
                        detail = " flags=%d selectedProtocol=%d" % (
                            p[12], int.from_bytes(p[15:19], "little"))
                    logging.info(
                        "native RDP relay X.224 response code=%s li=%s negotiationType=%s negotiationLength=%s%s",
                        code, p[4] if len(p) > 4 else None, neg_type,
                        neg_length, detail)
                extra_start = max(0, self.cc_total - old_len)
                tls_data = data[extra_start:]
                self.cc_done = True
                self.cc.clear()
            elif self.cc_total == 0:
                self.cc_done = True
                self.cc.clear()
                tls_data = b""

        tlsbuf = self.tls[direction]
        if tls_data and self.tls_record_count[direction] < 8:
            tlsbuf.extend(tls_data)
        while self.tls_record_count[direction] < 8:
            remaining = self.tls_remaining[direction]
            if remaining:
                consumed = min(remaining, len(tlsbuf))
                del tlsbuf[:consumed]
                self.tls_remaining[direction] -= consumed
                if self.tls_remaining[direction]:
                    break
                continue
            if len(tlsbuf) < 5:
                break
            header = bytes(tlsbuf[:5])
            del tlsbuf[:5]
            if not (20 <= header[0] <= 23 and header[1] == 3):
                # Stop observing this direction when its stream is not TLS;
                # never include payload bytes in diagnostics.
                self.tls_record_count[direction] = 8
                tlsbuf.clear()
                break
            record_number = self.tls_record_count[direction] + 1
            self.tls_record_count[direction] = record_number
            payload_length = int.from_bytes(header[3:5], "big")
            logging.info("native RDP relay TLS record %s #%d type=%d version=%d.%d length=%d",
                         direction, record_number, header[0], header[1], header[2],
                         payload_length)
            self.tls_remaining[direction] = payload_length

def _is_renderable(target: str) -> bool:
    """True if target is something the browser renderer can load."""
    t = (target or "").strip()
    if not t:
        return False
    if t.startswith(("http://", "https://")):
        return True
    return os.path.isfile(t)


def _normalize_page_target(target: str) -> str:
    """Return a URL the headless browser can load.

    RDP_HTML is normally a plain Windows path (run.bat points it at
    pin_portal.html).  The interactive branch in _send_image only recognises
    http(s)/file URLs, so an un-normalised path silently fell through to the
    static renderer: the page was visible but the PIN field never received a
    keystroke.  Percent-encoding matters here because the branch lives under
    a directory with a space in its name.
    """
    t = (target or "").strip()
    if not t or t.startswith(("http://", "https://", "file://")):
        return t
    try:
        if os.path.isfile(t):
            return pathlib.Path(t).resolve().as_uri()
    except OSError:
        pass
    return t


def _is_portal_page(target: str) -> bool:
    """True when the target is the PIN portal page (matched by file name)."""
    path = (target or "").split("?", 1)[0].split("#", 1)[0]
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return name.lower() == "pin_portal.html"


def _should_use_polling_fallback(portal_page: bool, *, low_fps=False,
                                 silent=False) -> bool:
    """Poll active pages when screencast is slow or quiet, but keep OTP push.

    Chrome screencast is damage-driven. A quiet OTP page is normal, and a
    screenshot round trip for every quiet interval only adds latency.
    """
    return not portal_page and (low_fps or silent)


def _convert_audio_pcm(pcm, source_format, target_format):
    """Convert captured s16le PCM to the negotiated rdpsnd PCM format."""
    source_channels = source_format.channels
    target_channels = target_format.channels
    # Process loopback currently supplies precisely this format. Preserve the
    # samples byte-for-byte instead of running them through a float resampler.
    if (source_format.format_tag == rdpsnd.WAVE_FORMAT_PCM and
            source_format.bits_per_sample == target_format.bits_per_sample == 16 and
            source_channels == target_channels and
            source_format.sample_rate == target_format.samples_per_sec and
            target_format.format_tag == rdpsnd.WAVE_FORMAT_PCM):
        usable = len(pcm) - len(pcm) % (source_channels * 2)
        return bytes(pcm[:usable])
    if source_channels < 1 or target_channels not in (1, 2):
        return b""
    usable = len(pcm) - len(pcm) % (source_channels * 2)
    if not usable:
        return b""
    count = usable // (source_channels * 2)
    samples = struct.unpack("<" + "h" * (count * source_channels), pcm[:usable])
    mixed = []
    for i in range(count):
        frame = samples[i * source_channels:(i + 1) * source_channels]
        if target_channels == 1:
            mixed.append((sum(frame) // source_channels,))
        elif source_channels == 1:
            mixed.append((frame[0], frame[0]))
        else:
            mixed.append((frame[0], frame[1]))
    src_rate, dst_rate = source_format.sample_rate, target_format.samples_per_sec
    if src_rate <= 0 or dst_rate <= 0:
        return b""
    out_count = max(1, int(round(count * dst_rate / src_rate)))
    out = bytearray(out_count * target_channels * 2)
    for j in range(out_count):
        pos = j * src_rate / dst_rate
        left = min(int(pos), count - 1)
        right = min(left + 1, count - 1)
        frac = pos - left
        for ch in range(target_channels):
            value = int(round(mixed[left][ch] * (1.0 - frac) + mixed[right][ch] * frac))
            struct.pack_into("<h", out, (j * target_channels + ch) * 2,
                             max(-32768, min(32767, value)))
    if target_format.bits_per_sample == 16:
        return bytes(out)
    if target_format.bits_per_sample == 8:
        return bytes(max(0, min(255, (struct.unpack_from("<h", out, i)[0] >> 8) + 128))
                     for i in range(0, len(out), 2))
    return b""


class ClientAbort(Exception):
    pass


class RDPConnection:
    def __init__(self, sock, client_addr=None):
        self.sock = sock
        self.client_addr = client_addr[0] if client_addr else "unknown"
        self.buf = b""
        self.width = contract.DEFAULT_WIDTH
        self.height = contract.DEFAULT_HEIGHT
        self.bpp = contract.DEFAULT_BPP
        self.input_width = self.width
        self.input_height = self.height
        self.channel_ids = []
        self.static_channels = {}
        self._send_lock = threading.Lock()
        self._audio_capture = None
        self._audio_starting = False
        self._audio_thread = None
        self._audio_stop = threading.Event()
        self._audio_format = None
        self._audio_alive = False
        self._audio_format_no = 0
        self._audio_block_no = 0
        self._audio_waiting_block = None
        self._audio_confirm_condition = threading.Condition()
        self._audio_confirm_count = 0
        self._audio_confirm_mode = None
        self._audio_ready = threading.Event()
        self._training_pending = False
        self._training_timestamp = 0
        self._training_pack_size = 0
        self._audio_confirms_seen = 0
        self._audio_rx = bytearray()
        self._audio_vc_rx = bytearray()
        self._audio_vc_expected = None
        self._audio_offered_formats = ()
        self.requested_protocols = 0
        self.sent_attach_confirm = False
        # Client input arrives as FastPath PDUs, which are NOT TPKT framed, so
        # they need their own buffer.  TCP may split a PDU across recvs, so
        # anything unparsed is kept here until the rest shows up.
        self.inbuf = bytearray()
        self.input = fastpath.InputState()
        # Hooks the painter installs so client input can drive the screen.
        self.on_input = None
        self.browser = None
        self._sensitive_page_active = False
        self._redirect_sent = False
        self._nscodec_id = None
        self._nscodec_color_loss_level = 3
        self._surface_bits_supported = False
        self._client_gfx_supported = False
        self._rdpgfx_dvc_ready = False
        self._rdpgfx_dvc_state = "disabled"
        self._rdpgfx_static_channel_id = None
        self._rdpgfx_channel_id = None
        self._rdpgfx_pending_channels = set()
        self._rdpgfx_dvc_rx = {}
        self._rdpgfx_vc_rx = bytearray()
        self._rdpgfx_vc_expected = None
        self._rdpgfx_caps_confirmed = False
        self._rdpgfx_avc420 = False
        self._rdpgfx_codec = None
        self._rdpgfx_clear_sequence = 0
        self._rdpgfx_surface_ready = False
        self._rdpgfx_surface_id = 0
        self._rdpgfx_frame_id = 0
        self._rdpgfx_last_frame = None
        self._rdpgfx_encoder = None

        # Set RDP_PERF=1 to emit aggregate capture/paint/send/FPS summaries.
        self._perf_enabled = bool(os.environ.get("RDP_PERF"))
        self._perf_socket_send_s = 0.0
        self._perf_window_start = None
        self._perf_window_frames = 0
        self._perf_window_capture_s = 0.0
        self._perf_window_convert_s = 0.0
        self._perf_window_pdu_s = 0.0
        self._perf_window_socket_s = 0.0
        self._perf_window_sent_tiles = 0
        self._perf_window_skipped_tiles = 0

    # ---------- transport ----------
    def _fill(self, n):
        while len(self.buf) < n:
            try:
                c = self.sock.recv(4096)
            except socket.timeout:
                raise
            if not c:
                logging.info("EOF with %d buffered bytes: %s", len(self.buf), self.buf.hex())
                raise ClientAbort("eof")
            logging.info("recv %d bytes", len(c))
            self.buf += c

    def recv(self, n):
        self._fill(n)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, b, quiet=False):
        if not quiet:
            logging.info("send %d bytes", len(b))
        if not quiet and len(b) <= 30:
            logging.debug("send small pdu raw=%s", b.hex())
        try:
            if getattr(self, "_perf_enabled", False):
                started = time.perf_counter()
                try:
                    with self._send_lock:
                        self.sock.sendall(b)
                finally:
                    self._perf_socket_send_s += time.perf_counter() - started
            else:
                with self._send_lock:
                    self.sock.sendall(b)
        except ssl.SSLEOFError:
            logging.info("SSL connection closed by peer (EOF)")
            raise ClientAbort("SSL connection closed by peer")
        except OSError as exc:
            if exc.errno == 104:  # Connection reset by peer
                logging.info("Connection reset by peer")
                raise ClientAbort("Connection reset by peer")
            raise

    def read_tpkt(self):
        while True:
            hdr = self.recv(4)
            # TPKT = version 0x03, reserved 0x00, then BE length.  mstsc starts
            # sending FastPath input (keys/mouse) the moment the user touches
            # the session -- sometimes before finalization is even done -- and
            # those PDUs are not TPKT framed.  Absorb them into the input
            # buffer instead of killing the connection (this used to abort
            # with "ValueError: not tpkt" right after the handshake).
            if hdr[0] == 3 and hdr[1] == 0:
                length = struct.unpack(">H", hdr[2:4])[0]
                if length < 7:
                    raise ValueError("tpkt too short")
                rest = self.recv(length - 4)
                return hdr + rest
            self.buf = hdr + self.buf   # put the bytes back and parse as input
            if len(self.buf) > 65535:
                self._raw_dump()
                raise ValueError("not tpkt (buffer too large)")
            try:
                events, consumed = fastpath.parse_stream(self.buf)
            except Exception:
                logging.exception("fastpath parse failed on non-TPKT bytes")
                self._raw_dump()
                raise ValueError("not tpkt")
            if consumed:
                self.inbuf += self.buf[:consumed]
                # self.buf is a bytes object (recv() uses immutable slices).
                # Deleting from it raises TypeError and aborts mstsc during
                # finalization as soon as an early FastPath PDU is absorbed.
                self.buf = self.buf[consumed:]
                logging.info("early fastpath input absorbed: %d events, %d bytes",
                             len(events), consumed)
                self._dispatch_input()
                continue
            # Either an incomplete fastpath PDU (loop back to read more) or
            # garbage (the 64KB cap above eventually turns it into an error).
            continue

    def _raw_dump(self):
        logging.error("RAW non-TPKT frame (%d bytes): %s",
                      len(self.buf), bytes(self.buf[:64]).hex(" "))
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "client_raw.bin"), "wb") as f:
            f.write(bytes(self.buf))

    def send_pdu(self, user_data, channel_id=contract.MCS_GLOBAL_CHANNEL_ID, quiet=False,
                 initiator=SERVER_INITIATOR):
        import os as _o2
        if _o2.environ.get("RDP_TRACE_TX"):
            try:
                logging.info("TX %d bytes channel=%d initiator=%d pduType=0x%04x type2=0x%02x len=%d data=%s",
                             len(user_data),
                             channel_id,
                             initiator,
                             struct.unpack_from("<H", user_data, 2)[0],
                             user_data[14],
                             struct.unpack_from("<H", user_data, 12)[0],
                             bytes(user_data[:96]).hex())
            except Exception:
                pass
        self.send(framing.wrap_pdu(user_data, initiator, channel_id), quiet=quiet)

    def _start_rdpgfx_negotiation(self):
        """Start DVC negotiation only for clients advertising the GFX flag."""
        if GRAPHICS_CODEC == "bitmap":
            logging.info("RDPGFX disabled by graphics_codec=bitmap; using bitmap/NSCodec path")
            return False
        if not getattr(self, "_client_gfx_supported", False):
            logging.info("RDPGFX unavailable: client Core earlyCapabilityFlags lacks 0x0100; using bitmap path")
            return False
        static_id = getattr(self, "_rdpgfx_static_channel_id", None)
        if static_id is None:
            logging.info("RDPGFX unavailable: client did not join drdynvc; using bitmap path")
            return False
        self._send_dvc_pdu(rdpgfx.build_dvc_capabilities_request(1))
        self._rdpgfx_dvc_state = "capabilities_sent"
        logging.info("DRDYNVC capabilities request sent on static channel %d (version 1)",
                     static_id)
        return True

    def _send_dvc_pdu(self, packet):
        static_id = getattr(self, "_rdpgfx_static_channel_id", None)
        if static_id is None:
            return
        for chunk in rdpsnd.wrap_virtual_channel(packet, chunk_size=1600):
            # MS-RDPBCGR requires server-originated virtual-channel MCS
            # SendDataIndication PDUs to use the server channel ID as initiator.
            # Keep legacy share-PDU framing unchanged while validating GFX.
            self.send_pdu(chunk, static_id, quiet=True,
                          initiator=contract.MCS_SERVER_CHANNEL_ID)

    def _send_gfx_pdu(self, packet):
        """Send one server graphics PDU as a DVC message, including wrapper."""
        if self._rdpgfx_channel_id is None:
            raise ValueError("RDPGFX DVC channel is not open")
        wire_message = rdpgfx.wrap_server_gfx_message(packet)
        for dvc_packet in rdpgfx.fragment_dvc_message(
                self._rdpgfx_channel_id, wire_message):
            self._send_dvc_pdu(dvc_packet)

    def _activate_rdpgfx_surface(self):
        if not self._rdpgfx_caps_confirmed or self._rdpgfx_surface_ready:
            return False
        encoder = None
        codec = "AVC420" if self._rdpgfx_avc420 else "ClearCodec-raw"
        try:
            if self._rdpgfx_avc420:
                fps = max(1, int(MAX_FRAME_RATE)) if MAX_FRAME_RATE else 30
                encoder = rdpgfx.H264FrameEncoder(
                    self.width, self.height, fps=fps, qp=23)
            self._send_gfx_pdu(rdpgfx.build_gfx_reset_graphics(
                self.width, self.height))
            # Surface 0 is the implicit primary graphics output surface. It is
            # mapped directly after RESET_GRAPHICS; offscreen surfaces use
            # CREATE_SURFACE with a nonzero ID.
            if self._rdpgfx_surface_id != 0:
                self._send_gfx_pdu(rdpgfx.build_gfx_create_surface(
                    self._rdpgfx_surface_id, self.width, self.height))
            self._send_gfx_pdu(rdpgfx.build_gfx_map_surface_to_output(
                self._rdpgfx_surface_id, 0, 0))
        except ClientAbort:
            try:
                encoder.close()
            except Exception:
                pass
            raise
        except Exception:
            logging.exception("RDPGFX %s surface setup failed; using bitmap path", codec)
            try:
                encoder.close()
            except Exception:
                pass
            self._rdpgfx_avc420 = False
            return False
        self._rdpgfx_encoder = encoder
        self._rdpgfx_codec = "AVC420" if self._rdpgfx_avc420 else "CLEARCODEC"
        self._rdpgfx_clear_sequence = 0
        self._rdpgfx_surface_ready = True
        logging.info("RDPGFX surface ready: surface=%d size=%dx%d codec=%s",
                     self._rdpgfx_surface_id, self.width, self.height, codec)
        previous = getattr(self, "_last_frame", None)
        if previous is not None:
            tiles = (((self.width + BITMAP_TILE_WIDTH - 1) // BITMAP_TILE_WIDTH) *
                     ((self.height + BITMAP_TILE_HEIGHT - 1) // BITMAP_TILE_HEIGHT))
            self._paint_rdpgfx(previous, tiles, drain=False)
        return True

    def _handle_gfx_message(self, message):
        """Consume complete client-to-server RDPGFX messages."""
        message = bytes(message)
        offset = 0
        while offset < len(message):
            command, payload, length = rdpgfx.parse_gfx_pdu(message[offset:])
            if length > len(message) - offset:
                raise ValueError("RDPGFX message exceeds DVC payload")
            if command == rdpgfx.GFX_CAPS_ADVERTISE:
                capsets = rdpgfx.parse_gfx_caps_advertise(payload)
                logging.info("RDPGFX client capsets: %s",
                             ", ".join("version=0x%08x length=%d data=%s" %
                                       (version, length, data.hex())
                                       for version, length, data in capsets))
                selected = rdpgfx.select_graphics_capset(capsets)
                if selected is None:
                    self._rdpgfx_caps_confirmed = False
                    self._rdpgfx_avc420 = False
                    logging.info("RDPGFX fallback: no supported v8/v8.1 capability set; using bitmap path")
                else:
                    version, cap_data, avc420 = selected
                    self._send_gfx_pdu(rdpgfx.build_gfx_caps_confirm(version, cap_data))
                    self._rdpgfx_caps_confirmed = True
                    self._rdpgfx_avc420 = avc420
                    logging.info("RDPGFX capabilities confirmed version=0x%08x AVC420=%s",
                                 version, avc420)
                    self._activate_rdpgfx_surface()
            elif command in (0x000D, 0x0016):
                # Frame/QoE acknowledgements carry no state needed by this
                # unacknowledged, one-frame-at-a-time AVC420 sender.
                logging.debug("RDPGFX acknowledgement received cmd=0x%04x", command)
            else:
                logging.debug("RDPGFX client PDU ignored cmd=0x%04x", command)
            offset += length

    def _handle_drdynvc_data(self, static_channel_id, data):
        """Handle DVC control/data PDUs and route the opened GFX channel."""
        if (getattr(self, "_rdpgfx_static_channel_id", None) is None or
                static_channel_id != self._rdpgfx_static_channel_id):
            return False
        try:
            vc = rdpsnd.parse_virtual_channel(data)
            flags = vc["flags"]
            if flags & rdpsnd.CHANNEL_FLAG_FIRST:
                self._rdpgfx_vc_rx = bytearray()
                self._rdpgfx_vc_expected = vc["total_length"]
            elif self._rdpgfx_vc_expected is None:
                raise ValueError("DRDYNVC static-channel fragment without FIRST")
            expected = self._rdpgfx_vc_expected
            if expected is None or expected > 1_048_576:
                raise ValueError("invalid DRDYNVC static-channel length")
            self._rdpgfx_vc_rx.extend(vc["data"])
            if len(self._rdpgfx_vc_rx) > expected:
                raise ValueError("DRDYNVC static-channel fragments exceed total length")
            if flags & rdpsnd.CHANNEL_FLAG_LAST:
                if len(self._rdpgfx_vc_rx) != expected:
                    raise ValueError("DRDYNVC static-channel LAST length mismatch")
                data = bytes(self._rdpgfx_vc_rx)
                self._rdpgfx_vc_rx.clear()
                self._rdpgfx_vc_expected = None
            else:
                return True
            pdu_info = rdpgfx.parse_dvc_pdu(data)
            command = pdu_info["command"]
            if command == "capabilities":
                if self._rdpgfx_dvc_state != "capabilities_sent":
                    return True
                if pdu_info["version"] < 1:
                    self._rdpgfx_dvc_state = "disabled"
                    logging.info("DRDYNVC rejected version %d; using bitmap path",
                                 pdu_info["version"])
                    return True
                channel_id = 1
                while channel_id in self._rdpgfx_pending_channels:
                    channel_id += 1
                self._rdpgfx_pending_channels.add(channel_id)
                self._rdpgfx_channel_id = channel_id
                self._send_dvc_pdu(rdpgfx.build_dvc_create_request(channel_id))
                self._rdpgfx_dvc_state = "channel_create_sent"
                logging.info("DRDYNVC graphics channel create requested id=%d name=%s",
                             channel_id, rdpgfx.GFX_CHANNEL_NAME)
                return True
            if command == "create_request":
                # Reserve client-selected IDs to prevent collision with our
                # server-initiated Graphics channel; unsupported channels are
                # rejected explicitly so the static DVC manager stays usable.
                client_id = pdu_info["channel_id"]
                self._rdpgfx_pending_channels.add(client_id)
                self._send_dvc_pdu(rdpgfx.build_dvc_create_response(
                    client_id, status=0xC0000225))  # STATUS_NOT_FOUND
                logging.info("DRDYNVC client channel rejected name=%s id=%d",
                             pdu_info.get("name"), client_id)
                return True
            if command == "create_response":
                if pdu_info["channel_id"] != self._rdpgfx_channel_id:
                    return True
                if pdu_info["status"] != 0:
                    self._rdpgfx_channel_id = None
                    self._rdpgfx_dvc_state = "disabled"
                    logging.info("DRDYNVC graphics channel open failed status=0x%08x; using bitmap path",
                                 pdu_info["status"])
                    return True
                self._rdpgfx_dvc_state = "channel_open"
                self._rdpgfx_dvc_ready = True
                logging.info("DRDYNVC graphics channel open id=%d", pdu_info["channel_id"])
                return True
            if command == "data_first":
                message_length = pdu_info["length"]
                first = pdu_info["data"]
                if message_length > 1_048_576 or len(first) > message_length:
                    raise ValueError("oversized or inconsistent DVC message")
                if pdu_info["channel_id"] == self._rdpgfx_channel_id:
                    if len(first) == message_length:
                        self._handle_gfx_message(first)
                    else:
                        self._rdpgfx_dvc_rx[pdu_info["channel_id"]] = [message_length,
                                                                      bytearray(first)]
                return True
            if command == "data":
                channel_id = pdu_info["channel_id"]
                fragment = pdu_info["data"]
                pending = self._rdpgfx_dvc_rx.get(channel_id)
                if pending is not None:
                    expected, accumulated = pending
                    if len(accumulated) + len(fragment) > expected:
                        del self._rdpgfx_dvc_rx[channel_id]
                        raise ValueError("DVC fragments exceed declared message length")
                    accumulated.extend(fragment)
                    if len(accumulated) == expected:
                        del self._rdpgfx_dvc_rx[channel_id]
                        if channel_id == self._rdpgfx_channel_id:
                            self._handle_gfx_message(accumulated)
                elif channel_id == self._rdpgfx_channel_id:
                    self._handle_gfx_message(fragment)
                return True
            if command == "close" and pdu_info["channel_id"] == self._rdpgfx_channel_id:
                self._rdpgfx_dvc_ready = False
                self._rdpgfx_surface_ready = False
                self._rdpgfx_avc420 = False
                self._rdpgfx_dvc_state = "closed"
                self._close_rdpgfx_encoder()
                logging.info("DRDYNVC graphics channel closed; using bitmap path")
                return True
            return True
        except ClientAbort:
            raise
        except Exception:
            logging.exception("DRDYNVC graphics dispatch failed; retaining bitmap path")
            self._rdpgfx_dvc_state = "disabled"
            self._rdpgfx_dvc_ready = False
            self._rdpgfx_avc420 = False
            self._rdpgfx_surface_ready = False
            self._rdpgfx_vc_rx.clear()
            self._rdpgfx_vc_expected = None
            self._close_rdpgfx_encoder()
            return True

    def _close_rdpgfx_encoder(self):
        encoder, self._rdpgfx_encoder = self._rdpgfx_encoder, None
        if encoder is not None:
            try:
                encoder.close()
            except Exception:
                logging.debug("RDPGFX encoder close failed", exc_info=True)

    def _paint_rdpgfx(self, rgb, total_tiles, *, drain=True):
        """Send a full-surface frame using the negotiated RDPGFX codec."""
        frame_id = self._rdpgfx_frame_id
        timestamp = int(time.monotonic() * 1000) & 0xFFFFFFFF
        try:
            if self._rdpgfx_codec == "AVC420":
                bitstream = self._rdpgfx_encoder.encode(rgb)
                bitmap_pdu = rdpgfx.build_wire_to_surface_avc420(
                    self._rdpgfx_surface_id, (0, 0, self.width, self.height),
                    bitstream, qp=self._rdpgfx_encoder.qp)
                payload_bytes = len(bitstream)
            else:
                sequence = self._rdpgfx_clear_sequence
                stream = rdpgfx.build_clearcodec_bitmap_stream(
                    self.width, self.height, rgb, sequence)
                bitmap_pdu = rdpgfx.build_wire_to_surface_clearcodec(
                    self._rdpgfx_surface_id, (0, 0, self.width, self.height), stream)
                self._rdpgfx_clear_sequence = (sequence + 1) & 0xFF
                payload_bytes = len(stream)
        except Exception:
            logging.exception("RDPGFX frame encode failed; reverting to bitmap path")
            self._rdpgfx_avc420 = False
            self._rdpgfx_surface_ready = False
            self._close_rdpgfx_encoder()
            return None
        self._send_gfx_pdu(rdpgfx.build_gfx_frame_start(frame_id, timestamp))
        self._send_gfx_pdu(bitmap_pdu)
        self._send_gfx_pdu(rdpgfx.build_gfx_frame_end(frame_id))
        self._rdpgfx_frame_id = (frame_id + 1) & 0xFFFFFFFF
        self._rdpgfx_last_frame = rgb
        logging.info("RDPGFX %s frame sent frame=%d bytes=%d",
                     self._rdpgfx_codec, frame_id, payload_bytes)
        if drain:
            self._drain_input()
        return 1, max(0, total_tiles - 1)

    # ---------- flow ----------
    def run(self):
        try:
            self._handshake()
            if getattr(self, "_proxy_authorized", False):
                self._proxy_to_native_rdp()
                return
            self._connect_initial()
            self._channel_connect()
            self._secure_settings()
            self._capability_exchange()
            self._start_rdpsnd_negotiation()
            self._finalization()
            # Open RDPGFX only after the full core activation handshake
            # (including control grant and Font Map) has completed.
            self._start_rdpgfx_negotiation()
            self._send_image()
            if self._redirect_sent:
                # MS-RDPBCGR 3.2.5.13.1: once the client has processed the
                # Server Redirection PDU it terminates this connection and
                # reconnects to the target on its own, so only drain it for a
                # short while instead of holding the socket open forever.
                self._read_loop(
                    deadline=time.monotonic() + REDIRECT_DRAIN_SECONDS)
            else:
                self._read_loop()
        except ClientAbort as e:
            logging.info("client aborted: %s", e)
        except Exception:
            logging.exception("conn error")
        finally:
            self._close_rdpgfx_encoder()
            self._stop_audio()
            if self.browser is not None:
                self.browser.stop()
                self.browser = None
            try:
                self.sock.close()
            except OSError:
                pass

    # ---------- phase 1: x.224 ----------
    def _handshake(self):
        raw = self.read_tpkt()
        payload = raw[4:]
        info = framing.parse_x224_cr(payload)
        routing_token = info.get("routing_token")
        if routing_token is not None:
            neg = info.get("neg_req")
            requested = neg.get("requested_protocols") if neg else None
            if requested is not None:
                logging.info("native RDP relay CR requestedProtocols=%d", requested)
            self._proxy_authorized = ROUTING_TICKETS.consume(
                routing_token, self.client_addr)
            if not self._proxy_authorized:
                raise ClientAbort("invalid or expired routing token")
            # The ticket is gateway-only routing metadata. Forward a normal
            # X.224 CR so native TermService does not interpret it as routing.
            self._initial_connection_request = framing.strip_x224_routing_token(raw)
            if DISABLE_HYBRID_EX:
                self._initial_connection_request, before, after = framing.clear_x224_hybrid_ex(
                    self._initial_connection_request)
                if before is not None and after != before:
                    logging.info("native RDP relay compatibility mask requestedProtocols=%d->%d",
                                 before, after)
            logging.info("valid bounded-use routing ticket; proxying native RDP")
            return
        neg = info.get("neg_req")
        logging.info("cr neg=%s", neg)
        if neg is None:
            self.send(framing.build_cc(0, False))
            return
        rproto = neg["requested_protocols"]
        self.requested_protocols = rproto
        neg_flags = framing.RDP_NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED
        if GRAPHICS_CODEC != "bitmap":
            neg_flags |= framing.RDP_NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED
        if rproto & 0x1:
            self.send(framing.build_cc(1, True, neg_flags))
            logging.info("cc sel=1 SSL")
            self._start_tls()
        else:
            self.send(framing.build_cc(0, True, neg_flags))
            logging.info("cc sel=0 RDP")

    def _proxy_to_native_rdp(self):
        """Relay raw TCP bytes so native Windows RDP owns TLS and NLA."""
        try:
            upstream = socket.create_connection(
                (NATIVE_RDP_HOST, NATIVE_RDP_PORT), timeout=5.0)
        except OSError:
            logging.warning("authorized native RDP endpoint unavailable")
            return
        # The relay carries interactive RDP input and small protocol replies;
        # disable Nagle on both TCP legs so they are not held for coalescing.
        for relay_sock in (self.sock, upstream):
            try:
                relay_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                logging.debug("TCP_NODELAY unavailable on RDP relay leg: %s", exc)
        initial_request = getattr(self, "_initial_connection_request", None)
        if initial_request is not None:
            try:
                upstream.sendall(initial_request)
            except OSError:
                upstream.close()
                logging.warning("native RDP proxy failed forwarding initial request")
                return
        self.sock.settimeout(None)
        upstream.settimeout(None)
        errors = []
        byte_counts = {"client": 0, "native": 0}
        error_lock = threading.Lock()
        diagnostics = _NativeRelayDiagnostics()

        def record_error(label, operation, exc):
            # Exception text contains only socket diagnostics; never include
            # bytes from the native RDP/TLS stream in logs.
            with error_lock:
                errors.append((label, operation, exc))
            logging.warning("native RDP relay %s %s failed: %s",
                            label, operation, exc)

        def relay(src, dst, label):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        logging.info("native RDP relay %s EOF after %d bytes",
                                     label, byte_counts[label])
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError as exc:
                            record_error(label, "half-close", exc)
                        return
                    diagnostics.observe(label, data)
                    dst.sendall(data)
                    byte_counts[label] += len(data)
            except OSError as exc:
                record_error(label, "copy", exc)
                # Tell the peer this direction has ended, but leave the
                # reverse pump alive so any final native response can drain.
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError as shutdown_exc:
                    record_error(label, "error-half-close", shutdown_exc)
                # A failure in one direction must stop that direction without
                # destroying the reverse relay. The other pump owns its own
                # EOF/error lifecycle and will finish independently.

        worker = threading.Thread(target=relay,
                                  args=(self.sock, upstream, "client"),
                                  daemon=True)
        worker.start()
        relay(upstream, self.sock, "native")
        worker.join(timeout=2.0)
        upstream.close()
        logging.info("native RDP proxy closed (client_bytes=%d native_bytes=%d "
                     "client_errors=%d native_errors=%d)",
                     byte_counts["client"], byte_counts["native"],
                     sum(1 for label, _, _ in errors if label == "client"),
                     sum(1 for label, _, _ in errors if label == "native"))

    def _start_tls(self):
        logging.info("starting TLS")
        self.sock = ssl_setup.SSL_CTX.wrap_socket(
            self.sock, server_side=True, do_handshake_on_connect=False
        )
        self.sock.do_handshake()
        self.buf = b""
        logging.info("TLS ok cipher=%s", self.sock.cipher()[0])

    # ---------- phase 2: basic settings exchange ----------
    def _connect_initial(self):
        raw = self.read_tpkt()
        info = gcc.parse_connect_initial(raw[4:])
        client_gfx_flag = bool(info.get("gfx_supported"))
        self.width = info["desktop_width"] or self.width
        self.height = info["desktop_height"] or self.height
        self.bpp = info["color_depth"] or self.bpp
        # The dimensions in Client Core Data are the negotiated RDP canvas.
        # A previously observed client viewport may be a phone's portrait
        # dimensions; using it here changes the server desktop and can make
        # the captured frame disagree with the canvas mstsc requested.
        self.input_width = self.width
        self.input_height = self.height
        n = len(info["channels"]) or 4
        # The MCS user channel is 1004 for SERVER_USER_ID=1004. Static
        # virtual channels must start after it; 1004 is not available here.
        self.channel_ids = [contract.MCS_GLOBAL_CHANNEL_ID + 2 + i for i in range(n)]
        self.static_channels = {
            channel.get("name", "").rstrip("\0"): cid
            for channel, cid in zip(info["channels"], self.channel_ids)
        }
        self._rdpgfx_static_channel_id = next(
            (cid for name, cid in self.static_channels.items()
             if name.casefold() == "drdynvc"), None)
        self._client_gfx_supported = (client_gfx_flag and
                                      self._rdpgfx_static_channel_id is not None and
                                      GRAPHICS_CODEC != "bitmap")
        logging.info(
            "client desktop %dx%d bpp=%s chans=%s -> ids %s",
            self.width, self.height, info["color_depth"],
            [c["name"] for c in info["channels"]], self.channel_ids,
        )
        logging.info("graphics_codec=%s client GFX support=%s earlyCapabilityFlags=0x%04x drdynvc=%s",
                     GRAPHICS_CODEC,
                     self._client_gfx_supported,
                     info.get("early_capability_flags", 0),
                     self._rdpgfx_static_channel_id)
        resp = gcc.build_connect_response(
            self.width, self.height, self.channel_ids, self.requested_protocols
        )
        self.send(resp)
        logging.info("connect response sent (%d bytes)", len(resp))

    # ---------- phase 3: channel connection ----------
    def _channel_connect(self):
        self.sock.settimeout(10.0)
        joined = set()
        expected = 2 + len(self.channel_ids)  # user channel + global + statics
        logging.info("expecting %d channel joins", expected)
        while True:
            try:
                raw = self.read_tpkt()
            except socket.timeout:
                logging.info("channel connect timeout after %d joins", len(joined))
                break
            except ClientAbort:
                logging.info("client aborted during channel connect")
                break
            parsed = gcc.parse_domain_pdu(raw)
            name = parsed["name"]
            uid = parsed.get("user_id")
            cid = parsed.get("channel_id")
            logging.info("chan pdu=%s uid=%s cid=%s raw=%s", name, uid, cid, raw.hex())
            if "erect_domain_request" in name:
                continue
            if "attach_user_request" in name:
                if not self.sent_attach_confirm:
                    self.send(gcc.attach_user_confirm(SERVER_USER_ID))
                    self.sent_attach_confirm = True
                    logging.info("attach user confirm sent")
                continue
            if "channel_join_request" in name:
                if cid is None:
                    cid = contract.MCS_GLOBAL_CHANNEL_ID
                self.send(gcc.channel_join_confirm(cid, SERVER_USER_ID, True))
                joined.add(cid)
                logging.info("joined %d (%d/%d)", cid, len(joined), expected)
                if len(joined) >= expected:
                    break
                continue
            if "send_data_request" in name or "send_data_indication" in name:
                # client moved ahead of channel joins
                self.buf = raw + self.buf
                logging.info("send-data seen during channel connect; deferring")
                break
            logging.debug("channel connect: unhandled %s", name)
        self.sock.settimeout(None)

    # ---------- phase 5: secure settings (client info) ----------
    def _secure_settings(self):
        self.sock.settimeout(5.0)
        try:
            raw = self.read_tpkt()
            parsed = gcc.parse_domain_pdu(raw)
            ud = parsed.get("user_data") or b""
            logging.info("client info frame len=%d", len(ud))
            info = pdu.parse_client_info(ud) if hasattr(pdu, "parse_client_info") else None
            if info:
                logging.info("client info parsed %s", info)
        except socket.timeout:
            logging.info("no client info frame (continuing)")
        except ClientAbort:
            logging.info("client aborted before client info (continuing)")
        self.sock.settimeout(None)

    # ---------- phase 6/8: licensing + capability exchange ----------
    def _capability_exchange(self):
        # Send license error PDU first (required by some clients)
        lic = pdu.build_license_error_valid_client()
        self.send_pdu(lic)
        logging.info("license valid client sent")
        da = pdu.build_demand_active(self.width, self.height, self.bpp)
        self.send_pdu(da)
        logging.info("demand active sent")
        self.sock.settimeout(8.0)
        got = False
        while True:
            try:
                raw = self.read_tpkt()
            except socket.timeout:
                logging.info("confirm active timeout")
                break
            except ClientAbort:
                logging.info("client aborted before confirm active")
                break
            parsed = gcc.parse_domain_pdu(raw)
            channel_id = parsed.get("channel_id")
            if channel_id == self._rdpgfx_static_channel_id:
                self._handle_drdynvc_data(channel_id,
                                           parsed.get("user_data") or b"")
                continue
            ud = parsed.get("user_data") or b""
            if len(ud) < 6:
                continue
            pt = struct.unpack_from("<H", ud, 2)[0] & 0x0F
            logging.info("capability exchange rx pdu_type=%d", pt)
            if pt == 3:
                info = pdu.parse_confirm_active(ud)
                self._nscodec_id = info.get("nscodec_id")
                client_cll = info.get("nscodec_color_loss_level")
                if client_cll and 1 <= client_cll <= 7:
                    self._nscodec_color_loss_level = min(3, client_cll)
                self._surface_bits_supported = bool(
                    info.get("surface_command_flags", 0) & 0x00000002)
                if self._nscodec_id is not None and self._surface_bits_supported:
                    logging.info("NSCodec negotiated: codec_id=%d color_loss=%d",
                                 self._nscodec_id,
                                 self._nscodec_color_loss_level)
                else:
                    logging.info("NSCodec unavailable; using legacy bitmap RLE")
                if (0 < info["desktop_width"] <= 8192 and
                        0 < info["desktop_height"] <= 8192):
                    self.input_width = info["desktop_width"]
                    self.input_height = info["desktop_height"]
                logging.info("confirm active client viewport %dx%d; "
                             "render canvas remains %dx%d",
                             self.input_width, self.input_height,
                             self.width, self.height)
                logging.debug("confirm active capabilities %s", info)
                fit_scale = min(self.input_width / max(1, self.width),
                                self.input_height / max(1, self.height))
                logging.info(
                    "pointer canvas %dx%d; fitted desktop %dx%d at %.3fx offset %.1f,%.1f",
                    self.input_width, self.input_height, self.width, self.height,
                    fit_scale,
                    (self.input_width - self.width * fit_scale) / 2,
                    (self.input_height - self.height * fit_scale) / 2,
                )
                got = True
                break
        self.sock.settimeout(None)
        logging.info("confirm active received=%s", got)

    def _start_rdpsnd_negotiation(self):
        channel_id = self.static_channels.get("rdpsnd")
        if channel_id is None:
            logging.info("client did not negotiate rdpsnd; audio disabled")
            return
        self._audio_offered_formats = (
            rdpsnd.AudioFormat.pcm(48000, 2),
            rdpsnd.AudioFormat.pcm(44100, 2),
            rdpsnd.AudioFormat.pcm(16000, 1),
        )
        self._send_rdpsnd(rdpsnd.build_server_formats(self._audio_offered_formats), channel_id)
        logging.info("rdpsnd server formats sent on channel %d", channel_id)

    def _send_rdpsnd(self, packet, channel_id=None):
        channel_id = channel_id or self.static_channels.get("rdpsnd")
        if channel_id is None:
            return
        for chunk in rdpsnd.wrap_virtual_channel(packet, chunk_size=1200):
            self.send_pdu(chunk, channel_id, quiet=True)

    def _handle_rdpsnd_packet(self, packet):
        parsed = rdpsnd.parse_pdu(packet)
        if parsed["msg_type"] == rdpsnd.SNDC_FORMATS:
            reply = rdpsnd.parse_client_formats(
                packet, server_formats=self._audio_offered_formats)
            selected = rdpsnd.select_pcm_format(reply)
            if selected is None:
                logging.warning("rdpsnd client offered no supported PCM formats")
                return
            self._audio_format_no, self._audio_format = selected
            self._audio_alive = bool(reply["flags"] & 1)
            logging.info("rdpsnd selected format index=%d %dHz/%dch/%dbit client_alive=%s",
                         self._audio_format_no, self._audio_format.samples_per_sec,
                         self._audio_format.channels, self._audio_format.bits_per_sample,
                         self._audio_alive)
            if self._audio_alive:
                if self._sensitive_page_active:
                    # The OTP portal is static UI. Capturing loopback silence
                    # wastes scarce bandwidth and competes with its first
                    # bitmap updates; native RDP starts after OTP redirection.
                    self._audio_alive = False
                    logging.info("rdpsnd playback disabled for OTP portal")
                else:
                    if reply["version"] < 6:
                        self._send_rdpsnd_training()
                    self._start_audio_capture()
            else:
                logging.warning("rdpsnd client did not advertise audio playback capability")
        elif parsed["msg_type"] == rdpsnd.SNDC_WAVECONFIRM:
            confirm = rdpsnd.parse_wave_confirm(packet)
            if self._audio_confirms_seen < 8:
                logging.info("rdpsnd wave confirm block=%d waiting=%s timestamp=%d",
                             confirm["block_no"], self._audio_waiting_block,
                             confirm["timestamp"])
            self._audio_confirms_seen += 1
            with self._audio_confirm_condition:
                if confirm["block_no"] == self._audio_waiting_block:
                    self._audio_confirm_count += 1
                    self._audio_confirm_condition.notify_all()
        elif parsed["msg_type"] == rdpsnd.SNDC_QUALITYMODE:
            self._send_rdpsnd_training()
        elif parsed["msg_type"] == rdpsnd.SNDC_TRAINING:
            confirm = rdpsnd.parse_training(packet)
            if (self._training_pending and
                    confirm["timestamp"] == self._training_timestamp and
                    confirm["pack_size"] == self._training_pack_size):
                self._training_pending = False
                self._audio_ready.set()
                logging.info("rdpsnd training exchange complete; audio stream ready")

    def _send_rdpsnd_training(self):
        if self._training_pending or self._audio_ready.is_set():
            return
        self._training_timestamp = int(time.monotonic() * 1000) & 0xFFFF
        self._training_pack_size = 0
        self._training_pending = True
        self._send_rdpsnd(rdpsnd.build_training(
            timestamp=self._training_timestamp, pack_size=self._training_pack_size))
        logging.info("rdpsnd training request sent")

    def _handle_rdpsnd_channel(self, channel_id, data):
        if channel_id != self.static_channels.get("rdpsnd"):
            return
        vc = rdpsnd.parse_virtual_channel(data)
        flags = vc["flags"]
        if flags & rdpsnd.CHANNEL_FLAG_FIRST:
            self._audio_vc_rx.clear()
            self._audio_vc_expected = vc["total_length"]
        if self._audio_vc_expected is None:
            return
        self._audio_vc_rx.extend(vc["data"])
        if not flags & rdpsnd.CHANNEL_FLAG_LAST:
            return
        expected = self._audio_vc_expected
        payload = bytes(self._audio_vc_rx)
        self._audio_vc_rx.clear()
        self._audio_vc_expected = None
        if len(payload) != expected:
            logging.warning("rdpsnd virtual-channel size mismatch: %d != %d",
                            len(payload), expected)
            return
        self._audio_rx.extend(payload)
        while len(self._audio_rx) >= 4:
            packet_len = 4 + struct.unpack_from("<H", self._audio_rx, 2)[0]
            if len(self._audio_rx) < packet_len:
                break
            packet = bytes(self._audio_rx[:packet_len])
            del self._audio_rx[:packet_len]
            self._handle_rdpsnd_packet(packet)

    def _start_audio_capture(self):
        if (not self._audio_alive or self._audio_format is None or self.browser is None or
                self._audio_capture is not None or self._audio_starting):
            return
        self._audio_starting = True
        try:
            import audio_capture
            capture = audio_capture.ProcessLoopbackCapture(
                self.browser.proc.pid, queue_size=64).start()
            if capture.format is None:
                capture.stop()
                raise RuntimeError("process loopback started without a PCM format")
            self._audio_capture = capture
            self._audio_stop.clear()
            self._audio_thread = threading.Thread(
                target=self._audio_send_loop, name="rdpsnd-send", daemon=True)
            self._audio_thread.start()
            logging.info("rdpsnd loopback capture started pid=%d source=%dHz/%dch",
                         self.browser.proc.pid, capture.format.sample_rate,
                         capture.format.channels)
        except Exception:
            self._audio_capture = None
            logging.exception("rdpsnd loopback capture failed")
        finally:
            self._audio_starting = False

    def _audio_send_loop(self):
        audio_clock = int(time.monotonic() * 1000) & 0xFFFFFFFF
        pending_pcm = bytearray()
        last_capture_stats = time.monotonic()
        last_dropped_chunks = 0
        sent_blocks = 0
        block_bytes = max(self._audio_format.block_align,
                          self._audio_format.samples_per_sec *
                          self._audio_format.block_align // 25)
        block_bytes -= block_bytes % self._audio_format.block_align
        try:
            while not self._audio_stop.is_set():
                if not self._audio_ready.wait(0.25):
                    continue
                try:
                    chunk = self._audio_capture.get(timeout=0.25)
                except Exception:
                    continue
                pcm = _convert_audio_pcm(chunk.pcm, self._audio_capture.format,
                                         self._audio_format)
                pending_pcm.extend(pcm)
                now = time.monotonic()
                if now - last_capture_stats >= 5.0:
                    dropped = self._audio_capture.dropped_chunks
                    logging.info("rdpsnd capture queue: dropped=%d in last %.1fs",
                                 dropped - last_dropped_chunks,
                                 now - last_capture_stats)
                    last_dropped_chunks = dropped
                    last_capture_stats = now
                while len(pending_pcm) >= block_bytes and not self._audio_stop.is_set():
                    part = bytes(pending_pcm[:block_bytes])
                    del pending_pcm[:block_bytes]
                    wave = rdpsnd.build_wave2(
                        part, format_no=self._audio_format_no,
                        block_no=self._audio_block_no,
                        audio_timestamp=audio_clock & 0xFFFFFFFF)
                    with self._audio_confirm_condition:
                        self._audio_waiting_block = self._audio_block_no
                        self._audio_confirm_count = 0
                    self._send_rdpsnd(wave)
                    # Captured PCM already arrives in real time. Waiting here
                    # for MSTSC's playback confirmation made the sender slower
                    # than the capture clock and caused the bounded capture
                    # queue to discard hundreds of chunks per minute. Keep
                    # confirmations diagnostic only; the capture clock paces
                    # these 40 ms blocks naturally.
                    frames = len(part) // self._audio_format.block_align
                    audio_clock += int(frames * 1000 /
                                       self._audio_format.samples_per_sec)
                    self._audio_block_no = (self._audio_block_no + 1) & 0xFF
                    sent_blocks += 1
                    if sent_blocks % 125 == 0:
                        logging.info("rdpsnd sent %d audio blocks (~%d s)",
                                     sent_blocks,
                                     sent_blocks * block_bytes //
                                     (self._audio_format.samples_per_sec *
                                      self._audio_format.block_align))
        except Exception:
            if not self._audio_stop.is_set():
                logging.exception("rdpsnd sender stopped")

    def _stop_audio(self):
        self._audio_stop.set()
        with self._audio_confirm_condition:
            self._audio_confirm_condition.notify_all()
        capture, self._audio_capture = self._audio_capture, None
        if capture is not None:
            capture.stop()
        thread, self._audio_thread = self._audio_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    # ---------- phase 9: connection finalization ----------
    def _finalization(self):
        self.send_pdu(pdu.build_synchronize())
        self.send_pdu(pdu.build_control_cooperate())
        logging.info("server sync + control(cooperate) sent")
        self.sock.settimeout(5.0)
        granted = False
        font = False
        while not font:
            try:
                raw = self.read_tpkt()
            except socket.timeout:
                logging.info("finalization timeout granted=%s font=%s", granted, font)
                break
            except ClientAbort:
                logging.info("client aborted in finalization")
                break
            parsed = gcc.parse_domain_pdu(raw)
            channel_id = parsed.get("channel_id")
            if channel_id == self._rdpgfx_static_channel_id:
                self._handle_drdynvc_data(channel_id,
                                           parsed.get("user_data") or b"")
                continue
            if channel_id == self.static_channels.get("rdpsnd"):
                try:
                    self._handle_rdpsnd_channel(channel_id, parsed.get("user_data") or b"")
                except Exception:
                    logging.exception("rdpsnd receive failed during finalization")
                continue
            ud = parsed.get("user_data") or b""
            if len(ud) < 18:
                continue
            pt = struct.unpack_from("<H", ud, 2)[0] & 0x0F
            if pt != 7:
                logging.info("finalization non-data pdu %d", pt)
                continue
            pt2 = ud[14]
            logging.info("finalization pduType2=0x%02x", pt2)
            if pt2 == 0x14:
                action = struct.unpack_from("<H", ud, 18)[0] if len(ud) >= 20 else 0
                logging.info("finalization control action=0x%04x", action)
                if action == 0x0001 and not granted:  # CTRLACTION_REQUEST_CONTROL
                    self.send_pdu(pdu.build_control_granted())
                    granted = True
                    logging.info("granted control sent")
            elif pt2 == 0x27:
                self.send_pdu(pdu.build_font_map())
                font = True
                logging.info("font list received; font map sent")
        self.sock.settimeout(None)

    # ---------- graphics ----------
    def _send_image(self):
        if SKIP_IMAGE:
            logging.info("SKIP_IMAGE set - not painting")
            return
        if SEND_POINTER:
            try:
                self.send_pdu(bitmap.build_pointer_default())
                logging.info("pointer sent")
            except Exception:
                logging.warning("pointer send failed")

        import os as _os
        self.bpp = int(_os.environ.get('RDP_BPP') or 0) or self.bpp
        tile_width, tile_height = BITMAP_TILE_WIDTH, BITMAP_TILE_HEIGHT

        # A live URL goes straight to the persistent browser: taking one
        # throwaway screenshot first would stall the session for many seconds
        # (and time out entirely on a heavy page such as YouTube).
        _html0 = _normalize_page_target(_os.environ.get("RDP_HTML") or DEFAULT_HTML)
        if _html0.startswith(("http://", "https://", "file://")) and \
                not _os.environ.get("RDP_STATIC", ""):
            logging.info("initial frame: %dx%d bpp=%d tile=%dx%d",
                         self.width, self.height, self.bpp,
                         tile_width, tile_height)
            try:
                self._browser_session(_html0, tile_width)
                return
            except ClientAbort:
                raise
            except Exception:
                logging.exception("browser session failed; falling back")
                self._read_loop()
                return

        img = self._frame_source()
        logging.info(
            "sending image %dx%d bpp=%d tiles=%dx%d (%d rectangles)",
            self.width, self.height, self.bpp, tile_width, tile_height,
            ((self.width + tile_width - 1) // tile_width) *
            ((self.height + tile_height - 1) // tile_height),
        )

        # make sure the client has left Confirm Active before painting
        self.sock.settimeout(1.0)
        try:
            import time as _t
            _t.sleep(0.4)
        finally:
            self.sock.settimeout(None)

        import os as _oe
        import time as _time
        test = _oe.environ.get("RDP_TEST_UPDATE") or ""
        if test:
            logging.info("TEST UPDATE MODE: %s", test)
            if test == "sync":
                updu = pdu.share_data(contract.PDUTYPE2_UPDATE, struct.pack("<HH", 0x0003, 0))
                self.send_pdu(updu)
                logging.info("test: synchronize update sent (%d bytes)", len(updu))
                self._drain_input()
                _time.sleep(3.0)
                logging.info("test RESULT: sync update SURVIVED")
            elif test == "tiny":
                updu = bitmap.build_bitmap_update_slow([{
                    "left": 0, "top": 0, "right": 7, "bottom": 7,
                    "width": 8, "height": 8, "bpp": self.bpp,
                    "data": bitmap.pack_pixels(b"\x00\x00\x00" * 64, 8, 8, self.bpp),
                }])
                self.send_pdu(updu)
                logging.info("test: tiny 8x8 bitmap sent (%d bytes)", len(updu))
                self._drain_input()
                _time.sleep(3.0)
                logging.info("test RESULT: tiny bitmap SURVIVED")
            elif test.startswith("rows:"):
                nrows = int(test.split(":", 1)[1])
                packed = bitmap.pack_pixels(
                    b"\x20\x40\x60" * (self.width * nrows), self.width, nrows, self.bpp
                )
                updu = bitmap.build_bitmap_update_slow([{
                    "left": 0, "top": 0, "right": self.width - 1, "bottom": nrows - 1,
                    "width": self.width, "height": nrows, "bpp": self.bpp,
                    "data": packed,
                }])
                logging.info("test: bitmap %dx%d pdu=%d bytes",
                             self.width, nrows, len(updu))
                self.send_pdu(updu)
                self._drain_input()
                _time.sleep(3.0)
                logging.info("test RESULT: rows=%d SURVIVED", nrows)
            elif test.startswith("cols:"):
                ncols = int(test.split(":", 1)[1])
                packed = bitmap.pack_pixels(b"\x20\x40\x60" * ncols, ncols, 1, self.bpp)
                updu = bitmap.build_bitmap_update_slow([{
                    "left": 0, "top": 0, "right": ncols - 1, "bottom": 0,
                    "width": ncols, "height": 1, "bpp": self.bpp,
                    "data": packed,
                }])
                logging.info("test: bitmap %dx1 pdu=%d bytes", ncols, len(updu))
                self.send_pdu(updu)
                self._drain_input()
                _time.sleep(3.0)
                logging.info("test RESULT: cols=%d SURVIVED", ncols)
            return

        import time as _time
        import os as _oe2
        sent, skipped = self._paint(img, tile_width, force=True)
        logging.info("image complete (%d rectangles sent, %d unchanged skipped)", sent, skipped)

        # Keep the session alive and re-paint when the source changes.
        # Only tiles whose pixels actually changed are sent (tile diffing).
        html = _oe2.environ.get("RDP_HTML") or DEFAULT_HTML
        if not html or not _is_renderable(html):
            self._read_loop()
            return

        page_url = _normalize_page_target(html)
        interval = float(_oe2.environ.get("RDP_HTML_INTERVAL") or 0.5)
        logging.info("watching %s for changes (interval %.2fs)", html, interval)
        import render as _render
        last_sig = None

        # Client input drives the screen: any key press marks the frame dirty
        # so the watch loop re-renders and pushes only the changed tiles.
        # This is the input -> output half of the session.
        def _on_input(ev):
            if ev["code"] == fastpath.CODE_SCANCODE and not ev["released"]:
                self.input.dirty = True
            elif ev["code"] == fastpath.CODE_UNICODE and not ev["released"]:
                self.input.dirty = True
        self.on_input = _on_input

        while True:
            self._drain_input()
            dirty = self.input.dirty
            if dirty:
                self.input.dirty = False
                # A live URL has a constant signature, so drop the cached
                # frame to force a fresh browser screenshot.
                _render._cache.clear()
            try:
                sig = _render.page_signature(page_url, self.width, self.height)
            except OSError:
                break
            if dirty or sig != last_sig:
                last_sig = sig
                try:
                    new = _render.render_page(page_url, self.width, self.height)
                except Exception as exc:
                    logging.warning("re-render failed: %s", exc)
                    _time.sleep(interval)
                    continue
                s, k = self._paint(new, tile_size)
                reason = "input" if dirty else "source"
                logging.info("repaint (%s): %d tiles sent, %d unchanged skipped",
                             reason, s, k)
            _time.sleep(interval)

    def _frame_source(self):
        """RGB frame to paint: a page rendered by the browser, or a test image."""
        html = os.environ.get("RDP_HTML") or DEFAULT_HTML
        if html and _is_renderable(html):
            import render
            logging.info("rendering %s", html)
            return render.render_page(_normalize_page_target(html),
                                      self.width, self.height)
        return bitmap.make_test_image(self.width, self.height)

    def _redirect_target(self):
        """Client reachable address of this server, as an IP literal.

        MS-RDPBCGR 2.2.13.1: TargetNetAddress carries the IP address of the
        server the client has to reconnect to, so a name is resolved first.
        The port is not part of the PDU: the client uses the standard RDP
        port 3389 of that address.
        """
        target = os.environ.get("RDP_REDIRECT_HOST", "").strip()
        if not target:
            try:
                target = self.sock.getsockname()[0]
            except OSError:
                target = "127.0.0.1"
        if target in ("0.0.0.0", "::", ""):
            target = "127.0.0.1"
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, target)
            except OSError:
                continue
            return target
        try:
            return socket.gethostbyname(target)
        except OSError:
            logging.warning("redirect target %r is not an IP address; "
                            "falling back to 127.0.0.1", target)
            return "127.0.0.1"

    # ---------- live browser session ----------
    def _browser_session(self, html, tile_size):
        """Drive a persistent headless Chrome over CDP and stream its frames.

        Chrome pushes frames via Page.startScreencast when the compositor has
        damage.  Screencast frames are JPEG over the websocket and decoded with
        PyAV (NVENC GPU).  If the cast goes silent (idle page or a YouTube
        player that tears down its <video> element), fall back to polling
        Page.captureScreenshot so the screen never freezes.

        Client input is forwarded into the same browser, so a click in mstsc
        is a click on the page.
        """
        import browser as _br
        br = _br.Browser(self.width, self.height)
        self.browser = br
        br.start()
        touch_mode = self.input_height > self.input_width * 1.4
        if touch_mode:
            br._send("Emulation.setTouchEmulationEnabled", {
                "enabled": True, "maxTouchPoints": 1,
            })
            br._send("Page.addScriptToEvaluateOnNewDocument", {
                "source": (
                    "(function(){"
                    "if(window.__rdpTouchMouseGuard)return;"
                    "window.__rdpTouchMouseGuard=true;"
                    "['mousemove','mousedown','mouseup','mouseover','mouseout']"
                    ".forEach(function(type){document.addEventListener(type,function(e){"
                    "if(e.sourceCapabilities&&e.sourceCapabilities.firesTouchEvents){"
                    "e.preventDefault();e.stopImmediatePropagation();}"
                    "},true);});"
                    "function moveCursor(x,y){"
                    "var d=document.getElementById('__rdp-virtual-cursor');"
                    "if(!d){d=document.createElement('div');"
                    "d.id='__rdp-virtual-cursor';d.setAttribute('aria-hidden','true');"
                    "d.style.cssText='position:fixed;z-index:2147483646;width:24px;height:32px;'+"
                    "'pointer-events:none;filter:drop-shadow(1px 1px 1px #000b);';"
                    "d.innerHTML='<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"32\" viewBox=\"0 0 24 32\"><path d=\"M2 1v25l6-6 4 10 5-2-5-10h9L2 1z\" fill=\"white\" stroke=\"black\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/><path d=\"M4 5v16l4-4 4 9 2-1-4-10h6L4 5z\" fill=\"#d9e8ff\"/></svg>';"
                    "document.documentElement.appendChild(d);}"
                    "d.style.left=x+'px';d.style.top=y+'px';}"
                    "document.addEventListener('pointermove',function(e){"
                    "moveCursor(e.clientX,e.clientY);},true);"
                    "document.addEventListener('pointerdown',function(e){"
                    "moveCursor(e.clientX,e.clientY);},true);"
                    "window.__rdpMoveVirtualCursor=moveCursor;"
                    "})();"
                ),
            })
            logging.info("phone input enabled as native browser touch (%dx%d)",
                         self.input_width, self.input_height)
        html = _normalize_page_target(html)
        portal_page = _is_portal_page(html)
        self._sensitive_page_active = portal_page
        br.navigate(html)
        if touch_mode:
            try:
                br.show_virtual_cursor(self.width // 2, self.height // 2)
            except Exception as exc:
                logging.debug("virtual cursor init failed: %s",
                              type(exc).__name__)
        otp_challenge = None
        otp_delivery_ok = False
        otp_delivery_event = None
        otp_delivery_result = {}
        if portal_page:
            allowed, retry_after = OTP_RATE_LIMITER.allow(self.client_addr)
            if allowed:
                otp_challenge = portal.OtpChallenge(
                    self.client_addr, ttl_seconds=OTP_TTL_SECONDS,
                    max_attempts=OTP_MAX_ATTEMPTS)
                otp_code = otp_challenge.take_delivery_code()
                otp_delivery_event = threading.Event()

                def deliver_initial_otp(code):
                    try:
                        otp_delivery_result["ok"] = _send_otp_notification(code)
                    finally:
                        otp_delivery_event.set()

                threading.Thread(target=deliver_initial_otp, args=(otp_code,),
                                 name="rdpotp-initial-notify", daemon=True).start()
                otp_code = None
                status = "Sending access code..."
            else:
                status = "Too many codes requested. Try again in %d seconds." % retry_after
                logging.warning("OTP notification rate limit reached")
            br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus(%s, %s, %s)" % (
                json.dumps("error" if not allowed else "success"),
                json.dumps(status),
                json.dumps(otp_challenge.seconds_remaining()
                           if allowed and otp_challenge is not None else 0.0)))
        if not portal_page:
            self._start_audio_capture()

        scale = float(os.environ.get("RDP_CAST_SCALE") or RENDER_SCALE)
        if not 0.25 <= scale <= 1.0:
            raise ValueError("RDP_CAST_SCALE must be between 0.25 and 1.0")
        interval = float(os.environ.get("RDP_HTML_INTERVAL") or 0.03)
        logging.info("streaming %s (screencast scale=%.2f, interval=%.3fs)",
                     html, scale, interval)

        pressed_buttons = set()
        ignored_buttons = set()
        button_down_at = {}
        last_click = {"time": 0.0, "x": -10000, "y": -10000, "button": None}
        shift_keys = set()
        hangul_mode = False
        last_hangul_toggle = 0.0
        composer = hangul_input.HangulComposer()

        def _map_pointer(x, y):
            # Scale only for actual viewport letterboxing. When phone and
            # desktop dimensions match, preserve the reported touch coordinate
            # exactly; never apply a device-specific cursor offset.
            return _map_pointer_to_desktop(
                x, y, self.input_width, self.input_height,
                self.width, self.height)

        def _apply_composition(change):
            if change is None:
                return False
            delete, insert = change
            for _ in range(delete):
                br.key("Backspace", code="Backspace", vk=8, kind="keyDown")
                br.key("Backspace", code="Backspace", vk=8, kind="keyUp")
            br.insert_text(insert)
            return True

        def _on_input(ev):
            nonlocal frames, USE_POLLING, cast_frames, cast_start, last_cast
            nonlocal hangul_mode, last_hangul_toggle
            code = ev["code"]
            if code in (fastpath.CODE_MOUSE, fastpath.CODE_MOUSEX):
                x, y, outside = _map_pointer(ev["x"], ev["y"])
                if ev["wheel"]:
                    try:
                        if ev["horizontal"]:
                            br.wheel(x, y, delta_x=ev["wheel"])
                        else:
                            br.wheel(x, y, delta_y=-ev["wheel"])
                    except Exception as exc:
                        logging.warning("wheel failed: %s", exc)
                elif ev["button"]:
                    composer.commit()
                    button = ev["button_name"]
                    try:
                        if ev["down"] and button not in pressed_buttons:
                            now = time.monotonic()
                            if (last_click["button"] == button and
                                    now - last_click["time"] < 0.05 and
                                    abs(x - last_click["x"]) <= 8 and
                                    abs(y - last_click["y"]) <= 8):
                                ignored_buttons.add(button)
                                return
                            ignored_buttons.discard(button)
                            if touch_mode and button == "left":
                                br.touch("touchStart", x, y)
                                logging.info(
                                    "phone touch start raw=(%d,%d) desktop=(%d,%d) flags=0x%04x",
                                    ev["x"], ev["y"], x, y,
                                    ev["pointer_flags"])
                            else:
                                br.mouse(x, y, "mouseMoved", "none")
                                br.mouse(x, y, "mousePressed", button,
                                         click_count=1)
                            pressed_buttons.add(button)
                            button_down_at[button] = time.monotonic()
                        elif ev["down"] and button in pressed_buttons and ev["moved"]:
                            if touch_mode and button == "left":
                                br.touch("touchMove", x, y)
                            else:
                                br.mouse(x, y, "mouseMoved", button)
                        elif (not ev["down"] and button in ignored_buttons):
                            ignored_buttons.discard(button)
                        elif not ev["down"] and button in pressed_buttons:
                            if touch_mode and button == "left":
                                br.touch("touchEnd")
                            else:
                                br.mouse(x, y, "mouseReleased", button,
                                         click_count=1)
                            pressed_buttons.discard(button)
                            pressed_at = button_down_at.pop(button, None)
                            held_for = (time.monotonic() - pressed_at
                                        if pressed_at is not None else 0.0)
                            last_click.update(time=time.monotonic(), x=x, y=y,
                                              button=button)
                            if (portal_page and button == "left" and
                                    held_for >= 0.65):
                                try:
                                    br.evaluate(
                                        "window.__rdpRequestResend && "
                                        "window.__rdpRequestResend()")
                                    logging.info(
                                        "portal resend requested by %.2fs phone hold",
                                        held_for)
                                except Exception as exc:
                                    logging.warning(
                                        "portal hold-to-resend failed: %s",
                                        type(exc).__name__)
                            logging.info(
                                "touch %s raw=(%d,%d) desktop=(%d,%d) clamped=%s",
                                button, ev["x"], ev["y"], x, y, outside)
                    except Exception as exc:
                        logging.warning("mouse button failed: %s", exc)
                elif touch_mode and (ev["down"] or "touch" in pressed_buttons):
                    # Some mobile RDP clients encode a tap as a generic
                    # PTR_DOWN sequence without PTR_BUTTON1. Preserve those
                    # touch coordinates instead of waiting for a drag/move.
                    try:
                        if ev["down"] and "touch" not in pressed_buttons:
                            br.touch("touchStart", x, y)
                            pressed_buttons.add("touch")
                            button_down_at["touch"] = time.monotonic()
                            logging.info(
                                "phone touch start raw=(%d,%d) desktop=(%d,%d) flags=0x%04x",
                                ev["x"], ev["y"], x, y, ev["pointer_flags"])
                        elif ev["down"] and ev["moved"]:
                            br.touch("touchMove", x, y)
                        elif not ev["down"]:
                            br.touch("touchEnd")
                            pressed_buttons.discard("touch")
                            button_down_at.pop("touch", None)
                            logging.info(
                                "phone touch end raw=(%d,%d) desktop=(%d,%d) flags=0x%04x",
                                ev["x"], ev["y"], x, y, ev["pointer_flags"])
                    except Exception as exc:
                        logging.warning("phone touch event failed: %s", exc)
                elif ev["moved"]:
                    try:
                        if touch_mode and "left" in pressed_buttons:
                            br.touch("touchMove", x, y)
                        elif touch_mode:
                            br.mouse(x, y, "mouseMoved", "none")
                        else:
                            br.mouse(x, y, "mouseMoved",
                                     next(iter(pressed_buttons), "none"))
                    except Exception:
                        pass
            elif code == fastpath.CODE_SCANCODE:
                sc = ev["scancode"]
                if sc in (0x2A, 0x36):
                    if ev["released"]:
                        shift_keys.discard(sc)
                    else:
                        shift_keys.add(sc)
                    return
                if sc in (0x72, 0xF2) or (sc == 0x38 and ev["extended"]):
                    if not ev["released"] and time.monotonic() - last_hangul_toggle > 0.15:
                        composer.commit()
                        hangul_mode = not hangul_mode
                        last_hangul_toggle = time.monotonic()
                        logging.info("Hangul input %s", "on" if hangul_mode else "off")
                    return
                if ev["released"]:
                    return
                name = ev["name"]
                if not self._sensitive_page_active:
                    logging.info("key %s -> browser", name)
                try:
                    t0 = time.time()
                    if hangul_mode and name == "Backspace" and _apply_composition(
                            composer.update(backspace=True)):
                        return
                    if len(name) == 1 and name.isalpha():
                        key = name.upper() if shift_keys else name.lower()
                        if hangul_mode and key.lower() in hangul_input.KEYS:
                            _apply_composition(composer.update(key))
                            return
                    composer.commit()
                    if len(name) == 1:
                        br.type_text(key if name.isalpha() else name)
                    elif name == "Enter":
                        br.key("Enter", code="Enter", text="\r", vk=13, kind="keyDown")
                        br.key("Enter", code="Enter", text="\r", vk=13, kind="keyUp")
                    elif name == "Backspace":
                        br.key("Backspace", code="Backspace", vk=8, kind="keyDown")
                        br.key("Backspace", code="Backspace", vk=8, kind="keyUp")
                    elif name == "Space":
                        br.type_text(" ")
                    elif name == "Tab":
                        br.key("Tab", code="Tab", vk=9, kind="keyDown")
                        br.key("Tab", code="Tab", vk=9, kind="keyUp")
                    logging.info("key injected in %.3fs", time.time() - t0)
                except Exception as exc:
                    logging.warning("key inject failed: %s", exc)
            elif code == fastpath.CODE_UNICODE and not ev["released"]:
                ch = ev.get("unicode") or ""
                if ch:
                    composer.commit()
                    if not self._sensitive_page_active:
                        logging.info("key unicode %r -> browser", ch)
                    try:
                        t0 = time.time()
                        br.insert_text(ch)
                        logging.info("key injected in %.3fs", time.time() - t0)
                    except Exception as exc:
                        logging.warning("key inject failed: %s", exc)

            # ?낅젰 ??利됱떆 ?꾨젅???붿껌? ?대쭅???대? 20fps濡??뚭퀬 ?덉뼱 遺덊븘??

        self.on_input = _on_input

        # Start screencast with JPEG + NVENC decode
# JPEG q=60 is the sweet spot; 70+ gives diminishing returns on size.
        # maxFramesInFlight=5 + sendLastFrame keeps the Chrome pipe full.
        cast_format = "png" if portal_page else "jpeg"
        br.start_screencast(
            quality=int(os.environ.get("RDP_CAST_QUALITY") or 60),
            scale=scale, format=cast_format)

        frames = 0
        last_change = time.time()
        last_cast = time.time()
        fallback = float(os.environ.get("RDP_CAST_FALLBACK") or 0.5)
        # Track screencast framerate; if it stays below threshold, switch to
        # pure JPEG polling which is more predictable for video content.
        cast_frames = 0
        cast_start = time.time()
        USE_POLLING = False
        MIN_CAST_FPS = 15.0
        EVAL_WINDOW = 2.0
        # Keep fallback polling on the same capture scale. Browser.screenshot
        # resizes each frame back to the negotiated RDP canvas before painting.
        poll_scale = float(os.environ.get("RDP_POLL_SCALE") or scale)
        # Never exit this loop on a capture error: leaving it used to drop the
        # session into _read_loop(), which keeps draining input but paints
        # nothing -- the screen froze while keystrokes still worked.
        # Repeated screenshot timeouts mean the Chrome compositor is stuck.
        fails = 0
        frame_interval = 1.0 / MAX_FRAME_RATE if MAX_FRAME_RATE > 0 else 0.0
        last_paint_at = 0.0
        next_pin_poll = 0.0

        def check_portal_otp():
            """Process code resend and verification over the private CDP bridge."""
            nonlocal otp_challenge, otp_delivery_ok
            if otp_delivery_event is not None and otp_delivery_event.is_set():
                delivered = bool(otp_delivery_result.get("ok"))
                otp_delivery_event.clear()
                if delivered:
                    otp_delivery_ok = True
                    status = "Access code ready. Enter it to continue."
                    logging.info("OTP notification sent for a portal connection")
                    br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('success', %s, %s)" % (
                        json.dumps(status),
                        json.dumps(otp_challenge.seconds_remaining()
                                   if otp_challenge is not None else 0.0)))
                else:
                    if otp_challenge is not None:
                        otp_challenge.invalidate()
                    status = "Notification delivery failed. Reconnect and try again."
                    logging.warning("OTP notification failed for a portal connection")
                    br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('error', %s)" %
                                json.dumps(status))
            if (otp_delivery_ok and otp_challenge is not None and
                    otp_challenge.is_expired()):
                otp_challenge.invalidate()
                logging.warning("unauthenticated portal session expired; closing client")
                raise ClientAbort("OTP expired before authentication")
            request_raw = br.evaluate(
                "JSON.stringify((function(){"
                "var resend=window.__rdpTakeResend ? window.__rdpTakeResend() : false;"
                "return {resend:resend,otp:resend ? null : "
                "(window.__rdpTakeOtp ? window.__rdpTakeOtp() : null)};"
                "})())"
            )
            try:
                requests = json.loads(request_raw or "{}")
            except (TypeError, ValueError):
                requests = {}
            resend_requested = requests.get("resend") is True
            if (resend_requested and otp_delivery_event is not None and
                    not otp_delivery_event.is_set()):
                br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('success', %s)" %
                            json.dumps("Sending access code..."))
                return False
            if resend_requested:
                allowed, retry_after = OTP_RATE_LIMITER.allow(self.client_addr)
                if not allowed:
                    message = "Too many codes requested. Try again in %d seconds." % retry_after
                    logging.warning("OTP notification rate limit reached on resend")
                    br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('error', %s)"
                                % json.dumps(message))
                    return False
                replacement = portal.OtpChallenge(
                    self.client_addr, ttl_seconds=OTP_TTL_SECONDS,
                    max_attempts=OTP_MAX_ATTEMPTS)
                code = replacement.take_delivery_code()
                delivered = _send_otp_notification(code)
                code = None
                if delivered:
                    if otp_challenge is not None:
                        otp_challenge.invalidate()
                    otp_challenge = replacement
                    otp_delivery_ok = True
                    message = "New access code ready. Enter it to continue."
                    logging.info("OTP resend sent for a portal connection")
                    br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('success', %s, %s)"
                                % (json.dumps(message),
                                   json.dumps(replacement.seconds_remaining())))
                else:
                    replacement.invalidate()
                    message = "Notification delivery failed. Please try again."
                    logging.warning("OTP resend delivery failed")
                    br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('error', %s)"
                                % json.dumps(message))
                return False
            candidate = requests.get("otp")
            if candidate is None:
                return False
            if not otp_delivery_ok or otp_challenge is None:
                br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('error', %s)" %
                            json.dumps("Notification delivery failed. Reconnect and try again."))
                return False
            accepted, result = otp_challenge.verify(candidate, self.client_addr)
            if accepted:
                token = ROUTING_TICKETS.issue(self.client_addr)
                self.send(portal.build_enhanced_redirection_pdu(
                    load_balance_info=token))
                self._redirect_sent = True
                logging.info("portal OTP accepted; sent opaque bounded-use RDP routing redirect")
                return True

            if result == "expired":
                message = "Code expired. Reconnect to request a new one."
            elif result == "locked":
                message = "Too many incorrect codes. Reconnect to request a new one."
            else:
                message = "Incorrect code. Please try again."
            br.evaluate("window.__rdpOtpStatus && window.__rdpOtpStatus('error', %s)"
                        % json.dumps(message))
            return False

        def pace_paint():
            nonlocal last_paint_at
            now = time.perf_counter()
            if frame_interval and last_paint_at:
                delay = frame_interval - (now - last_paint_at)
                if delay > 0:
                    time.sleep(delay)
            last_paint_at = time.perf_counter()

        while True:
            loop_started = time.perf_counter() if self._perf_enabled else 0.0
            self._drain_input()
            if portal_page and time.monotonic() >= next_pin_poll:
                next_pin_poll = time.monotonic() + 0.1
                try:
                    if check_portal_otp():
                        return
                except ClientAbort:
                    raise
                except Exception as exc:
                    logging.warning("portal OTP bridge failed: %s", type(exc).__name__)
            frame = None
            if not USE_POLLING:
                capture_started = time.perf_counter() if self._perf_enabled else 0.0
                try:
                    frame = br.pump(budget=0.016)
                except Exception as exc:
                    logging.warning("screencast pump failed: %s", exc)
                capture_s = (time.perf_counter() - capture_started
                             if self._perf_enabled else 0.0)
            if frame is not None:
                last_cast = time.time()
                cast_frames += 1
                now = time.time()
                if now - cast_start >= EVAL_WINDOW:
                    fps = cast_frames / (now - cast_start)
                    if _should_use_polling_fallback(
                            portal_page, low_fps=fps < MIN_CAST_FPS):
                        logging.info("cast fps %.1f < %.1f -> switching to JPEG polling (scale=%.2f)",
                                     fps, MIN_CAST_FPS, poll_scale)
                        USE_POLLING = True
                        try:
                            br.stop_screencast()
                        except Exception:
                            pass
                        br.drain_events()
                    cast_frames = 0
                    cast_start = now
                try:
                    pace_paint()
                    send_before = self._perf_socket_send_s
                    s, k = self._paint(frame, tile_size)
                except ClientAbort:
                    raise
                except Exception:
                    logging.exception("cast paint failed")
                    time.sleep(0.05)
                    continue
                self._perf_record_frame(
                    loop_started, capture_s, s, k,
                    self._perf_socket_send_s - send_before
                    if self._perf_enabled else 0.0,
                )
                frames += 1
                if s:
                    logging.info("cast frame #%d: %d tiles sent, %d unchanged",
                                 frames, s, k)
                continue

            # Screencast idle or switched to polling -> use JPEG capture
            silent = time.time() - last_cast >= fallback
            if (not USE_POLLING and
                    not _should_use_polling_fallback(portal_page,
                                                     silent=silent)):
                continue
            if not USE_POLLING:
                logging.info("screencast silent -> JPEG polling (scale=%.2f)", poll_scale)
                USE_POLLING = True
                try:
                    br.stop_screencast()
                except Exception:
                    pass
                br.drain_events()
            try:
                capture_started = time.perf_counter() if self._perf_enabled else 0.0
                _w, _h, shot = br.screenshot(scale=poll_scale)
                capture_s = (time.perf_counter() - capture_started
                             if self._perf_enabled else 0.0)
            except Exception as exc:
                fails += 1
                logging.warning("jpeg capture failed (%d consecutive): %s",
                                fails, exc)
                if fails >= 2:
                    fails = 0
                    try:
                        br.recover()
                        br.start_screencast(
                            quality=int(os.environ.get("RDP_CAST_QUALITY") or 60),
                            scale=scale, format=cast_format)
                        USE_POLLING = False
                        last_cast = time.time()
                        cast_start = last_cast
                        cast_frames = 0
                        logging.info("recovered; resuming captures")
                    except Exception as e2:
                        logging.warning("browser recover failed: %s", e2)
                time.sleep(0.2)
                continue
            fails = 0
            try:
                pace_paint()
                send_before = self._perf_socket_send_s
                s, k = self._paint(shot, tile_size)
            except ClientAbort:
                raise
            except Exception:
                logging.exception("poll paint failed")
                time.sleep(0.05)
                continue
            self._perf_record_frame(
                loop_started, capture_s, s, k,
                self._perf_socket_send_s - send_before
                if self._perf_enabled else 0.0,
            )
            frames += 1
            now = time.time()
            if s or frames <= 3:
                logging.info("jpeg frame #%d: %d tiles sent, %d unchanged",
                             frames, s, k)
                last_change = now
            elif now - last_change >= 10.0:
                # Zero-diff frames log nothing, which looked like a freeze
                # ("screen stopped updating") when the page was merely
                # static.  Make liveness visible instead.
                logging.info("screen static for %.0fs (painting alive, "
                             "%d frames)", now - last_change, frames)
                last_change = now
            time.sleep(0.005)

    def _paint(self, img, tile_size=BITMAP_TILE_WIDTH, force=False):
        """Send changed screen rectangles using the negotiated MSTSC codecs."""
        tile_width = BITMAP_TILE_WIDTH
        tile_height = BITMAP_TILE_HEIGHT
        if len(img) != self.width * self.height * 3:
            raise ValueError("RGB frame size does not match negotiated desktop")
        total_tiles = (((self.width + tile_width - 1) // tile_width) *
                       ((self.height + tile_height - 1) // tile_height))
        prev = getattr(self, "_last_frame", None)
        perf = getattr(self, "_perf_enabled", False)
        if perf:
            self._perf_last_convert_s = 0.0
            self._perf_last_pdu_s = 0.0
        if getattr(self, "_rdpgfx_surface_ready", False):
            if not force and self._rdpgfx_last_frame == img:
                self._drain_input()
                self._last_frame = img
                return 0, total_tiles
            result = self._paint_rdpgfx(img, total_tiles)
            if result is not None:
                self._last_frame = img
                return result
        if not force and prev is not None and prev == img:
            self._drain_input()
            self._last_frame = img
            return 0, total_tiles

        sent = skipped = processed = 0
        batch = []
        batch_rects = []
        batch_bytes = 0
        surface_batch = []
        surface_batch_bytes = 0

        def flush_surface_batch():
            nonlocal sent, surface_batch_bytes
            if not surface_batch:
                return
            packets = fastpath.build_surface_bits_batch(
                surface_batch, max_packet=BITMAP_UPDATE_CHUNK_BYTES)
            for packet in packets:
                self.send(packet, quiet=True)
            logging.info("surface tile batch sent (%d tiles, %d packets, %d bytes)",
                         len(surface_batch), len(packets),
                         sum(map(len, packets)))
            sent += len(surface_batch)
            surface_batch.clear()
            surface_batch_bytes = 0
            self._drain_input()

        def flush_bitmap_batch():
            nonlocal sent, batch_bytes
            if not batch:
                return
            updu = bitmap.build_bitmap_update_slow(batch)
            if len(updu) > 16000:
                raise ValueError("batched bitmap update exceeds safe TPKT size")
            self.send_pdu(updu)
            logging.info("bitmap batch sent (%d rectangles, %d bytes)",
                         len(batch), len(updu))
            for left, top, right, bottom, data_size, compressed in batch_rects:
                logging.debug("bitmap tile (%d,%d)-(%d,%d) sent (%d bytes, compressed=%s)",
                              left, top, right, bottom, data_size, compressed)
            sent += len(batch)
            batch.clear()
            batch_rects.clear()
            batch_bytes = 0
            self._drain_input()

        stop_after_limit = False
        tile_positions = _tile_origins(
            self.width, self.height, tile_width, tile_height,
            center_first=(self._sensitive_page_active and prev is None))
        for left, top in tile_positions:
            if MAX_TILES and processed >= MAX_TILES:
                stop_after_limit = True
                break
            processed += 1
            rect_width = min(tile_width, self.width - left)
            rect_height = min(tile_height, self.height - top)
            src = _extract_rgb_region(img, self.width, left, top,
                                      rect_width, rect_height)
            if (not force and prev is not None and
                    _extract_rgb_region(prev, self.width, left, top,
                                        rect_width, rect_height) == src):
                skipped += 1
                continue

            # A new MSTSC bitmap surface starts black. The OTP portal also
            # uses an exact black surround, so omit only all-black tiles in
            # its first bitmap frame; subsequent changes still compare
            # against the full cached frame and are transmitted normally.
            if (self._sensitive_page_active and prev is None and
                    not any(src)):
                skipped += 1
                continue

            if perf:
                convert_started = time.perf_counter()
            mode = (BITMAP_COMPRESSION_MODE
                    if self._sensitive_page_active else "standard")
            legacy_pixels = legacy_rle = None
            if (mode == "max" and NSCODEC_SURFACE_UPDATES and
                    self._nscodec_id is not None and
                    self._surface_bits_supported):
                encoded = bitmap.encode_nscodec_rgb(
                    src, rect_width, rect_height,
                    self._nscodec_color_loss_level)
                legacy_pixels = bitmap.pack_pixels(
                    src, rect_width, rect_height, 16)
                legacy_rle = bitmap.encode_interleaved_rle(
                    legacy_pixels, rect_width, rect_height, 16)
                if len(encoded) < len(legacy_rle):
                    surface_batch.append({
                        "left": left, "top": top,
                        "width": rect_width, "height": rect_height,
                        "bpp": 32, "codec_id": self._nscodec_id,
                        "data": encoded,
                    })
                    surface_batch_bytes += 25 + len(encoded)
                    if surface_batch_bytes >= BITMAP_UPDATE_CHUNK_BYTES:
                        flush_surface_batch()
                    if BAND_DELAY:
                        time.sleep(BAND_DELAY)
                    continue

            # Keep separate batches per codec. Tiles cover disjoint
            # rectangles, so they can be grouped by codec without changing
            # the final image; avoiding codec-switch flushes cuts PDU count.

            wire_bpp = 16 if self.bpp <= 16 or mode == "max" else 24
            if wire_bpp == 16 and legacy_pixels is not None:
                # NSCodec was considered above. Reuse its 16-bpp fallback
                # candidates instead of converting and RLE-encoding this
                # same tile a second time on the CPU.
                packed = legacy_pixels
            else:
                packed = bitmap.pack_pixels(src, rect_width, rect_height,
                                            wire_bpp)
            if perf:
                self._perf_last_convert_s += time.perf_counter() - convert_started
            wire_stride = (rect_width * (wire_bpp // 8) + 3) & ~3
            if len(packed) != wire_stride * rect_height:
                raise ValueError(
                    "bad packed size %d != %d" %
                    (len(packed), wire_stride * rect_height)
                )
            if wire_bpp == 16 and legacy_rle is not None:
                encoded = legacy_rle
            else:
                encoded = (bitmap.encode_interleaved_rle(
                    packed, rect_width, rect_height, wire_bpp)
                    if mode != "off" else packed)
            compressed = mode != "off" and len(encoded) < len(packed)
            bitmap_data = encoded if compressed else packed
            bitmap_flags = ((contract.BITMAP_COMPRESSION |
                             contract.NO_BITMAP_COMPRESSION_HDR)
                            if compressed else 0)
            rect = {
                "left": left,
                "top": top,
                # MS-RDPBCGR 2.2.9.1.1.3.1.2.2: bounds are inclusive.
                "right": left + rect_width - 1,
                "bottom": top + rect_height - 1,
                "width": rect_width,
                "height": rect_height,
                "bpp": wire_bpp,
                "flags": bitmap_flags,
                "data": bitmap_data,
            }
            if perf:
                pdu_started = time.perf_counter()
            tile_wire_size = len(bitmap_data) + 24
            if batch and batch_bytes + tile_wire_size > BITMAP_UPDATE_CHUNK_BYTES:
                flush_bitmap_batch()
            candidate = batch + [rect]
            updu = bitmap.build_bitmap_update_slow(candidate)
            if len(updu) > 16000 and batch:
                flush_bitmap_batch()
                candidate = [rect]
                updu = bitmap.build_bitmap_update_slow(candidate)
            if len(updu) > 16000:
                raise ValueError("single bitmap tile exceeds safe TPKT size")
            if perf:
                self._perf_last_pdu_s += time.perf_counter() - pdu_started
            if sent == 0 and not batch and force:
                open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "first_bitmap.bin"), "wb").write(updu)
                logging.info("dumped first bitmap PDU %d bytes", len(updu))
            batch.append(rect)
            batch_bytes += tile_wire_size
            batch_rects.append((left, top, left + rect_width,
                                top + rect_height, len(bitmap_data), compressed))
            if BAND_DELAY:
                time.sleep(BAND_DELAY)

        flush_surface_batch()
        flush_bitmap_batch()
        if stop_after_limit:
            logging.info("stopped after %d tiles (MAX_TILES)", sent)
        self._last_frame = img
        return sent, skipped

    def _perf_record_frame(self, loop_started, capture_s, sent, skipped,
                           socket_send_s):
        """Aggregate opt-in frame timing and log a two-second summary."""
        if not self._perf_enabled:
            return
        now = time.perf_counter()
        if self._perf_window_start is None:
            self._perf_window_start = loop_started
        self._perf_window_frames += 1
        self._perf_window_capture_s += capture_s
        self._perf_window_convert_s += getattr(self, "_perf_last_convert_s", 0.0)
        self._perf_window_pdu_s += getattr(self, "_perf_last_pdu_s", 0.0)
        self._perf_window_socket_s += socket_send_s
        self._perf_window_sent_tiles += sent
        self._perf_window_skipped_tiles += skipped
        elapsed = now - self._perf_window_start
        if elapsed < 2.0:
            return
        frames = self._perf_window_frames
        divisor = max(frames, 1)
        logging.info(
            "RDP perf fps=%.1f frames=%d capture=%.2fms convert=%.2fms "
            "pdu=%.2fms socket_send=%.2fms tiles_sent=%.1f tiles_skipped=%.1f",
            frames / elapsed, frames,
            self._perf_window_capture_s * 1000 / divisor,
            self._perf_window_convert_s * 1000 / divisor,
            self._perf_window_pdu_s * 1000 / divisor,
            self._perf_window_socket_s * 1000 / divisor,
            self._perf_window_sent_tiles / divisor,
            self._perf_window_skipped_tiles / divisor,
        )
        self._perf_window_start = now
        self._perf_window_frames = 0
        self._perf_window_capture_s = 0.0
        self._perf_window_convert_s = 0.0
        self._perf_window_pdu_s = 0.0
        self._perf_window_socket_s = 0.0
        self._perf_window_sent_tiles = 0
        self._perf_window_skipped_tiles = 0

    def _pump_input(self, timeout=0.0):
        """Read whatever the client sent, parse it, and dispatch input events.

        After graphics start, the client sends FastPath input PDUs (keyboard /
        mouse). FastPath PDUs are NOT TPKT framed, so parsing them with
        read_tpkt() used to raise and kill the whole session right after the
        first Bitmap Update -- which is what made mstsc abort with 0x2904.
        They are parsed by fastpath.py instead, which was reverse-engineered
        from the FreeRDP sources here and validated on a live mstsc capture
        (341 bytes / 6 PDUs / 63 events, zero bytes left over).

        timeout=0.0 keeps the socket non-blocking so this costs nothing when
        the client is idle; the old 0.05s block per tile made painting ~8s
        slower than it needed to be.

        Note settimeout(0.0) == non-blocking (recv raises BlockingIOError
        immediately); settimeout(None) would be the block-forever case.
        We only swallow the "would block" error -- real network errors such
        as ECONNRESET must propagate so a client disconnect is detected.
        """
        # SSLSocket timeout mode is shared by every thread using the socket.
        # The RDPSND sender calls sendall() from another thread, so changing
        # timeout here without the send lock can turn that concurrent write
        # non-blocking halfway through a TLS record. Collect bytes while the
        # mode is protected, then dispatch after releasing the lock because
        # dispatch may itself send protocol replies.
        chunks = []
        with self._send_lock:
            previous_timeout = self.sock.gettimeout()
            self.sock.settimeout(timeout)
            try:
                for _ in range(64):
                    try:
                        chunk = self.sock.recv(65536)
                    except (socket.timeout, BlockingIOError,
                            ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        break
                    if not chunk:
                        raise ClientAbort("client closed")
                    logging.info("recv %d bytes", len(chunk))
                    chunks.append(chunk)
            finally:
                self.sock.settimeout(previous_timeout)

        for chunk in chunks:
            self.inbuf += chunk
        if chunks:
            self._dispatch_input()

    def _drain_input(self, timeout=0.0):
        """Name kept for the painter; same work as _pump_input."""
        self._pump_input(timeout)

    def _dispatch_input(self):
        """Parse every complete input PDU buffered so far and fire hooks.

        The stream mixes FastPath PDUs (unframed) with TPKT-framed
        slow-path client PDUs (03 00 ... -- e.g. periodic data PDUs that
        mstsc starts sending mid-session).  Slow-path frames are consumed
        whole via fastpath.parse_slowpath(); feeding them to the FastPath
        parser used to poison inbuf and permanently kill all input.

        FastPath PDUs can be split across TCP segments, so only whole PDUs
        are consumed; the remainder stays in self.inbuf for the next read.
        """
        if not self.inbuf:
            return
        if os.environ.get("RDP_INPUT_RAW"):
            logging.info("INPUT %d bytes: %s", len(self.inbuf),
                         bytes(self.inbuf).hex(" "))
        events = []
        while self.inbuf:
            if self.inbuf[0] == 3:
                if len(self.inbuf) < 2:
                    break
                # rdpsnd acknowledgements can be short TPKT frames (below the
                # generic slow-path input parser's minimum Share Data size).
                if len(self.inbuf) >= 4:
                    tpkt_len = (self.inbuf[2] << 8) | self.inbuf[3]
                    if 7 <= tpkt_len <= fastpath.MAX_TPKT and len(self.inbuf) >= tpkt_len:
                        try:
                            parsed = gcc.parse_domain_pdu(bytes(self.inbuf[:tpkt_len]))
                            channel_id = parsed.get("channel_id")
                            if channel_id == self.static_channels.get("rdpsnd"):
                                self._handle_rdpsnd_channel(
                                    channel_id, parsed.get("user_data") or b"")
                                del self.inbuf[:tpkt_len]
                                continue
                            if channel_id == self._rdpgfx_static_channel_id:
                                self._handle_drdynvc_data(
                                    channel_id, parsed.get("user_data") or b"")
                                del self.inbuf[:tpkt_len]
                                continue
                        except Exception:
                            logging.exception("rdpsnd TPKT dispatch failed")
                status, evs, need = fastpath.parse_slowpath(self.inbuf)
                if status == "incomplete":
                    break
                if status == "invalid":
                    logging.warning(
                        "input slow-path: dropping %d bad bytes (head=%s)",
                        need, bytes(self.inbuf[:16]).hex(" "))
                    del self.inbuf[:need]
                    continue
                try:
                    parsed = gcc.parse_domain_pdu(bytes(self.inbuf[:need]))
                    channel_id = parsed.get("channel_id")
                    if channel_id == self.static_channels.get("rdpsnd"):
                        self._handle_rdpsnd_channel(
                            channel_id, parsed.get("user_data") or b"")
                    elif channel_id == self._rdpgfx_static_channel_id:
                        self._handle_drdynvc_data(
                            channel_id, parsed.get("user_data") or b"")
                except Exception:
                    logging.exception("static virtual-channel dispatch failed")
                if evs:
                    events.extend(evs)
                else:
                    logging.debug("slow-path PDU consumed (%d bytes)", need)
                del self.inbuf[:need]
                continue

            # --- FastPath ---
            try:
                evs, consumed = fastpath.parse_stream(self.inbuf)
            except Exception:
                logging.exception("input parse failed; dropping %d bytes",
                                  len(self.inbuf))
                self.inbuf.clear()
                break
            if consumed:
                del self.inbuf[:consumed]
                events.extend(evs)
                continue
            # Nothing parsed.  Distinguish "PDU split across TCP segments"
            # (wait for more bytes) from "garbage at the head of the buffer"
            # (would otherwise sit there forever and silently swallow every
            # input packet that follows -- this actually happened: clicks and
            # keys stopped arriving while recv() kept logging).
            poison = None
            try:
                fastpath.parse_pdu(self.inbuf, 0)
            except fastpath.MalformedInput as exc:
                reason = str(exc)
                if reason.startswith("truncated: need"):
                    # A real split PDU claims a sane length; garbage (e.g.
                    # wheel-event bytes read as a 2-byte length field)
                    # claims tens of KB -- poison it immediately instead of
                    # letting inbuf swell to 4096 waiting for a frame that
                    # will never arrive.
                    claim = int(reason.split("need ")[1].split(" ")[0])
                    wait = claim <= 8192 and len(self.inbuf) < 4096
                elif reason.startswith(("short header",
                                        "short 2-byte length")):
                    wait = len(self.inbuf) < 4096
                else:
                    wait = False
                if wait:
                    break           # plausible partial PDU, keep waiting
                poison = reason
            else:
                break               # complete PDU but zero events: done
            logging.warning(
                "input STALL: %d bytes stuck, head=%s (%s) -- resyncing",
                len(self.inbuf), bytes(self.inbuf[:32]).hex(" "), poison)
            drop = None
            for off in range(1, min(len(self.inbuf), 1024)):
                # Only FastPath action=0 can start a PDU, and the candidate
                # must parse COMPLETELY: accepting "truncated" offsets used
                # to land mid-TPKT / mid-event (e.g. wheel events whose
                # pointerFlags byte >= 0x80 reads as a huge 2-byte length)
                # and the buffer never recovered alignment again.
                if self.inbuf[off] & 0x03:
                    continue
                try:
                    fastpath.parse_pdu(self.inbuf, off)
                except fastpath.MalformedInput:
                    continue
                drop = off
                break
            if drop is None:
                logging.warning("input resync: no PDU boundary found, "
                                "clearing %d bytes", len(self.inbuf))
                self.inbuf.clear()
                break
            logging.warning("input resync: dropped %d garbage bytes", drop)
            del self.inbuf[:drop]

        if not events:
            return

        self.input.dispatch(events)

        # Keyboard / sync / unicode events are rare and worth always logging;
        # mouse motion is not, unless the raw stream is requested.
        log_mouse = bool(os.environ.get("RDP_INPUT_LOG"))
        for ev in events:
            if ev["code"] in (fastpath.CODE_MOUSE, fastpath.CODE_MOUSEX,
                              fastpath.CODE_MOUSEREL) and not log_mouse:
                continue
            if self._sensitive_page_active:
                logging.info("IN  portal input event")
            else:
                logging.info("IN  %s", self.input.describe(ev))

        if self.on_input:
            for ev in events:
                try:
                    self.on_input(ev)
                except Exception:
                    logging.exception("on_input hook failed")

    def _read_loop(self, deadline=None):
        # Client input after painting is FastPath (non-TPKT); keep reading,
        # parsing and dispatching it until the client goes away.
        self.sock.settimeout(1.0)
        try:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    chunk = self.sock.recv(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                self.inbuf += chunk
                self._dispatch_input()
        finally:
            self.sock.settimeout(None)


def serve(host=None, port=None):
    host = host or settings.get("server", "host", "0.0.0.0", str, "RDP_BIND_HOST")
    port = port or settings.get("server", "port", 3390, int, "RDP_PORT")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    logging.info("RDP server listening on %s:%d", host, port)
    while True:
        c, addr = s.accept()
        logging.info("client %s", addr)
        threading.Thread(target=RDPConnection(c, addr).run, daemon=True).start()


if __name__ == "__main__":
    import sys
    serve(port=int(sys.argv[1]) if len(sys.argv) > 1 else None)
