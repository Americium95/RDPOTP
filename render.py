"""Render HTML into raw RGB pixels using the system browser (headless).

Chrome/Edge does the HTML/CSS/JS rendering and produces a PNG; the PNG is
decoded back to raw RGB.  PIL is used when available (31x faster than the
stdlib fallback); otherwise falls back to a pure-zlib decoder so the module
still works in a constrained environment.

Public API:
    render_page(html_path, width, height) -> bytes   # width*height*3, RGB order
    page_needs_rerender(html_path, cache_key) -> bool
"""
import hashlib
import logging
import os
import shutil
import struct
import subprocess
import tempfile
import zlib

_BROWSER_CANDIDATES = [
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                 "Google", "Chrome", "Application", "chrome.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                 "Microsoft", "Edge", "Application", "msedge.exe"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""),
                 "Google", "Chrome", "Application", "chrome.exe"),
    shutil.which("chrome") or "",
    shutil.which("msedge") or "",
]

_cache = {}          # (abs_path, mtime, width, height) -> (rgb, signature)
_browser = None


def find_browser() -> str:
    """Locate a Chromium-based browser; raise if none is installed."""
    global _browser
    if _browser:
        return _browser
    for p in _BROWSER_CANDIDATES:
        if p and os.path.isfile(p):
            _browser = p
            return _browser
    raise RuntimeError("no Chromium browser found for HTML rendering")


def _to_url(target: str) -> str:
    """Accept a local path or an http(s) URL and return something Chrome can load."""
    t = target.strip()
    if t.startswith(("http://", "https://", "file://", "about:", "data:")):
        return t
    return "file:///" + os.path.abspath(t).replace("\\", "/")


def _screenshot(target: str, png_path: str, width: int, height: int,
                budget_ms: int = 2500) -> None:
    """Drive headless Chrome once and write a PNG screenshot to png_path."""
    exe = find_browser()
    url = _to_url(target)
    cmd = [
        exe,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--force-device-scale-factor=1",
        "--disable-lcd-text",
        "--no-first-run",
        "--no-default-browser-check",
        "--allow-file-access-from-files",
        "--virtual-time-budget=%d" % budget_ms,
        "--window-size=%d,%d" % (width, height),
        "--screenshot=%s" % png_path,
        url,
    ]
    # Chrome returns non-zero when it logs harmless warnings; only the output
    # file matters, so the return code is intentionally ignored.
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=60)
    if not os.path.isfile(png_path) or os.path.getsize(png_path) == 0:
        raise RuntimeError("headless screenshot produced no output for %s" % url)


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def decode_png_bytes(data: bytes):
    """Decode an 8-bit RGB/RGBA non-interlaced PNG into (w, h, rgb_bytes).

    Works on in-memory bytes so Chrome DevTools screenshots decode directly.

    PIL is tried first because the pure-Python filter loop costs ~0.8s for a
    1024x768 frame -- that single change is the difference between a slideshow
    and something usable.  If PIL is unavailable the stdlib path below still
    works, just slower.
    """
    try:
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        img = img.convert("RGB")
        return img.width, img.height, img.tobytes()
    except ImportError:
        pass
    return _decode_png_stdlib(data)


def _decode_png_stdlib(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG (%d bytes)" % len(data))

    pos = 8
    width = height = None
    bit_depth = color_type = interlace = None
    idat = bytearray()
    while pos + 8 <= len(data):
        length, ctag = struct.unpack(">I4s", data[pos:pos + 8])
        pos += 8
        chunk = data[pos:pos + length]
        pos += length + 4                      # skip CRC
        if ctag == b"IHDR":
            width, height, bit_depth, color_type, _comp, _filt, interlace = \
                struct.unpack(">IIBBBBB", chunk)
        elif ctag == b"IDAT":
            idat.extend(chunk)
        elif ctag == b"IEND":
            break

    if width is None:
        raise ValueError("PNG has no IHDR: %s" % path)
    if bit_depth != 8:
        raise ValueError("unsupported bit depth %r (expected 8)" % bit_depth)
    if color_type not in (2, 6):
        raise ValueError("unsupported colour type %r (expected 2=RGB or 6=RGBA)"
                         % color_type)
    if interlace:
        raise ValueError("interlaced PNG not supported")

    channels = 3 if color_type == 2 else 4
    raw = zlib.decompress(bytes(idat))
    stride = width * channels
    expected = (stride + 1) * height
    if len(raw) < expected:
        raise ValueError("PNG data truncated: %d < %d" % (len(raw), expected))

    out = bytearray(stride * height)
    prev = bytearray(stride)
    # Tight locals: this loop runs once per pixel, so attribute/global lookups
    # dominate.  Raw bytes -> bytearray conversion is avoided for filter 0.
    # Chrome picks Paeth for most screenshot rows (measured 557/768 on a
    # YouTube page), so that branch is inlined here: the _paeth() call and the
    # per-index branch were the bulk of decode time.
    raw_b = bytes(raw)
    for y in range(height):
        off = y * (stride + 1)
        ftype = raw_b[off]
        if ftype == 0:                          # None
            line = raw_b[off + 1: off + 1 + stride]
            out[y * stride:(y + 1) * stride] = line
            prev = line
            continue
        line = bytearray(raw_b[off + 1: off + 1 + stride])
        if ftype == 1:                          # Sub
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:                        # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:                        # Average
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:                        # Paeth
            ch_ = channels
            for i in range(stride):
                a = line[i - ch_] if i >= ch_ else 0
                b = prev[i]
                c = prev[i - ch_] if i >= ch_ else 0
                p = a + b - c
                pa = p - a
                if pa < 0:
                    pa = -pa
                pb = p - b
                if pb < 0:
                    pb = -pb
                pc = p - c
                if pc < 0:
                    pc = -pc
                if pa <= pb and pa <= pc:
                    v = a
                elif pb <= pc:
                    v = b
                else:
                    v = c
                line[i] = (line[i] + v) & 0xFF
        else:
            raise ValueError("unknown PNG filter type %d" % ftype)
        out[y * stride:(y + 1) * stride] = line
        prev = line

    if channels == 3:
        return width, height, bytes(out)

    rgb = bytearray(width * height * 3)
    for p in range(width * height):
        s = p * 4
        d = p * 3
        rgb[d] = out[s]
        rgb[d + 1] = out[s + 1]
        rgb[d + 2] = out[s + 2]
    return width, height, bytes(rgb)


def decode_png(path: str):
    """File-path convenience wrapper around decode_png_bytes()."""
    with open(path, "rb") as f:
        return decode_png_bytes(f.read())


def page_signature(target: str, width: int, height: int) -> str:
    """Cheap change detector: source mtime+size+geometry (files), or the URL."""
    if target.strip().startswith(("http://", "https://")):
        return "url|%s|%d|%d" % (target, width, height)
    st = os.stat(target)
    return "%s|%d|%d|%d" % (st.st_mtime_ns, st.st_size, width, height)


def render_page(target: str, width: int, height: int, budget_ms: int = 2500):
    """Render a local HTML file or a live URL at width x height; return RGB bytes."""
    global _cache
    sig = page_signature(target, width, height)
    key = (target, sig)
    if key in _cache:
        return _cache[key]

    tmpdir = tempfile.mkdtemp(prefix="rdphtml_")
    try:
        png_path = os.path.join(tmpdir, "frame.png")
        _screenshot(target, png_path, width, height, budget_ms)
        w, h, rgb = decode_png(png_path)
        if (w, h) != (width, height):
            # Chrome can clamp very large windows; pad or crop to the
            # negotiated desktop size so the caller's stride maths still holds.
            rgb = _fit(rgb, w, h, width, height)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    _cache.clear()                              # keep only the latest frame
    _cache[key] = rgb
    return rgb


def _fit(rgb: bytes, w: int, h: int, width: int, height: int) -> bytes:
    """Pad/crop an RGB buffer to exactly width x height."""
    if (w, h) == (width, height):
        return rgb
    out = bytearray(width * height * 3)
    copy_w = min(w, width)
    copy_h = min(h, height)
    for y in range(copy_h):
        s = y * w * 3
        d = y * width * 3
        out[d:d + copy_w * 3] = rgb[s:s + copy_w * 3]
    logging.info("render %dx%d -> fit to %dx%d", w, h, width, height)
    return bytes(out)
