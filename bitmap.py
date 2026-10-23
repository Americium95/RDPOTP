import struct

try:
    from . import contract
    from . import pdu
except ImportError:
    import contract
    import pdu


def rgb_to_bgr_rows(pixels: bytes, width: int, height: int) -> bytes:
    """RGB -> BGR with a vertical flip (RDP bitmaps are bottom-up).

    The pure-Python per-pixel loop here was the single biggest cost in the
    whole pipeline: 1024x768 is ~786k iterations, and it ran once per changed
    band.  numpy does the same work in C.
    """
    try:
        import numpy as np
        arr = np.frombuffer(pixels, dtype=np.uint8)
        if arr.size == width * height * 4:
            arr = arr.reshape(height, width, 4)[:, :, :3]
        else:
            arr = arr.reshape(height, width, 3)
        # [R,G,B] -> [B,G,R] and flip vertically (RDP is bottom-up).
        out = arr[:, :, ::-1][::-1]
        out = np.ascontiguousarray(out)
        # RDP rows are 4-byte aligned.
        dst_stride = (width * 3 + 3) & ~3
        if dst_stride != width * 3:
            padded = np.zeros((height, dst_stride), dtype=np.uint8)
            padded[:, :width * 3] = out.reshape(height, width * 3)
            return padded.tobytes()
        return out.tobytes()
    except ImportError:
        pass
    px = 4 if len(pixels) == width * height * 4 else 3
    src_stride = width * 3
    dst_stride = (src_stride + 3) & ~3
    out = bytearray(dst_stride * height)
    for y in range(height):
        src = (height - 1 - y) * width * px
        dst = y * dst_stride
        for x in range(width):
            s = src + x * px
            d = dst + x * 3
            out[d] = pixels[s + 2]
            out[d + 1] = pixels[s + 1]
            out[d + 2] = pixels[s]
    return bytes(out)


def pack_pixels(pixels: bytes, width: int, height: int, bpp: int) -> bytes:
    px = 4 if len(pixels) == width * height * 4 else 3
    if bpp == 24:
        return rgb_to_bgr_rows(pixels, width, height)
    if bpp == 32:
        try:
            import numpy as np
            arr = np.frombuffer(pixels, dtype=np.uint8)
            if arr.size == width * height * 4:
                arr = arr.reshape(height, width, 4)[:, :, :3]
            else:
                arr = arr.reshape(height, width, 3)
            out = arr[:, :, ::-1][::-1]
            out = np.ascontiguousarray(out)
            # RDP rows are 4-byte aligned.
            dst_stride = (width * 3 + 3) & ~3
            if dst_stride != width * 3:
                padded = np.zeros((height, dst_stride), dtype=np.uint8)
                padded[:, :width * 3] = out.reshape(height, width * 3)
                out = padded
            # Append a zero alpha byte per pixel.
            if out.shape[1] != width * 3:
                # Re-pack without padding for the 4-byte path.
                out = arr[:, :, ::-1][::-1]
                out = np.ascontiguousarray(out)
            alpha = np.zeros((height, width, 1), dtype=np.uint8)
            return np.concatenate([out.reshape(height, width, 3), alpha],
                                  axis=2).tobytes()
        except ImportError:
            pass
        row_stride = width * 4
        out = bytearray(row_stride * height)
        for y in range(height):
            src = (height - 1 - y) * width * px
            dst = y * row_stride
            for x in range(width):
                s = src + x * px
                d = dst + x * 4
                out[d] = pixels[s + 2]
                out[d + 1] = pixels[s + 1]
                out[d + 2] = pixels[s]
                out[d + 3] = 0
        return bytes(out)
    if bpp == 16:
        try:
            import numpy as np
            arr = np.frombuffer(pixels, dtype=np.uint8)
            if arr.size == width * height * 4:
                arr = arr.reshape(height, width, 4)[:, :, :3]
            else:
                arr = arr.reshape(height, width, 3)
            r = arr[:, :, 0].astype(np.uint16)
            g = arr[:, :, 1].astype(np.uint16)
            b = arr[:, :, 2].astype(np.uint16)
            # RGB565: rrrrrggg gggbbbbb, little-endian
            v = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
            v = v[::-1]                                   # bottom-up
            lo = (v & 0xFF).astype(np.uint8)
            hi = ((v >> 8) & 0xFF).astype(np.uint8)
            out = np.empty((height, width, 2), dtype=np.uint8)
            out[:, :, 0] = lo
            out[:, :, 1] = hi
            out = np.ascontiguousarray(out)
            # RDP rows are 4-byte aligned.
            row_stride = (width * 2 + 3) & ~3
            if row_stride != width * 2:
                padded = np.zeros((height, row_stride), dtype=np.uint8)
                padded[:, :width * 2] = out.reshape(height, width * 2)
                return padded.tobytes()
            return out.tobytes()
        except ImportError:
            pass
        row_stride = (width * 2 + 3) & ~3
        out = bytearray(row_stride * height)
        for y in range(height):
            src = (height - 1 - y) * width * px
            dst = y * row_stride
            for x in range(width):
                s = src + x * px
                r = pixels[s]
                g = pixels[s + 1]
                b = pixels[s + 2]
                v = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                d = dst + x * 2
                out[d] = v & 0xFF
                out[d + 1] = (v >> 8) & 0xFF
        return bytes(out)
    raise ValueError("unsupported bpp: %d" % (bpp,))


def encode_interleaved_rle(packed: bytes, width: int, height: int,
                           bpp: int) -> bytes:
    """Encode a bottom-up bitmap with MS-RDPBCGR Interleaved RLE orders.

    Emits only COLOR_RUN (0x03) and COLOR_IMAGE (0x04), both standard
    compression orders. Row alignment bytes from the uncompressed bitmap are
    omitted from the compressed stream as required by the pixel stream.
    """
    if bpp not in (16, 24):
        raise ValueError("Interleaved RLE supports 16/24 bpp, got %d" % bpp)
    bytes_per_pixel = bpp // 8
    stride = (width * bytes_per_pixel + 3) & ~3
    if len(packed) != stride * height:
        raise ValueError("bad bitmap size for RLE")
    pixels = b"".join(
        packed[y * stride:y * stride + width * bytes_per_pixel]
        for y in range(height)
    )
    pixel_count = width * height
    out = bytearray()
    pos = 0

    def emit_header(code, count):
        # Standard orders encode 1..31 in the low five bits. A zero low field
        # is followed by an unsigned extension representing count - 32.
        if not 1 <= count <= 287:
            raise ValueError("RLE order run out of range")
        out.append((code << 5) | (count if count <= 31 else 0))
        if count > 31:
            out.append(count - 32)

    while pos < pixel_count:
        pixel_at = pos * bytes_per_pixel
        pixel = pixels[pixel_at:pixel_at + bytes_per_pixel]
        run = 1
        while pos + run < pixel_count and run < 287:
            at = (pos + run) * bytes_per_pixel
            if pixels[at:at + bytes_per_pixel] != pixel:
                break
            run += 1
        if run >= 2:
            emit_header(0x03, run)  # REGULAR_COLOR_RUN
            out.extend(pixel)
            pos += run
            continue

        # Gather a literal span, stopping before a repeated-color run.
        start = pos
        pos += 1
        while pos < pixel_count and pos - start < 287:
            at = pos * bytes_per_pixel
            next_pixel = pixels[at:at + bytes_per_pixel]
            next_run = 1
            while pos + next_run < pixel_count and next_run < 2:
                nxt = (pos + next_run) * bytes_per_pixel
                if pixels[nxt:nxt + bytes_per_pixel] != next_pixel:
                    break
                next_run += 1
            if next_run >= 2:
                break
            pos += 1
        count = pos - start
        emit_header(0x04, count)  # REGULAR_COLOR_IMAGE
        begin = start * bytes_per_pixel
        end = pos * bytes_per_pixel
        out.extend(pixels[begin:end])
    return bytes(out)


def encode_nscodec_rgb(pixels: bytes, width: int, height: int,
                       color_loss_level: int = 3) -> bytes:
    """Encode top-down RGB pixels as an MS-RDPNSC frame (no chroma subsampling)."""
    if not 1 <= color_loss_level <= 7:
        raise ValueError("NSCodec color loss level must be 1..7")
    if len(pixels) != width * height * 3:
        raise ValueError("bad RGB buffer size for NSCodec")
    planes = [bytearray(), bytearray(), bytearray(), bytearray()]
    shift = color_loss_level
    for y in range(height - 1, -1, -1):
        row = y * width * 3
        for x in range(width):
            i = row + x * 3
            r, g, b = pixels[i], pixels[i + 1], pixels[i + 2]
            planes[0].append((r >> 2) + (g >> 1) + (b >> 2))
            co = max(-128, min(127, (r - b) >> shift))
            cg = max(-128, min(127, (-(r >> 1) + g - (b >> 1)) >> shift))
            planes[1].append(co & 0xFF)
            planes[2].append(cg & 0xFF)
            planes[3].append(0xFF)

    def rle(plane):
        n = len(plane)
        if n <= 4:
            return bytes(plane)
        end = n - 4
        out = bytearray()
        i = 0
        while i < end:
            value = plane[i]
            run = 1
            while i + run < end and plane[i + run] == value:
                run += 1
            if run == 1:
                out.append(value)
            elif run <= 255:
                out.extend((value, value, run - 2))
            else:
                out.extend((value, value, 0xFF))
                out.extend(struct.pack("<I", run))
            i += run
        out.extend(plane[end:])
        # NSCodec signals an uncompressed plane by giving it its original
        # pixel count.  A larger RLE stream is not a valid substitute: clients
        # still try to decode it as runs and can lose the containing tile.
        # Match the interoperable encoder behavior and keep raw data unless
        # RLE strictly reduces the plane size.
        return bytes(out) if len(out) < n else bytes(plane)

    encoded = [rle(p) for p in planes]
    return (b"".join(struct.pack("<I", len(p)) for p in encoded) +
            bytes((color_loss_level, 0, 0, 0)) + b"".join(encoded))


def make_test_image(width: int, height: int) -> bytes:
    buf = bytearray(width * height * 3)
    wx = max(width - 1, 1)
    hy = max(height - 1, 1)
    for y in range(height):
        g = (y * 255) // hy
        row = y * width * 3
        for x in range(width):
            i = row + x * 3
            buf[i] = (x * 255) // wx
            buf[i + 1] = g
            buf[i + 2] = 96
    rx0 = max(width // 8, 0)
    ry0 = max(height // 4, 0)
    rx1 = max((width * 5) // 8, rx0 + 1)
    ry1 = max((height * 3) // 4, ry0 + 1)
    for y in range(ry0, min(ry1, height)):
        row = y * width * 3
        for x in range(rx0, min(rx1, width)):
            i = row + x * 3
            buf[i] = 255
            buf[i + 1] = 165
            buf[i + 2] = 0
    cx = (width * 3) // 4
    cy = height // 2
    rad = max(min(width, height) // 6, 1)
    rr = rad * rad
    for y in range(max(cy - rad, 0), min(cy + rad + 1, height)):
        dy2 = (y - cy) * (y - cy)
        row = y * width * 3
        for x in range(max(cx - rad, 0), min(cx + rad + 1, width)):
            if (x - cx) * (x - cx) + dy2 <= rr:
                i = row + x * 3
                buf[i] = 200
                buf[i + 1] = 30
                buf[i + 2] = 30
    bw = 1 if min(width, height) < 6 else 2
    for y in range(min(bw, height)):
        row = y * width * 3
        for x in range(width):
            i = row + x * 3
            buf[i] = 255
            buf[i + 1] = 255
            buf[i + 2] = 255
    for y in range(max(height - bw, 0), height):
        row = y * width * 3
        for x in range(width):
            i = row + x * 3
            buf[i] = 255
            buf[i + 1] = 255
            buf[i + 2] = 255
    for y in range(height):
        row = y * width * 3
        for x in range(min(bw, width)):
            i = row + x * 3
            buf[i] = 255
            buf[i + 1] = 255
            buf[i + 2] = 255
    for y in range(height):
        row = y * width * 3
        for x in range(max(width - bw, 0), width):
            i = row + x * 3
            buf[i] = 255
            buf[i + 1] = 255
            buf[i + 2] = 255
    return bytes(buf)


def encode_bitmap_rect(left: int, top: int, right: int, bottom: int,
                        width: int, height: int, bpp: int,
                        bitmap_data: bytes, flags: int = 0) -> bytes:
    """TS_BITMAP_DATA - 9 x u16 header, NO padding (FreeRDP update_read_bitmap_data)."""
    header = struct.pack(
        "<HHHHHHHHH",
        left,
        top,
        right,
        bottom,
        width,
        height,
        bpp,
        flags,
        len(bitmap_data),
    )
    if (flags & contract.BITMAP_COMPRESSION) and not (flags & contract.NO_BITMAP_COMPRESSION_HDR):
        header += b"\x00" * 8
    return header + bitmap_data


def build_bitmap_update_slow(rects: list) -> bytes:
    # update_recv(): updateType(2) then IMMEDIATELY numberRectangles(2) - no pad.
    # update_read_bitmap_update(): rectangles are packed back-to-back, no per-rect pad.
    body = struct.pack("<HH", contract.UPDATETYPE_BITMAP, len(rects))
    for r in rects:
        body += encode_bitmap_rect(
            r["left"],
            r["top"],
            r["right"],
            r["bottom"],
            r["width"],
            r["height"],
            r["bpp"],
            r["data"],
            r.get("flags", 0),
        )
    return pdu.share_data(contract.PDUTYPE2_UPDATE, body)


def build_bitmap_update_fast(rects: list) -> bytes:
    update_data = struct.pack("<HH", contract.UPDATETYPE_BITMAP, len(rects))
    for r in rects:
        update_data += encode_bitmap_rect(
            r["left"],
            r["top"],
            r["right"],
            r["bottom"],
            r["width"],
            r["height"],
            r["bpp"],
            r["data"],
            r.get("flags", 0),
        )
    ts_fp_update = b"\x01" + struct.pack("<H", len(update_data)) + update_data
    if len(ts_fp_update) + 2 <= 127:
        total = len(ts_fp_update) + 2
        return b"\x00" + bytes((total,)) + ts_fp_update
    total = len(ts_fp_update) + 3
    if total > 16383:
        raise ValueError("fast-path PDU too large: %d" % (total,))
    return b"\x00" + bytes((0x80 | (total >> 8), total & 0xFF)) + ts_fp_update


def build_pointer_default() -> bytes:
    body = struct.pack("<HHH", 0x0001, 0, contract.SYSTEM_POINTER_DEFAULT)
    return pdu.share_data(contract.PDUTYPE2_POINTER, body)
