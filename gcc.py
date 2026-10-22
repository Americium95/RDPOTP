from struct import pack, unpack
import contract


def _ber_len(n):
    if n <= 127:
        return bytes([n])
    if n > 0xFFFF:
        raise ValueError("ber len too big")
    return bytes([0x80 | ((n >> 8) & 0x7F), n & 0xFF])


def _ber_int(v):
    if v <= 0x7F:
        return bytes([0x02, 0x01, v & 0xFF])
    if v <= 0x7FFF:
        return bytes([0x02, 0x02, (v >> 8) & 0xFF, v & 0xFF])
    return bytes([0x02, 0x03, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def _ber_seq(body):
    return bytes([0x30]) + _ber_len(len(body)) + body


def _ber_int_multi(values):
    return b"".join(_ber_int(v) for v in values)


DOMAIN_PARAMS = _ber_int(34) + _ber_int(3) + _ber_int(0) + _ber_int(1) + _ber_int(0) + _ber_int(1) + _ber_int(65528) + _ber_int(2)
# as sequence:
DOMAIN_PARAMS = _ber_seq(_ber_int(34) + _ber_int(3) + _ber_int(0) + _ber_int(1) + _ber_int(0) + _ber_int(1) + _ber_int(65528) + _ber_int(2))


def _read_ber_len(data, off):
    L = data[off]; off += 1
    if L & 0x80 and L != 0x80:
        n = L & 0x7F
        if n == 1:
            v = data[off:off + 1]; off += 1
        elif n == 2:
            v = data[off:off + 2]; off += 2
        else:
            v = bytes([])
            off += n
    else:
        off += L
        return L, off
    # handle stuff inconsistently; simpler below:
    return L, off


# ---------------- parse connect initial ----------------
def _strip_tpkt_x224(payload):
    # payload starts with 02 f0 80
    return payload[3:]


def _find(state, needle):
    i = state.find(needle)
    if i < 0:
        return -1
    return i


def parse_connect_initial(tpkt_payload):
    res = {"desktop_width": 1024, "desktop_height": 768, "color_depth": 16,
           "client_name": "RDP CLIENT", "client_protocols": 0, "encryption_methods": 0x00000002,
           "channels": [], "raw": tpkt_payload}
    try:
        body = tpkt_payload[3:]  # skip 02 f0 80
        # find MCS Connect-Initial APPLICATION 101
        # find gcc user data by locating "Duca" bytes b"Duca"
        idx = body.find(b"Duca")
        if idx < 0:
            return res
        # after "Duca" skip tag/length-ish bytes; locate CS_CORE header by searching for 0xC0 0x01? as two bytes LE? text markers.
        # We'll scan for data blocks by finding CS_CORE type 0xC001 (LE bytes 01 c0)
        # desktop width/height locate from common MS-RDPBCGR layout: at offset +8/10 of CS_CORE
        # strategy: find the bytes b'\x01\xc0' (CS_CORE) then offset.
        # CS_CORE: type(2)=0xC001 len(2) version(4) width(2) height(2) colorDepth(2) ...
        # Validate by the version field so we never latch onto a stray 0x01C0 pair.
        dw = dh = 0
        color_depth = 0
        search = idx
        while True:
            pos = body.find(b"\x01\xc0", search)
            if pos < 0 or pos + 16 > len(body):
                break
            search = pos + 1
            try:
                blk_len = unpack("<H", body[pos + 2:pos + 4])[0]
                version = unpack("<I", body[pos + 4:pos + 8])[0]
            except Exception:
                continue
            if version != 0x00080004 or not (4 <= blk_len <= 0x0400):
                continue
            w_ = unpack("<H", body[pos + 8:pos + 10])[0]
            h_ = unpack("<H", body[pos + 10:pos + 12])[0]
            cd = unpack("<H", body[pos + 12:pos + 14])[0]
            if 0 < w_ <= 8192 and 0 < h_ <= 8192 and cd in (8, 15, 16, 24, 32):
                dw, dh, color_depth = w_, h_, (16 if cd == 15 else cd)
                break
        if dw and dh:
            # clamp to a sane desktop the server is willing to paint
            res["desktop_width"] = max(640, min(dw, 1920))
            res["desktop_height"] = max(480, min(dh, 1080))
            if color_depth:
                res["color_depth"] = color_depth
        # color depth
        if pos >= 0:
            try:
                cd = body[pos + 12]
                if cd in (8, 15, 16, 24, 32):
                    res["color_depth"] = cd if cd != 15 else 16
            except Exception:
                pass
        # channels from CS_NET: channel count u32; find 0x03 c0 block, count at +4
        npos = body.find(b"\x03\xc0", idx)
        if npos >= 0 and npos + 8 <= len(body):
            try:
                cnt = unpack("<I", body[npos + 4:npos + 8])[0]
                if 0 <= cnt <= 64:
                    res["channels"] = []
                    off = npos + 8
                    for i in range(cnt):
                        name_raw = body[off:off + 8]; off += 8
                        opts = unpack("<I", body[off:off + 4])[0]; off += 4
                        name = name_raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
                        res["channels"].append({"name": name, "options": opts})
            except Exception:
                pass
        # encryption methods from CS_SECURITY: 0xC0 0x02, u32 at +4
        spos = body.find(b"\x02\xc0", idx)
        if spos >= 0 and spos + 8 <= len(body):
            try:
                em = unpack("<I", body[spos + 4:spos + 8])[0]
                res["encryption_methods"] = em
            except Exception:
                pass
        # client protocols from CS_CORE optional field serverSelectedProtocol is not parsed; read clientRequestedProtocols if present after CS_CORE last fields.
        # figure client name from CS_CORE clientName (UNICODE string) — find first printable ASCII run after "Duca" headers; skip for now, default.
        # Try to extract username/server selected protocol by heuristic: search for 4-byte value that is small (≤0x10).
        cpos = pos
        if cpos >= 0:
            # protocols field often at cpos+?? + 4 u32; attempt cpos+24..cpos+40 scan
            tail = body[cpos:]
            window = tail[:120]
            # search last aligned 4-byte int <= 0x0F in the first 96 bytes beyond CS_CORE base
            best = None
            for k in range(0, 96 - 4, 4):
                v = unpack("<I", window[k:k + 4])[0]
                if v <= 0x1F:
                    best = v
            if best is not None and best <= 0x1F:
                # only set if not clearly zero-init; keep default requested protocols 0
                pass
    except Exception:
        pass
    return res


# ---------------- build connect response ----------------
def _build_domain_params():
    return (bytes([0x30]) + _ber_len(4 + len(DOMAIN_PARAMS) if False else len(DOMAIN_PARAMS)) + ... )  # placeholder fix below


def build_connect_response(desktop_width, desktop_height, channel_ids, req_protocols=0):
    channel_count = len(channel_ids)

    sc_core = pack("<HHII", contract.SC_CORE, 16, contract.SERVER_VERSION, req_protocols) + pack("<I", 0x00000008)

    sc_net_body = pack("<HH", contract.MCS_GLOBAL_CHANNEL_ID, channel_count)
    sc_net_body += b"".join(pack("<H", cid) for cid in channel_ids)
    if channel_count % 2 == 1:
        sc_net_body += pack("<H", 0x0000)
    sc_net = pack("<HH", contract.SC_NET, 4 + len(sc_net_body)) + sc_net_body

    sc_sec = pack("<HH II", contract.SC_SECURITY, 12, 0, 0)
    server_blocks = sc_core + sc_net + sc_sec

    gcc_hdr = bytes.fromhex("000500147c00012a14760a01010001c0004d63446e") + pack(">H", len(server_blocks) | 0x8000)
    user_data = gcc_hdr + server_blocks

    dp_bytes = _ber_int(22) + _ber_int(3) + _ber_int(0) + _ber_int(1) + _ber_int(0) + _ber_int(1) + _ber_int(65528) + _ber_int(2)
    dp_seq = b"\x30" + _ber_len(len(dp_bytes)) + dp_bytes

    result_byte = bytes([0x0a, 0x01, 0x00])
    called_id = bytes([0x02, 0x01, 0x00])
    body = result_byte + called_id + dp_seq + b"\x04" + _ber_len(len(user_data)) + user_data
    mcspdu = bytes([0x7f, 0x66]) + _ber_len(len(body)) + body
    full = bytes([0x03, 0x00]) + (4 + 3 + len(mcspdu)).to_bytes(2, "big") + bytes([0x02, 0xf0, 0x80]) + mcspdu
    return full


def erect_domain_confirm():
    return bytes.fromhex("03 00 00 0c 02 f0 80 06 00 01 00 01 00")


def attach_user_confirm(user_id=1004):
    diff = user_id - 1001
    b = bytes([0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80, 0x2e, 0x00, (diff >> 8) & 0xff, diff & 0xff])
    return b


def channel_join_confirm(channel_id, user_id=1004, joined=True):
    res = 0 if joined else 1
    uidiff = user_id - 1001
    b = bytes([0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80, 0x3e, res, (uidiff >> 8) & 0xff, uidiff & 0xff,
               (channel_id >> 8) & 0xff, channel_id & 0xff, (channel_id >> 8) & 0xff, channel_id & 0xff])
    return b


def parse_domain_pdu(tpkt_payload):
    # tpkt_payload includes TPKT? assume payload after 4 bytes? We handle both
    data = tpkt_payload
    if data[:3] == bytes([0x03, 0x00, 0x30]):  # no
        pass
    # strip leading TPKT if present
    if len(data) > 4 and data[0] == 0x03 and data[3] == (len(data) & 0xFF):
        # TPKT present; use bytes 4:
        off = 4
    else:
        off = 0
    # skip x224
    if data[off:off + 3] == b"\x02\xf0\x80":
        off += 3
    choice = data[off] if off < len(data) else 0
    dtype = choice >> 2
    name_map = {1: "erect_domain_request", 2: "erect_domain_confirm", 10: "attach_user_request",
                11: "attach_user_confirm", 14: "channel_join_request", 15: "channel_join_confirm",
                25: "send_data_request", 26: "send_data_indication"}
    # patch names to match spec
    if dtype == 10:
        name = "attach_user_request"
    elif dtype == 11:
        name = "attach_user_confirm"
    elif dtype == 14:
        name = "channel_join_request"
    elif dtype == 15:
        name = "channel_join_confirm"
    elif dtype == 25:
        name = "send_data_request"
    elif dtype == 26:
        name = "send_data_indication"
    elif dtype == 1:
        name = "erect_domain_request"
    elif dtype == 2:
        name = "erect_domain_confirm"
    else:
        name = name_map.get(dtype, f"choice_{dtype}")
    uid = None
    cid = None
    user_data = None
    # parse after domain header
    rest = data[off + 1:]
    # many forms. Try locate two-byte big-endian fields.
    # send data: after choice byte there is initiator u16 BE, channel u16 BE, 0x70, BER len
    if dtype in (25, 26):
        if len(rest) >= 5:
            uid = (rest[0] << 8) | rest[1] if len(rest) >= 2 else None
            cid = (rest[2] << 8) | rest[3] if len(rest) >= 4 else None
            ber_pos = 5  # after priority byte
            if ber_pos < len(rest):
                L = rest[ber_pos]
                if L & 0x80 and L != 0x80:
                    ln = ((L & 0x7F) << 8) | rest[ber_pos + 1]
                    pos = ber_pos + 2
                else:
                    ln = L
                    pos = ber_pos + 1
                user_data = rest[pos:pos + ln]
    elif dtype == 14:
        if len(rest) >= 4:
            uid = (rest[0] << 8) | rest[1]
            cid = (rest[2] << 8) | rest[3]
    elif dtype in (10, 11):
        # attach user request/confirm carries user id at tail
        if len(rest) >= 2:
            uid = (rest[-2] << 8) | rest[-1]
    return {"choice": choice, "name": name, "user_id": uid, "channel_id": cid, "user_data": user_data}


# remove unused helpers accidentally left
try:
    del _build_domain_params
except NameError:
    pass
