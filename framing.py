from contract import (
    TPKT_VERSION,
    X224_DT,
    MCS_GLOBAL_CHANNEL_ID,
    MCS_SEND_DATA_INDICATION,
    MCS_SEND_DATA_REQUEST,
)


def tpkt(payload):
    total = 4 + len(payload)
    return bytes([TPKT_VERSION, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + payload


def parse_tpkt(data):
    if len(data) < 4:
        raise ValueError("incomplete")
    if data[0] != TPKT_VERSION:
        raise ValueError("bad tpkt")
    length = (data[2] << 8) | data[3]
    if length < 4:
        raise ValueError("bad tpkt")
    if len(data) < length:
        raise ValueError("incomplete")
    return data[4:length], length


def x224_data(payload):
    return tpkt(X224_DT + payload)


def parse_x224_cr(tpkt_payload):
    if len(tpkt_payload) < 7:
        raise ValueError("bad cr")
    li = tpkt_payload[0]
    if li < 6 or len(tpkt_payload) < li + 1 or tpkt_payload[1] != 0xE0:
        raise ValueError("bad cr")
    src_ref = (tpkt_payload[4] << 8) | tpkt_payload[5]
    var = tpkt_payload[7:li + 1]
    cookie = None
    routing_token = None
    neg_req = None
    offset = 0
    if var.startswith(b"Cookie: "):
        end = var.find(b"\r\n")
        if end == -1:
            raise ValueError("malformed x224 cookie")
        cookie = var[:end].decode("ascii", "replace")
        offset = end + 2
    rest = var[offset:]
    if cookie is not None and rest and not rest.startswith(b"\x01"):
        raise ValueError("cookie and x224 routing token cannot be combined")
    if rest and rest.startswith(b"\x01"):
        if len(rest) != 8:
            raise ValueError("malformed x224 negotiation request")
    elif rest:
        # Accept the standard CRLF form, including a trailing negotiation
        # request. MSTSC also sends its generated 43-byte base64url ticket
        # directly before the 8-byte negotiation structure, without CRLF.
        marker = rest.find(b"\r\n")
        if marker > 0:
            routing_token = rest[:marker]
            if b"\r" in routing_token or b"\n" in routing_token:
                raise ValueError("malformed x224 routing token")
            rest = rest[marker + 2:]
        elif marker == 0 or b"\r" in rest or b"\n" in rest:
            raise ValueError("malformed x224 routing token")
        elif len(rest) == 51 and rest[43] == 0x01:
            candidate = rest[:43]
            if any(ch not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   for ch in candidate):
                raise ValueError("malformed x224 routing token")
            routing_token = candidate
            rest = rest[43:]
        else:
            raise ValueError("malformed x224 routing token")
        if rest and (len(rest) != 8 or rest[0] != 0x01):
            raise ValueError("malformed x224 negotiation request")
    if len(rest) == 8 and rest[0] == 0x01:
        flags = rest[1]
        requested = int.from_bytes(rest[4:8], "little")
        neg_req = {"flags": flags, "requested_protocols": requested}
    elif rest:
        raise ValueError("malformed x224 negotiation request")
    return {"cookie": cookie, "src_ref": src_ref, "neg_req": neg_req,
            "routing_token": routing_token}


def strip_x224_routing_token(packet):
    """Return a normalized TPKT/X.224 CR without its gateway routing token."""
    payload, consumed = parse_tpkt(packet)
    if consumed != len(packet):
        raise ValueError("trailing data after x224 connection request")
    info = parse_x224_cr(payload)
    if info["routing_token"] is None:
        raise ValueError("x224 routing token required")
    variable = payload[7:payload[0] + 1]
    marker = variable.find(b"\r\n")
    if marker > 0:
        remainder = variable[marker + 2:]
    else:
        # MSTSC's observed 43-byte base64url ticket followed by an 8-byte
        # negotiation request has no delimiter.
        remainder = variable[43:]
    body = bytearray(payload[:7])
    body[0] = 6 + len(remainder)
    body.extend(remainder)
    return tpkt(bytes(body))


def clear_x224_hybrid_ex(packet):
    """Clear only PROTOCOL_HYBRID_EX from a complete X.224 CR, if present.

    This preserves SSL and regular CredSSP negotiation. It is an opt-in
    compatibility fallback for native RDP servers that select HYBRID_EX but
    fail during the subsequent TLS handshake.
    """
    payload, consumed = parse_tpkt(packet)
    if consumed != len(packet):
        raise ValueError("trailing data after x224 connection request")
    info = parse_x224_cr(payload)
    neg = info.get("neg_req")
    if neg is None:
        return packet, None, None
    before = neg["requested_protocols"]
    # Do not remove the hybrid path if it is the only NLA option advertised.
    if before & 0x08 and before & 0x02:
        after = before & ~0x08
        request_offset = payload[0] - 7
        field_offset = 4 + request_offset + 4
        result = bytearray(packet)
        result[field_offset:field_offset + 4] = after.to_bytes(4, "little")
        return bytes(result), before, after
    return packet, before, before


def build_cr_routing_token(token):
    """Build a TPKT/X.224 Connection Request carrying an opaque token."""
    token = bytes(token)
    if not token or b"\r" in token or b"\n" in token or len(token) > 220:
        raise ValueError("invalid x224 routing token")
    variable = token + b"\r\n"
    li = 6 + len(variable)
    body = bytes((li, 0xE0, 0, 0, 0, 0, 0)) + variable
    return tpkt(body)


RDP_NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
RDP_NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02


def build_cc(selected_protocol, client_negotiated, server_flags=0):
    varlen = 8 if client_negotiated else 0
    li = 6 + varlen
    body = bytes([li, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
    if client_negotiated:
        if not 0 <= server_flags <= 0xFF:
            raise ValueError("server_flags must fit in one byte")
        body += bytes([0x02, server_flags, 0x08, 0x00])
        body += (selected_protocol & 0xFFFFFFFF).to_bytes(4, "little")
    return tpkt(body)


def ber_len(n):
    if n < 0:
        raise ValueError("bad ber length")
    if n <= 127:
        return bytes([n])
    if n > 0xFFFF:
        raise ValueError("ber length too large")
    return bytes([0x80 | ((n >> 8) & 0xFF), n & 0xFF])


def mcs_send_data(user_data, initiator=1, channel_id=MCS_GLOBAL_CHANNEL_ID, request=False):
    header = MCS_SEND_DATA_REQUEST if request else MCS_SEND_DATA_INDICATION
    out = bytes([header])
    out += (initiator & 0xFFFF).to_bytes(2, "big")
    out += (channel_id & 0xFFFF).to_bytes(2, "big")
    out += bytes([0x70])
    out += ber_len(len(user_data))
    out += user_data
    return out


def wrap_pdu(user_data, initiator=1, channel_id=MCS_GLOBAL_CHANNEL_ID):
    return x224_data(mcs_send_data(user_data, initiator, channel_id))


def _read_exact(reader, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = reader.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def read_tpkt(reader):
    header = _read_exact(reader, 4)
    if len(header) < 4:
        raise ValueError("eof")
    if header[0] != TPKT_VERSION:
        raise ValueError("bad tpkt")
    length = (header[2] << 8) | header[3]
    if length < 4:
        raise ValueError("bad tpkt")
    payload = _read_exact(reader, length - 4)
    if len(payload) < length - 4:
        raise ValueError("eof")
    return payload


def _read_ber_len(data, pos):
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    hi = b & 0x7F
    lo = data[pos]
    pos += 1
    return (hi << 8) | lo, pos


def read_mcs_user_data(reader):
    payload = read_tpkt(reader)
    pos = 0
    if payload[0:3] == X224_DT:
        pos = 3
    choice = payload[pos]
    pos += 1
    initiator = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    channel_id = (payload[pos] << 8) | payload[pos + 1]
    pos += 2
    pos += 1
    length, pos = _read_ber_len(payload, pos)
    user_data = payload[pos:pos + length]
    return {
        "initiator": initiator,
        "channel_id": channel_id,
        "user_data": user_data,
        "domain_type": choice >> 2,
    }
