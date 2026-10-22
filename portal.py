"""PIN validation and enhanced-security RDP server redirection."""

import hmac
import hashlib
import secrets
import struct
import threading
import time

import contract
import framing


class PinGate:
    """Per-source PIN throttling for the short-lived portal connection."""

    def __init__(self, pin="1234", max_attempts=5, window_seconds=60,
                 lockout_seconds=60, clock=time.monotonic):
        if not pin:
            raise ValueError("portal PIN must not be empty")
        self._pin = str(pin)
        self._max_attempts = int(max_attempts)
        self._window_seconds = float(window_seconds)
        self._lockout_seconds = float(lockout_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._attempts = {}
        self._pin_bytes = self._pin.encode("utf-8")

    def verify(self, candidate, source):
        """Return (accepted, retry_after_seconds), without logging secrets."""
        now = self._clock()
        source = str(source or "unknown")
        with self._lock:
            attempts, blocked_until = self._attempts.get(source, ([], 0.0))
            if now < blocked_until:
                return False, max(1, int(blocked_until - now + 0.999))

            attempts = [stamp for stamp in attempts
                        if now - stamp < self._window_seconds]
            candidate_bytes = str(candidate).encode("utf-8", "replace")
            if hmac.compare_digest(candidate_bytes, self._pin_bytes):
                self._attempts.pop(source, None)
                return True, 0

            attempts.append(now)
            if len(attempts) >= self._max_attempts:
                blocked_until = now + self._lockout_seconds
                self._attempts[source] = ([], blocked_until)
                return False, int(self._lockout_seconds)
            self._attempts[source] = (attempts, 0.0)
            return False, 0


class OtpChallenge:
    """Short-lived, source-bound, single-use numeric login challenge."""

    def __init__(self, source, ttl_seconds=60, max_attempts=5,
                 clock=time.monotonic, code_factory=None):
        self._source = str(source or "unknown")
        self._ttl = float(ttl_seconds)
        if self._ttl <= 0:
            raise ValueError("OTP lifetime must be positive")
        self._max_attempts = max(1, int(max_attempts))
        self._clock = clock
        self._salt = secrets.token_bytes(16)
        code = (code_factory() if code_factory else
                "%04d" % secrets.randbelow(10_000))
        if not isinstance(code, str) or len(code) != 4 or not code.isascii() or not code.isdigit():
            raise ValueError("OTP must be a four-digit string")
        self._digest = self._hash(code)
        self._delivery_code = code
        self._expires_at = clock() + self._ttl
        self._attempts = 0
        self._used = False
        self._lock = threading.Lock()

    def _hash(self, code):
        return hashlib.sha256(self._salt + code.encode("ascii")).digest()

    def take_delivery_code(self):
        """Return the code once so the caller can send it to the user."""
        with self._lock:
            code = self._delivery_code
            self._delivery_code = None
            return code

    def invalidate(self):
        with self._lock:
            self._used = True
            self._delivery_code = None

    def is_expired(self):
        """Return whether the challenge lifetime has elapsed."""
        with self._lock:
            return self._clock() >= self._expires_at

    def seconds_remaining(self):
        """Return the remaining lifetime for a synchronized UI countdown."""
        with self._lock:
            return max(0.0, self._expires_at - self._clock())

    def verify(self, candidate, source):
        """Return (accepted, status) without retaining or logging the input."""
        now = self._clock()
        with self._lock:
            if self._used:
                return False, "used"
            if now >= self._expires_at:
                self._used = True
                self._delivery_code = None
                return False, "expired"
            if not hmac.compare_digest(self._source.encode("utf-8"),
                                       str(source or "unknown").encode("utf-8")):
                return False, "source_mismatch"
            if self._attempts >= self._max_attempts:
                return False, "locked"
            self._attempts += 1
            value = str(candidate) if candidate is not None else ""
            if len(value) != 4 or not value.isascii() or not value.isdigit():
                return False, ("locked" if self._attempts >= self._max_attempts
                               else "incorrect")
            if not hmac.compare_digest(self._digest, self._hash(value)):
                return False, ("locked" if self._attempts >= self._max_attempts
                               else "incorrect")
            self._used = True
            self._delivery_code = None
            return True, "accepted"


class OtpRateLimiter:
    """Bound OTP notifications per source to reduce phone spam."""

    def __init__(self, max_issues=5, window_seconds=600, clock=time.monotonic):
        self._max_issues = max(1, int(max_issues))
        self._window = float(window_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._issues = {}

    def allow(self, source):
        now = self._clock()
        key = str(source or "unknown")
        with self._lock:
            self._issues = {
                address: recent
                for address, stamps in self._issues.items()
                if (recent := [stamp for stamp in stamps
                               if now - stamp < self._window])
            }
            stamps = self._issues.get(key, [])
            if len(stamps) >= self._max_issues:
                retry = max(1, int(self._window - (now - stamps[0]) + 0.999))
                return False, retry
            stamps.append(now)
            self._issues[key] = stamps
            return True, 0


class RoutingTickets:
    """Short-lived opaque tickets, bound to a source and capped reconnect count."""

    def __init__(self, ttl_seconds=900, max_uses=4, clock=time.monotonic,
                 bind_source=True):
        self._ttl = float(ttl_seconds)
        self._max_uses = max(1, int(max_uses))
        self._bind_source = bool(bind_source)
        self._clock = clock
        self._lock = threading.Lock()
        self._tickets = {}

    def issue(self, source):
        now = self._clock()
        with self._lock:
            self._tickets = {key: value for key, value in self._tickets.items()
                             if value[1] > now}
            token = secrets.token_urlsafe(32).encode("ascii")
            while token in self._tickets:
                token = secrets.token_urlsafe(32).encode("ascii")
            self._tickets[token] = (str(source or "unknown"), now + self._ttl,
                                    self._max_uses)
            return token

    def consume(self, token, source):
        now = self._clock()
        if not isinstance(token, bytes) or not token or len(token) > 220:
            return False
        with self._lock:
            record = self._tickets.get(token)
            if not record:
                return False
            if record[1] <= now:
                del self._tickets[token]
                return False
            if (self._bind_source and
                    not hmac.compare_digest(record[0].encode(),
                                            str(source or "unknown").encode())):
                return False
            remaining = record[2] - 1
            if remaining <= 0:
                del self._tickets[token]
            else:
                self._tickets[token] = (record[0], record[1], remaining)
            return True


def build_enhanced_redirection_pdu(target_host=None, session_id=0,
                                   load_balance_info=None):
    """Build an Enhanced Security Server Redirection PDU inside MCS/TPKT.

    MS-RDPBCGR 2.2.13.3.1: a Share Control Header with pduType
    PDUTYPE_SERVER_REDIR_PKT (10) and PDUVersion 0, two pad octets, the
    Server Redirection Packet of section 2.2.13.1 and one optional pad
    octet.  There is no Share Data Header in this PDU.

    The Server Redirection Packet holds Flags (SEC_REDIRECTION_PKT), its own
    Length, the session id, RedirFlags and either target address or opaque
    LoadBalanceInfo. Its Length
    covers the whole packet including the trailing 8 byte Pad, so it is
    24 bytes plus the null terminated UTF-16 address.

    The current connection is protected by TLS, so the enhanced-security
    variant is required. LoadBalanceInfo returns as an opaque X.224 routing
    token on reconnect to the same host and port.
    """
    if load_balance_info is not None:
        field = bytes(load_balance_info)
        if not field or len(field) > 0xFFFF:
            raise ValueError("invalid redirection routing token")
        redir_flags = contract.LB_LOAD_BALANCE_INFO
    else:
        address = (str(target_host).strip() + "\0").encode("utf-16le")
        field = address
        redir_flags = contract.LB_TARGET_NET_ADDRESS
    packet_length = contract.REDIRECTION_PACKET_OVERHEAD + len(field)
    if packet_length > 0xFFFF:
        raise ValueError("redirection packet is too large")
    redirection = (
        struct.pack("<HHII", contract.SEC_REDIRECTION_PKT, packet_length,
                    int(session_id), redir_flags)
        + struct.pack("<I", len(field))
        + field
        + b"\0" * 8
    )

    # Enhanced redirection is a Share Control PDU (type 10, version zero),
    # followed by two pad bytes, the server-redirection packet and the
    # optional trailing pad byte.  It has no Share Data Header.
    share_length = 6 + 2 + len(redirection) + 1
    share_control = struct.pack(
        "<HHH", share_length, contract.PDUTYPE_SERVER_REDIR_PKT,
        contract.PDU_SOURCE,
    ) + b"\0\0" + redirection + b"\0"
    initiator = 1004 - contract.MCS_BASE_CHANNEL_ID
    return framing.wrap_pdu(
        share_control, initiator, contract.MCS_GLOBAL_CHANNEL_ID
    )
