"""Persistent headless Chrome driven over the Chrome DevTools Protocol.

Why this exists: spawning Chrome per screenshot takes ~3-5s, which is fine for
a static page but hopeless for video, and it cannot receive input at all.
A browser kept alive behind a CDP WebSocket can be navigated, clicked, typed
into and screenshotted as fast as the protocol allows.

Chrome is launched with --remote-debugging-port; the page target's
webSocketDebuggerUrl is fetched over HTTP from /json/list and then spoken to
over the WebSocket in wsclient.py.  Pure stdlib.
"""

import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

import av
import wsclient
import render


# GPU-accelerated JPEG decode via PyAV (uses NVENC/NVDEC on NVIDIA).
# Falls back to PIL if PyAV/NVENC unavailable.
def _decode_jpeg_nvenc(data: bytes):
    """Decode JPEG bytes to RGB using PyAV NVENC/NVDEC."""
    try:
        # PyAV uses FFmpeg's hardware decoders; mjpeg decoder can use NVDEC.
        packet = av.Packet(data)
        # Create a codec context for mjpeg with hardware acceleration
        codec = av.codec.Codec('mjpeg', 'r')
        # Try to use hardware acceleration if available
        codec_ctx = av.CodecContext.create('mjpeg', 'r')
        # Some builds expose hwaccel via options
        try:
            codec_ctx.options = {'hwaccel': 'cuda', 'hwaccel_output_format': 'cuda'}
        except Exception:
            pass
        frames = codec_ctx.decode(packet)
        for frame in frames:
            # Convert to RGB
            rgb_frame = frame.to_ndarray(format='rgb24')
            import numpy as np
            h, w, _ = rgb_frame.shape
            return w, h, rgb_frame.tobytes()
    except Exception:
        # Fallback to PIL (fast enough and reliable)
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert('RGB')
        return img.width, img.height, img.tobytes()

# Chrome DevTools Protocol ids are just a counter; one connection, one thread.
_ID_LOCK = threading.Lock()
_NEXT_ID = [0]


def _next_id():
    with _ID_LOCK:
        _NEXT_ID[0] += 1
        return _NEXT_ID[0]


class CDPError(Exception):
    pass


class Browser:
    """A headless Chrome kept alive for the whole RDP session."""

    def __init__(self, width, height, port=0):
        self.width = width
        self.height = height
        self._requested_port = port
        self.port = port
        self.proc = None
        self.ws = None
        self.ws_url = None    # remembered so _reconnect can rebuild the socket
        self.profile = None
        self.url = None
        self._pending = {}          # id -> result dict
        self._queue = []            # [(method, params)] events waiting
        self._lock = threading.Lock()
        self._reconnect_lock = threading.Lock()
        self._reader = None
        self._stop = threading.Event()
        self._dead = None           # set to an exception once the socket dies
        self._frame_rgb = None      # newest screencast frame, as RGB bytes
        self._frame_seq = 0
        self._screencasting = False

    # ---------- lifecycle ----------
    def start(self, timeout=25.0):
        exe = render.find_browser()
        self.profile = tempfile.mkdtemp(prefix="rdpchrome_")
        cmd = [
            exe,
            "--headless=new",
            "--disable-gpu",
            "--disable-accelerated-video-decode",
            "--force-device-scale-factor=1",
            "--disable-lcd-text",
            "--no-first-run",
            "--no-default-browser-check",
            "--autoplay-policy=no-user-gesture-required",
            "--disable-features=TranslateUI",
            "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding",
            "--disable-backgrounding-occluded-windows",
            "--disable-background-networking",
            "--disable-extensions",
            "--disable-default-apps",
            "--disable-sync",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-features=TranslateUI,MediaEngagementBypassAutoplayPolicies,PreloadMediaEngagementData,AutoplayIgnoreWebAudio",
            "--js-flags=--max-old-space-size=1024",
            "--remote-allow-origins=*",
            "--remote-debugging-port=%d" % self.port,
            "--user-data-dir=%s" % self.profile,
            "--window-size=%d,%d" % (self.width, self.height),
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "about:blank",
        ]
        logging.info("launching chrome on port %d", self.port)
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_ready(timeout)

        target = self._find_page_target()
        self.ws_url = target["webSocketDebuggerUrl"]
        self.ws = wsclient.WebSocket.connect(self.ws_url)
        # All websocket reads happen on one dedicated thread.  Reading frames
        # from the main thread with a non-blocking socket corrupts the stream:
        # a BlockingIOError mid-frame leaves the parser desynchronised and the
        # next call decodes garbage (observed as "unsupported opcode 0x4").
        # A blocking reader keeps frame boundaries intact no matter what.
        self._stop.clear()
        self._reader = threading.Thread(target=self._read_loop,
                                        name="cdp-reader", daemon=True)
        self._reader.start()
        self._send("Page.enable")
        self._send("Runtime.enable")
        # Headless window-size is not the viewport size; force exact pixels so
        # screenshots land on the negotiated RDP desktop with no letterboxing.
        self._send("Emulation.setDeviceMetricsOverride", {
            "width": self.width,
            "height": self.height,
            "deviceScaleFactor": 1,
            "mobile": False,
        })
        logging.info("chrome ready pid=%d port=%d url=%s",
                     self.proc.pid, self.port, target.get("url"))

    def _wait_ready(self, timeout):
        deadline = time.time() + timeout
        last = None
        exited_at = None
        while time.time() < deadline:
            try:
                if self.port == 0:
                    with open(os.path.join(self.profile, "DevToolsActivePort"),
                              encoding="ascii") as port_file:
                        self.port = int(port_file.readline().strip())
                self._json("http://127.0.0.1:%d/json/version" % self.port)
                return
            except Exception as exc:               # not up yet
                last = exc
            # On Windows, the launcher process can exit successfully after
            # handing startup to Chrome's browser process.  Give the CDP
            # endpoint a short grace period instead of treating that handoff
            # as a failed launch.  The unique profile directory means a stale
            # DevToolsActivePort file cannot belong to another session.
            if self.proc.poll() is not None:
                if exited_at is None:
                    exited_at = time.monotonic()
                elif time.monotonic() - exited_at >= 3.0:
                    raise CDPError("chrome launcher exited (code %s) before "
                                   "debugging port became ready: %s"
                                   % (self.proc.returncode, last))
            else:
                exited_at = None
            time.sleep(0.15)
        raise CDPError("chrome debugging port never came up: %s" % last)

    def _json(self, url):
        with urllib.request.urlopen(url, timeout=5) as r:
            import json
            return json.loads(r.read().decode("utf-8"))

    def _find_page_target(self):
        import json
        deadline = time.time() + 10
        last = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        "http://127.0.0.1:%d/json/list" % self.port, timeout=5) as r:
                    targets = json.loads(r.read().decode("utf-8"))
            except Exception as exc:
                last = exc
                time.sleep(0.2)
                continue
            pages = [t for t in targets
                     if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
            if pages:
                return pages[0]
            last = "no page targets in %r" % (targets,)
            time.sleep(0.2)
        raise CDPError("no page target: %s" % last)

    def stop(self):
        self._stop.set()
        try:
            if self.ws:
                self.ws.close()
        except OSError:
            pass
        self.ws = None
        if self._reader and self._reader.is_alive():
            self._reader.join(timeout=2.0)
        self._reader = None
        if self.proc:
            try:
                if os.name == "nt" and self.proc.poll() is None:
                    subprocess.run(
                        ["taskkill", "/PID", str(self.proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5, creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                elif self.proc.poll() is None:
                    self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None
        if self.profile:
            shutil.rmtree(self.profile, ignore_errors=True)
        self.profile = None

    # ---------- protocol ----------
    def _read_loop(self):
        """Dedicated thread: keep the websocket framed and route messages.

        Auto-reconnects if the socket dies.  Each reader is bound to the exact
        websocket it was started for: when a reconnect replaces self.ws the old
        reader retires quietly instead of spawning a second reader on the new
        socket (two readers stealing each other's responses is what made
        Page.captureScreenshot time out and froze the RDP screen).
        """
        ws = self.ws
        while not self._stop.is_set():
            if self.ws is not ws:
                return  # superseded by a newer connection
            try:
                self._read_loop_once(ws)
            except wsclient.WebSocketClosed as exc:
                if self.ws is not ws or self._stop.is_set():
                    return
                self._dead = exc
                logging.warning("cdp reader died, reconnecting: %s", exc)
                time.sleep(0.5)
                if self.ws is not ws:
                    return
                try:
                    self._reconnect()
                except Exception as e2:
                    self._dead = e2
                    logging.warning("reconnect failed: %s", e2)
                    time.sleep(1.0)
            except Exception as exc:
                if self.ws is not ws or self._stop.is_set():
                    return
                self._dead = exc
                logging.warning("cdp reader error: %s", exc)
                time.sleep(1.0)

    def _read_loop_once(self, ws):
        """Single read loop iteration. Raises WebSocketClosed on disconnect."""
        try:
            msg = ws.recv_json()
        except (socket.timeout, TimeoutError):
            return  # idle, try again
        if not isinstance(msg, dict):
            return
        with self._lock:
            if "id" in msg:
                self._pending[msg["id"]] = msg
            else:
                self._queue.append(
                    (msg.get("method"), msg.get("params") or {}))

    def _send(self, method, params=None, timeout=30.0):
        """Send a command and block until its result arrives.
        Auto-reconnects if the WebSocket is dead."""
        if self.ws is None or self._dead is not None:
            self._reconnect()
        cid = _next_id()
        self.ws.send_json({"id": cid, "method": method, "params": params or {}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if cid in self._pending:
                    item = self._pending.pop(cid)
                    if "error" in item:
                        raise CDPError("%s: %s" % (method, item["error"]))
                    return item.get("result", {})
            if self._dead is not None:
                self._reconnect()
                cid = _next_id()
                self.ws.send_json({"id": cid, "method": method, "params": params or {}})
                deadline = time.time() + timeout
            time.sleep(0.002)
        raise CDPError("timed out waiting for %s (id=%s)" % (method, cid))

    def _reconnect(self):
        """Re-establish the WebSocket connection after it dies.

        Serialised under _reconnect_lock: the reader thread and any blocked
        _send() can both notice the death, and the loser must simply reuse the
        connection the winner rebuilt instead of killing it again.
        """
        if self._stop.is_set():
            raise CDPError("browser stopped")
        with self._reconnect_lock:
            if self._dead is None and self.ws is not None:
                return  # someone else already rebuilt it
            url = self.ws_url or (self.ws.url if self.ws else None)
            if url is None:
                raise CDPError("no websocket url to reconnect to")
            try:
                if self.ws is not None:
                    self.ws.close()
            except OSError:
                pass
            self._pending.clear()
            self.ws = wsclient.WebSocket.connect(url)
            self._dead = None
            self._reader = threading.Thread(target=self._read_loop,
                                            name="cdp-reader", daemon=True)
            self._reader.start()
            # Re-enable required CDP domains (after clearing _dead above so
            # these _send() calls do not recurse back into _reconnect).
            self._send("Page.enable")
            self._send("Runtime.enable")
            logging.info("CDP reconnected")

    def _pop_events(self, limit=None):
        with self._lock:
            if not self._queue:
                return []
            if limit is None:
                out, self._queue = self._queue, []
            else:
                out, self._queue = self._queue[:limit], self._queue[limit:]
            return out

    def drain_events(self):
        """Whatever protocol events the reader thread has collected."""
        return self._pop_events()

    # ---------- page control ----------
    def navigate(self, url, wait=True, timeout=30.0):
        self.url = url
        self._send("Page.navigate", {"url": url})
        if wait:
            self.wait_loaded(timeout)

    def media_state(self):
        """Small diagnostic about the page's <video>, or None."""
        try:
            return self.evaluate(
                "(function(){var v=document.querySelector('video');"
                "return v?{paused:v.paused,ct:+v.currentTime.toFixed(2),"
                "rs:v.readyState,w:v.videoWidth,h:v.videoHeight}:null})()")
        except CDPError:
            return None

    def wait_loaded(self, timeout=30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for method, _params in self.drain_events():
                if method == "Page.loadEventFired":
                    return
            time.sleep(0.02)
        # Not fatal: some pages never fire load (long-polling, websockets).

    def evaluate(self, expression, await_promise=False):
        res = self._send("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": await_promise,
        })
        return res.get("result", {}).get("value")

    def screenshot(self, scale=1.0):
        """Capture the viewport and return (w, h, rgb_bytes).

        scale < 1 asks Chrome for a smaller capture (e.g. 0.5 -> half the
        pixels in each axis).  That is the single biggest speedup available
        here: PNG decoding is pure Python, so 4x fewer pixels is ~4x faster per
        frame, and the server upscales the result to the RDP desktop size.
        """
        params = {"format": "jpeg", "quality": 60, "optimizeForSpeed": True, "fromSurface": True}
        if scale != 1.0:
            params["clip"] = {"x": 0, "y": 0,
                              "width": self.width, "height": self.height,
                              "scale": scale}
        res = self._send("Page.captureScreenshot", params, timeout=3.0)
        jpg = base64.b64decode(res["data"])
        w, h, rgb = render.decode_png_bytes(jpg)
        if (w, h) != (self.width, self.height):
            rgb = render.resize_rgb(rgb, w, h, self.width, self.height)
        return self.width, self.height, rgb

    # ---------- screencast ----------
    # Page.startScreencast makes Chrome PUSH frames as Page.screencastFrame
    # events instead of us paying for a Page.captureScreenshot round trip per
    # frame.  That is what makes live video over RDP possible at all: a
    # screenshot costs ~1.2s, a screencast frame costs one websocket read.
    def start_screencast(self, quality=60, every_nth=1, scale=1.0,
                         format="jpeg"):
        if format not in ("jpeg", "png"):
            raise ValueError("screencast format must be 'jpeg' or 'png'")
        self._frame_rgb = None
        self._frame_seq = 0
        # The browser is a process-wide singleton, so a previous RDP session can
        # leave the screencast running.  Chrome rejects a second start with
        # "Screencast is already active", which used to make the whole browser
        # session fall back and leave the screen blank.  Always stop first.
        if self._screencasting:
            try:
                self._send("Page.stopScreencast")
            except CDPError:
                pass
            self._screencasting = False
        # JPEG remains the default for smaller websocket frames; PNG is lossless.
        mw = max(64, int(self.width * scale))
        mh = max(64, int(self.height * scale))
        params = {
            "format": format,
            "maxWidth": mw,
            "maxHeight": mh,
            "everyNthFrame": every_nth,
            "maxFramesInFlight": 5,
            "sendLastFrame": True,
        }
        if format == "jpeg":
            params["quality"] = quality
        deadline = time.monotonic() + 5.0
        while True:
            try:
                self._send("Page.startScreencast", params)
                break
            except CDPError as exc:
                if "Not attached to an active page" not in str(exc) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        self._screencasting = True
        logging.info("screencast started (%s%s, %dx%d, everyNth=%d)",
                     format, " q=%d" % quality if format == "jpeg" else "",
                     mw, mh, every_nth)

    def stop_screencast(self):
        if self._screencasting:
            try:
                self._send("Page.stopScreencast")
            except CDPError:
                pass
            self._screencasting = False

    def pump(self, budget=0.02):
        """Consume queued screencast frames; returns the newest RGB or None.

        Acks every frame Chrome sends (it will stall otherwise) and keeps only
        the latest decoded image, so a slow RDP painter never falls behind.
        Reading happens on the dedicated reader thread, so this just drains
        the queue -- no socket timeouts, no desynchronisation.

        JPEG frames use PyAV; PNG frames use the lossless PNG decoder.
        """
        newest = None
        deadline = time.time() + max(0.0, budget)
        while True:
            batch = self._pop_events(limit=64)
            if not batch:
                if time.time() >= deadline:
                    break
                time.sleep(0.002)
                continue
            for method, params in batch:
                if method != "Page.screencastFrame":
                    continue
                # Chrome will not send another frame until this one is acked.
                try:
                    self.ws.send_json({
                        "id": _next_id(),
                        "method": "Page.screencastFrameAck",
                        "params": {"sessionId": params.get("sessionId")},
                    })
                except OSError:
                    pass
                data = params.get("data")
                if not data:
                    continue
                try:
                    frame_data = base64.b64decode(data)
                    if frame_data.startswith(b"\x89PNG\r\n\x1a\n"):
                        w, h, rgb = render.decode_png_bytes(frame_data)
                    else:
                        w, h, rgb = _decode_jpeg_nvenc(frame_data)
                except Exception:
                    continue
                if (w, h) != (self.width, self.height):
                    rgb = render.resize_rgb(rgb, w, h, self.width, self.height)
                newest = rgb
                self._frame_seq += 1
        if newest is not None:
            self._frame_rgb = newest
        return newest

    def latest_frame(self):
        """The most recently decoded screencast frame, or None."""
        return self._frame_rgb

    # ---------- input ----------
    def _send_with_retry(self, method, params=None, timeout=30.0, retries=3):
        """Send a CDP command with retry + auto-reconnect on connection loss."""
        last_err = None
        for attempt in range(retries + 1):
            try:
                return self._send(method, params, timeout)
            except CDPError as exc:
                last_err = exc
                if "not connected" in str(exc) or "dead" in str(exc):
                    self._reconnect()
                elif attempt < retries:
                    time.sleep(0.05)
                    continue
                raise
        raise last_err

    def recover(self):
        """Replace Chrome when screenshots time out despite a healthy CDP socket."""
        url = self.url
        try:
            url = self.evaluate("location.href") or url
        except Exception:
            pass
        self.stop()
        self.port = self._requested_port
        self.ws_url = None
        self._dead = None
        self._screencasting = False
        self._frame_rgb = None
        with self._lock:
            self._pending.clear()
            self._queue.clear()
        self.start()
        if url:
            self.navigate(url, wait=False)
        logging.info("browser restarted after capture stall; url=%s", url)

    def mouse(self, x, y, kind="mouseMoved", button="none", click_count=0):
        """Dispatch a mouse event. Fire-and-forget for speed."""
        try:
            self.ws.send_json({
                "id": _next_id(),
                "method": "Input.dispatchMouseEvent",
                "params": {
                    "type": kind,
                    "x": x, "y": y,
                    "button": button,
                    "clickCount": click_count,
                    "buttons": self._button_mask(button, kind),
                }
            })
        except OSError:
            self._reconnect()
            raise CDPError("mouse event failed")

    def touch(self, kind, x=None, y=None, touch_id=0):
        """Dispatch a native Chrome touch event at viewport coordinates."""
        points = []
        if kind != "touchEnd" and x is not None and y is not None:
            points.append({
                "x": int(x), "y": int(y), "id": int(touch_id),
                "radiusX": 1, "radiusY": 1, "force": 1,
            })
        try:
            self.ws.send_json({
                "id": _next_id(),
                "method": "Input.dispatchTouchEvent",
                "params": {"type": kind, "touchPoints": points},
            })
        except OSError:
            self._reconnect()
            raise CDPError("touch event failed")

    def show_virtual_cursor(self, x, y):
        """Draw a persistent, non-interactive cursor for touch RDP clients."""
        point = json.dumps([int(x), int(y)], separators=(",", ":"))
        expression = (
            "(function(p){"
            "var d=document.getElementById('__rdp-virtual-cursor');"
            "if(!d){d=document.createElement('div');"
            "d.id='__rdp-virtual-cursor';d.setAttribute('aria-hidden','true');"
            "document.documentElement.appendChild(d);}"
            "d.style.cssText='position:fixed;z-index:2147483646;width:24px;height:32px;'+"
            "'pointer-events:none;filter:drop-shadow(1px 1px 1px #000b);';"
            "d.innerHTML='<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"32\" viewBox=\"0 0 24 32\"><path d=\"M2 1v25l6-6 4 10 5-2-5-10h9L2 1z\" fill=\"white\" stroke=\"black\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/><path d=\"M4 5v16l4-4 4 9 2-1-4-10h6L4 5z\" fill=\"#d9e8ff\"/></svg>';"
            "d.style.left=p[0]+'px';d.style.top=p[1]+'px';return true;"
            "})(" + point + ")")
        return self.evaluate(expression)

    @staticmethod
    def _button_mask(button, kind):
        bit = {"left": 1, "middle": 2, "right": 4}.get(button, 0)
        return 0 if kind == "mouseReleased" else bit

    def click(self, x, y, button="left"):
        """Full press+release click at viewport coordinates. Fire-and-forget."""
        try:
            self.mouse(x, y, "mouseMoved", "none")
        except CDPError:
            pass
        try:
            self.mouse(x, y, "mousePressed", button, click_count=1)
        except CDPError:
            pass
        try:
            self.mouse(x, y, "mouseReleased", button, click_count=1)
        except CDPError:
            pass

    def wheel(self, x, y, delta_x=0, delta_y=0):
        """Dispatch a mouse wheel event. Fire-and-forget."""
        try:
            self.ws.send_json({
                "id": _next_id(),
                "method": "Input.dispatchMouseEvent",
                "params": {
                    "type": "mouseWheel",
                    "x": x, "y": y,
                    "deltaX": delta_x,
                    "deltaY": delta_y,
                    "buttons": 0,
                }
            })
        except OSError:
            self._reconnect()
            raise CDPError("wheel event failed")

    def key(self, key, code=None, text=None, vk=0, kind="keyDown"):
        """Dispatch a key event. kind: keyDown/keyUp/rawKeyDown/char."""
        params = {
            "type": kind,
            "key": key,
            "code": code or key,
            "windowsVirtualKeyCode": vk,
            "nativeVirtualKeyCode": vk,
        }
        if text is not None:
            params["text"] = text
            params["unmodifiedText"] = text
        self._send_with_retry("Input.dispatchKeyEvent", params)

    def type_text(self, text):
        """Type a run of characters, one rawKeyDown+char+keyUp per character.

        keyDown (non-raw) with text also inserts the character in Chrome, so
        pairing it with a char event typed every character twice; rawKeyDown
        fires keydown without inserting and char does the single insertion.
        """
        for ch in text:
            if ch.isascii() and ch.isalpha():
                vk = ord(ch.upper())
            elif ch.isdigit() and ch.isascii():
                vk = ord(ch)
            else:
                vk = 0
            self.key(ch, code=ch, text=ch, vk=vk, kind="rawKeyDown")
            self.key(ch, code=ch, text=ch, vk=vk, kind="char")
            self.key(ch, code=ch, vk=vk, kind="keyUp")

    def insert_text(self, text):
        """Insert committed IME text into the focused browser control."""
        if text:
            self._send_with_retry("Input.insertText", {"text": text})


# ---------- process-wide singleton -----------------------------------------
_LOCK = threading.Lock()
_INSTANCE = None


def get_browser(width, height):
    """Return a started Browser, launching one on first use."""
    global _INSTANCE
    with _LOCK:
        if _INSTANCE is None:
            b = Browser(width, height)
            b.start()
            _INSTANCE = b
        return _INSTANCE


def shutdown():
    global _INSTANCE
    with _LOCK:
        if _INSTANCE is not None:
            _INSTANCE.stop()
            _INSTANCE = None
