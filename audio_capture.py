"""Capture PCM rendered by a Windows process tree without rendering audio here.

This module is intentionally capture-only. It uses Windows process loopback and
exposes samples through a bounded queue or callback; it never opens a render
client or changes endpoint/session volume.
"""

from __future__ import annotations

import ctypes
import os
import queue
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class AudioFormat:
    sample_rate: int
    channels: int
    bits_per_sample: int
    block_align: int
    format_tag: int


@dataclass(frozen=True)
class AudioChunk:
    pcm: bytes
    frames: int
    timestamp: float


class ProcessLoopbackCapture:
    """Capture a target process and its descendants as interleaved PCM bytes.

    ``start`` waits for WASAPI initialization and raises on failure. Captured
    chunks are delivered to ``callback`` (on the capture thread) and/or placed
    in a queue whose maximum size is fixed by ``queue_size``. When full, the
    oldest queued chunk is discarded to keep latency and memory bounded.

    Requires Windows 10 build 20348 or newer. ``process_id`` should identify
    the browser parent process so Chromium child renderers are included.
    """

    def __init__(self, process_id: int, *, callback: Optional[Callable[[AudioChunk], None]] = None,
                 queue_size: int = 32, poll_interval: float = 0.005):
        if os.name != "nt":
            raise OSError("Windows process loopback capture is only available on Windows")
        if process_id <= 0:
            raise ValueError("process_id must be a positive Windows process ID")
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")
        self.process_id = int(process_id)
        self.callback = callback
        self.chunks: queue.Queue[AudioChunk] = queue.Queue(maxsize=queue_size)
        self.poll_interval = max(0.001, float(poll_interval))
        self.format: Optional[AudioFormat] = None
        self.dropped_chunks = 0
        self.callback_errors = 0
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[BaseException] = None

    def start(self, timeout: float = 10.0) -> "ProcessLoopbackCapture":
        if self._thread is not None:
            raise RuntimeError("capture has already been started")
        self._thread = threading.Thread(target=self._capture_main, name="process-loopback", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop()
            raise TimeoutError("timed out initializing Windows process loopback")
        if self._error is not None:
            self._thread.join(timeout=1)
            raise RuntimeError("Windows process loopback initialization failed") from self._error
        return self

    def get(self, timeout: Optional[float] = None) -> AudioChunk:
        """Return the next PCM chunk from the bounded queue."""
        return self.chunks.get(timeout=timeout)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(0.0, timeout))

    close = stop

    def __enter__(self) -> "ProcessLoopbackCapture":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _publish(self, chunk: AudioChunk) -> None:
        if self.callback is not None:
            try:
                self.callback(chunk)
            except Exception:
                self.callback_errors += 1
        try:
            self.chunks.put_nowait(chunk)
        except queue.Full:
            try:
                self.chunks.get_nowait()
            except queue.Empty:
                pass
            self.dropped_chunks += 1
            try:
                self.chunks.put_nowait(chunk)
            except queue.Full:
                self.dropped_chunks += 1

    def _capture_main(self) -> None:
        try:
            _run_wasapi_process_loopback(self)
        except BaseException as exc:
            self._error = exc
        finally:
            # Only signal readiness after the error is visible to start().
            # The capture routine sets this event after successful Start().
            self._ready.set()


def _run_wasapi_process_loopback(owner: ProcessLoopbackCapture) -> None:
    """Private ctypes implementation of ActivateAudioInterfaceAsync + WASAPI."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError("process loopback ctypes layout currently requires 64-bit Python")

    HRESULT = ctypes.c_long
    ULONG = ctypes.c_ulong
    DWORD = ctypes.c_ulong
    UINT32 = ctypes.c_uint32
    UINT64 = ctypes.c_uint64
    BYTE = ctypes.c_ubyte
    GUID = ctypes.c_byte * 16
    WINFUNCTYPE = ctypes.WINFUNCTYPE
    S_OK = 0
    FAILED = lambda hr: ctypes.c_long(hr).value < 0
    CLSCTX_ALL = 23
    COINIT_MULTITHREADED = 0
    AUDCLNT_SHAREMODE_SHARED = 0
    AUDCLNT_STREAMFLAGS_LOOPBACK = 0x00020000
    AUDCLNT_STREAMFLAGS_EVENTCALLBACK = 0x00040000
    AUDCLNT_BUFFERFLAGS_SILENT = 0x2
    VT_BLOB = 0x41

    def guid(value: str) -> GUID:
        parsed = ctypes.create_string_buffer(16)
        ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(value), ctypes.byref(parsed))
        return GUID.from_buffer_copy(parsed.raw)

    def check(hr, action):
        if FAILED(hr):
            raise OSError(f"{action} failed with HRESULT 0x{ctypes.c_uint32(hr).value:08X}")

    class Blob(ctypes.Structure):
        _fields_ = [("cbSize", ULONG), ("pBlobData", ctypes.POINTER(BYTE))]

    class PropUnion(ctypes.Union):
        _fields_ = [("blob", Blob), ("raw", ctypes.c_ubyte * 16)]

    class PropVariant(ctypes.Structure):
        _fields_ = [("vt", ctypes.c_ushort), ("reserved1", ctypes.c_ushort),
                    ("reserved2", ctypes.c_ushort), ("reserved3", ctypes.c_ushort),
                    ("value", PropUnion)]

    class ProcessLoopbackParams(ctypes.Structure):
        _fields_ = [("TargetProcessId", DWORD), ("ProcessLoopbackMode", ctypes.c_int)]

    class ActivationParams(ctypes.Structure):
        _fields_ = [("ActivationType", ctypes.c_int), ("ProcessLoopbackParams", ProcessLoopbackParams)]

    class WaveFormatEx(ctypes.Structure):
        _fields_ = [("wFormatTag", ctypes.c_ushort), ("nChannels", ctypes.c_ushort),
                    ("nSamplesPerSec", DWORD), ("nAvgBytesPerSec", DWORD),
                    ("nBlockAlign", ctypes.c_ushort), ("wBitsPerSample", ctypes.c_ushort),
                    ("cbSize", ctypes.c_ushort)]

    class WaveFormatExtensible(ctypes.Structure):
        _fields_ = WaveFormatEx._fields_ + [("wValidBitsPerSample", ctypes.c_ushort),
                    ("dwChannelMask", DWORD), ("SubFormat", ctypes.c_ubyte * 16)]

    class AudioBuffer(ctypes.Structure):
        _fields_ = [("data", ctypes.POINTER(BYTE)), ("frames", UINT32), ("flags", DWORD),
                    ("device_position", UINT64), ("qpc_position", UINT64)]

    # Activation parameters are passed as a VT_BLOB containing the two native
    # structures required by audioclientactivationparams.h.
    params = ActivationParams(1, ProcessLoopbackParams(owner.process_id, 0))
    params_blob = (BYTE * ctypes.sizeof(params)).from_buffer_copy(params)
    prop = PropVariant()
    prop.vt = VT_BLOB
    prop.value.blob = Blob(ctypes.sizeof(params), ctypes.cast(params_blob, ctypes.POINTER(BYTE)))

    # IActivateAudioInterfaceCompletionHandler + IAgileObject. The callback
    # only publishes the activation result; WASAPI is initialized on this MTA.
    iid_unknown = guid("{00000000-0000-0000-C000-000000000046}")
    iid_handler = guid("{41D949AB-9862-444A-80F6-C261334DA5EB}")
    iid_agile = guid("{94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}")
    iid_audio_client = guid("{1CB9AD4C-DBFA-4c32-B178-C2F568A703B2}")

    class ComInterface(ctypes.Structure):
        pass

    PCom = ctypes.POINTER(ComInterface)
    QueryInterface = WINFUNCTYPE(HRESULT, PCom, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p))
    AddRef = WINFUNCTYPE(ULONG, PCom)
    Release = WINFUNCTYPE(ULONG, PCom)
    ActivateCompleted = WINFUNCTYPE(HRESULT, PCom, ctypes.c_void_p)

    class HandlerVTable(ctypes.Structure):
        _fields_ = [("QueryInterface", QueryInterface), ("AddRef", AddRef),
                    ("Release", Release), ("ActivateCompleted", ActivateCompleted)]

    ComInterface._fields_ = [("lpVtbl", ctypes.POINTER(HandlerVTable))]
    ref_count = [1]
    activated = {"event": threading.Event(), "client": None, "hr": None, "activation_hr": None}
    interface = ComInterface()

    @QueryInterface
    def query_interface(this, riid, result):
        if bytes(riid.contents) in (bytes(iid_unknown), bytes(iid_handler), bytes(iid_agile)):
            result[0] = ctypes.cast(this, ctypes.c_void_p)
            ref_count[0] += 1
            return S_OK
        result[0] = None
        return ctypes.c_long(0x80004002).value

    @AddRef
    def add_ref(this):
        ref_count[0] += 1
        return ref_count[0]

    @Release
    def release(this):
        ref_count[0] = max(0, ref_count[0] - 1)
        return ref_count[0]

    @ActivateCompleted
    def activate_completed(this, operation):
        try:
            vtable = ctypes.cast(operation, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            get_result_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.POINTER(HRESULT),
                                          ctypes.POINTER(ctypes.c_void_p))
            get_result = get_result_type(vtable[3])
            client = ctypes.c_void_p()
            activation_hr = HRESULT()
            hr = get_result(operation, ctypes.byref(activation_hr), ctypes.byref(client))
            activated.update(client=client, hr=hr, activation_hr=activation_hr.value)
        except BaseException as exc:
            activated["exception"] = exc
        finally:
            activated["event"].set()
        return S_OK

    vtable = HandlerVTable(query_interface, add_ref, release, activate_completed)
    interface.lpVtbl = ctypes.pointer(vtable)

    ole32 = ctypes.windll.ole32
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, DWORD]
    ole32.CoInitializeEx.restype = HRESULT
    ole32.CoUninitialize.restype = None
    initialized_com = False
    audio_client = ctypes.c_void_p()
    capture_client = ctypes.c_void_p()
    operation = ctypes.c_void_p()
    mix_format = ctypes.c_void_p()
    audio_event = None
    client_started = False

    try:
        hr = ole32.CoInitializeEx(None, COINIT_MULTITHREADED)
        check(hr, "CoInitializeEx")
        initialized_com = True
        activate = ctypes.windll.mmdevapi.ActivateAudioInterfaceAsync
        activate.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(GUID), ctypes.POINTER(PropVariant),
                             PCom, ctypes.POINTER(ctypes.c_void_p)]
        activate.restype = HRESULT
        hr = activate("VAD\\Process_Loopback", ctypes.byref(iid_audio_client), ctypes.byref(prop),
                      ctypes.byref(interface), ctypes.byref(operation))
        check(hr, "ActivateAudioInterfaceAsync")
        if not activated["event"].wait(10.0):
            raise TimeoutError("process loopback activation callback timed out")
        if "exception" in activated:
            raise RuntimeError("process loopback activation callback failed") from activated["exception"]
        check(activated["hr"], "IActivateAudioInterfaceAsyncOperation.GetActivateResult")
        check(activated["activation_hr"], "process loopback activation")
        audio_client = activated["client"]
        if not audio_client:
            raise OSError("process loopback returned no IAudioClient")

        ac_vt = ctypes.cast(audio_client, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        # The VAD process-loopback virtual device returns E_NOTIMPL from
        # IAudioClient.GetMixFormat. Supply a supported format explicitly.
        wf = WaveFormatEx(1, 2, 48000, 192000, 4, 16, 0)
        mix_format = ctypes.cast(ctypes.pointer(wf), ctypes.c_void_p)
        source_bits = wf.wBitsPerSample
        source_format = wf.wFormatTag
        owner.format = AudioFormat(48000, 2, 16, 4, 1)
        create_event = ctypes.windll.kernel32.CreateEventW
        create_event.restype = ctypes.c_void_p
        audio_event = create_event(None, False, False, None)
        if not audio_event:
            raise ctypes.WinError()

        init_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.c_int, DWORD, UINT64,
                                UINT64, ctypes.c_void_p, ctypes.c_void_p)
        initialize = init_type(ac_vt[3])
        check(initialize(audio_client, AUDCLNT_SHAREMODE_SHARED,
                         AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                         0, 0, mix_format, None), "IAudioClient.Initialize")
        set_event_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.c_void_p)
        check(set_event_type(ac_vt[13])(audio_client, audio_event),
              "IAudioClient.SetEventHandle")
        get_service_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.POINTER(GUID),
                                       ctypes.POINTER(ctypes.c_void_p))
        get_service = get_service_type(ac_vt[14])
        iid_capture = guid("{C8ADBD64-E71E-48a0-A4DE-185C395CD317}")
        check(get_service(audio_client, ctypes.byref(iid_capture), ctypes.byref(capture_client)),
              "IAudioClient.GetService(IAudioCaptureClient)")
        start_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p)
        start = start_type(ac_vt[10])
        check(start(audio_client), "IAudioClient.Start")
        client_started = True
        owner._ready.set()

        cc_vt = ctypes.cast(capture_client, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        next_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.POINTER(UINT32))
        get_next = next_type(cc_vt[5])
        get_buffer_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(BYTE)),
                                      ctypes.POINTER(UINT32), ctypes.POINTER(DWORD),
                                      ctypes.POINTER(UINT64), ctypes.POINTER(UINT64))
        get_buffer = get_buffer_type(cc_vt[3])
        release_buffer_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p, UINT32)
        release_buffer = release_buffer_type(cc_vt[4])
        while not owner._stop.is_set():
            wait_fn = ctypes.windll.kernel32.WaitForSingleObject
            wait_fn.argtypes = [ctypes.c_void_p, DWORD]
            wait_result = wait_fn(audio_event, max(1, int(owner.poll_interval * 1000)))
            if wait_result == 0xFFFFFFFF:
                raise ctypes.WinError()
            packet_frames = UINT32()
            check(get_next(capture_client, ctypes.byref(packet_frames)), "IAudioCaptureClient.GetNextPacketSize")
            if not packet_frames.value:
                continue
            while packet_frames.value:
                data = ctypes.POINTER(BYTE)()
                frames, flags, devpos, qpc = UINT32(), DWORD(), UINT64(), UINT64()
                check(get_buffer(capture_client, ctypes.byref(data), ctypes.byref(frames), ctypes.byref(flags),
                                 ctypes.byref(devpos), ctypes.byref(qpc)), "IAudioCaptureClient.GetBuffer")
                size = frames.value * wf.nBlockAlign
                source = bytes(size) if flags.value & AUDCLNT_BUFFERFLAGS_SILENT else ctypes.string_at(data, size)
                pcm = _to_s16le(source, source_format, wf.wBitsPerSample, source_bits)
                check(release_buffer(capture_client, frames), "IAudioCaptureClient.ReleaseBuffer")
                if pcm:
                    owner._publish(AudioChunk(pcm, frames.value, time.monotonic()))
                check(get_next(capture_client, ctypes.byref(packet_frames)),
                      "IAudioCaptureClient.GetNextPacketSize")
    finally:
        if not owner._ready.is_set():
            owner._ready.set()
        if client_started and audio_client:
            vt = ctypes.cast(audio_client, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            stop_type = WINFUNCTYPE(HRESULT, ctypes.c_void_p)
            stop = stop_type(vt[11])
            stop(audio_client)
        release_type = WINFUNCTYPE(ULONG, ctypes.c_void_p)
        if capture_client:
            vt = ctypes.cast(capture_client, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            release_type(vt[2])(capture_client)
        if audio_client:
            vt = ctypes.cast(audio_client, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            release_type(vt[2])(audio_client)
        if operation:
            vt = ctypes.cast(operation, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            release_type(vt[2])(operation)
        if audio_event:
            close_handle = ctypes.windll.kernel32.CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle(audio_event)
        if initialized_com:
            ole32.CoUninitialize()


def _to_s16le(data: bytes, format_tag: int, container_bits: int, valid_bits: int) -> bytes:
    """Convert the Windows mix format (PCM integer or IEEE float) to s16le."""
    if format_tag == 1 and container_bits == 16 and valid_bits == 16:
        return data
    if container_bits not in (8, 16, 24, 32):
        raise OSError(f"unsupported WASAPI PCM container width {container_bits}")
    if format_tag == 3:
        if container_bits != 32:
            raise OSError(f"unsupported WASAPI IEEE float width {container_bits}")
        count = len(data) // 4
        samples = struct.unpack("<" + "f" * count, data[:count * 4])
        out = bytearray(count * 2)
        for i, sample in enumerate(samples):
            value = max(-1.0, min(1.0, sample))
            struct.pack_into("<h", out, i * 2, int(round(value * 32767.0)))
        return bytes(out)
    if format_tag != 1:
        raise OSError(f"unsupported WASAPI sample format {format_tag}")
    if not 1 <= valid_bits <= container_bits:
        raise OSError(f"invalid WASAPI PCM valid bit count {valid_bits}")
    width = container_bits // 8
    count = len(data) // width
    shift = max(0, valid_bits - 16)
    out = bytearray(count * 2)
    for i in range(count):
        raw = data[i * width:(i + 1) * width]
        value = int.from_bytes(raw, "little", signed=(container_bits != 8))
        if container_bits == 8:
            value -= 1 << 7
        # Extensible PCM stores valid bits left-aligned in the container.
        if valid_bits < container_bits:
            value >>= container_bits - valid_bits
        value >>= shift
        value = max(-32768, min(32767, value))
        struct.pack_into("<h", out, i * 2, value)
    return bytes(out)
