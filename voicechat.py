#!/usr/bin/env python3
# coding: utf-8
"""
UDP voice call safe edition
- anti-spam for logs
- Windows-friendly (ProactorEventLoop compatibility)
- input device selection (--input-device)
- --list-devices to enumerate audio devices and exit
"""

import argparse
import asyncio
import numpy as np
import pyaudio
import socket
import sys
import time
from typing import Tuple, Optional


# Конфигурация (можно менять)
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
EXPECTED_BYTES = CHUNK * CHANNELS * 2  # 2 bytes per sample (Int16)
INACTIVITY_TIMEOUT = 60  # секунд без входящих пакетов -> стоп
MAX_PEAK = 30000  # порог пикового значения перед применением лимитера


class UDPVoiceCall:
    def __init__(
        self,
        local_port: int,
        remote_addr: Tuple[str, int],
        debug: bool = False,
        input_device_index: Optional[int] = None,
    ):
        self.running = True
        self.muted = False
        self.debug = debug

        # Audio
        self.audio = pyaudio.PyAudio()
        self.input_device_index = input_device_index
        self.output_device_index = None

        # Remote address and IP filter
        self.remote_addr = (remote_addr[0], int(remote_addr[1]))
        self.remote_ip = self.remote_addr[0]

        # UDP socket (we will NOT set non-blocking to support executor blocking recv/send)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", local_port))
        # don't set non-blocking, we use run_in_executor when needed for compatibility

        self.input_stream = None
        self.output_stream = None

        self.last_recv_time = time.time()

        # LOG anti-spam: debug logs (cooldown) and info logs (one-time limit)
        self._debug_log_count = 0
        self._debug_log_limit = 5
        self._debug_log_cooldown = 5.0
        self._debug_last_time = 0.0
        self._debug_suppressed_notice = False

        self._info_log_count = 0
        self._info_log_limit = 5
        self._info_suppressed_notice = False

    # ----- Logging helpers -----
    def debug_log(self, *args):
        """Debug messages: obey debug flag, cooldown and per-cooldown limit."""
        if not self.debug:
            return

        now = time.time()
        if now - self._debug_last_time >= self._debug_log_cooldown:
            # reset after cooldown
            self._debug_log_count = 0
            self._debug_suppressed_notice = False

        if self._debug_log_count < self._debug_log_limit:
            print("[DEBUG]", *args)
            self._debug_log_count += 1
            self._debug_last_time = now
        else:
            if not self._debug_suppressed_notice:
                print("[DEBUG] log spam suppressed (cooldown {:.0f}s)".format(self._debug_log_cooldown))
                self._debug_suppressed_notice = True

    def info_once(self, *args):
        """Informational prints but limited to _info_log_limit times total to avoid spam."""
        if self._info_log_count < self._info_log_limit:
            print(*args)
            self._info_log_count += 1
        else:
            if not self._info_suppressed_notice:
                print("[INFO] further info messages suppressed")
                self._info_suppressed_notice = True

    # ----- Device utilities -----
    def list_devices(self):
        """Вернуть список устройств ввода/вывода (в виде кортежей)."""
        devices = []
        try:
            cnt = self.audio.get_device_count()
            for i in range(cnt):
                info = self.audio.get_device_info_by_index(i)
                devices.append((i, info.get("name"), info))
        except Exception as e:
            print("Ошибка при перечислении устройств:", e)
        return devices

    def print_devices(self):
        devs = self.list_devices()
        if not devs:
            print("Устройств не найдено.")
            return
        print("Available audio devices:")
        for idx, name, info in devs:
            io = []
            if info.get("maxInputChannels", 0) > 0:
                io.append("INPUT")
            if info.get("maxOutputChannels", 0) > 0:
                io.append("OUTPUT")
            print(f"  [{idx}] {name} {'/'.join(io)}")
        default_in = None
        default_out = None
        try:
            default_in = self.audio.get_default_input_device_info().get("name")
            default_out = self.audio.get_default_output_device_info().get("name")
        except Exception:
            pass
        if default_in or default_out:
            print("Defaults:", default_in, "/", default_out)

    def check_devices(self) -> bool:
        """Проверить, доступны ли input/output и выбрать индекс, если надо."""
        try:
            cnt = self.audio.get_device_count()
            if cnt == 0:
                raise RuntimeError("No audio devices")
            # выбор input device
            if self.input_device_index is not None:
                try:
                    info = self.audio.get_device_info_by_index(self.input_device_index)
                    if info.get("maxInputChannels", 0) <= 0:
                        print("Выбранный индекс не является input-устройством.")
                        return False
                    self.debug_log("Using input device index", self.input_device_index, "name:", info.get("name"))
                except Exception as e:
                    print("Неверный индекс устройства:", e)
                    return False
            else:
                # пробуем использовать дефолт
                try:
                    default_input = self.audio.get_default_input_device_info()
                    self.input_device_index = int(default_input.get("index"))
                    self.debug_log("Auto-selected default input device:", default_input.get("name"))
                except Exception:
                    # если нет дефолта, попытаемся найти первое с input
                    found = False
                    for i in range(cnt):
                        info = self.audio.get_device_info_by_index(i)
                        if info.get("maxInputChannels", 0) > 0:
                            self.input_device_index = i
                            found = True
                            self.debug_log("Auto-selected input device by scan:", info.get("name"), "index", i)
                            break
                    if not found:
                        print("Ошибка: не найдено input-устройство.")
                        return False
            # выбор output (попытаемся дефолт)
            try:
                default_output = self.audio.get_default_output_device_info()
                self.output_device_index = int(default_output.get("index"))
            except Exception:
                # пробуем найти первое с output
                self.output_device_index = None
                for i in range(cnt):
                    info = self.audio.get_device_info_by_index(i)
                    if info.get("maxOutputChannels", 0) > 0:
                        self.output_device_index = i
                        break
                if self.output_device_index is None:
                    print("Ошибка: не найдено output-устройство.")
                    return False

            self.debug_log("Devices ready. input_index=", self.input_device_index, "output_index=", self.output_device_index)
            return True
        except Exception as e:
            print("Ошибка: не найдено корректное аудио-устройство:", e)
            return False

    # ----- Audio processing with numpy -----
    def apply_limiter_numpy(self, data: bytes) -> bytes:
        """Apply limiter to audio data using numpy instead of audioop."""
        try:
            # Convert bytes to numpy array (int16)
            audio_array = np.frombuffer(data, dtype=np.int16)
            
            # Find peak
            peak = np.max(np.abs(audio_array))
            
            if peak > MAX_PEAK:
                # Apply limiter
                factor = MAX_PEAK / float(peak)
                audio_array = (audio_array * factor).astype(np.int16)
                self.debug_log(f"Limiter: peak={peak} scaled by {factor:.3f}")
            
            # Convert back to bytes
            return audio_array.tobytes()
        except Exception as e:
            self.debug_log("numpy limiter error:", e)
            return data  # Return original data on error

    # ----- Async socket wrappers for cross-loop compatibility -----
    async def _async_sendto(self, data: bytes) -> bool:
        loop = asyncio.get_running_loop()
        # Prefer native sock_sendto if available (UNIX/SelectorEventLoop)
        if hasattr(loop, "sock_sendto"):
            try:
                await loop.sock_sendto(self.sock, data, self.remote_addr)
                return True
            except Exception as e:
                self.debug_log("Ошибка отправки (sock_sendto):", e)
                return False
        else:
            # Fall back to blocking sendto in executor (Windows ProactorEventLoop)
            try:
                await loop.run_in_executor(None, self.sock.sendto, data, self.remote_addr)
                return True
            except Exception as e:
                self.debug_log("Ошибка отправки (executor sendto):", e)
                return False

    async def _async_recvfrom(self, nbytes: int):
        loop = asyncio.get_running_loop()
        if hasattr(loop, "sock_recvfrom"):
            try:
                data, addr = await loop.sock_recvfrom(self.sock, nbytes)
                return data, addr
            except Exception as e:
                # Can log but keep lightweight
                self.debug_log("sock_recvfrom error:", e)
                raise
        else:
            # blocking recvfrom in executor
            try:
                result = await loop.run_in_executor(None, self.sock.recvfrom, nbytes)
                return result
            except Exception as e:
                self.debug_log("recvfrom (executor) error:", e)
                raise

    # ----- Main tasks -----
    async def send_audio(self):
        """Чтение с микрофона и отправка (с поддержкой mute, лимитером громкости)."""
        try:
            self.input_stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK,
                input_device_index=self.input_device_index,
            )
        except Exception as e:
            print("Не удалось открыть input stream:", e)
            self.stop()
            return

        loop = asyncio.get_running_loop()
        self.print_mic_state()

        try:
            while self.running:
                # Читаем кусок через executor (чтобы не блокировать loop при pyaudio.read)
                try:
                    data = await loop.run_in_executor(None, lambda: self.input_stream.read(CHUNK, exception_on_overflow=False))
                except Exception as e:
                    self.debug_log("Ошибка чтения микрофона:", e)
                    await asyncio.sleep(0.05)
                    continue

                if self.muted:
                    await asyncio.sleep(0.01)
                    continue

                # Apply limiter using numpy
                data = self.apply_limiter_numpy(data)

                # Отправляем через совместимый wrapper
                ok = await self._async_sendto(data)
                if ok:
                    self.debug_log("sent", len(data), "bytes to", self.remote_addr)
                else:
                    self.debug_log("send failed")

                await asyncio.sleep(0)  # yield
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.debug_log("send_audio exception:", e)

    async def receive_audio(self):
        """Приём и воспроизведение; проверка IP, длины пакета, таймаут."""
        try:
            self.output_stream = self.audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                frames_per_buffer=CHUNK,
                output_device_index=self.output_device_index,
            )
        except Exception as e:
            print("Не удалось открыть output stream:", e)
            self.stop()
            return

        try:
            while self.running:
                if time.time() - self.last_recv_time > INACTIVITY_TIMEOUT:
                    print(f"No incoming audio for {INACTIVITY_TIMEOUT} seconds stopping.")
                    self.stop()
                    break

                # Получаем пакет (через обёртку, которая использует executor при необходимости)
                try:
                    data, addr = await self._async_recvfrom(65536)
                except Exception:
                    # нет данных сейчас или ошибка даём цикл
                    await asyncio.sleep(0.01)
                    continue

                # Проверяем IP
                if addr[0] != self.remote_ip:
                    self.debug_log("Packet from unknown IP", addr[0], "ignored")
                    continue

                self.last_recv_time = time.time()

                # Проверяем длину
                if len(data) != EXPECTED_BYTES:
                    self.debug_log(f"Invalid packet size: {len(data)} bytes (expected {EXPECTED_BYTES}) discarded")
                    continue

                # Apply limiter on input using numpy
                data = self.apply_limiter_numpy(data)

                # Play
                try:
                    self.output_stream.write(data)
                    self.debug_log("played", len(data), "bytes from", addr)
                except Exception as e:
                    self.debug_log("Ошибка вывода аудио:", e)
                    await asyncio.sleep(0.05)

                await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.debug_log("receive_audio exception:", e)

    async def command_listener(self):
        """Асинхронно слушаем команды из stdin: /mute, /unmute, /stop, /status, /debug, /choose, /blyat."""
        loop = asyncio.get_running_loop()
        while self.running:
            # run_in_executor чтобы неблокирующе читать stdin
            cmd = await loop.run_in_executor(None, sys.stdin.readline)
            if not cmd:
                await asyncio.sleep(0.05)
                continue
            cmd = cmd.strip().lower()
            if cmd == "/mute":
                self.muted = True
                self.print_mic_state()
            elif cmd == "/unmute":
                self.muted = False
                self.print_mic_state()
            elif cmd == "/stop":
                print("Stopping by user command...")
                self.stop()
                break
            elif cmd == "/blyat":
                print("suka")
                break
            elif cmd == "/status":
                print(self.status_text())
            elif cmd == "/debug":
                self.debug = not self.debug
                print("Debug =", self.debug)
            elif cmd.startswith("/choose"):
                # /choose <index>
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        idx = int(parts[1])
                        # попытка сменить input (будет применена при следующем рестарте стрима)
                        self.input_device_index = idx
                        print("Selected input device index:", idx, "will be used on next start (restart required).")
                    except Exception as e:
                        print("Invalid index:", e)
                else:
                    print("Usage: /choose <input-device-index>")
            elif cmd == "":
                continue
            else:
                print("Команды: /mute /unmute /stop /status /debug /choose /blyat <idx>")

            await asyncio.sleep(0.01)

    def print_mic_state(self):
        self.info_once("MIC ON" if not self.muted else "MIC OFF")

    async def start(self):
        # Проверка устройств до запуска потоков
        if not self.check_devices():
            print("Аудио-устройства не обнаружены; выходим.")
            return

        # Запускаем задачи
        try:
            tasks = [
                asyncio.create_task(self.send_audio(), name="send_audio"),
                asyncio.create_task(self.receive_audio(), name="receive_audio"),
                asyncio.create_task(self.command_listener(), name="cmd_listener"),
            ]
            await asyncio.gather(*tasks)
        finally:
            self.stop()

    def stop(self):
        if not self.running:
            return
        self.running = False

        # Close input stream
        try:
            if self.input_stream is not None:
                try:
                    self.input_stream.stop_stream()
                except Exception:
                    pass
                try:
                    self.input_stream.close()
                except Exception:
                    pass
                self.input_stream = None
        except Exception:
            pass

        # Close output stream
        try:
            if self.output_stream is not None:
                try:
                    self.output_stream.stop_stream()
                except Exception:
                    pass
                try:
                    self.output_stream.close()
                except Exception:
                    pass
                self.output_stream = None
        except Exception:
            pass

        # Terminate pyaudio
        try:
            self.audio.terminate()
        except Exception:
            pass

        # Close socket
        try:
            self.sock.close()
        except Exception:
            pass

        print("Voice call stopped cleanly")

    def status_text(self):
        return f"running={self.running} muted={self.muted} remote={self.remote_addr} last_recv={int(time.time()-self.last_recv_time)}s"


# ----- Runner -----
async def main_async(local_port: int, remote: str, debug: bool, input_device_index: Optional[int], list_devices: bool):
    ip, port = remote.split(":")
    remote_addr = (ip.strip(), int(port.strip()))
    call = UDPVoiceCall(local_port, remote_addr, debug=debug, input_device_index=input_device_index)

    if list_devices:
        call.print_devices()
        call.stop()
        return

    print("Edited by Hollow Software")
    print("This program uses microphone and sends raw audio via UDP to", remote_addr)
    print("Commands: /mute /unmute /stop /status /debug /choose /blyat <idx>")
    print("No audio is saved, no autostart. INACTIVITY_TIMEOUT =", INACTIVITY_TIMEOUT, "seconds")

    try:
        await call.start()
    except KeyboardInterrupt:
        print("\nStopping (KeyboardInterrupt)...")
        call.stop()


def main():
    parser = argparse.ArgumentParser(description="Simple UDP voice call (safe edition).")
    parser.add_argument("--local-port", "-l", type=int, required=False, default=5000, help="Local UDP port to bind")
    parser.add_argument("--remote", "-r", type=str, required=False, default="127.0.0.1:5001", help="Remote ip:port")
    parser.add_argument("--debug", action="store_true", help="Enable debug prints")
    parser.add_argument("--input-device", "-i", type=int, required=False, default=None, help="Input device index (optional)")
    parser.add_argument("--list-devices", action="store_true", help="List audio devices and exit")
    args = parser.parse_args()

    # Interactive fallback for convenience
    if sys.stdin.isatty() and (args.remote == "127.0.0.1:5001" and args.local_port == 5000):
        try:
            lp = input(f"Local port [{args.local_port}]: ").strip()
            if lp:
                args.local_port = int(lp)
            ra = input(f"Remote address ip:port [{args.remote}]: ").strip()
            if ra:
                args.remote = ra
            dbg = input("Debug? (y/N): ").strip().lower()
            if dbg == "y":
                args.debug = True
            li = input("List audio devices? (y/N): ").strip().lower()
            if li == "y":
                args.list_devices = True
            if not args.list_devices:
                idi = input("Input device index (empty = auto): ").strip()
                if idi:
                    args.input_device = int(idi)
        except Exception:
            pass

    try:
        asyncio.run(main_async(args.local_port, args.remote, args.debug, args.input_device, args.list_devices))
    except KeyboardInterrupt:
        print("\nStopped by KeyboardInterrupt")


if __name__ == "__main__":
    main()
