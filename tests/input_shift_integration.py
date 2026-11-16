#!/usr/bin/env python3
"""Real-binary shift tests: no DVB hardware, credentials or external streams."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest


BINARY = str(Path(os.environ.get('TSDECRYPT_BIN', './tsdecrypt')).resolve())


def packet(pid, marker):
    return bytes((0x47, pid >> 8, pid & 255, 0x10 | (marker & 15))) + bytes([marker]) * 184


# Includes EPG, CAT/EMM, PCR/data and PSI PIDs: forwarding cannot discard them.
FRAME = b''.join(packet(pid, i) for i, pid in enumerate((0, 1, 0x10, 0x11, 0x12, 0x14, 0x100)))


def section(table, service, body):
    data = bytes((table, 0xb0, len(body) + 9)) + struct.pack('>HBBB', service, 0xc1, 0, 0) + body
    crc = 0xffffffff
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
    return data + struct.pack('>I', crc)


def psi_packet(pid, data):
    return (bytes((0x47, 0x40 | (pid >> 8), pid & 255, 0x10, 0)) + data).ljust(188, b'\xff')


def ecm_input():
    pat = section(0, 1, struct.pack('>HH', 21, 0xe100))
    descriptor = b'\x09\x04\x09\xbd\xe1\xec'  # CAID09BD, ECM PID0x1ec.
    pmt = section(2, 21, struct.pack('>HH', 0xe101, 0xf000 | len(descriptor)) + descriptor +
                  b'\x1b\xe1\x01\xf0\x00')
    return psi_packet(0, pat) + psi_packet(0x100, pmt) + psi_packet(0x1ec, b'\x80\x30\x08synthecm')


class ShiftTest(unittest.TestCase):
    def command(self, shift=150, memory=1024 * 1024):
        return [BINARY, '--input-passthrough', '--input', '-', '--output', '-',
                '--input-shift', str(shift), '--input-shift-memory', str(memory)]

    def test_zero_passthrough_without_camd(self):
        result = subprocess.run(self.command(0), input=FRAME, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, FRAME)
        self.assertNotIn(b'CAMD addr', result.stderr)

    def test_pipe_short_reads_and_eof_draining(self):
        process = subprocess.Popen(self.command(180), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start = time.monotonic()
        for chunk in (FRAME[:17], FRAME[17:203], FRAME[203:599], FRAME[599:]):
            process.stdin.write(chunk)
            process.stdin.flush()
            time.sleep(.012)
        process.stdin.close()
        process.stdin = None
        output, errors = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(output, FRAME)
        self.assertGreaterEqual(time.monotonic() - start, .175)

    def test_cap_overflow_exits_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            status = Path(temporary) / 'shift.json'
            result = subprocess.run(self.command(1500, 4096) + ['--input-shift-status', str(status)],
                                    input=FRAME * 16, capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            report = json.loads(status.read_text())
            self.assertEqual(report['state'], 'overflow')
            self.assertEqual(report['overflows'], 1)
            self.assertLessEqual(report['allocated_bytes'], 4096)
            self.assertLessEqual(report['used_bytes'], report['allocated_bytes'])

    def test_invalid_cli(self):
        for arguments in (['--input-shift', '-1'], ['--input-shift', '10001'],
                          ['--input-shift', '150'], ['--input-shift-memory', '12oops']):
            result = subprocess.run([BINARY, '--input-passthrough'] + arguments,
                                    input=b'', capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0, arguments)

    def test_truncated_pipe_packet_is_an_error(self):
        result = subprocess.run(self.command(), input=FRAME + b'\x47x', capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Truncated TS packet', result.stderr)

    def test_udp_deadlines_order_and_drain_during_silence(self):
        source = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        destination = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(source.close)
        self.addCleanup(reserve.close)
        self.addCleanup(destination.close)
        reserve.bind(('127.0.0.1', 0))
        input_port = reserve.getsockname()[1]
        reserve.close()
        destination.bind(('127.0.0.1', 0))
        destination.settimeout(2)
        with tempfile.TemporaryDirectory() as temporary:
            status = Path(temporary) / 'shift.json'
            process = subprocess.Popen([
                BINARY, '--input-passthrough', '--input', f'127.0.0.1:{input_port}',
                '--output', f'127.0.0.1:{destination.getsockname()[1]}',
                '--input-shift', '250', '--input-shift-memory', '1048576',
                '--input-shift-status', str(status)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 2
                while not status.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(status.exists())
                sent = []
                expected = [FRAME, packet(0x12, 41), FRAME]
                for block in expected:
                    sent.append(time.monotonic())
                    source.sendto(block, ('127.0.0.1', input_port))
                    time.sleep(.04)
                received = []
                for block in expected:
                    actual, _ = destination.recvfrom(4096)
                    received.append(time.monotonic())
                    self.assertEqual(actual, block)
                for arrival, release in zip(sent, received):
                    self.assertGreaterEqual(release - arrival, .235)
                    self.assertLess(release - arrival, .7)
                for previous, current in zip(received, received[1:]):
                    self.assertGreater(current - previous, .02)
            finally:
                process.terminate()
                _, errors = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, errors.decode())
            report = json.loads(status.read_text())
            self.assertEqual(report['released_blocks'], 3)
            self.assertEqual(report['overflows'], 0)
            self.assertEqual(report['queued_blocks'], 0)

    def test_stop_does_not_wait_for_long_shift(self):
        process = subprocess.Popen(self.command(10000), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdin.write(FRAME)
        process.stdin.flush()
        time.sleep(.1)
        start = time.monotonic()
        process.terminate()
        output, _ = process.communicate(timeout=2)
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(output, b'')

    def test_ecm_request_is_shifted_before_camd(self):
        # CS378x does not send a login handshake: its first TCP payload is this
        # synthetic ECM request. No real smartcard or key is involved.
        for milliseconds in (0, 350):
            with self.subTest(shift_ms=milliseconds), socket.socket() as server:
                server.bind(('127.0.0.1', 0))
                server.listen(1)
                server.settimeout(2)
                process = subprocess.Popen([
                    BINARY, '--input', '-', '--output', '/dev/null', '--input-service', '21',
                    '--caid', '0x09BD', '--camd-server', f'127.0.0.1:{server.getsockname()[1]}',
                    '--camd-user', 'synthetic', '--camd-pass', 'synthetic', '--ecm-no-log',
                    '--input-shift', str(milliseconds), '--input-shift-memory', '1048576'],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                connection = None
                try:
                    connection, _ = server.accept()
                    sent_at = time.monotonic()
                    process.stdin.write(ecm_input())
                    process.stdin.flush()
                    if milliseconds:
                        connection.settimeout(.22)
                        with self.assertRaises(socket.timeout):
                            connection.recv(4096)
                    connection.settimeout(2)
                    request = connection.recv(4096)
                    elapsed = time.monotonic() - sent_at
                    self.assertTrue(request, 'No ECM sent after shift deadline')
                    self.assertGreaterEqual(elapsed, milliseconds / 1000 - .015)
                    self.assertLess(elapsed, milliseconds / 1000 + .5)
                finally:
                    process.terminate()
                    if connection:
                        connection.close()  # Unblock the real CAMD receive worker.
                    _, errors = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, errors.decode())

    def test_overflow_cancels_pending_camd_reply(self):
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(2)
            status = Path(temporary) / 'shift.json'
            process = subprocess.Popen([
                BINARY, '--input', '-', '--output', '/dev/null', '--input-service', '21',
                '--caid', '0x09BD', '--camd-server', f'127.0.0.1:{server.getsockname()[1]}',
                '--camd-user', 'synthetic', '--camd-pass', 'synthetic', '--ecm-no-log',
                '--input-shift', '50', '--input-shift-memory', '4096',
                '--input-shift-status', str(status)], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            connection = None
            try:
                connection, _ = server.accept()
                connection.settimeout(2)
                process.stdin.write(ecm_input())
                process.stdin.flush()
                self.assertTrue(connection.recv(4096))
                # Keep the server connection OPEN and never answer. Overflow
                # must cancel that blocked CW receive itself, not need SIGTERM.
                start = time.monotonic()
                try:
                    process.stdin.write(FRAME * 16)
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
                code = process.wait(timeout=1)
                self.assertNotEqual(code, 0)
                self.assertLess(time.monotonic() - start, 1)
                self.assertEqual(json.loads(status.read_text())['state'], 'overflow')
            finally:
                if process.poll() is None:
                    process.terminate()
                if connection:
                    connection.close()
                process.communicate(timeout=3)


if __name__ == '__main__':
    unittest.main()
