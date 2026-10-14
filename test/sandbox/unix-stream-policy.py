#!/usr/bin/env python3
"""Linux-only build-policy regression: python3 test/sandbox/unix-stream-policy.py.

Requires gcc and libseccomp-dev. Compiles both policies into a temporary directory
and loads each real BPF filter in a child process; no root privileges required.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile


def check_filter(path, allow_stream):
    class Instruction(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort),
                    ('instructions', ctypes.POINTER(Instruction))]

    raw = Path(path).read_bytes()
    assert len(raw) % ctypes.sizeof(Instruction) == 0
    count = len(raw) // ctypes.sizeof(Instruction)
    instructions = (Instruction * count).from_buffer_copy(raw)
    program = Program(count, instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    assert libc.prctl(38, 1, 0, 0, 0) == 0, ctypes.get_errno()
    assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0, ctypes.get_errno()
    nr_socket = {'x86_64': 41, 'aarch64': 198}[platform.machine()]
    # Independent upper bits in both int arguments, plus common socket flags.
    for family in (socket.AF_UNIX, 40):  # AF_VSOCK
        for kind in range(16):
            for flags in (0, socket.SOCK_CLOEXEC, socket.SOCK_NONBLOCK,
                          socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK):
                for upper_domain in (0, 1 << 32, 0xffffffff00000000):
                    for upper_type in (0, 1 << 32, 0xffffffff00000000):
                        ctypes.set_errno(0)
                        fd = libc.syscall(nr_socket,
                            ctypes.c_ulonglong(family | upper_domain),
                            ctypes.c_ulonglong(kind | flags | upper_type), 0)
                        error = ctypes.get_errno()
                        if fd >= 0:
                            os.close(fd)
                        expected = allow_stream and family == socket.AF_UNIX and kind == 1
                        # An outer container policy can reject upper-bit encodings.
                        if expected and (upper_domain or upper_type):
                            assert fd >= 0 or error == errno.EPERM
                        else:
                            assert (fd >= 0) if expected else (fd == -1 and error == errno.EPERM), (
                                family, kind, flags, upper_domain, upper_type, fd, error)
    for nr in (425, 426, 427):  # io_uring_setup, enter, register on both arches
        ctypes.set_errno(0)
        assert libc.syscall(nr, 0, 0, 0, 0, 0, 0) == -1
        assert ctypes.get_errno() == errno.EPERM
    if allow_stream:
        for address in (str(Path(path).with_suffix('.sock')),
                        '\0srt-stream-policy-' + str(os.getpid())):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.settimeout(3)
                server.bind(address)
                server.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.connect(address)
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(3)
                        client.sendall(b'ipc')
                        assert peer.recv(3) == b'ipc'
                        peer.sendall(b'ok')
                        assert client.recv(2) == b'ok'


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--probe':
        check_filter(sys.argv[2], sys.argv[3] == '1')
        return
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise SystemExit('Requires Linux x86_64 or aarch64; not a passing skip.')
    source = Path(__file__).resolve().parents[2] / 'vendor/seccomp-src/seccomp-unix-block.c'
    with tempfile.TemporaryDirectory(prefix='srt-stream-policy-') as tmp:
        namespace_filters = []
        for enabled in (False, True):
            generator = Path(tmp) / ('generator-' + str(int(enabled)))
            subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror',
                *(['-DSRT_ALLOW_UNIX_STREAM'] if enabled else []),
                str(source), '-lseccomp', '-o', str(generator)], check=True)
            for rules in ('unix', 'namespaces'):
                output = Path(str(generator) + '.' + rules + '.bpf')
                subprocess.run([str(generator), str(output), platform.machine(), rules], check=True)
                if rules == 'namespaces':
                    namespace_filters.append(output.read_bytes())
                else:
                    # Workload environment cannot flip the compiled policy.
                    env = dict(os.environ, SRT_ALLOW_UNIX_STREAM=str(int(not enabled)))
                    subprocess.run([sys.executable, __file__, '--probe', str(output),
                                    str(int(enabled))], env=env, check=True, timeout=20)
            print('PASS: compiled Unix stream policy enabled=' + str(enabled), flush=True)
        assert namespace_filters[0] == namespace_filters[1], 'Namespace filter changed'
        print('PASS: namespace filter byte-identical between policies')


if __name__ == '__main__':
    main()
