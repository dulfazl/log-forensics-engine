"""
A tiny in-process SSH server for testing ssh_tail without a real sshd.

It accepts password auth, and answers an exec request by running the
requested command (only `tail ...` is allowed) locally with the argv that
a POSIX shell would produce (shlex.split), streaming its stdout back over
the channel. That exercises the real client code path: host-key policy,
authentication, exec, line framing, quoting and reconnects.
"""

import shlex
import socket
import subprocess
import threading

import paramiko


class _Handler(paramiko.ServerInterface):
    def __init__(self, user, password):
        self.user, self.password = user, password
        self.command = None
        self.exec_ready = threading.Event()

    def check_auth_password(self, username, password):
        if (username, password) == (self.user, self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode() if isinstance(command, bytes) else command
        self.exec_ready.set()
        return True


class FakeSSHServer:
    def __init__(self, user="tester", password="secret"):
        self.user, self.password = user, password
        self.host_key = paramiko.ECDSAKey.generate()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.commands = []
        self.connections = 0
        self._transports = []
        self._procs = []
        self._closed = threading.Event()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def write_known_hosts(self, path):
        hk = paramiko.HostKeys()
        hk.add(f"[127.0.0.1]:{self.port}", self.host_key.get_name(), self.host_key)
        hk.save(str(path))
        return str(path)

    def _accept_loop(self):
        while not self._closed.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        handler = _Handler(self.user, self.password)
        try:
            transport.start_server(server=handler)
        except (paramiko.SSHException, EOFError, OSError):
            return
        self._transports.append(transport)
        channel = transport.accept(10)
        if channel is None or not handler.exec_ready.wait(10):
            transport.close()
            return
        self.connections += 1
        self.commands.append(handler.command)
        argv = shlex.split(handler.command)
        if not argv or argv[0] != "tail":
            channel.send_exit_status(127)
            channel.close()
            return
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self._procs.append(proc)
        try:
            while True:
                data = proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else proc.stdout.read(1)
                if not data:
                    break
                channel.sendall(data)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            proc.kill()
            channel.close()

    def drop_connections(self):
        """Simulate the network dropping every open session."""
        for proc in self._procs:
            proc.kill()
        for t in self._transports:
            t.close()
        self._transports.clear()

    def close(self):
        self._closed.set()
        self.drop_connections()
        self.sock.close()
