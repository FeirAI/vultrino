# Minimal Postgres wire-protocol stub (trust auth, answers every simple query with an empty
# result). It is NOT Postgres: it only lets a REAL psql connect so psql's CLIENT-SIDE handling of
# backslash meta-commands can be observed. Usage: python3 -I fake_pg_server.py PORT
import socketserver, struct, sys

def msg(t, body=b""):
    return t + struct.pack("!I", len(body) + 4) + body

class H(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        def rd(n):
            b = b""
            while len(b) < n:
                c = s.recv(n - len(b))
                if not c:
                    raise EOFError
                b += c
            return b
        try:
            ln = struct.unpack("!I", rd(4))[0]
            body = rd(ln - 4)
            if struct.unpack("!I", body[:4])[0] == 80877103:   # SSLRequest -> refuse
                s.sendall(b"N")
                ln = struct.unpack("!I", rd(4))[0]
                body = rd(ln - 4)
            out = msg(b"R", struct.pack("!I", 0))
            for k, v in ((b"server_version", b"16.0"), (b"client_encoding", b"UTF8"),
                         (b"standard_conforming_strings", b"on"), (b"server_encoding", b"UTF8")):
                out += msg(b"S", k + b"\0" + v + b"\0")
            out += msg(b"K", struct.pack("!II", 1, 2)) + msg(b"Z", b"I")
            s.sendall(out)
            while True:
                t = rd(1)
                ln = struct.unpack("!I", rd(4))[0]
                payload = rd(ln - 4)
                if t == b"X":
                    return
                if t == b"Q":
                    s.sendall(msg(b"C", b"SELECT 0\0") + msg(b"Z", b"I"))
        except EOFError:
            return

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
