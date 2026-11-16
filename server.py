import socketserver
import sqlite3
import base64
from dnslib import DNSRecord, RR, QTYPE, A

DOMAIN_SUFFIX = ".t.nnxsw-proyect.date."
DB_PATH = "C:/dns_tunnel/messages.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        seq INTEGER,
        total INTEGER,
        chunk TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit()
    conn.close()

def decode_chunk(b32_string):
    try:
        b32_string = b32_string.upper()
        padding = (8 - len(b32_string) % 8) % 8
        b32_string += "=" * padding
        return base64.b32decode(b32_string).decode("utf-8", errors="replace")
    except:
        return ""

def save_chunk(user_id, seq, total, chunk_text):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO messages (user_id, seq, total, chunk) VALUES (?, ?, ?, ?)",
        (user_id, int(seq), int(total), chunk_text))
    conn.commit()
    conn.close()

def check_complete(user_id, total):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT chunk FROM messages WHERE user_id=? ORDER BY seq",
        (user_id,)).fetchall()
    conn.close()
    if len(rows) >= int(total):
        full_message = "".join(r[0] for r in rows)
        print("MENSAJE COMPLETO de " + user_id + ": " + full_message)

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            req = DNSRecord.parse(data)
            qname = str(req.q.qname)
            reply = req.reply()
            if qname.endswith(DOMAIN_SUFFIX):
                sub = qname[:-len(DOMAIN_SUFFIX)]
                parts = sub.split(".", 3)
                if len(parts) == 4:
                    uid, seq, total, payload = parts
                    text = decode_chunk(payload)
                    save_chunk(uid, seq, total, text)
                    print("Chunk " + seq + "/" + total + " de " + uid + ": " + text)
                    check_complete(uid, total)
                    ack = "10." + str(int(seq)) + "." + str(int(total)) + ".1"
                else:
                    ack = "10.0.0.0"
                reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(ack), ttl=0))
            else:
                reply.header.rcode = 3
            sock.sendto(reply.pack(), self.client_address)
        except Exception as e:
            print("Error: " + str(e))

class DNSServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    init_db()
    print("Servidor DNS escuchando en 0.0.0.0:53...")
    print("Esperando mensajes en *.t.nnxsw-proyect.date")
    server = DNSServer(("0.0.0.0", 53), DNSHandler)
    server.serve_forever()
