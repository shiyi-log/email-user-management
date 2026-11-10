import os
import socketserver
import threading
import unittest
from email import policy
from email.parser import BytesParser
from unittest.mock import patch

from user_management import Mailer


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 local-test ESMTP\r\n")
        self.wfile.flush()
        data = False
        message = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.upper()
            if data:
                if line.rstrip(b"\r\n") == b".":
                    self.server.messages.append(b"".join(message))
                    self.wfile.write(b"250 queued\r\n")
                    data = False
                else:
                    message.append(line)
            elif command.startswith(b"EHLO") or command.startswith(b"HELO"):
                self.wfile.write(b"250-local-test\r\n250 OK\r\n")
            elif command.startswith(b"MAIL FROM") or command.startswith(b"RCPT TO"):
                self.wfile.write(b"250 OK\r\n")
            elif command.strip() == b"DATA":
                self.wfile.write(b"354 send data\r\n")
                data = True
                message = []
            elif command.strip() == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                self.wfile.flush()
                return
            else:
                self.wfile.write(b"250 OK\r\n")
            self.wfile.flush()


class MailerTests(unittest.TestCase):
    def test_sends_verification_message_over_smtp(self):
        with socketserver.TCPServer(("127.0.0.1", 0), SMTPHandler) as server:
            server.messages = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            settings = {
                "SMTP_HOST": "127.0.0.1",
                "SMTP_PORT": str(server.server_address[1]),
                "SMTP_FROM": "accounts@example.com",
                "SMTP_USERNAME": "",
                "SMTP_PASSWORD": "",
                "SMTP_USE_TLS": "false",
                "SMTP_USE_SSL": "false",
            }
            try:
                with patch.dict(os.environ, settings):
                    Mailer().send_code("person@example.com", "482913")
            finally:
                server.shutdown()
                thread.join()
            self.assertEqual(len(server.messages), 1)
            delivered = BytesParser(policy=policy.default).parsebytes(server.messages[0])
            self.assertEqual(delivered["To"], "person@example.com")
            self.assertEqual(delivered["From"], "accounts@example.com")
            self.assertIn("482913", delivered.get_content())
            self.assertIn("10 分钟内有效", delivered.get_content())


if __name__ == "__main__":
    unittest.main()
