import tempfile
import unittest
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from user_management import AuthService, FakeMailer, InvalidCode, UserExists, create_server


class AuthServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.mailer = FakeMailer()
        self.now = 1_700_000_000
        self.service = AuthService(
            Path(self.temp.name) / "users.sqlite3",
            self.mailer,
            code_factory=lambda: "482913",
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_registration_requires_the_email_code(self):
        self.service.send_code("person@example.com")
        with self.assertRaises(InvalidCode):
            self.service.register("person@example.com", "correct horse battery", "000000")
        user = self.service.register("person@example.com", "correct horse battery", "482913")
        self.assertEqual(user["email"], "person@example.com")
        self.assertTrue(self.service.authenticate("person@example.com", "correct horse battery"))
        self.assertFalse(self.service.authenticate("person@example.com", "wrong password"))
        with self.assertRaises(InvalidCode):
            self.service.register("person@example.com", "correct horse battery", "482913")

    def test_code_expires_and_cannot_be_reused(self):
        self.service.send_code("person@example.com")
        self.now += 601
        with self.assertRaises(InvalidCode):
            self.service.register("person@example.com", "correct horse battery", "482913")

    def test_duplicate_email_is_rejected(self):
        self.service.send_code("person@example.com")
        self.service.register("person@example.com", "correct horse battery", "482913")
        with self.assertRaises(UserExists):
            self.service.send_code("person@example.com")

    def test_sending_code_is_rate_limited(self):
        self.service.send_code("person@example.com")
        with self.assertRaises(InvalidCode):
            self.service.send_code("person@example.com")

    def test_code_is_invalidated_after_five_failed_attempts(self):
        self.service.send_code("person@example.com")
        for _ in range(5):
            with self.assertRaises(InvalidCode):
                self.service.register("person@example.com", "correct horse battery", "000000")
        with self.assertRaises(InvalidCode):
            self.service.register("person@example.com", "correct horse battery", "482913")


class HttpApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = create_server(port=0, database=Path(self.temp.name) / "api.sqlite3")
        self.mailer = FakeMailer()
        self.server.auth_service.mailer = self.mailer
        self.server.auth_service.code_factory = lambda: "482913"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:{}".format(self.server.server_address[1])
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def post(self, path, payload):
        request = urllib.request.Request(self.base + path, json.dumps(payload).encode(), {"Content-Type": "application/json"})
        try:
            response = self.client.open(request)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, json.loads(response.read().decode())

    def test_http_registration_creates_session_and_login_roundtrip(self):
        status, _ = self.post("/api/register", {"email": "api@example.com", "password": "correct horse battery", "code": "482913"})
        self.assertEqual(status, 400)
        self.post("/api/send-code", {"email": "api@example.com"})
        status, body = self.post("/api/register", {"email": "api@example.com", "password": "correct horse battery", "code": "482913"})
        self.assertEqual(status, 201)
        self.assertEqual(body["user"]["email"], "api@example.com")
        status = self.client.open(self.base + "/api/me").status
        self.assertEqual(status, 200)
        status, body = self.post("/api/login", {"email": "api@example.com", "password": "correct horse battery"})
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["email"], "api@example.com")

if __name__ == "__main__":
    unittest.main()
