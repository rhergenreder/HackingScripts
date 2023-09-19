import smtpd
import email
import asyncore
import threading

class SMTPServer(smtpd.SMTPServer):

    def __init__(self, addr='0.0.0.0', port=25):
        super().__init__((addr, port), None)
        self.listen_thread = None
        self.verbose = False
        self.on_message = None
        self.is_running = True

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        if self.verbose:
            print(f"SMTP IN: {peer=} {mailfrom=} {rcpttos=} {len(data)} bytes, extra:", kwargs)
        if self.on_message and callable(self.on_message):
            mail = email.message_from_bytes(data)
            self.on_message(peer, mailfrom, rcpttos, mail)

    def start(self):
        if self.verbose:
            print(f"SMTP server running on: {self._localaddr[0]}:{self._localaddr[1]}")
        try:
            while self.is_running:
                asyncore.loop(timeout=1, use_poll=True)
        except KeyboardInterrupt:
            self.close()

    def start_background(self):
        self.listen_thread = threading.Thread(target=self.start)
        self.listen_thread.start()
        return self.listen_thread

    def stop(self):
        self.is_running = False
        self.close()
        if self.listen_thread:
            self.listen_thread.join()