import os
import logging
import argparse
import signal
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import ThreadedFTPServer
from pyftpdlib.authorizers import DummyAuthorizer

logger = logging.getLogger()
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(message)s")
stream_handler.setFormatter(formatter)

logger.addHandler(stream_handler)

MSG_LOGIN = "Login successful"
MSG_CLOSE = "Goodbye"


# Class to log every action the user takes
class CustomFTPHandler(FTPHandler):
    def on_login(self, username):
        logging.info(f"User '{username}' logged in successfully.")

    def on_login_failed(self, username, password):
        logging.warning(
            f"Failed login attempt for user '{username}' with password '{password}'."
        )

    def on_file_received(self, file):
        logging.info(f"File received: {file}")

    def on_file_sent(self, file):
        logging.info(f"File sent: {file}")

    def on_file_deleted(self, file):
        logging.info(f"File deleted: {file}")

    def on_file_renamed(self, old_file, new_file):
        logging.info(f"File renamed from '{old_file}' to '{new_file}'")

    def on_file_downloaded(self, file):
        logging.info(f"File downloaded: {file}")

    def on_file_stored(self, file):
        logging.info(f"File stored: {file}")

    def on_file_retrieved(self, file):
        logging.info(f"File retrieved: {file}")

    def on_file_aborted(self, file):
        logging.info(f"File transfer aborted: {file}")

    def on_file_changed(self, file):
        logging.info(f"File changed: {file}")

    def on_file_moved(self, old_file, new_file):
        logging.info(f"File moved from '{old_file}' to '{new_file}'")

    def on_file_uploaded(self, file):
        logging.info(f"File uploaded: {file}")

    def on_connect(self):
        logger.info(f"Client connected: {self.remote_ip}")

    def on_disconnect(self):
        logger.info(f"Client disconnected: {self.remote_ip}")

    def on_logout(self, username):
        logger.info(f"User logged out: {username}")

    def on_incomplete_file_received(self, file):
        logger.warning(f"Incomplete file received: {file}")

    def on_incomplete_file_sent(self, file):
        logger.warning(f"Incomplete file received: {file}")


class AnyUserAuthorizer(DummyAuthorizer):
    """
    Authorization class that allows any combination of username/password.
    """

    def __init__(self, directory):
        DummyAuthorizer.__init__(self)
        self.directory = directory
        self.default_params = {
            "pwd": "",
            "home": self.directory,
            "perm": "elr",
            "operms": {},
            "msg_login": MSG_LOGIN,
            "msg_quit": MSG_CLOSE,
        }

    def validate_authentication(self, username, password, handler):
        logger.info(f"User '{username}' tried logging in with password: '{password}'")

        return True

    def get_home_dir(self, username):
        return self.directory

    def has_user(self, username):
        if username in self.user_table:
            return True

        self.add_user(username, "", self.directory)
        return True

    def has_perm(self, username, perm, path=None) -> bool:
        if username not in self.user_table:
            # add user manually and not via add_user due to infinite recursion
            self.user_table[username] = self.default_params

        return True

    def get_msg_login(self, username: str) -> str:
        return MSG_LOGIN

    def get_msg_quit(self, username: str) -> str:
        return MSG_CLOSE


class FastFTPServer:
    def __init__(self, directory, port):
        self.directory = directory
        self.port = port
        self.server = None

    def start(self):
        authorizer = AnyUserAuthorizer(directory=self.directory)

        handler = CustomFTPHandler
        handler.authorizer = authorizer

        self.server = ThreadedFTPServer(("", self.port), handler)
        logging.info(f"Starting FTP server on port {self.port}")

        self.server.serve_forever()

    def cleanup(self):
        logging.info("Shutting down FTP server...")
        if self.server:
            self.server.close_all()
        logging.info("FTP server shut down.")


def signal_handler(sig, frame):
    logging.info("Received Ctrl+C, shutting down...")
    ftp_server.cleanup()
    exit(0)


def main():
    parser = argparse.ArgumentParser(description="Temporary FTP Server")
    parser.add_argument(
        "--dir", "-d", type=str, default=".", help="Directory to serve files from"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=21, help="Port to run the FTP server on"
    )

    args = parser.parse_args()

    if not os.path.exists(args.dir):
        print(f"Error: The directory '{args.dir}' does not exist.")
        return

    global ftp_server
    ftp_server = FastFTPServer(args.dir, args.port)
    signal.signal(signal.SIGINT, signal_handler)
    ftp_server.start()


if __name__ == "__main__":
    main()
