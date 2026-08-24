import socket
import re
from urllib.parse import urlparse

class TargetResolver:
    def __init__(self, target_input: str):
        self.input = target_input.strip()
        self.target_id = None
        self.url = None
        self.domain = None
        self.ip = None

        self._resolve()

    def _resolve(self):
        # URL
        if self.input.startswith("http"):
            parsed = urlparse(self.input)
            self.url = f"{parsed.scheme}://{parsed.netloc}"
            self.domain = parsed.netloc

        # IP
        elif re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", self.input):
            self.ip = self.input
            try:
                self.domain = socket.gethostbyaddr(self.ip)[0]
            except:
                self.domain = None

        # Domain
        elif "." in self.input:
            self.domain = self.input
            try:
                self.ip = socket.gethostbyname(self.domain)
            except:
                self.ip = None

        # Target ID
        else:
            self.target_id = self.input

        if self.domain and not self.url:
            self.url = f"http://{self.domain}"

    def as_dict(self):
        return {
            "input": self.input,
            "target_id": self.target_id,
            "url": self.url,
            "domain": self.domain,
            "ip": self.ip
        }
