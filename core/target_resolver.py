# core/target_resolver.py
import socket
from urllib.parse import urlparse


class TargetResolver:
    def __init__(self, target_input):
        self.input = target_input
        self.url = self._normalize_url(target_input)
        self.domain = self._extract_domain()
        self.base_domain = self._extract_base_domain()
        self.ip = self._resolve_ip()

    def _normalize_url(self, target):
        if not target.startswith(("http://", "https://")):
            return "https://" + target
        return target

    def _extract_domain(self):
        parsed = urlparse(self.url)
        return parsed.hostname

    def _extract_base_domain(self):
        if not self.domain:
            return None
        parts = self.domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return self.domain

    def _resolve_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except Exception:
            return None

    def as_dict(self):
        return {
            "input": self.input,
            "url": self.url,
            "domain": self.domain,
            "base_domain": self.base_domain,
            "ip": self.ip
        }
