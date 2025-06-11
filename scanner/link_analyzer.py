from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

class LinkAnalyzer:
    """Fetch and analyze HTML for phishing indicators."""

    def __init__(self, url: str):
        self.url = url
        self.resp = None

    def fetch(self) -> None:
        self.resp = requests.get(self.url, timeout=10)
        self.resp.raise_for_status()

    def indicators(self) -> list[str]:
        if self.resp is None:
            self.fetch()
        html = self.resp.text
        soup = BeautifulSoup(html, 'html.parser')
        indicators = []
        if soup.find('form') and soup.find('input', {'type': 'password'}):
            indicators.append('login_form')
        parsed = urlparse(self.url)
        if parsed.hostname and '-' in parsed.hostname:
            indicators.append('suspicious_domain')
        return indicators
