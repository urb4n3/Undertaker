from pathlib import Path

class YaraGenerator:
    """Generate a very simple YARA rule from extracted hashes."""

    def __init__(self, name: str, md5: str):
        self.name = name
        self.md5 = md5

    def build(self) -> str:
        rule = f"rule {self.name} \n{{\n    strings:\n        $a = {{{self.md5}}}\n    condition:\n        $a\n}}"
        return rule

    def save(self, path: str) -> Path:
        rule = self.build()
        p = Path(path)
        p.write_text(rule)
        return p
