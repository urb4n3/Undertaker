class SummaryBuilder:
    """Build a text summary from analyzer data."""

    def build_malware_summary(self, hashes: dict, imports: list, strings: list) -> str:
        lines = ["Malware Analysis Summary", "=======================", ""]
        lines.append(f"MD5: {hashes['md5']}")
        lines.append(f"SHA256: {hashes['sha256']}")
        if imports:
            lines.append("Risky Imports:")
            lines.extend(f"  - {i}" for i in imports)
        if strings:
            lines.append("Strings:")
            lines.extend(f"  - {s}" for s in strings[:10])
        return "\n".join(lines)

    def build_link_summary(self, indicators: list[str]) -> str:
        lines = ["Link Analysis Summary", "====================", ""]
        if indicators:
            lines.append("Indicators:")
            lines.extend(f"  - {i}" for i in indicators)
        else:
            lines.append("No obvious indicators.")
        return "\n".join(lines)
