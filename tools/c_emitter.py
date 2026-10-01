"""Shared formatting helpers for generated C sources."""


def byte_array(name, data, columns=12):
    """Format bytes as the repository's multiline static C array."""
    if len(data) == 0:
        return f"static const uint8_t {name}[1] = {{ 0x00 }}; /* empty, length 0 */\n"
    lines = []
    for offset in range(0, len(data), columns):
        chunk = data[offset:offset + columns]
        lines.append("  " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    body = "\n".join(lines).rstrip(",")
    return f"static const uint8_t {name}[{len(data)}] = {{\n{body}\n}};\n"
