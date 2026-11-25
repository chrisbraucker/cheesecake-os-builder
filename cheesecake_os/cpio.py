MAX_NAME = 4096


def align(n: int, boundary: int = 4) -> int:
    return (n + boundary - 1) & ~(boundary - 1)


def read_cpio(blob: bytes) -> list[tuple[str, bytes]]:
    pos, entries = 0, []
    while pos + 110 <= len(blob):
        header = blob[pos : pos + 110]
        if header[:6] not in {b"070701", b"070702"}:
            raise ValueError(f"invalid newc header at {pos}")
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        name_end = pos + 110 + name_size
        if not 1 <= name_size <= MAX_NAME or name_end > len(blob):
            raise ValueError("invalid newc name")
        name_raw = blob[pos + 110 : name_end]
        if name_raw[-1:] != b"\0":
            raise ValueError("unterminated newc name")
        name = name_raw[:-1].decode()
        start = align(name_end)
        end = start + size
        if end > len(blob):
            raise ValueError("truncated newc data")
        entries.append((name, blob[start:end]))
        pos = align(end)
        if name == "TRAILER!!!":
            return entries
    raise ValueError("newc archive has no trailer")
