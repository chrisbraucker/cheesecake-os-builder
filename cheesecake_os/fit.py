from __future__ import annotations

import struct

BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
FIT_MAGIC = 0xD00DFEED
SELECTED = 2


class Fit:
    def __init__(self, data: bytes) -> None:
        self.data = data
        h = struct.unpack_from(">10I", data)
        if h[0] != FIT_MAGIC or h[1] > len(data):
            msg = "invalid FIT header"
            raise ValueError(msg)
        self.total, self.so, self.st, self.ss, self.sz = h[1], h[2], h[3], h[8], h[9]
        self.struct = data[self.so : self.so + self.sz]
        self.strings = data[self.st : self.st + self.ss]
        self.events = []
        self.nodes = {}
        self.props = {}
        self._parse()

    def _parse(self) -> None:
        i, stack, names = 0, [], []
        s = self.struct
        while i < len(s):
            start = i
            tag = be32(s, i)
            i += 4
            if tag == BEGIN_NODE:
                end = s.index(0, i)
                name = s[i:end].decode()
                i = (end + 4) & ~3
                names.append(name)
                path = "/" + "/".join(names[1:])
                stack.append((path, start))
                self.events.append((tag, start, i, path, None))
            elif tag == END_NODE:
                path, node_start = stack.pop()
                self.nodes[path] = (node_start, i)
                names.pop()
                self.events.append((tag, start, i, path, None))
            elif tag == PROP:
                size, nameoff = struct.unpack_from(">II", s, i)
                i += 8
                end = self.strings.index(0, nameoff)
                name = self.strings[nameoff:end].decode()
                value_start = i
                i = (i + size + 3) & ~3
                path = stack[-1][0]
                self.props[path, name] = (start, i, value_start, size)
                self.events.append((tag, start, i, path, name))
            elif tag in {4, 9}:
                self.events.append((tag, start, i, stack[-1][0] if stack else "", None))
                if tag == END:
                    break
            else:
                msg = f"invalid FDT token {tag} at 0x{start:x}"
                raise ValueError(msg)
        if stack or i != len(s):
            msg = "malformed FIT structure"
            raise ValueError(msg)

    def prop(self, path: str, name: str) -> bytes:
        _, _, start, size = self.props[path, name]
        return self.struct[start : start + size]

    def prop_replace(
        self, path: str, name: str, value: bytes
    ) -> tuple[bytes, tuple[int, int]]:
        start, end, _, _ = self.props[path, name]
        nameoff = be32(self.struct, start + 8)
        raw = struct.pack(">III", 3, len(value), nameoff) + value
        return raw + b"\0" * (-len(raw) % 4), (start, end)

    def signed_stream(self, sig_path: str) -> bytes:  # ruff: ignore[complex-structure, too-many-branches]
        included = [
            x.decode() for x in self.prop(sig_path, "hashed-nodes").split(b"\0") if x
        ]
        if not included:
            msg = "empty hashed-nodes"
            raise ValueError(msg)
        hashed_strings = self.prop(sig_path, "hashed-strings")
        start, length = struct.unpack(">II", hashed_strings)
        if start + length > len(self.strings):
            msg = "invalid hashed-strings range"
            raise ValueError(msg)
        pieces, wants = [], []
        want = 0
        region_start = None
        for tag, start_off, end_off, path, name in self.events:
            stop_at = end_off
            if tag == BEGIN_NODE:
                wants.append(want)
                if want == 1:
                    stop_at = start_off
                if path in included:
                    want = SELECTED
                elif want:
                    want -= 1
                else:
                    stop_at = start_off
                take = want > 0
            elif tag == END_NODE:
                take = want > 0
                want = wants.pop()
            elif tag == PROP:
                take = want >= SELECTED and name != "data"
                stop_at = start_off
            elif tag == NOP:
                take = want >= SELECTED
                stop_at = start_off
            else:
                take = True
            if take and region_start is None:
                region_start = start_off
            if not take and region_start is not None:
                pieces.append(self.struct[region_start:stop_at])
                region_start = None
        if region_start is not None:
            pieces.append(self.struct[region_start : self.events[-1][2]])
        pieces.append(self.strings[start : start + length])
        return b"".join(pieces)


def be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]
