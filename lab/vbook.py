"""Read/write Vertical's `VERTICAL 1` case format, byte-compatible with Vertical's src/book.cpp.

Field encoding = Vertical's encode() (\\ -> \\\\, LF -> \\n, CR -> \\r) wrapped by C++
std::quoted (adds "..." and backslash-escapes '"' and '\\'). validate() mirrors
Book::validate(). This module never imports or links Vertical's code.
"""

NODE_KINDS = ("event", "observation", "process", "command", "note", "gap")
LINK_STATUSES = ("assumed", "untested", "id-match", "confirmed", "dropped")


class VBookError(ValueError):
    pass


def _encode(v):
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")


def _decode(v):
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(v):
            raise VBookError("invalid field escape")
        m = {"n": "\n", "r": "\r", "\\": "\\"}.get(v[i])
        if m is None:
            raise VBookError("invalid field escape")
        out.append(m)
        i += 1
    return "".join(out)


def _quoted(v):
    return '"' + _encode(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _fields(line):
    """Tokenize like `in >> tag >> std::quoted(a) >> ...` and return [tag, f1, f2, ...]."""
    out, i, n = [], 0, len(line)
    while True:
        while i < n and line[i] in " \t\v\f":
            i += 1
        if i >= n:
            return out
        if line[i] == '"' and out:
            i += 1
            buf = []
            while True:
                if i >= n:   # std::quoted stops at end of input without error
                    break
                c = line[i]
                if c == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            out.append("".join(buf))
        else:
            j = i
            while j < n and line[j] not in " \t\v\f":
                j += 1
            out.append(line[i:j])
            i = j


class Book(object):
    def __init__(self, id, title, kind):
        self.id, self.title, self.kind = id, title, kind
        self.nodes = []   # dicts: id, parent, kind, title, source, text
        self.links = []   # dicts: id, from, to, relationship, status, basis

    def add_node(self, id, parent, kind, title, source="", text=""):
        self.nodes.append(dict(id=id, parent=parent, kind=kind, title=title, source=source, text=text))
        return id

    def add_link(self, id, frm, to, relationship, status, basis=""):
        self.links.append({"id": id, "from": frm, "to": to, "relationship": relationship,
                           "status": status, "basis": basis})
        return id

    # ------------------------------------------------ validation (mirrors Book::validate)
    def validate(self):
        def req(ok, msg):
            if not ok:
                raise VBookError(msg)
        req(self.id and self.title, "Book ID and title are required")
        req(self.kind in ("REAL", "SIMULATION"), "Book kind must be REAL or SIMULATION")
        ids = {self.id}
        by_id = {}
        for n in self.nodes:
            req(n["id"] and n["title"] and n["kind"] in NODE_KINDS, "invalid node")
            req(n["id"] not in ids, "duplicate ID: " + n["id"])
            ids.add(n["id"])
            by_id[n["id"]] = n
        for n in self.nodes:
            req(n["parent"] == self.id or n["parent"] in by_id, "missing parent for: " + n["id"])
            req(n["parent"] != n["id"], "self-parent: " + n["id"])
            seen, p = {n["id"]}, n["parent"]
            while p != self.id:
                req(p not in seen, "parent cycle at: " + n["id"])
                seen.add(p)
                req(p in by_id, "missing parent for: " + n["id"])
                p = by_id[p]["parent"]
        for l in self.links:
            req(l["id"] and l["relationship"] and l["status"] in LINK_STATUSES, "invalid link")
            req(l["id"] not in ids, "duplicate ID: " + l["id"])
            ids.add(l["id"])
            ok_from = l["from"] == self.id or l["from"] in by_id
            ok_to = l["to"] == self.id or l["to"] in by_id
            req(ok_from and ok_to, "dangling link: " + l["id"])
            if l["status"] in ("confirmed", "dropped"):
                req(l["basis"], "link basis required: " + l["id"])

    # ------------------------------------------------ io
    def dumps(self):
        self.validate()
        out = ["VERTICAL 1", "BOOK %s %s %s" % (_quoted(self.id), _quoted(self.title), _quoted(self.kind))]
        for n in self.nodes:
            out.append("NODE " + " ".join(_quoted(n[k]) for k in ("id", "parent", "kind", "title", "source", "text")))
        for l in self.links:
            out.append("LINK " + " ".join(_quoted(l[k]) for k in ("id", "from", "to", "relationship", "status", "basis")))
        return "\n".join(out) + "\n"

    def save(self, path):
        data = self.dumps().encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)

    @classmethod
    def loads(cls, text):
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        lines = [l[:-1] if l.endswith("\r") else l for l in lines]
        if not lines or lines[0] != "VERTICAL 1":
            raise VBookError("unsupported case format")
        if len(lines) < 2:
            raise VBookError("missing BOOK record")
        f = _fields(lines[1])
        if len(f) != 4 or f[0] != "BOOK":
            raise VBookError("invalid BOOK record")
        b = cls(_decode(f[1]), _decode(f[2]), _decode(f[3]))
        for line in lines[2:]:
            f = _fields(line)
            tag = f[0] if f else ""
            if tag == "NODE":
                if len(f) != 7:
                    raise VBookError("invalid NODE record")
                b.add_node(*[_decode(x) for x in f[1:]])
            elif tag == "LINK":
                if len(f) != 7:
                    raise VBookError("invalid LINK record")
                b.add_link(*[_decode(x) for x in f[1:]])
            else:
                raise VBookError("unknown case record")
        b.validate()
        return b

    @classmethod
    def load(cls, path):
        with open(path, "rb") as fh:
            return cls.loads(fh.read().decode("utf-8"))
