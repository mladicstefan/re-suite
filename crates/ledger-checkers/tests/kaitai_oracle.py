"""Reads files with a parser the Kaitai Struct compiler generated and prints each as JSON.

usage: kaitai_oracle.py <directory of the generated module> <module> <file>...

One line per file: the parsed tree, or {"error": ...} when the parser refuses the file.
Every instance is read, so one that fails makes the file fail.
"""
import importlib
import json
import sys

from kaitaistruct import KaitaiStruct


def dump(value):
    if isinstance(value, KaitaiStruct):
        out = {k: dump(v) for k, v in vars(value).items() if not k.startswith("_")}
        for name in dir(type(value)):
            if not name.startswith("_") and isinstance(getattr(type(value), name), property):
                out[name] = dump(getattr(value, name))
        return out
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [dump(v) for v in value]
    return value


sys.path.insert(0, sys.argv[1])
module = importlib.import_module(sys.argv[2])
parser = getattr(module, sys.argv[2].title().replace("_", ""))
for path in sys.argv[3:]:
    try:
        print(json.dumps(dump(parser.from_file(path))))
    except Exception as error:  # the generated code raises several unrelated types
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}))
