# Typed claims about a file

A claim is a JSON object with a `kind`. Each file is one "snapshot". All offsets
count from the start of the file, all integers are little-endian, and
`type_name` is any name you choose for the kind of file. There are five kinds.

## memory_layout: typed fields at fixed offsets

```json
{"kind": "memory_layout", "type_name": "CacheFile", "size": 24, "fields": [
  {"name": "magic",   "offset": 0,  "len": 4, "is": {"bytes": "4a534156"}},
  {"name": "version", "offset": 4,  "len": 4, "is": {"uint": {"min": 113, "max": 113}}},
  {"name": "mode",    "offset": 8,  "len": 4, "is": {"one_of": [0, 1, 5]}},
  {"name": "scale",   "offset": 12, "len": 4, "is": {"float": {"min": 0, "max": 100}}},
  {"name": "padding", "offset": 16, "len": 8, "is": "zero"}
]}
```

Every file must be at least `size` bytes long, and every field with an `is`
must look like that in every file. A field without `is` only names a place and
says nothing. The forms of `is`:

| `is` | The field's bytes are |
| --- | --- |
| `{"bytes": "<hex>"}` | exactly these bytes; the hex is as long as the field |
| `{"uint": {"min": a, "max": b}}` | an unsigned integer of 1, 2, 4 or 8 bytes in `a..=b` |
| `{"int": {"min": a, "max": b}}` | a signed integer of 1, 2, 4 or 8 bytes in `a..=b` |
| `{"one_of": [v, ...]}` | an unsigned integer of 1, 2, 4 or 8 bytes equal to one of the values |
| `{"float": {"min": a, "max": b}}` | a float of 4 or 8 bytes in `a..=b` (integer bounds) that is zero or normal |
| `{"pointer": {"min": a, "max": b}}` | zero, or an address of 4 or 8 bytes in `a..=b` |
| `{"text": {"min": n}}` | at least `n` printable ASCII characters, then a NUL inside the field |
| `"zero"` | all zero |

A range that allows every value of the field is refused: leave `is` out instead.

## field_relation: one integer equals a length or a sum

```json
{"kind": "field_relation", "type_name": "CacheFile",
 "field": {"offset": 4, "len": 4}, "equals": "snapshot_length"}
```

`equals` is one of:

- `"snapshot_length"`: the length of the whole file;
- `{"bytes_after": {"from": 16}}`: the number of bytes from offset 16 to the end of the file;
- `{"sum": {"fields": [{"offset": 8, "len": 4}, {"offset": 12, "len": 4}], "plus": -4}}`:
  the sum of other integer fields plus a constant.

## record_array: a count, then that many fixed-size records

```json
{"kind": "record_array", "type_name": "CacheFile", "count_offset": 16, "count_len": 4,
 "first": 20, "stride": 12, "exact": false, "fields": [
  {"name": "id", "offset": 0, "len": 4, "is": {"uint": {"min": 1, "max": 4096}}}
]}
```

The count is at `count_offset`; the records start at `first` and are `stride`
bytes each. `fields` are typed as in a memory layout, with offsets from the
start of each record, and must hold in every record. `exact: true` adds that
the file ends right after the last record.

## tagged_records: a run of (size, tag, value) records

```json
{"kind": "tagged_records", "type_name": "CacheFile", "start": 32,
 "size_len": 4, "tag_len": 2, "count": 3, "tags": [1, 2, 7]}
```

From `start`, each record is a size of `size_len` bytes, then a tag of
`tag_len` bytes (each 1, 2 or 4), then `size` bytes of value. With `count`
there are that many records; without it the run goes on to the end of the
file and must end exactly there. `tags` lists the tags that may appear; empty
means any.

## string_table: NUL-terminated strings and nothing else

```json
{"kind": "string_table", "type_name": "CacheFile", "start": 64, "len": 40,
 "count": 5, "min_chars": 1}
```

The `len` bytes from `start` (to the end of the file if `len` is left out) hold
exactly `count` printable ASCII strings, each ended by one NUL and at least
`min_chars` characters long.
