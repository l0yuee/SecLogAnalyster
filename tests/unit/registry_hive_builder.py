"""Builds a minimal-but-valid REGF registry hive in-memory, for tests --
no real registry hive files are bundled with this repo.

Built directly from regipy's own `construct` Structs (REGF_HEADER,
HBIN_HEADER, CM_KEY_NODE, VALUE_KEY, INDEX_LEAF) so the produced bytes
are guaranteed compatible with the exact regipy version this project
depends on, rather than hand-rolling an independent (and potentially
subtly wrong) implementation of the format. The exact offset arithmetic
below was derived by reading regipy's own reader code
(`regipy/registry.py`: `HBin.iter_cells`, `NKRecord.iter_subkeys`/
`_parse_subkeys`/`iter_values`, `RegistryHive.__init__`) and validated by
round-tripping the output through `RegistryHive` -- see the comments
inline for the reasoning, since none of this is written down anywhere
else and is easy to get subtly wrong.

Not a test module itself (no `test_` prefix) -- imported by
test_registry_parser.py and test_logsources.py's registry tests, and used
once to generate the committed binary fixture at
tests/fixtures/registry/SOFTWARE.

Produces one hive shaped like:
    ROOT
      CurrentVersion
        Run            (values: Updater=REG_SZ, Payload=REG_BINARY high-entropy)
      Services
        TestSvc        (values: ImagePath=REG_SZ)
      Plain            (values: Data=REG_BINARY low-entropy)
      Empty            (no values)
"""
from __future__ import annotations

from regipy.structs import CM_KEY_NODE, HBIN_HEADER, INDEX_LEAF, REGF_HEADER, REGF_HEADER_SIZE, VALUE_KEY

REG_SZ = 1
REG_BINARY = 3

_HBIN_HEADER_SIZE = 32  # HBIN_HEADER.sizeof()


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


class _HiveBuilder:
    """Assembles one hbin's worth of cells. Every *_offset field this
    format stores (subkeys_list_offset, key_node_offset,
    values_list_offset, data_offset) is consumed by regipy as
    `REGF_HEADER_SIZE + offset` (or `+ 4 + offset` when the reader also
    skips the cell's own 4-byte size header) -- i.e. relative to the
    START of the hbin block, which itself starts with a 32-byte
    HBIN_HEADER. So a position P in this builder's own buffer (which
    starts right after that header) must be stored as (P + 32) in any
    such field -- `_write_cell` returns exactly that "stored offset
    field" value. The one exception is the root key, which regipy always
    finds as literally the first cell in hbin offset 0 (`next(iter_cells())`,
    not through a stored offset field) -- see `build_hive`.
    """

    def __init__(self):
        self.buf = bytearray()

    def _write_cell(self, prefix: bytes, body: bytes) -> int:
        cell_offset = len(self.buf)
        total_size = 4 + len(prefix) + len(body)
        pad = (-total_size) % 8
        total_size += pad
        size_header = (-total_size).to_bytes(4, "little", signed=True)
        self.buf += size_header + prefix + body + (b"\x00" * pad)
        return cell_offset + _HBIN_HEADER_SIZE


def _value_cell(b: _HiveBuilder, name: str, value_type: int, raw_data: bytes) -> int:
    data_offset = b._write_cell(b"", raw_data)
    vk_body = VALUE_KEY.build(
        dict(
            name_size=len(name),
            data_size=len(raw_data),
            data_offset=data_offset,
            data_type=value_type,
            flags=dict(VALUE_COMP_NAME=True),
            name=name.encode("ascii"),
        )
        | {None: 0}  # anonymous "padding" field construct still expects a value for
    )
    return b._write_cell(b"", vk_body)  # VALUE_KEY's struct already includes the "vk" signature


def _values_list_cell(b: _HiveBuilder, vk_offsets: list[int]) -> int:
    entries = b"".join(off.to_bytes(4, "little") for off in vk_offsets)
    return b._write_cell(b"", entries)


def _nk_body(name: str, **kwargs) -> bytes:
    defaults = dict(
        flags=dict(KEY_COMP_NAME=True),
        last_modified=133700000000000000,  # 2024-01-01-ish, exact value not asserted on
        access_bits=b"\x00\x00\x00\x00",
        parent_key_offset=0,
        subkey_count=0,
        volatile_subkey_count=0,
        subkeys_list_offset=0xFFFFFFFF,
        volatile_subkeys_list_offset=0xFFFFFFFF,
        values_count=0,
        values_list_offset=0xFFFFFFFF,
        security_key_offset=0xFFFFFFFF,
        class_name_offset=0xFFFFFFFF,
        largest_sk_name=0,
        largest_sk_class_name=0,
        largest_value_name=0,
        largest_value_data=0,
        key_name_size=len(name),
        class_name_size=0,
        key_name_string=name.encode("ascii"),
    )
    defaults.update(kwargs)
    return CM_KEY_NODE.build(defaults | {None: b"\x00\x00\x00\x00"})  # anonymous "unknown" field


def _cell_total_size(prefix: bytes, body: bytes) -> int:
    total_size = 4 + len(prefix) + len(body)
    return total_size + (-total_size) % 8


def _nk_cell(b: _HiveBuilder, name: str, **kwargs) -> int:
    return b._write_cell(b"nk", _nk_body(name, **kwargs))


def _index_leaf_cell(b: _HiveBuilder, nk_offsets: list[int]) -> int:
    body = INDEX_LEAF.build(dict(element_count=len(nk_offsets), elements=[dict(key_node_offset=o) for o in nk_offsets]))
    return b._write_cell(b"li", body)


def build_hive(embedded_name: str) -> bytes:
    """`embedded_name` is the hive's own recorded original path (e.g.
    `\\System32\\Config\\SOFTWARE`) -- capped at 32 UTF-16 chars by the
    format itself (`PaddedString(64, "utf-16-le")`), same as real Windows
    hives. This is what `regipy.identify_hive_type`/seclogx's own DEFAULT-
    hive check key off of, not the on-disk filename."""
    b = _HiveBuilder()

    # Root must physically be the first cell in the hbin (regipy always
    # takes literally the first cell it finds as root -- see
    # RegistryHive.__init__), but its body references the subkey-list
    # offset, which isn't known until every child/value/index-leaf cell
    # (built *after* root in file order) has been placed. Reserve root's
    # exact byte size up front (a placeholder offset value doesn't change
    # the size of the fixed-width field it's stored in), build everything
    # else after that reservation, then patch the real root bytes in.
    dummy_root_body = _nk_body("ROOT", subkey_count=4, subkeys_list_offset=0)
    root_cell_size = _cell_total_size(b"nk", dummy_root_body)
    b.buf += b"\x00" * root_cell_size

    # CurrentVersion\Run -- matches suspicious_registry()'s Run-key path
    # check the same way a real \Microsoft\Windows\CurrentVersion\Run key
    # would (that heuristic matches on the '\CurrentVersion\Run' segment,
    # not a specific vendor prefix, so this shorter shape is equivalent).
    v1 = _value_cell(b, "Updater", REG_SZ, _utf16("C:\\Windows\\System32\\update.exe"))
    high_entropy_payload = bytes((i * 2654435761 + 17) % 256 for i in range(200))
    v2 = _value_cell(b, "Payload", REG_BINARY, high_entropy_payload)
    values_list_run = _values_list_cell(b, [v1, v2])
    nk_run = _nk_cell(b, "Run", values_count=2, values_list_offset=values_list_run)
    current_version_subkey_list_offset = _index_leaf_cell(b, [nk_run])
    nk_current_version = _nk_cell(
        b, "CurrentVersion", subkey_count=1, subkeys_list_offset=current_version_subkey_list_offset
    )

    # Services\TestSvc\ImagePath -- one extra nesting level so
    # suspicious_registry()'s '\Services\' path check has a real match to
    # find, the same shape a real SYSTEM hive's service keys have.
    v3 = _value_cell(b, "ImagePath", REG_SZ, _utf16("C:\\Windows\\System32\\svchost.exe -k netsvcs"))
    values_list_svc = _values_list_cell(b, [v3])
    nk_testsvc = _nk_cell(b, "TestSvc", values_count=1, values_list_offset=values_list_svc)
    services_subkey_list_offset = _index_leaf_cell(b, [nk_testsvc])
    nk_services = _nk_cell(b, "Services", subkey_count=1, subkeys_list_offset=services_subkey_list_offset)

    low_entropy_payload = bytes([0x41] * 40)
    v4 = _value_cell(b, "Data", REG_BINARY, low_entropy_payload)
    values_list_plain = _values_list_cell(b, [v4])
    nk_plain = _nk_cell(b, "Plain", values_count=1, values_list_offset=values_list_plain)

    nk_empty = _nk_cell(b, "Empty")

    subkey_list_offset = _index_leaf_cell(b, [nk_current_version, nk_services, nk_plain, nk_empty])

    real_root_body = _nk_body("ROOT", subkey_count=4, subkeys_list_offset=subkey_list_offset)
    real_root_size = _cell_total_size(b"nk", real_root_body)
    assert real_root_size == root_cell_size
    size_header = (-real_root_size).to_bytes(4, "little", signed=True)
    pad = root_cell_size - (4 + 2 + len(real_root_body))
    b.buf[0:root_cell_size] = size_header + b"nk" + real_root_body + (b"\x00" * pad)

    hbin_data = bytes(b.buf)
    hbin_size = HBIN_HEADER.sizeof() + len(hbin_data)
    pad_to = ((hbin_size + 4095) // 4096) * 4096
    hbin_data += b"\x00" * (pad_to - hbin_size)
    hbin_size = pad_to

    hbin_header = HBIN_HEADER.build(dict(offset=0, size=hbin_size, timestamp=0) | {None: 0})
    hbin_blob = hbin_header + hbin_data

    header_body = REGF_HEADER.build(
        dict(
            primary_sequence_num=1,
            secondary_sequence_num=1,
            last_modification_time=133700000000000000,
            major_version=1,
            minor_version=5,
            file_type=0,
            file_format=1,
            root_key_offset=0,
            hive_bins_data_size=hbin_size,
            clustering_factor=1,
            file_name=embedded_name,
            checksum=0,
        )
        | {None: b"\x00" * 396}
    )
    header_blob = header_body + b"\x00" * (REGF_HEADER_SIZE - len(header_body))

    return header_blob + hbin_blob
