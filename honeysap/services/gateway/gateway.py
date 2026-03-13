# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import os
import re
import struct
from socket import error
from random import SystemRandom
# External imports
from scapy.packet import Raw
from pysap.SAPRFC import (SAPRFC, SAPRFCDTStruct, SAPRFCEXTEND,
                          rfc_req_type_values, rfc_func_type_values,
                          rfc_monitor_cmd_values, cpic_padd)
from pysap.SAPNI import (SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient)
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService
from honeysap.services.gateway.rfcsi_data import get_ddif_body
from honeysap.services.gateway.rfm_catalog import load_rfm_catalog
from honeysap.services.gateway.ddic_catalog import load_ddic_catalog


# Full 4-byte CPIC field paddings from pysap.  In the login handshake the
# TLV sequence is fixed, so the full padd (prev_end + field_start) reliably
# matches.  Using .find() on 4 bytes is faster than scanning for 2-byte
# markers byte-by-byte.
CPIC_RFC_F_PADD = cpic_padd["cpic_RFC_f_padd"].encode("latin-1")
CPIC_PROGRAM_PADD = cpic_padd["cpic_program_padd"].encode("latin-1")
CPIC_USERNAME_PADD = cpic_padd["cpic_username1_padd"].encode("latin-1")
CPIC_CLI_NBR_PADD = cpic_padd["cpic_cli_nbr1_padd"].encode("latin-1")
CPIC_IP_PADD = cpic_padd["cpic_ip_padd"].encode("latin-1")
CPIC_HOSTNAME_PADD = cpic_padd["cpic_host_sid_inbr_padd"].encode("latin-1")
CPIC_DEST_PADD = cpic_padd["cpic_dest_padd"].encode("latin-1")

# 2-byte start-markers for login CPIC fields.
# The 4-byte cpic_padd values encode [prev_end(2)][curr_start(2)], so they
# only match when the preceding field is exactly the one that was captured.
# Field order varies across NWRFC SDK versions, so we use the last 2 bytes
# (the actual field-start marker) with the flexible marker scanner instead.
MARKER_PASSWORD = b"\x01\x17"  # cpic_password (scrambled)
MARKER_USERNAME  = b"\x01\x11"  # cpic_username1
MARKER_CLI_NBR   = b"\x01\x14"  # cpic_cli_nbr1
MARKER_IP        = b"\x00\x07"  # cpic_ip
MARKER_HOSTNAME  = b"\x00\x08"  # cpic_host_sid_inbr
MARKER_DEST      = b"\x00\x06"  # cpic_dest

# 64-byte lookup table used by SAP's ab_scramble function (from NWRFC SDK).
# The password field is: [4-byte LE seed][scrambled password bytes].
# Each byte is XOR'd with table[(start_idx + i) % 64] ^ ((seed*i*i - i) & 0xFF).
_AB_SCRAMBLE_TABLE = bytes([
    0xf0, 0xed, 0x53, 0xb8, 0x32, 0x44, 0xf1, 0xf8,
    0x76, 0xc6, 0x79, 0x59, 0xfd, 0x4f, 0x13, 0xa2,
    0xc1, 0x51, 0x95, 0xec, 0x54, 0x83, 0xc2, 0x34,
    0x77, 0x49, 0x43, 0xa2, 0x7d, 0xe2, 0x65, 0x96,
    0x5e, 0x53, 0x98, 0x78, 0x9a, 0x17, 0xa3, 0x3c,
    0xd3, 0x83, 0xa8, 0xb8, 0x29, 0xfb, 0xdc, 0xa5,
    0x55, 0xd7, 0x02, 0x77, 0x84, 0x13, 0xac, 0xdd,
    0xf9, 0xb8, 0x31, 0x16, 0x61, 0x0e, 0x6d, 0xfa,
])


def _descramble_rfc_password(raw_field):
    """Descramble an RFC password using SAP's ab_scramble algorithm.

    The password field layout is [4-byte LE seed][scrambled bytes].
    Each byte is XOR'd with: table[(start_idx + i) % 64] ^ ((seed*i*i - i) & 0xFF)
    where start_idx is derived from the seed.

    Returns the plaintext password string, or the hex representation
    if descrambling fails.
    """
    if len(raw_field) < 5:
        return raw_field.hex()

    seed = struct.unpack_from("<I", raw_field, 0)[0]
    data = bytearray(raw_field[4:])

    # Compute starting table index (same derivation as in ab_scramble)
    tmp = (seed ^ (seed >> 5)) & 0xFFFFFFFF
    start_idx = (tmp ^ ((seed << 1) & 0xFFFFFFFF)) & 0xFFFFFFFF

    for i in range(len(data)):
        tidx = (start_idx + i) & 0x3f
        sval = ((seed * i * i) - i) & 0xFFFFFFFF
        data[i] ^= _AB_SCRAMBLE_TABLE[tidx] ^ (sval & 0xFF)

    plain = bytes(data).rstrip(b"\x00")
    try:
        text = plain.decode("ascii")
        if text.isprintable():
            return text
    except (UnicodeDecodeError, ValueError):
        pass
    return raw_field.hex()


def _strip_field(val):
    """Strip padding from a bytes or str value, return str."""
    if isinstance(val, bytes):
        val = val.strip(b"\x00 ")
        return val.decode("utf-8", errors="replace")
    if isinstance(val, str):
        return val.strip("\x00 ")
    return str(val) if val is not None else None


def _extract_cpic_field_by_padd(data, padd_bytes):
    """Find a CPIC TLV field by its full 4-byte padding marker.

    Layout: [4-byte padd][2-byte big-endian length][data]
    Returns the raw data bytes, or None.
    """
    idx = data.find(padd_bytes)
    if idx < 0:
        return None
    offset = idx + 4
    if offset + 2 > len(data):
        return None
    length = struct.unpack("!H", data[offset:offset + 2])[0]
    if length == 0 or offset + 2 + length > len(data):
        return None
    return data[offset + 2:offset + 2 + length]


def _extract_cpic_field_by_marker(data, marker, search_start=0):
    """Find a CPIC TLV field by its 2-byte start-marker.

    Scans for any 4-byte delimiter where bytes[2:4] == marker.
    Layout: [2-byte end-of-prev][2-byte start-marker][2-byte length][data]
    Returns (raw_data_bytes, end_offset) or (None, search_start).
    """
    idx = search_start
    while idx < len(data) - 7:
        if data[idx + 2:idx + 4] == marker:
            length = struct.unpack("!H", data[idx + 4:idx + 6])[0]
            end = idx + 6 + length
            if length > 0 and end <= len(data):
                return data[idx + 6:end], end
        idx += 1
    return None, search_start


def _decode_rfc_string(raw):
    """Decode an RFC string field, trying ASCII first then UTF-16LE."""
    if raw is None:
        return None
    # Check if it looks like UTF-16LE (every other byte is 0x00 for ASCII range)
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        try:
            return raw.decode("utf-16-le").strip("\x00 ")
        except (UnicodeDecodeError, ValueError):
            pass
    return raw.decode("ascii", errors="replace").strip("\x00 ")


# Pre-compiled regex for fallback UTF-16LE function name extraction.
_RE_UTF16LE_FUNCNAME = re.compile(rb"((?:[A-Z/][A-Z0-9_/]\x00){4,})")

# Monitor commands (GW_SEND_CMD) that indicate hostile intent.
_DANGEROUS_MONITOR_CMDS = frozenset({
    "SUICIDE", "DELETE_CONN", "CANCEL_CONN",
    "DISCONNECT", "DELETE_CLIENT", "DELETE_REMGW",
})

# SDK-internal function modules — logged at INFO level (infrastructure noise).
# Everything else is a business call and gets highlighted at WARNING level.
_INFRA_FUNCS = frozenset({
    "RFC_GET_FUNCTION_INTERFACE", "RFC_SYSTEM_INFO",
    "DDIF_FIELDINFO_GET", "RFC_PING",
})


def _extract_rfc_params(raw):
    """Extract import parameters from an RFC function call request.

    Scans for 0x0201 (parameter-name) TLVs that carry a UTF-16LE name,
    then reads the immediately following 0x0203 (parameter-value) TLV.

    Returns a dict of {name: value} strings.  Names that look like
    internal SDK fields (no letters, very short, or all-digits) are skipped.
    """
    params = {}
    idx = 0
    while idx < len(raw) - 7:
        if raw[idx + 2:idx + 4] == b"\x02\x01":
            name_len = struct.unpack("!H", raw[idx + 4:idx + 6])[0]
            name_end = idx + 6 + name_len
            if 2 <= name_len <= 120 and name_end <= len(raw):
                name_raw = raw[idx + 6:name_end]
                name = _decode_rfc_string(name_raw)
                if name and name.replace("_", "").replace("/", "").isalnum():
                    val, _ = _extract_cpic_field_by_marker(raw, b"\x02\x03", name_end)
                    if val:
                        decoded = _decode_rfc_string(val)
                        if decoded is not None:
                            params[name] = decoded
        idx += 1
    return params


def _make_conversation_id():
    """Generate an 8-digit numeric conversation ID like a real SAP gateway."""
    return "".join([str(SystemRandom().randint(0, 9)) for _ in range(8)])


def _tlv(prev_marker, marker, data):
    """Build one TLV entry: [prev_marker:2][marker:2][length:2][data]."""
    return struct.pack("!HHH", prev_marker, marker, len(data)) + data


# CPIC header bytes from a real SAP server login response.  These encode
# server capability flags and are constant across connections.
_CPIC_HEADER = bytes.fromhex(
    "01010008010101050401000301010103"
    "000400000e0b01030106000b04010003"
    "00030200000023"
)

# RFCSI structure field widths (SAP NW 7.52).  Total: 245 characters.
_RFCSI_FIELDS = [
    ("RFCPROTO", 3), ("RFCCHARTYP", 4), ("RFCINTTYP", 3), ("RFCFLOTYP", 3),
    ("RFCDEST", 32), ("RFCHOST", 8), ("RFCSYSID", 8), ("RFCDATABS", 8),
    ("RFCDBHOST", 32), ("RFCDBSYS", 10), ("RFCSAPRL", 4), ("RFCMACH", 5),
    ("RFCOPSYS", 10), ("RFCTZONE", 6), ("RFCDAYST", 1), ("RFCIPADDR", 15),
    ("RFCKERNRL", 4), ("RFCHOST2", 32), ("RFCSI_RESV", 12),
    ("RFCIPV6ADDR", 45),
]


# ---------------------------------------------------------------------------
# DFIES structure layout for NWRFC binary serialisation.
# Derived from the DFIES DDIC definition (Unicode-only, 1350 bytes per row).
# Each entry: dfies_field_name → (byte_offset, intlen, kind)
#   kind "c" = space-padded CHAR; kind "n" = zero-padded NUMC
# All fields are Unicode-encoded (UTF-16-LE).
# ---------------------------------------------------------------------------
_DFIES_LAYOUT = {
    "TABNAME":     (0,    60, "c"),
    "FIELDNAME":   (60,   60, "c"),
    "LANGU":       (120,   2, "c"),
    "POSITION":    (122,   8, "n"),
    "OFFSET":      (130,  12, "n"),
    "DOMNAME":     (142,  60, "c"),
    "ROLLNAME":    (202,  60, "c"),
    "CHECKTABLE":  (262,  60, "c"),
    "LENG":        (322,  12, "n"),
    "INTLEN":      (334,  12, "n"),
    "OUTPUTLEN":   (346,  12, "n"),
    "DECIMALS":    (358,  12, "n"),
    "DATATYPE":    (370,   8, "c"),
    "INTTYPE":     (378,   2, "c"),
    "REFTABLE":    (380,  60, "c"),
    "REFFIELD":    (440,  60, "c"),
    "PRECFIELD":   (500,  60, "c"),
    "AUTHORID":    (560,   6, "c"),
    "MEMORYID":    (566,  40, "c"),
    "LOGFLAG":     (606,   2, "c"),
    "MASK":        (608,  40, "c"),
    "MASKLEN":     (648,   8, "n"),
    "CONVEXIT":    (656,  10, "c"),
    "HEADLEN":     (666,   4, "n"),
    "SCRLEN1":     (670,   4, "n"),
    "SCRLEN2":     (674,   4, "n"),
    "SCRLEN3":     (678,   4, "n"),
    "FIELDTEXT":   (682, 120, "c"),
    "REPTEXT":     (802, 110, "c"),
    "SCRTEXT_S":   (912,  20, "c"),
    "SCRTEXT_M":   (932,  40, "c"),
    "SCRTEXT_L":   (972,  80, "c"),
    "KEYFLAG":    (1052,   2, "c"),
    "LOWERCASE":  (1054,   2, "c"),
    "MAC":        (1056,   2, "c"),
    "GENKEY":     (1058,   2, "c"),
    "NOFORKEY":   (1060,   2, "c"),
    "VALEXI":     (1062,   2, "c"),
    "NOAUTHCH":   (1064,   2, "c"),
    "SIGN_FLAG":  (1066,   2, "c"),   # DFIES.SIGN (numeric sign indicator)
    "DYNPFLD":    (1068,   2, "c"),
    "F4AVAILABL": (1070,   2, "c"),
    "COMPTYPE":   (1072,   2, "c"),
    "LFIELDNAME": (1074, 264, "c"),
    "LTRFLDDIS":  (1338,   2, "c"),
    "BIDICTRLC":  (1340,   2, "c"),
    "OUTPUTSTYLE":(1342,   4, "n"),
    "NOHISTORY":  (1346,   2, "c"),
    "AMPMFORMAT": (1348,   2, "c"),
}

# Initialised empty DFIES row: each field set to its "blank" value.
# CHAR ("c") → space (0x0020); NUMC ("n") → '0' (0x0030).
_DFIES_EMPTY_ROW = bytearray(1350)
for _fname, (_off, _ilen, _kind) in _DFIES_LAYOUT.items():
    _char = b"\x20\x00" if _kind == "c" else b"\x30\x00"
    _DFIES_EMPTY_ROW[_off:_off + _ilen] = _char * (_ilen // 2)
_DFIES_EMPTY_ROW = bytes(_DFIES_EMPTY_ROW)


def _build_dfies_row(field):
    """Build a 1350-byte DFIES row from a field dict (from ddic_catalog).

    field dict keys: tabname, fieldname, position, keyflag, datatype,
                     leng, outputlen, decimals, inttype, intlen, offset,
                     rollname, reptext
    """
    row = bytearray(_DFIES_EMPTY_ROW)

    def _wc(dfname, value):
        """Write a space-padded CHAR value."""
        off, intlen, _ = _DFIES_LAYOUT[dfname]
        chars = intlen // 2
        s = str(value or "")[:chars].ljust(chars)
        row[off:off + intlen] = s.encode("utf-16-le")

    def _wn(dfname, value):
        """Write a zero-padded NUMC value."""
        off, intlen, _ = _DFIES_LAYOUT[dfname]
        chars = intlen // 2
        s = str(int(value or 0)).zfill(chars)[:chars]
        row[off:off + intlen] = s.encode("utf-16-le")

    _wc("TABNAME",    field["tabname"])
    _wc("FIELDNAME",  field["fieldname"])
    _wn("POSITION",   field["position"])
    _wn("OFFSET",     field["offset"])
    _wn("LENG",       field["leng"])
    _wn("INTLEN",     field["intlen"])
    _wn("OUTPUTLEN",  field["outputlen"])
    _wn("DECIMALS",   field["decimals"])
    _wc("DATATYPE",   field["datatype"])
    _wc("INTTYPE",    field["inttype"])
    _wc("KEYFLAG",    field["keyflag"])
    _wc("ROLLNAME",   field["rollname"])
    _wc("REPTEXT",    field["reptext"])
    # Optional extra fields for TTYP (embedded internal table) components.
    # REFTABLE carries the line-type name; COMPTYPE='T' flags embedded tables.
    # The NWRFC SDK may use these to resolve the nested table's row descriptor.
    if field.get("datatype") == "TTYP":
        _wc("REFTABLE", field.get("rollname", ""))
        _wc("COMPTYPE", "T")

    return bytes(row)


def _build_dfies_rows(fields, nuc_mode=False):
    """Build DFIES rows for *fields*, computing cumulative offsets.

    When *nuc_mode* is False (default, Unicode client / Communication
    Codepage 4103): the NWRFC SDK reads DFIES.INTLEN as UC byte length and
    halves CHAR-based values internally to derive NUC byte count.  Write UC
    lengths unchanged from the catalog.

    When *nuc_mode* is True (NUC client / Communication Codepage 1100): the
    NWRFC SDK reads DFIES.INTLEN directly as NUC byte count without halving.
    We write NUC lengths (halve CHAR-based UC values from the catalog) so the
    SDK's NUC sum matches X030L_WA.TABLEN and PARAMS.INTLENGTH.
    """
    rows = []
    offset = 0
    for f in fields:
        intlen_uc = int(f.get("intlen") or 0)
        # Skip zero-length fields (e.g. TTYP embedded-table placeholders).
        # DFIES rows with INTLEN=0 confuse the NWRFC SDK parser.
        if intlen_uc == 0:
            continue
        if nuc_mode and f.get("inttype", "") in _UC2_INTTYPES:
            intlen_wire = max(1, intlen_uc // 2)  # NUC value for CHAR-based
        else:
            intlen_wire = intlen_uc               # UC value (or non-CHAR type)
        f2 = dict(f)
        f2["intlen"] = intlen_wire  # value written into binary DFIES row
        f2["offset"] = offset       # cumulative offset in same units
        rows.append(_build_dfies_row(f2))
        offset += intlen_wire
    return rows


def _build_dfies_wa_row():
    """Build a blank DFIES_WA row (1350 bytes, all fields empty).

    On real SAP servers the DFIES_WA scalar export in the second
    DDIF_FIELDINFO_GET response is a fully blank DFIES row — all CHAR
    fields are spaces and all NUMC fields are zeros.  The SDK uses it as
    a signal that a structure descriptor follows (X030L_WA), NOT for the
    INTLEN value.  The authoritative NUC record length is in X030L_WA.TABLEN.
    """
    return _DFIES_EMPTY_ROW


def _build_x030l_wa_row(tabname, nuc_len):
    """Build a 416-byte X030L structure row for use as the DDIF X030L_WA export.

    X030L is the ABAP DDIC table/structure descriptor.  Real SAP servers send
    X030L_WA as a scalar export in the *second* DDIF_FIELDINFO_GET response.

    TABLEN (RAW4) is the authoritative NUC record length.  The SDK reads TABLEN
    from UC byte offset 164 in big-endian byte order.  Verified against a real
    SAP NW 7.52 pre-captured RFCSI blob: bytes[164:168] = 0x000000F5 (=245
    big-endian), matching X030L field layout from RFC trace addField lines.

    UC layout: 416 bytes total (SDK reads first 254 UC or 147 NUC bytes).
    """
    row = bytearray(416)
    # Initialise CHAR fields to UTF-16LE spaces (0x20 0x00 per char).
    # RAW fields remain zero.
    for off, size in (
        (0,   60),   # TABNAME   CHAR30
        (60,   2),   # DBASE     CHAR1
        (78,  28),   # CRSTAMP   CHAR14
        (106, 28),   # ABSTAMP   CHAR14
        (134, 28),   # DYSTAMP   CHAR14
        (172,  2),   # TABTYPE   CHAR1
        (174,  2),   # TABFORM   CHAR1
        (176, 60),   # REFNAME   CHAR30
        (242,  2),   # BUFSTATE  CHAR1
        (254, 34),   # DBSQLTIMESTMP CHAR17
    ):
        row[off:off + size] = b"\x20\x00" * (size // 2)
    # TABNAME (CHAR30 at UC offset 0, intlen 60)
    tn = tabname[:30].ljust(30)
    row[0:60] = tn.encode("utf-16-le")
    # TABLEN (RAW4) big-endian.  Must be written at TWO offsets:
    #
    #   NUC byte offset 91  — read by the SDK when UCLEN=0 (NUC/non-unicode server,
    #                         which is our mode).  The SDK uses the NUC layout of
    #                         X030L (147 bytes) and finds TABLEN at byte 91.
    #
    #   UC  byte offset 164 — read by the SDK when UCLEN=1 (Unicode server, as used
    #                         by real SAP NW; verified from pre-captured RFCSI blob:
    #                         bytes[164:168] = \x00\x00\x00\xf5 = 245 big-endian).
    #
    # Without the write at offset 91 (UCLEN=0 mode), the SDK reads the CRSTAMP
    # space bytes (0x20 0x00 ...) as TABLEN → non-zero garbage → rc=20.
    row[91:95]   = struct.pack(">I", nuc_len)   # NUC offset (UCLEN=0)
    row[164:168] = struct.pack(">I", nuc_len)   # UC  offset (UCLEN=1)
    return bytes(row)


# LINES_DESCR block: required by the NWRFC SDK between DFIES_WA and X030L_WA.
# Without this block the SDK cannot locate and parse X030L_WA.TABLEN, causing
# it to fall back to a wrong NUC length computation → rc=20.
# Captured verbatim from SAP NW 7.52; markers 0x3c02/0x3c05 are used for
# the <LINES_DESCR></LINES_DESCR> XML-style metadata tags (ASCII content).
# After the block, the current marker is 0x3c02 — use that as prev for X030L_WA.
_LINES_DESCR_BLOCK = bytes.fromhex(
    "02033c020000"                          # prev=0x0203 → 0x3c02, empty
    "3c023c05000d"
    "3c4c494e45535f44455343523e"            # <LINES_DESCR>  (13 bytes ASCII)
    "3c053c05000e"
    "3c2f4c494e45535f44455343523e"          # </LINES_DESCR> (14 bytes ASCII)
    "3c053c020000"                          # prev=0x3c05 → 0x3c02, empty
)
# After _LINES_DESCR_BLOCK the active marker is 0x3c02.
_LINES_DESCR_TRAIL_MARKER = 0x3c02


# ---------------------------------------------------------------------------
# Built-in DDIC entries for structures commonly needed but absent from the
# exported catalog (e.g. when the catalog was generated from a system where
# FUPARAREF stored incorrect TABNAME values).
#
# offset values are placeholder 0s — _build_dfies_rows recomputes them.
# ---------------------------------------------------------------------------
def _range_row(tabname, fieldname, pos, inttype, leng, intlen, rollname=""):
    """Helper to create one range-table field dict (offset computed later)."""
    return {
        "tabname":   tabname,
        "fieldname": fieldname,
        "position":  pos,
        "keyflag":   "",
        "datatype":  "CHAR",
        "leng":      leng,
        "outputlen": leng,
        "decimals":  0,
        "inttype":   inttype,
        "intlen":    intlen,
        "offset":    0,          # recomputed by _build_dfies_rows
        "rollname":  rollname,
        "reptext":   "",
    }


def _fld(tabname, fieldname, pos, datatype, inttype, leng, intlen, rollname=""):
    """General-purpose field dict helper (offset recomputed by _build_dfies_rows)."""
    return {
        "tabname":   tabname,
        "fieldname": fieldname,
        "position":  pos,
        "keyflag":   "",
        "datatype":  datatype,
        "leng":      leng,
        "outputlen": leng,
        "decimals":  0,
        "inttype":   inttype,
        "intlen":    intlen,
        "offset":    0,
        "rollname":  rollname,
        "reptext":   "",
    }


def _synthetic_ddic_fields(tabname, intlength):
    """Return DFIES field descriptors for types absent from the catalog.

    intlength is the raw A4HANA catalog value (unicode bytes, 2× non-unicode).
    We use CHAR ('C') fields so that the SDK computes uc = 2 * nuc for each
    field.  Because our RFCSI declares RFCCHARTYP=4103 (Unicode server), the
    SDK enforces uc >= 2*nuc for all structure fields; BYTE fields (uc==nuc)
    violate this and trigger "non-unicode length is too small".  CHAR fields
    satisfy the check since the SDK automatically doubles uc for CHAR types.

    intlen stored in the field dict is the UC byte count (intlength).
    _build_dfies_rows halves it for NUC-mode clients when INTTYPE is 'C'.
    nuc_total = intlength // 2 == RFCPARAM.INTLENGTH (NUC) == X030L.TABLEN.
    """
    uc_total = intlength if intlength > 0 else 2
    if uc_total % 2 != 0:
        uc_total += 1  # CHAR bytes must be even
    _MAX_CHAR_UC = 65534  # max CHAR field UC byte count (32767 chars × 2)

    fields = []
    remaining = uc_total
    pos = 1
    while remaining > 0:
        length = min(remaining, _MAX_CHAR_UC)
        fields.append(_fld(tabname, "DATA%d" % pos, pos,
                           "C", "C", length // 2, length))
        remaining -= length
        pos += 1
    return fields


# ---------------------------------------------------------------------------
# EXID type codes for which the unicode internal byte count is 2× the
# non-unicode byte count.  On a unicode SAP system (A4HANA) every CHAR-based
# type stores 2 bytes per logical character.
# ---------------------------------------------------------------------------
_UC2_EXIDS = frozenset({'C', 'N', 'D', 'T', 'Z'})

# INTTYPE codes (DFIES field) that are CHAR-based (unicode = 2 × non-unicode).
_UC2_INTTYPES = frozenset({'C', 'N', 'D', 'T', 'G', 'g'})

# Maximum number of flat DFIES rows to include in a single DDIF_FIELDINFO_GET
# response.  The NWRFC SDK cannot process responses with many DFIES rows
# (observed failure at 32 rows / ~44 KB body).  When more fields are present
# in the catalog the gateway falls back to a single synthetic RAW field so the
# SDK gets a valid (if opaque) type descriptor.
_MAX_DDIF_ROWS = 14


def _resolve_tabname(tabname, ddic_catalog):
    """Resolve a FUPARAREF tabname that may be a data-element reference.

    Some SAP systems (e.g. SolMan) store scalar parameter type info in
    FUPARAREF.STRUCTURE as "TYPENAME-TYPENAME" (same name on both sides of
    the hyphen) instead of the STRUCTURE field being empty and TYPE holding
    the name.  In that case the true catalog key is just the part before "-".

    Returns (resolved_tabname, is_scalar_deref) where is_scalar_deref=True
    means the tabname was a "X-X" data-element reference.
    """
    if not tabname or "-" not in tabname:
        return tabname, False
    parts = tabname.split("-", 1)
    base = parts[0]
    # Only normalise "ELEM-ELEM" patterns (both sides identical after trim)
    if parts[1].strip() != base.strip():
        return tabname, False
    if ddic_catalog and base in ddic_catalog:
        return base, True
    return tabname, False


def _nuc_intlength(exid, intlength, tabname, ddic_catalog):
    """Convert catalog unicode INTLENGTH to non-unicode byte count.

    The A4HANA RFC_GET_FUNCTION_INTERFACE response stores RFCPARAM.INTLENGTH
    in unicode bytes (2 per CHAR).  The NWRFC SDK wire protocol expects the
    non-unicode byte count.  This function converts accordingly so that the
    SDK check  sum(nucLen_from_DFIES) >= RFCPARAM.INTLENGTH  passes.

    For structure/table types ('u'/'h') the non-unicode total is computed
    field-by-field from the DDIC catalog when available; otherwise the
    catalog intlength is halved (NUC = UC/2) since synthetic RAW DFIES
    fields encode the NUC byte count directly.  PARAMS.INTLENGTH must
    match the NUC sum the SDK accumulates from DFIES rows.
    """
    if exid in _UC2_EXIDS:
        return intlength // 2
    elif exid in ('u', 'h'):
        # Resolve "ELEM-ELEM" data-element references (SolMan FUPARAREF quirk).
        resolved_tabname, _ = _resolve_tabname(tabname, ddic_catalog)
        # Check exported DDIC catalog first, then built-in hand-crafted entries.
        fields = (ddic_catalog.get(resolved_tabname) if ddic_catalog else None) \
                 or _BUILTIN_DDIC.get(resolved_tabname)
        if fields:
            total = 0
            for f in fields:
                finttype = f.get("inttype", "C")
                fintlen = int(f.get("intlen") or 0)
                # Skip zero-len and 'g' (STRG ref) — same filter as DFIES rows.
                if fintlen == 0 or finttype == "g":
                    continue
                total += fintlen // 2 if finttype in _UC2_INTTYPES else fintlen
            return total if total > 0 else max(1, intlength // 2)
        # Not in any catalog: synthesise CHAR fields (uc = 2*nuc satisfies the
        # SDK's uc >= 2*nuc check required for Unicode servers, RFCCHARTYP=4103).
        # DFIES.INTLEN stored as UC (intlength); halved to NUC on the wire.
        # PARAMS.INTLENGTH = NUC = intlength // 2.
        return max(1, intlength // 2)
    else:
        # INT4, INT2, INT1, FLOAT, PACKED, RAW, etc. — byte count unchanged.
        return intlength


_BUILTIN_DDIC = {
    # Range-of-username table (XUBNAME = CHAR 12 → unicode INTLEN 24 per field)
    # DFIES: unicode INTLEN values; nucLen = INTLEN/2 per CHAR field.
    # Sum nucLen: 1+2+12+12=27; _nuc_intlength(catalog_intlen=54) → 27 ✓
    "SUSR_T_RANGE_4_XUBNAME": [
        _range_row("SUSR_T_RANGE_4_XUBNAME", "SIGN",   1, "C",  1,  2),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "OPTION", 2, "C",  2,  4),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "LOW",    3, "C", 12, 24, "XUBNAME"),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "HIGH",   4, "C", 12, 24, "XUBNAME"),
    ],
    # Time interval structure for audit log API
    # DFIES: unicode INTLEN values; nucLen = INTLEN/2 per D/T field.
    # Sum nucLen: 8+8+6+6=28; _nuc_intlength(catalog_intlen=56) → 28 ✓
    "RSAU_SEL_INTV": [
        _fld("RSAU_SEL_INTV", "DAT_FROM", 1, "DATS", "D", 8, 16),
        _fld("RSAU_SEL_INTV", "DAT_TO",   2, "DATS", "D", 8, 16),
        _fld("RSAU_SEL_INTV", "TIM_FROM", 3, "TIMS", "T", 6, 12),
        _fld("RSAU_SEL_INTV", "TIM_TO",   4, "TIMS", "T", 6, 12),
    ],
    # Line type for the /SLOAE/T_CODE nested table (TTYP) inside
    # /SLOAE/T_MODULE_GENERATE.  The table carries ABAP source code lines;
    # each row is a single CHAR(255) value.  The NWRFC SDK calls
    # DDIF_FIELDINFO_GET for this type when it resolves the TTYP component
    # in the parent structure's DFIES.  Empty fieldname ("") is how ABAP
    # exposes "table of scalar" line types to pyrfc ({'' : "code line"}).
    "/SLOAE/T_CODE": [
        _fld("/SLOAE/T_CODE", "", 1, "CHAR", "C", 255, 510),
    ],
}


def _build_params_row(paramclass, parameter, tabname, fieldname, exid,
                      position, intlength, paramtext,
                      default="", optional=" "):
    """Build a single PARAMS table row (404 bytes).

    Matches the NWRFC SDK's hard-coded RFC_FUNINT structure layout exactly.
    The SDK reads fields at fixed UC byte offsets; any mismatch causes the
    wrong INTLENGTH to be read, leading to "non-unicode length is too small".

    Layout (UC byte offsets):
        PARAMCLASS (CHAR  1) →   2 bytes  @ offset   0
        PARAMETER  (CHAR 30) →  60 bytes  @ offset   2
        TABNAME    (CHAR 30) →  60 bytes  @ offset  62
        FIELDNAME  (CHAR 30) →  60 bytes  @ offset 122
        EXID       (CHAR  1) →   2 bytes  @ offset 182  (type code char, UTF-16LE)
        POSITION   (INT4)    →   4 bytes  @ offset 184
        OFFSET     (INT4)    →   4 bytes  @ offset 188
        INTLENGTH  (INT4)    →   4 bytes  @ offset 192
        DECIMALS   (INT4)    →   4 bytes  @ offset 196
        DEFAULT    (CHAR 21) →  42 bytes  @ offset 200
        PARAMTEXT  (CHAR 79) → 158 bytes  @ offset 242
        OPTIONAL   (CHAR  1) →   2 bytes  @ offset 400
        Total UC = 402 + 2 pad = 404.

    intlength - NUC byte length (computed via _nuc_intlength).  In NUC comm
                mode (Comm.CP 1100) the SDK reads RFC_FUNINT rows as 212-byte
                NUC structures; use _build_params_row_nuc() instead.
    """
    # CHAR fields: PARAMCLASS + PARAMETER + TABNAME + FIELDNAME (91 chars → 182 bytes)
    text = paramclass[0] if paramclass else " "
    text += parameter.ljust(30)[:30]
    text += tabname.ljust(30)[:30]
    text += fieldname.ljust(30)[:30]
    row = text.encode("utf-16-le")                                   # 182 bytes

    # EXID as CHAR(1) (2 bytes UTF-16LE), then POSITION, OFFSET, INTLENGTH,
    # DECIMALS — 2 + 4×INT4 = 18 bytes.  INTLENGTH lands at UC offset 192.
    exid_char = (exid[0] if exid else " ")
    row += exid_char.encode("utf-16-le")                             #   2 bytes EXID
    row += struct.pack("<IIII", position, 0, intlength, 0)           #  16 bytes

    # DEFAULT (21 chars), PARAMTEXT (79 chars), OPTIONAL (1 char), 2-byte pad
    row += default.ljust(21)[:21].encode("utf-16-le")               #  42 bytes
    row += paramtext.ljust(79)[:79].encode("utf-16-le")             # 158 bytes
    row += optional.ljust(1)[:1].encode("utf-16-le")                #   2 bytes
    row += b"\x00\x00"                                               #   2 bytes pad

    return row                                                        # total 404 bytes


def _build_params_row_nuc(paramclass, parameter, tabname, fieldname, exid,
                          position, intlength, paramtext,
                          default="", optional=" "):
    """Build a single PARAMS table row in NUC encoding (212 bytes).

    Used when the partner Communication Codepage is 1100 (NUC/Latin-1).
    In NUC mode the SDK reads RFC_FUNINT rows using 1-byte-per-CHAR encoding,
    so INTLENGTH lands at NUC offset 103 (not UC offset 194).

    Layout (NUC byte offsets):
        PARAMCLASS (CHAR  1) →   1 byte   @ offset   0
        PARAMETER  (CHAR 30) →  30 bytes  @ offset   1
        TABNAME    (CHAR 30) →  30 bytes  @ offset  31
        FIELDNAME  (CHAR 30) →  30 bytes  @ offset  61
        EXID       (CHAR  1) →   1 byte   @ offset  91  (type code char, Latin-1)
        POSITION   (INT4)    →   4 bytes  @ offset  92
        OFFSET     (INT4)    →   4 bytes  @ offset  96
        INTLENGTH  (INT4)    →   4 bytes  @ offset 100
        DECIMALS   (INT4)    →   4 bytes  @ offset 104
        DEFAULT    (CHAR 21) →  21 bytes  @ offset 108
        PARAMTEXT  (CHAR 79) →  79 bytes  @ offset 129
        OPTIONAL   (CHAR  1) →   1 byte   @ offset 208
        1-byte pad           →   1 byte   @ offset 209  (→ total 210; pad to 212)
        Total NUC = 212.
    """
    text = paramclass[0]
    text += parameter.ljust(30)[:30]
    text += tabname.ljust(30)[:30]
    text += fieldname.ljust(30)[:30]
    row = text.encode("latin-1")                                     # 91 bytes

    exid_char = (exid[0] if exid else " ")
    row += exid_char.encode("latin-1")                              #   1 byte  EXID
    row += struct.pack("<IIII", position, 0, intlength, 0)          #  16 bytes

    row += default.ljust(21)[:21].encode("latin-1")                 # 21 bytes
    row += paramtext.ljust(79)[:79].encode("latin-1")               # 79 bytes
    row += optional.ljust(1)[:1].encode("latin-1")                  #  1 byte
    row += b"\x00\x00\x00"                                          #  3 bytes pad

    return row                                                        # total 212 bytes


def _extract_session_id(raw):
    """Extract the 16-byte session ID from marker 0x0514 in an F_SAP_SEND."""
    pattern = b"\x05\x14\x00\x10"   # marker=0x0514, length=0x0010
    idx = raw.find(pattern)
    if idx >= 0 and idx + 20 <= len(raw):
        return raw[idx + 4:idx + 20]
    return os.urandom(16)


class SAPGatewayClient(Loggeable, SAPNIClient):

    registered = False
    username = None
    client_nbr = None
    conversation_id = None
    login_done = False  # True after the first F_SAP_SEND (login handshake)
    ddif_call_count = 0  # Tracks DDIF_FIELDINFO_GET call sequence (0-2)


class SAPGatewayServerHandler(Loggeable, SAPNIServerHandler):

    @property
    def hostname(self):
        return self.config.get("hostname", "sapnw702")

    @property
    def sid(self):
        return self.config.get("sid", "PRD")

    @property
    def instance_number(self):
        return self.config.get("instance_number", "00")

    @property
    def kernel_version(self):
        return self.config.get("kernel_version", "7200")

    @property
    def gateway_version(self):
        return self.config.get("gateway_version", "7200")

    @property
    def allow_monitor(self):
        return self.config.get("allow_monitor", True)

    @property
    def sap_release(self):
        return self.config.get("sap_release", "752")

    @property
    def db_system(self):
        return self.config.get("db_system", "HDB")

    @property
    def os_name(self):
        return self.config.get("os_name", "Linux")

    def __init__(self, request, client_address, server):
        self.config = server.config
        client_ip, client_port = client_address
        server_ip, server_port = server.server_address
        self.session = server.session_manager.get_session("gateway",
                                                          client_ip,
                                                          client_port,
                                                          server_ip,
                                                          server_port)
        # Codepage advertised by the client in the GW_NORMAL_CLIENT packet.
        # "1100" = non-Unicode (NUC) client; "4103" = Unicode client.
        # Defaults to "4103" (Unicode) so that catalog UC INTLEN values are
        # sent unchanged when we have not yet seen a GW_NORMAL_CLIENT.
        self._partner_codepage = "4103"
        SAPNIServerHandler.__init__(self, request, client_address, server)

    # ------------------------------------------------------------------
    # Main dispatch
    # ------------------------------------------------------------------

    def handle_data(self):
        """Handles a received packet, dispatching by version/type."""
        self.session.add_event("Received packet", request=str(self.packet))

        # With base_cls=None the NI payload is not auto-decoded as SAPRFC.
        # We extract raw bytes from the SAPNI "payload" field directly.
        try:
            raw = bytes(self.packet.payload)
        except Exception:
            self.logger.debug("Failed to get payload bytes from %s",
                              str(self.client_address))
            return
        if len(raw) < 2:
            return

        try:
            version = raw[0]
            if version == 0x06:
                # APPC layer — RFC function call protocol
                func_type = raw[1]
                self._handle_appc(raw, func_type)
            else:
                # Gateway layer — connection management, monitor commands
                self._handle_gateway(raw, version)
        except Exception as exc:
            self.logger.error(
                "Unhandled exception in handle_data from %s: %s",
                str(self.client_address), exc, exc_info=True,
            )
            raise

    # ------------------------------------------------------------------
    # Gateway-level handlers (version != 0x06)
    # ------------------------------------------------------------------

    def _handle_gateway(self, raw, version):
        """Handle gateway-level request types."""
        if len(raw) < 2:
            return

        req_type = raw[1]
        req_name = rfc_req_type_values.get(req_type, "UNKNOWN(0x%02x)" % req_type)

        if req_type == 0x01:  # CHECK_GATEWAY
            self._handle_check_gateway(req_name)

        elif req_type == 0x03:  # GW_NORMAL_CLIENT
            self._handle_normal_client(raw, version, req_name)

        elif req_type == 0x09:  # GW_SEND_CMD
            self._handle_send_cmd(raw, req_name)

        elif req_type == 0x05:  # STOP_GATEWAY
            self.logger.warning("STOP_GATEWAY from %s", str(self.client_address))
            self.session.add_event("Dangerous gateway command attempted",
                                   data={"req_type": req_name})

        elif req_type == 0x0b:  # GW_REGISTER_TP
            self.logger.debug("GW_REGISTER_TP from %s", str(self.client_address))
            self.session.add_event("TP registration request",
                                   data={"req_type": req_name})

        elif req_type == 0x0c:  # GW_UNREGISTER_TP
            self.logger.debug("GW_UNREGISTER_TP from %s", str(self.client_address))
            self.session.add_event("TP unregistration request",
                                   data={"req_type": req_name})

        else:
            self.logger.debug("Unhandled gateway request 0x%02x from %s",
                              req_type, str(self.client_address))
            self.session.add_event("Unhandled gateway request",
                                   data={"req_type": req_name,
                                         "req_type_id": req_type})

    def _handle_check_gateway(self, req_name):
        self.logger.debug("CHECK_GATEWAY from %s", str(self.client_address))
        self.session.add_event("Gateway check request",
                               data={"req_type": req_name})
        try:
            response = SAPRFC(version=3, req_type=0x01)
            self.request.send(response)
        except error:
            pass

    def _handle_normal_client(self, raw, version, req_name):
        """Handle GW_NORMAL_CLIENT — first packet in an RFC connection.

        Real SAP gateways echo the request back with additional accept_info
        flags (CODE_PAGE, NIPING).  We parse the request with pysap to log
        the fields and then build a response that matches the client version.
        """
        data = {"req_type": req_name}
        try:
            rfc = SAPRFC(raw)
            for field in ("lu", "tp", "service", "address", "conversation_id"):
                val = _strip_field(getattr(rfc, field, None))
                if val:
                    data[field] = val
        except Exception:
            pass

        self.logger.debug("GW_NORMAL_CLIENT from %s: lu=%s tp=%s service=%s",
                          str(self.client_address),
                          data.get("lu"), data.get("tp"), data.get("service"))
        self.session.add_event("Normal client connection", data=data)

        # Build response: echo the raw request but flip accept_info to add
        # CODE_PAGE (bit 4) and NIPING (bit 5).  In version 2 the
        # accept_info byte is at offset 41; in version 3 it is also at 41.
        #
        # Also override the codepage field (offset 20, 4 ASCII bytes) to
        # "4103" (Unicode).  The client sends "1100" (non-Unicode) by default;
        # if we echo it back unchanged the NWRFC SDK stores
        # Communication Codepage=1100 and treats every DFIES INTLEN as a NUC
        # byte count, causing the uc-len >= 2*nuc-len consistency check to
        # fail (rc=20) for any CHAR field whose INTLEN is already in UC bytes.
        # Record the client's codepage so DFIES INTLEN values can be sent in
        # the encoding the SDK expects.  The GW_NORMAL_CLIENT packet carries
        # the client's codepage as 4 ASCII bytes at offset 20.
        if len(raw) >= 24:
            try:
                cp = raw[20:24].decode("ascii").strip()
                if cp:
                    self._partner_codepage = cp
                    self.logger.debug("GW_NORMAL_CLIENT: partner_codepage=%s", cp)
            except (UnicodeDecodeError, AttributeError):
                pass

        try:
            resp = bytearray(raw)
            if len(resp) > 55:
                resp[55] = resp[55] | 0x10  # set CODE_PAGE bit in accept_info (offset 55)
                resp[20:24] = b"4103"       # advertise Unicode (4103) server codepage
            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    def _handle_send_cmd(self, raw, req_name):
        """Handle GW_SEND_CMD — gateway monitor commands."""
        try:
            rfc = SAPRFC(raw)
            cmd = rfc.cmd
        except Exception:
            cmd = raw[2] if len(raw) > 2 else 0

        cmd_name = rfc_monitor_cmd_values.get(cmd, "UNKNOWN(0x%02x)" % cmd)
        self.logger.debug("GW_SEND_CMD from %s: cmd=%s",
                          str(self.client_address), cmd_name)
        self.session.add_event("Monitor command received",
                               data={"req_type": req_name,
                                     "cmd": cmd_name,
                                     "cmd_id": cmd})

        if cmd_name in _DANGEROUS_MONITOR_CMDS:
            self.logger.warning("Dangerous monitor command '%s' from %s",
                                cmd_name, str(self.client_address))
            self.session.add_event("Dangerous monitor command attempted",
                                   data={"cmd": cmd_name})

        if cmd == 0x01:  # NOOP — respond to keep client happy
            try:
                response = SAPRFC(version=3, req_type=0x09, cmd=0x01)
                self.request.send(response)
            except error:
                pass

    def _close_connection(self):
        """Close the client connection and signal the handler loop to stop.

        Sets the ``closed`` event (breaking the recv loop in
        SAPNIServerHandler.handle) and closes the underlying socket so the
        server sends a TCP FIN to the client.
        """
        self.logger.debug("Closing connection to %s", str(self.client_address))
        try:
            self.request.close()
        except error:
            pass
        self.close()

    # ------------------------------------------------------------------
    # APPC-level handlers (version == 0x06)
    # ------------------------------------------------------------------

    def _handle_appc(self, raw, func_type):
        """Dispatch APPC packets by function type."""
        func_name = rfc_func_type_values.get(func_type,
                                              "UNKNOWN(0x%02x)" % func_type)

        if func_type == 0x01:  # F_INITIALIZE_CONVERSATION
            self._handle_init_conversation(raw, func_name)

        elif func_type == 0x0f:  # F_SET_PARTNER_LU_NAME
            self.logger.debug("F_SET_PARTNER_LU_NAME from %s",
                              str(self.client_address))
            self.session.add_event("APPC set partner LU name",
                                   data={"func_type": func_name})
            # No response needed; client sends F_ALLOCATE next

        elif func_type == 0x05:  # F_ALLOCATE
            self._handle_allocate(raw, func_name)

        elif func_type == 0xcb:  # F_SAP_SEND
            self._handle_sap_send(raw, func_name)

        elif func_type == 0x0b:  # F_DEALLOCATE
            self.logger.debug("F_DEALLOCATE from %s", str(self.client_address))
            self.session.add_event("APPC deallocate",
                                   data={"func_type": func_name})
            self._close_connection()

        elif func_type == 0xce:  # F_SAP_PING
            self.logger.debug("F_SAP_PING from %s", str(self.client_address))
            self.session.add_event("APPC ping request",
                                   data={"func_type": func_name})
            try:
                response = SAPRFC(version=0x06, func_type=0xce, appc_rc=0x00)
                self.request.send(response)
            except error:
                pass

        elif func_type in (0xca, 0xc9):  # F_SAP_INIT / F_SAP_ALLOCATE (old style)
            self._handle_old_style_init(raw, func_type, func_name)

        elif func_type in (0xcf, 0xd0):  # F_SAP_REGTP / F_SAP_UNREGTP
            self.logger.debug("%s from %s", func_name, str(self.client_address))
            self.session.add_event("APPC TP registration",
                                   data={"func_type": func_name})

        elif func_type == 0xd5:  # F_SAP_CANCEL
            self.logger.debug("F_SAP_CANCEL from %s", str(self.client_address))
            self.session.add_event("APPC cancel request",
                                   data={"func_type": func_name})
            self._close_connection()

        else:
            self.logger.debug("Unhandled APPC 0x%02x from %s",
                              func_type, str(self.client_address))
            self.session.add_event("Unhandled APPC request",
                                   data={"func_type": func_name,
                                         "func_type_id": func_type})

    # -- F_INITIALIZE_CONVERSATION (0x01) --------------------------------

    def _handle_init_conversation(self, raw, func_name):
        """Handle F_INITIALIZE_CONVERSATION — extract user, destination, LU/TP
        from the sap_param (SAPRFCDTStruct) and sap_ext_header (SAPRFCEXTEND).

        Real servers echo the first 80 bytes of the request (48-byte APPC
        header + 32-byte SAPRFCEXTEND) with a generated conv_id filled in.
        """
        data = {"func_type": func_name}

        try:
            rfc = SAPRFC(raw)

            # Extract user and destination from parsed packet
            sap_param = getattr(rfc, "sap_param", None)
            if sap_param and isinstance(sap_param, SAPRFCDTStruct):
                for field in ("user", "long_lu", "long_tp"):
                    val = _strip_field(getattr(sap_param, field, None))
                    if val:
                        data[field] = val

                # Track user on connection
                if data.get("user") and self.client_address in self.server.clients:
                    self.server.clients[self.client_address].username = data["user"]

            sap_ext = getattr(rfc, "sap_ext_header", None)
            if sap_ext and isinstance(sap_ext, SAPRFCEXTEND):
                for field in ("short_dest_name", "ncpic_lu", "ncpic_tp"):
                    val = _strip_field(getattr(sap_ext, field, None))
                    if val:
                        data[field] = val
        except Exception as e:
            self.logger.debug("Error parsing F_INITIALIZE_CONVERSATION: %s", e)

        self.logger.info("RFC connection from %s: user=%s dest=%s lu=%s",
                         str(self.client_address),
                         data.get("user", "N/A"),
                         data.get("short_dest_name", "N/A"),
                         data.get("long_lu", "N/A"))
        self.session.add_event("APPC init conversation", data=data)

        # Respond: first 80 bytes of the request with conv_id filled in.
        # The real server sends 48-byte APPC header + 32-byte SAPRFCEXTEND
        # (short_dest_name, ncpic_lu, ncpic_tp, flags, code_page_tail).
        conv_id = _make_conversation_id()
        if self.client_address in self.server.clients:
            self.server.clients[self.client_address].conversation_id = conv_id

        data["conversation_id"] = conv_id

        try:
            if len(raw) >= 80:
                resp = bytearray(raw[:80])
            else:
                resp = bytearray(raw) + bytearray(80 - len(raw))
            # Write conv_id at offset 40-47
            resp[40:48] = conv_id.encode("ascii")
            # info4 (byte 21): real servers set to 0x06
            resp[21] = 0x06
            # code_page_tail (last 2 bytes of SAPRFCEXTEND): set to 0x0004
            resp[78:80] = b"\x00\x04"
            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    # -- F_ALLOCATE (0x05) -----------------------------------------------

    def _handle_allocate(self, raw, func_name):
        """Handle F_ALLOCATE — accept the conversation allocation.

        Real servers respond with 80 bytes: 48-byte APPC header (with
        SYNC_CPIC_FUNCTION, GW_WITH_CODE_PAGE) + 32 bytes of codepage
        fields (mostly zeros, with the server instance port in codepage_v6).
        """
        self.logger.debug("F_ALLOCATE from %s", str(self.client_address))
        self.session.add_event("APPC allocate", data={"func_type": func_name})

        try:
            # Build 80-byte response from the request
            if len(raw) >= 80:
                resp = bytearray(raw[:80])
            else:
                resp = bytearray(raw) + bytearray(80 - len(raw))

            # info3 (byte 16): set GW_WITH_CODE_PAGE
            resp[16] = 0x01
            # info4 (byte 21): real server sets 0x02
            resp[21] = 0x02
            # info (bytes 29-30): set SYNC_CPIC_FUNCTION (0x0100 big-endian)
            resp[29] = 0x01
            resp[30] = 0x00
            # conv_id at bytes 40-47: keep from request (client already set it)
            # Write server instance port ("4103" format) into codepage_v6
            # at bytes 69-72 (offset 68 is codepage_v6 start, +1 for leading 0)
            svc_id = "41%s" % self.instance_number  # e.g. "4100"
            resp[69:69 + len(svc_id)] = svc_id.encode("ascii")
            # Clear the ffff at bytes 76-77 (old request padding)
            resp[76:78] = b"\x00\x00"
            # code_page_tail at byte 79
            resp[79] = 0x04

            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    # -- F_SAP_SEND (0xcb) — the main RFC data exchange ------------------

    def _handle_sap_send(self, raw, func_name):
        """Handle F_SAP_SEND — extract function module name and credentials.

        pysap's SAPRFC class cannot parse F_SAP_SEND bodies due to
        conditional field issues, so we extract fields from the raw bytes.
        The APPC header is the first 48 bytes; after conv_id (bytes 40-47)
        the body contains CPIC-serialized RFC data.

        The first F_SAP_SEND in a connection is always a login handshake
        carrying credentials and the "RFCPING" marker function.  The actual
        RFC function module name arrives in subsequent F_SAP_SEND packets.
        """
        data = {"func_type": func_name}

        # Extract conv_id from APPC header
        if len(raw) >= 48:
            conv_id = raw[40:48].decode("ascii", errors="replace").strip("\x00 ")
            if conv_id:
                data["conversation_id"] = conv_id

        # Determine whether this is the login handshake (first F_SAP_SEND)
        # or an actual RFC function call.  The login packet contains the
        # EBCDIC "RFC" marker (0xD9 0xC6 0xC3).
        ebcdic_rfc = b"\xd9\xc6\xc3"  # EBCDIC for "RFC"
        is_login = ebcdic_rfc in raw

        client = self.server.clients.get(self.client_address)

        if is_login:
            # Login / handshake — extract credentials, ignore the
            # "RFCPING" function module (it is always present here).
            self._extract_login_fields(raw, data)

            if client:
                client.login_done = True

            self.logger.info("RFC login from %s: user=%s client=%s password=%s ip=%s dest=%s",
                             str(self.client_address),
                             data.get("username", "N/A"),
                             data.get("client_number", "N/A"),
                             data.get("password", "N/A"),
                             data.get("client_ip", "N/A"),
                             data.get("destination", "N/A"))
            self.session.add_event("RFC login", data=data)

            # Respond with login success — full response with TLV body
            try:
                self._send_login_response(raw, data)
            except error:
                pass
        else:
            # Actual RFC function call — extract the function module name.
            func_module = self._extract_function_module(raw)
            if func_module:
                data["function_module"] = func_module

            user_display = (client.username if client else None) or "N/A"
            cli_display = (client.client_nbr if client else None) or "N/A"
            func_display = data.get("function_module", "unknown")

            if func_module not in _INFRA_FUNCS:
                # Business FM call — extract import parameters and highlight
                params = _extract_rfc_params(raw)
                if params:
                    data["parameters"] = params
                param_str = " ".join("%s=%r" % (k, v) for k, v in params.items()) if params else ""
                self.logger.warning(
                    ">>> RFC CALL: %s  (user=%s, client=%s, src=%s)%s",
                    func_display, user_display, cli_display,
                    str(self.client_address),
                    ("  [" + param_str + "]") if param_str else "",
                )
            else:
                self.logger.info("RFC call from %s: %s (user=%s, client=%s)",
                                 str(self.client_address), func_display,
                                 user_display, cli_display)
            self.session.add_event("RFC function call", data=data)

            # Dispatch based on function module name
            try:
                if func_module == "RFC_GET_FUNCTION_INTERFACE":
                    target = self._extract_target_function(raw)
                    if target:
                        data["target_function"] = target
                    self._send_rfcgfi_response(raw, target)
                elif func_module == "RFC_SYSTEM_INFO":
                    self._send_sysinfo_response(raw)
                elif func_module == "DDIF_FIELDINFO_GET":
                    self._send_ddif_response(raw)
                else:
                    self._send_rfc_response(raw)
            except error:
                pass

    def _extract_function_module(self, raw):
        """Extract the RFC function module name from raw packet bytes.

        Searches for the cpic_RFC_f_padd marker (\x00\x0b\x01\x02) followed
        by a 2-byte length and the function name.  The name can be ASCII
        (first F_SAP_SEND) or UTF-16LE (subsequent sends).
        """
        val = _extract_cpic_field_by_padd(raw, CPIC_RFC_F_PADD)
        if val:
            return _decode_rfc_string(val)

        # Fallback: search for UTF-16LE uppercase function-name patterns
        # like R\x00F\x00C\x00_\x00 in the body
        match = _RE_UTF16LE_FUNCNAME.search(
            raw[48:] if len(raw) > 48 else raw,
        )
        if match:
            try:
                candidate = match.group(1)
                # Ensure it's valid UTF-16LE
                name = candidate.decode("utf-16-le").strip()
                if len(name) >= 3 and name.replace("_", "").replace("/", "").isalnum():
                    return name
            except (UnicodeDecodeError, ValueError):
                pass

        return None

    def _extract_login_fields(self, raw, data):
        """Extract username, client number, IP, hostname, destination and
        program from the first F_SAP_SEND (the login handshake).

        All fields use the 2-byte marker scanner so that extraction is
        independent of field order, which varies across NWRFC SDK versions.
        """
        # Username
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_USERNAME)
        if val:
            username = val.decode("ascii", errors="replace").strip("\x00 ")
            if username:
                data["username"] = username
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].username = username

        # Client number
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_CLI_NBR)
        if val:
            cli_nbr = val.decode("ascii", errors="replace").strip("\x00 ")
            if cli_nbr:
                data["client_number"] = cli_nbr
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].client_nbr = cli_nbr

        # Password — SAP XOR-scrambled
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_PASSWORD)
        if val:
            data["password_hash"] = val.hex()
            data["password"] = _descramble_rfc_password(val)

        # Client IP
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_IP)
        if val:
            ip = val.decode("ascii", errors="replace").strip("\x00 ")
            if ip:
                data["client_ip"] = ip

        # Client hostname/SID/instance
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_HOSTNAME)
        if val:
            hostname = val.decode("ascii", errors="replace").strip("\x00 ")
            if hostname:
                data["client_hostname"] = hostname

        # Destination
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_DEST)
        if val:
            dest = val.decode("ascii", errors="replace").strip("\x00 ")
            if dest:
                data["destination"] = dest

        # Program / client library
        val = _extract_cpic_field_by_padd(raw, CPIC_PROGRAM_PADD)
        if val:
            program = val.decode("ascii", errors="replace").strip("\x00 ")
            if program:
                data["program"] = program

    # -- Login / RFC response builders ------------------------------------

    def _build_appc_header(self, raw, body_length):
        """Build an 80-byte APPC response header (48 APPC + 32 codepage).

        Copies the first 48 bytes from the request, then appends codepage
        fields with ``codepage_size2`` set to ``body_length`` so the NWRFC
        client knows how many additional bytes to read.
        """
        resp = bytearray(80)
        hdr_len = min(48, len(raw))
        resp[:hdr_len] = raw[:hdr_len]

        # info2 (byte 10): clear flags
        resp[10] = 0x00
        # trace_level (byte 11): 0
        resp[11] = 0x00
        # info3 (byte 16): GW_WITH_CODE_PAGE
        resp[16] = 0x01
        # timeout (bytes 17-20): -1
        resp[17:21] = b"\xff\xff\xff\xff"
        # info4 (byte 21): 0x02
        resp[21] = 0x02
        # seq_no (bytes 22-25): 1
        struct.pack_into("!I", resp, 22, 1)
        # sap_param_len (bytes 26-27): 8
        struct.pack_into("!H", resp, 26, 8)
        # padd_appc (byte 28): 0
        resp[28] = 0x00
        # info (bytes 29-30): SYNC_CPIC_FUNCTION | WITH_GW_SAP_PARAMS_HDR
        struct.pack_into("!H", resp, 29, 0x0005)
        # vector (byte 31): F_V_SEND_DATA | F_V_RECEIVE
        resp[31] = 0x0c
        # appc_rc (bytes 32-35): 0 (CM_OK)
        struct.pack_into("!I", resp, 32, 0)
        # sap_rc (bytes 36-39): 0
        struct.pack_into("!I", resp, 36, 0)
        # conv_id (bytes 40-47): keep from request

        # Codepage fields (bytes 48-79)
        # codepage_size1 (bytes 48-51): 28000 (constant from real servers)
        struct.pack_into("!I", resp, 48, 28000)
        # codepage_padd1 (bytes 52-55): 2
        struct.pack_into("!I", resp, 52, 2)
        # codepage_size2 (bytes 56-59): body length
        struct.pack_into("!I", resp, 56, body_length)
        # codepage_padd2 (bytes 60-63): 1
        struct.pack_into("!I", resp, 60, 1)
        # codepage_padd3 (bytes 64-67): 0
        struct.pack_into("!I", resp, 64, 0)
        # codepage_v6 (bytes 68-72): "\x004103" (instance port)
        svc_id = "41%s" % self.instance_number
        resp[68] = 0x00
        resp[69:69 + len(svc_id)] = svc_id.encode("ascii")
        # codepage_padd4 (bytes 73-79): zeros + 0x04 tail
        resp[73:79] = b"\x00\x00\x00\x00\x00\x00"
        resp[79] = 0x04

        return bytes(resp)

    def _build_login_body(self, username, client_nbr, language="E"):
        """Build the TLV body for a successful login response.

        Mimics a real SAP server by sending back server info (hostname, SID,
        kernel version) and echoing the client's credentials.
        """
        def utf16(s):
            return s.encode("utf-16-le")

        server_ip = self.server.server_address[0] or "127.0.0.1"
        host_sid = "%s_%s_%s" % (self.hostname, self.sid, self.instance_number)
        kver = self.kernel_version[:3].ljust(4)
        user_padded = (username or "").ljust(12)[:12]
        cli = (client_nbr or "000")[:3]
        short_host = self.hostname + "_"

        fields = b""
        fields += _tlv(0x0106, 0x0016, utf16("4103"))
        fields += _tlv(0x0016, 0x0007, utf16(server_ip.ljust(15)))
        fields += _tlv(0x0007, 0x0018, utf16(server_ip))
        fields += _tlv(0x0018, 0x0008, utf16(host_sid[:15].ljust(15)))
        fields += _tlv(0x0008, 0x0011, utf16("3"))
        fields += _tlv(0x0011, 0x0013, utf16(kver))
        fields += _tlv(0x0013, 0x0012, utf16(kver))
        fields += _tlv(0x0012, 0x0006, utf16(short_host))
        fields += _tlv(0x0006, 0x0130, utf16("SAPLSYST"))
        fields += _tlv(0x0130, 0x0150, utf16(user_padded))
        fields += _tlv(0x0150, 0x0151, utf16(cli))
        fields += _tlv(0x0151, 0x0152, utf16(language or "E"))
        fields += _tlv(0x0152, 0x0500, b"")
        fields += _tlv(0x0500, 0x0503, b"")
        fields += _tlv(0x0503, 0x0514, os.urandom(16))
        fields += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        fields += _tlv(0x0420, 0x0512, b"")
        fields += _tlv(0x0512, 0x0130, utf16("SAPLSYST".ljust(40)))
        fields += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\xe0\x60\x40")
        # End markers
        fields += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"

        return _CPIC_HEADER + fields

    def _build_rfc_body(self, program="SAPLSRFC"):
        """Build a minimal TLV body for an RFC function response."""
        def utf16(s):
            return s.encode("utf-16-le")

        fields = b""
        fields += _tlv(0x0500, 0x0503, b"")  # fake prev for first field
        fields += _tlv(0x0503, 0x0514, os.urandom(16))
        fields += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        fields += _tlv(0x0420, 0x0512, b"")
        fields += _tlv(0x0512, 0x0130, utf16(program.ljust(40)))
        fields += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x00\x57\x40")
        fields += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"

        # 4-byte preamble before TLV fields (matches real server)
        cpic_hdr = b"\x05\x00\x00\x00"
        return cpic_hdr + fields

    def _send_login_response(self, raw, data):
        """Send a login success response with full TLV body."""
        body = self._build_login_body(
            data.get("username", ""),
            data.get("client_number", "000"),
        )
        header = self._build_appc_header(raw, len(body))
        self.request.send(Raw(header + body))

    def _send_rfc_response(self, raw):
        """Send a minimal RFC function response."""
        body = self._build_rfc_body()
        header = self._build_appc_header(raw, len(body))
        self.request.send(Raw(header + body))

    # -- RFC_SYSTEM_INFO support -------------------------------------------

    @property
    def rfm_catalog(self):
        return getattr(self.server, "rfm_catalog", {})

    @property
    def ddic_catalog(self):
        return getattr(self.server, "ddic_catalog", {})

    def _extract_target_function(self, raw):
        """Extract the target function name from an RFC_GET_FUNCTION_INTERFACE
        request.

        The NWRFC SDK sends the target name as the value of an import
        parameter called FUNCNAME encoded as UTF-16LE.  We find that string
        in the packet body and then read the immediately following 0x0203
        (parameter-value) TLV to get the actual function name.

        Falls back to scanning for a small set of hardcoded names when the
        primary extraction fails (e.g. on older or non-standard clients).
        """
        funcname_bytes = "FUNCNAME".encode("utf-16-le")
        idx = raw.find(funcname_bytes)
        if idx >= 0:
            val, _ = _extract_cpic_field_by_marker(
                raw, b"\x02\x03", idx + len(funcname_bytes)
            )
            if val:
                name = _decode_rfc_string(val)
                if name:
                    return name

        # Fallback: scan for well-known names that need special handling.
        for name in ("RFC_SYSTEM_INFO", "DDIF_FIELDINFO_GET"):
            if name.encode("utf-16-le") in raw:
                return name
        return None

    def _build_rfcsi_string(self):
        """Build the 245-character RFCSI structure string with honeypot
        system information."""
        server_ip = self.server.server_address[0] or "127.0.0.1"
        dest = "%s_%s_%s" % (self.hostname, self.sid, self.instance_number)
        krel = self.kernel_version[:3]
        values = {
            "RFCPROTO": "011",
            "RFCCHARTYP": "4103",
            "RFCINTTYP": "LIT",
            "RFCFLOTYP": "IE3",
            "RFCDEST": dest,
            "RFCHOST": self.hostname[:8],
            "RFCSYSID": self.sid,
            "RFCDATABS": self.sid,
            "RFCDBHOST": self.hostname,
            "RFCDBSYS": self.db_system,
            "RFCSAPRL": self.sap_release,
            "RFCMACH": "390",
            "RFCOPSYS": self.os_name,
            "RFCTZONE": "7200",
            "RFCDAYST": "",
            "RFCIPADDR": server_ip,
            "RFCKERNRL": krel,
            "RFCHOST2": self.hostname,
            "RFCSI_RESV": "",
            "RFCIPV6ADDR": server_ip,
        }
        result = ""
        for name, width in _RFCSI_FIELDS:
            result += values.get(name, "").ljust(width)[:width]
        return result

    def _build_rfcgfi_sysinfo_body(self, session_id):
        """Build the RFC_GET_FUNCTION_INTERFACE response body describing
        RFC_SYSTEM_INFO's export parameters."""
        def utf16(s):
            return s.encode("utf-16-le")

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameters of RFC_GET_FUNCTION_INTERFACE itself
        body += _tlv(0x0512, 0x0201, utf16("REMOTE_BASXML_SUPPORTED"))
        body += _tlv(0x0201, 0x0203, utf16(" "))
        body += _tlv(0x0203, 0x0201, utf16("REMOTE_CALL"))
        body += _tlv(0x0201, 0x0203, utf16("R"))
        body += _tlv(0x0203, 0x0201, utf16("UPDATE_TASK"))
        body += _tlv(0x0201, 0x0203, utf16(" "))

        # PARAMS table — 6 rows describing RFC_SYSTEM_INFO's parameters.
        # Always send UC rows (404 bytes); the SDK always reads PARAMS rows as
        # 404-byte UC structures regardless of the partner's Communication Codepage.
        _row = _build_params_row
        _rs  = 404
        body += _tlv(0x0203, 0x0301, utf16("PARAMS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 1))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", _rs, 6))

        rows = [
            # INT4 params: NUC=4 bytes
            _row("E", "CURRENT_RESOURCES", "SYST", "INDEX",
                 "I", 1, 4, "Currently Available Resources"),
            _row("E", "FAST_SER_VERS", "INT4", "",
                 "I", 0, 4, ""),
            _row("E", "MAXIMAL_RESOURCES", "SYST", "INDEX",
                 "I", 1, 4, "Maximum Resources Available"),
            _row("E", "RECOMMENDED_DELAY", "SYST", "INDEX",
                 "I", 1, 4, "Default Value for Delay"),
            # RFCSI structure: NUC=245 bytes
            _row("E", "RFCSI_EXPORT", "RFCSI", "",
                 "u", 0, 245, "See structure RFCSI"),
            # CHAR1: NUC=1 byte
            _row("E", "S4_HANA", "CHAR1", "",
                 "C", 0, 1, ""),
        ]
        prev = 0x0302
        for row in rows:
            body += _tlv(prev, 0x0303, row)
            prev = 0x0303

        # RESUMABLE_EXCEPTIONS table (empty)
        body += _tlv(0x0303, 0x0301, utf16("RESUMABLE_EXCEPTIONS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 2))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 62, 0))

        # Program name and footer
        body += _tlv(0x0302, 0x0130, utf16("SAPLRFC1".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x40\x9d\xdf\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _build_rfcgfi_body(self, session_id, func_info):
        """Build a generic RFC_GET_FUNCTION_INTERFACE response from catalog data.

        *func_info* is the value from the RFM catalog dict — a dict with keys
        ``remote_call``, ``update_task``, ``remote_basxml_supported``, and
        ``params`` (list of parameter dicts matching _build_params_row args).
        """
        def utf16(s):
            return s.encode("utf-16-le")

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Scalar exports of RFC_GET_FUNCTION_INTERFACE itself.
        body += _tlv(0x0512, 0x0201, utf16("REMOTE_BASXML_SUPPORTED"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("remote_basxml_supported") or " "))
        body += _tlv(0x0203, 0x0201, utf16("REMOTE_CALL"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("remote_call") or " "))
        body += _tlv(0x0203, 0x0201, utf16("UPDATE_TASK"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("update_task") or " "))

        # PARAMS table.  INTLENGTH carries the NUC byte length.
        #
        # Always send 404-byte UC rows.  The SDK registers 0 parameters when it
        # receives 212-byte NUC rows regardless of the partner's Communication
        # Codepage — it always parses PARAMS rows as 404-byte UC structures.
        params = func_info.get("params", [])
        rows = []
        for p in params:
            exid = p["exid"]
            tabname = p["tabname"]
            # Resolve "ELEM-ELEM" data-element references produced by some SAP
            # systems (e.g. SolMan storing STRUCTURE="BAPIBNAME-BAPIBNAME" for
            # a scalar CHAR parameter).  These are single-field wrapper types;
            # change EXID to 'C' so the SDK treats the parameter as a plain
            # CHAR string rather than requiring a structure dict.
            resolved_tabname, is_scalar_deref = _resolve_tabname(
                tabname, self.ddic_catalog)
            if is_scalar_deref and exid in ('u', 'h'):
                fields = self.ddic_catalog.get(resolved_tabname) or []
                flat = [f for f in fields
                        if int(f.get("intlen") or 0) > 0
                        and f.get("inttype", "") != "g"]
                if len(flat) == 1 and flat[0].get("inttype", "") in _UC2_INTTYPES:
                    # Single CHAR-based field → treat as scalar CHAR
                    exid = "C"
                    tabname = resolved_tabname
            nuc_il = _nuc_intlength(exid, p["intlength"],
                                    tabname, self.ddic_catalog)
            self.logger.debug(
                "  PARAM %s/%s exid=%s tabname=%s "
                "catalog_intlength(UC)=%s params_intlength(NUC)=%s",
                p["paramclass"], p["parameter"],
                exid, tabname,
                p["intlength"], nuc_il,
            )
            row = _build_params_row(
                p["paramclass"], p["parameter"], tabname,
                p["fieldname"], exid, p["position"], nuc_il,
                p["paramtext"],
            )
            rows.append(row)

        body += _tlv(0x0203, 0x0301, utf16("PARAMS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 1))
        row_size = len(rows[0]) if rows else 404
        body += _tlv(0x0330, 0x0302, struct.pack("!II", row_size, len(rows)))

        prev = 0x0302
        for row in rows:
            body += _tlv(prev, 0x0303, row)
            prev = 0x0303

        # RESUMABLE_EXCEPTIONS table (empty)
        last = 0x0303 if rows else 0x0302
        body += _tlv(last, 0x0301, utf16("RESUMABLE_EXCEPTIONS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 2))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 62, 0))

        body += _tlv(0x0302, 0x0130, utf16("SAPLRFC1".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x40\x9d\xdf\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _build_sysinfo_response_body(self, session_id):
        """Build the RFC_SYSTEM_INFO response body with system data."""
        def utf16(s):
            return s.encode("utf-16-le")

        rfcsi = self._build_rfcsi_string()

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameter values
        body += _tlv(0x0512, 0x0201, utf16("CURRENT_RESOURCES"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 0))
        body += _tlv(0x0203, 0x0201, utf16("FAST_SER_VERS"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("MAXIMAL_RESOURCES"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("RECOMMENDED_DELAY"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("RFCSI_EXPORT"))
        body += _tlv(0x0201, 0x0203, utf16(rfcsi))
        body += _tlv(0x0203, 0x0201, utf16("S4_HANA"))
        body += _tlv(0x0201, 0x0203, utf16(" "))

        # Program name and footer
        body += _tlv(0x0203, 0x0130, utf16("SAPLSRFC".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x40\x6f\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _send_rfcgfi_response(self, raw, target_func):
        """Send RFC_GET_FUNCTION_INTERFACE response.

        Priority:
        1. RFC_SYSTEM_INFO — uses the hand-crafted sysinfo builder.
        2. Any function present in the loaded RFM catalog — uses the
           generic catalog-driven builder.
        3. Unknown function — sends a minimal generic RFC response.
        """
        session_id = _extract_session_id(raw)
        if target_func == "RFC_SYSTEM_INFO":
            body = self._build_rfcgfi_sysinfo_body(session_id)
        else:
            func_info = self.rfm_catalog.get(target_func) if target_func else None
            if func_info is not None:
                self.logger.debug(
                    "RFC_GET_FUNCTION_INTERFACE for %s: serving from catalog",
                    target_func,
                )
                body = self._build_rfcgfi_body(session_id, func_info)
            else:
                body = self._build_rfc_body()
        header = self._build_appc_header(raw, len(body))
        self.request.send(Raw(header + body))

    def _send_sysinfo_response(self, raw):
        """Send RFC_SYSTEM_INFO response with system data."""
        session_id = _extract_session_id(raw)
        body = self._build_sysinfo_response_body(session_id)
        header = self._build_appc_header(raw, len(body))
        self.request.send(Raw(header + body))

    def _extract_ddif_tabname(self, raw):
        """Extract the TABNAME import parameter from a DDIF_FIELDINFO_GET request.

        The type name is sent as a UTF-16LE 0x0203 value immediately following
        the UTF-16LE string 'TABNAME' (the 0x0201 parameter-name TLV).

        TLV layout: [prev_end:2][marker:2][length:2][data]
        For the TABNAME name TLV: marker=0x0201, data='TABNAME' in UTF-16LE.
        So at data position idx, raw[idx-4:idx-2] == b'\\x02\\x01'.

        Strategy:
          1. Prefer occurrences of 'TABNAME' that are preceded by 0x0201 —
             these are genuine parameter-name TLVs.
          2. Fall back to the first occurrence with any non-empty 0x0203 value,
             in case the marker assumption does not hold for this SDK version.
        """
        tabname_bytes = "TABNAME".encode("utf-16-le")
        search_from = 0
        first_nonempty = None   # fallback result

        while True:
            idx = raw.find(tabname_bytes, search_from)
            if idx < 0:
                break

            after_name = idx + len(tabname_bytes)
            val, _ = _extract_cpic_field_by_marker(
                raw, b"\x02\x03", after_name
            )
            if val:
                decoded = _decode_rfc_string(val)
                if decoded:
                    is_param_name = (idx >= 4 and
                                     raw[idx - 4:idx - 2] == b"\x02\x01")
                    self.logger.debug(
                        "DDIF: 'TABNAME' at idx=%d value='%s' "
                        "is_param_name=%s pre6=%s raw_len=%d",
                        idx, decoded, is_param_name,
                        raw[max(0, idx - 6):idx].hex(), len(raw),
                    )
                    if is_param_name:
                        return decoded
                    if first_nonempty is None:
                        first_nonempty = decoded

            search_from = idx + 1

        if first_nonempty:
            self.logger.debug("DDIF tabname (fallback, no 0x0201): '%s'", first_nonempty)
        return first_nonempty

    def _build_ddif_body(self, session_id, dfies_rows=None,
                         dfies_wa=None, x030l_wa=None):
        """Build a DDIF_FIELDINFO_GET response.

        When *dfies_rows* is a list of 1350-byte DFIES row blobs (produced by
        _build_dfies_row), they are embedded in the DFIES_TAB table.
        When empty / None, a zero-row response is returned.

        *dfies_wa* — optional 1350-byte DFIES row for the DFIES_WA scalar
        export (present on call #2+ from real SAP servers).

        *x030l_wa* — optional 416-byte X030L row for the X030L_WA scalar
        export (also present on call #2+ from real SAP servers).  Contains
        the authoritative NUC record length (TABLEN) that the NWRFC SDK
        validates against PARAMS.INTLENGTH.

        TLV structure reverse-engineered from captured RFCSI DDIF blobs.
        """
        def utf16(s):
            return s.encode("utf-16-le")

        rows = dfies_rows or []

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameter: DDOBJTYPE = 'INTTAB  ' (8-char padded)
        body += _tlv(0x0512, 0x0201, utf16("DDOBJTYPE"))
        body += _tlv(0x0201, 0x0203, utf16("INTTAB  "))

        # NOTE: Real SAP servers do NOT send UCLEN in DDIF_FIELDINFO_GET
        # responses.  We previously sent UCLEN=0x00 but that is not present
        # in captured blobs and may confuse the NWRFC SDK validation logic.
        # The SDK defaults appropriately when UCLEN is absent.

        # X030L_WA is sent in EVERY call (call #1 and call #2+):
        #   queryRecordMetaData packs both X030L_WA.TABLEN values into the
        #   type descriptor:
        #     metaData+0xd8 (nucSize) = call #1 X030L_WA TABLEN
        #     metaData+0xdc (ucSize)  = call #2 X030L_WA TABLEN
        #   lock() then validates:
        #     field_nuc_end > nucSize → "non-unicode length is too small"
        #     field_uc_end  > ucSize  → same error
        #   DFIES_WA and LINES_DESCR precede X030L_WA on call #2+.
        #   LINES_DESCR is required before X030L_WA in ALL calls so the SDK
        #   can parse the X030L_WA TLV marker chain (0x3c02 zone).
        prev_tab = 0x0203
        if dfies_wa is not None:
            body += _tlv(0x0203, 0x0201, utf16("DFIES_WA"))
            body += _tlv(0x0201, 0x0203, dfies_wa)
        if x030l_wa is not None:
            # LINES_DESCR block: transitions from 0x0203 → 0x3c02 marker zone.
            # Without this block the SDK cannot parse X030L_WA (TABLEN reads 0).
            body += _LINES_DESCR_BLOCK
            prev_tab = _LINES_DESCR_TRAIL_MARKER   # 0x3c02
            body += _tlv(prev_tab, 0x0201, utf16("X030L_WA"))
            body += _tlv(0x0201, 0x0203, x030l_wa)
            prev_tab = 0x0203

        # DFIES_TAB — row-width 1350 (from DFIES DDIC Unicode layout)
        # Type indicator: 3 on call #1 (no DFIES_WA);
        #                 5 on call #2+ when DFIES_WA is present.
        # Observed from captured SAP NW 7.52 RFCSI DDIF blobs.
        dfies_tab_type = 5 if dfies_wa is not None else 3
        body += _tlv(prev_tab, 0x0301, utf16("DFIES_TAB"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", dfies_tab_type))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 1350, len(rows)))

        prev = 0x0302
        for row_bytes in rows:
            body += _tlv(prev, 0x0303, row_bytes)
            prev = 0x0303

        # 0x0306 end-of-table terminator — required by the NWRFC SDK to
        # mark the end of DFIES_TAB rows.  Captured from SAP NW 7.52:
        # ...last 0x0305 row → [0x0305][0x0306][0] → [0x0306][0x0301]...
        last = 0x0303 if rows else 0x0302
        body += _tlv(last, 0x0306, b"")

        # FIXED_VALUES — 0 rows; type indicator 4, row-width 166 from captures
        body += _tlv(0x0306, 0x0301, utf16("FIXED_VALUES"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 4))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 166, 0))

        # Program name + footer (from captured DDIF1 blob)
        body += _tlv(0x0302, 0x0130, utf16("SAPLSDIFRUNTIME".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x48\x8f\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    @property
    def tabname_intlength(self):
        return getattr(self.server, "tabname_intlength", {})

    def _get_ddic_fields(self, tabname):
        """Return DFIES field list for *tabname*.

        Lookup order:
        1. ddic_catalog  — exported from SAP (most accurate)
        2. _BUILTIN_DDIC — hand-crafted entries for common types
        3. tabname_intlength index  — synthesise a single RAW field of the
           right total byte length.  Sufficient for empty / output-only
           parameters where the SDK only needs a valid descriptor, not
           individual field names.
        """
        fields = self.ddic_catalog.get(tabname)
        if fields is None:
            fields = _BUILTIN_DDIC.get(tabname)
        if fields is None:
            intlength = self.tabname_intlength.get(tabname, 0)
            if intlength > 0:
                fields = _synthetic_ddic_fields(tabname, intlength)
        return fields

    def _send_ddif_response(self, raw):
        """Send a DDIF_FIELDINFO_GET response.

        Lookup priority:
        1. RFCSI  — served from pre-captured blobs.
        2. ddic_catalog — real DFIES rows built from catalog field data.
        3. _BUILTIN_DDIC — hand-crafted rows for commonly needed structures.
        4. Unknown — zero-row response (SDK won't crash, but can't fill fields).
        """
        session_id = _extract_session_id(raw)
        tabname = self._extract_ddif_tabname(raw)

        if tabname == "RFCSI":
            client = self.server.clients.get(self.client_address)
            if client:
                client.ddif_call_count += 1
                call_num = client.ddif_call_count
            else:
                call_num = 1
            body = get_ddif_body(call_num, session_id)
            self.logger.debug("DDIF_FIELDINFO_GET for RFCSI (call #%d) from %s",
                              call_num, str(self.client_address))
        else:
            # Track per-tabname call count within this session.  The NWRFC SDK
            # calls DDIF twice for the same type.  On call #2+ we include a
            # DFIES_WA scalar export (structure-header descriptor) alongside the
            # same DFIES_TAB rows.  Real SAP servers do the same (see blob 2 vs
            # blob 1 in rfcsi_data.py).  DFIES_WA gives the SDK a single
            # authoritative total INTLEN for the structure so it does not
            # accumulate individual field INTLENs across both calls.
            client = self.server.clients.get(self.client_address)
            if client:
                if not hasattr(client, "ddif_tabname_counts"):
                    client.ddif_tabname_counts = {}
                tn_key = tabname or ""
                client.ddif_tabname_counts[tn_key] = \
                    client.ddif_tabname_counts.get(tn_key, 0) + 1
                tabname_call_num = client.ddif_tabname_counts[tn_key]
            else:
                tabname_call_num = 1

            self.logger.info(
                "DDIF '%s' (call #%d) from %s: processing request",
                tabname or "?", tabname_call_num, str(self.client_address),
            )
            fields = self._get_ddic_fields(tabname) if tabname else None
            if fields:
                # Detect partner codepage so we can send DFIES INTLEN values
                # in the encoding the NWRFC SDK expects.
                # NUC mode (Communication Codepage 1100): SDK reads INTLEN
                # directly as NUC bytes (no halving).  Send NUC values so
                # the SDK's NUC sum matches X030L_WA.TABLEN / PARAMS.INTLENGTH.
                # UC mode (Communication Codepage 4103): SDK halves CHAR
                # INTLEN internally.  Send UC values (unchanged from catalog).
                # Always send UC (catalog) INTLEN values.  UCLEN=1 tells the
                # NUC mode (Comm.CP=1100): send NUC intlen values so SDK reads
                # them directly as NUC bytes.  UCLEN=0 means no Unicode-server
                # uc>=2*nuc structure check, so RAW fields (uc==nuc) pass.
                nuc_mode = (getattr(self, "_partner_codepage", "4103") == "1100")
                # Filter out complex/reference types that the NWRFC SDK cannot
                # parse in flat DFIES rows: 'g' (STRG string-ref, intlen=8) and
                # zero-intlen placeholders (TTYP embedded tables, etc.).
                # Sort by POSITION so the cumulative DFIES offsets match the
                # real ABAP structure layout — avoids misaligned CHAR fields
                # when the catalog CSV is in non-position order.
                # Must match the filter in _nuc_intlength so PARAMS.INTLENGTH ==
                # X030L_WA.TABLEN == sum(NUC contribution from DFIES rows).
                flat_fields = sorted(
                    [
                        f for f in fields
                        if int(f.get("intlen") or 0) > 0
                        and f.get("inttype", "") != "g"
                    ],
                    key=lambda f: int(f.get("position") or 0),
                )
                if len(flat_fields) > _MAX_DDIF_ROWS:
                    intlen_total_full = sum(
                        int(f.get("intlen") or 0) for f in flat_fields
                    )
                    self.logger.info(
                        "DDIF '%s' (call #%d): %d catalog fields exceeds limit %d,"
                        " falling back to synthetic descriptor (intlen_total=%d)",
                        tabname, tabname_call_num, len(flat_fields), _MAX_DDIF_ROWS,
                        intlen_total_full,
                    )
                    flat_fields = _synthetic_ddic_fields(tabname, intlen_total_full)
                dfies_rows = _build_dfies_rows(flat_fields, nuc_mode=nuc_mode)
                intlen_total = sum(int(f.get("intlen") or 0) for f in flat_fields)
                # X030L_WA layout (from queryRecordMetaData reverse-engineering):
                #   queryRecordMetaData calls DDIF twice and packs both
                #   X030L_WA.TABLEN values at metaData+0xd8/+0xdc:
                #     +0xd8 (nucSize) = call #1 X030L_WA TABLEN
                #     +0xdc (ucSize)  = call #2 X030L_WA TABLEN
                #   lock() validates:
                #     field_nuc_end > nucSize → "non-unicode length is too small"
                #     field_uc_end  > ucSize  → same error (different message)
                #   RfcMetaDataBase::add auto-doubles uc_size for RFCTYPE_CHAR:
                #     stored_uc_size = nuc_len * 2  (ignores input uc_len for CHAR)
                #   So:
                #     nuc_total = sum(intlen//2 for CHAR, intlen for RAW)  ← NUC bytes
                #     uc_total  = sum(original UC intlen) = intlen_total   ← UC bytes
                #   Send X030L_WA in BOTH calls:
                #     call #1: TABLEN = nuc_total  → metaData+0xd8
                #     call #2: TABLEN = uc_total   → metaData+0xdc
                nuc_total = sum(
                    int(f.get("intlen") or 0) // 2
                    if f.get("inttype", "") in _UC2_INTTYPES
                    else int(f.get("intlen") or 0)
                    for f in flat_fields
                )
                uc_total = intlen_total  # sum of original UC intlens
                # Call #1: DFIES_TAB + X030L_WA(nuc_total); no DFIES_WA.
                # Call #2+: DFIES_WA + X030L_WA(uc_total) + DFIES_TAB.
                dfies_wa = None
                if tabname_call_num == 1:
                    x030l_wa = _build_x030l_wa_row(tabname, nuc_total)
                else:
                    dfies_wa = _build_dfies_wa_row()
                    x030l_wa = _build_x030l_wa_row(tabname, uc_total)
                body = self._build_ddif_body(session_id, dfies_rows,
                                             dfies_wa=dfies_wa,
                                             x030l_wa=x030l_wa)
                source = (
                    "catalog" if tabname in self.ddic_catalog
                    else "builtins" if tabname in _BUILTIN_DDIC
                    else "synthetic"
                )
                extras = ""
                if dfies_wa is not None:
                    extras += " [+DFIES_WA]"
                if x030l_wa is not None:
                    tablen = nuc_total if tabname_call_num == 1 else uc_total
                    extras += " [+X030L_WA tablen=%d]" % tablen
                skipped = len(fields) - len(flat_fields)
                self.logger.info(
                    "DDIF '%s' (call #%d): %d field(s) from %s%s, "
                    "intlen_total=%d (catalog UC; NUC in wire rows)%s",
                    tabname, tabname_call_num, len(flat_fields), source,
                    (" [%d complex skipped]" % skipped) if skipped else "",
                    intlen_total, extras,
                )
                for f in flat_fields:
                    self.logger.debug(
                        "  DFIES %s.%s: inttype=%s intlen=%s offset=%s",
                        tabname, f.get("fieldname", "?"),
                        f.get("inttype", "?"), f.get("intlen", "?"),
                        f.get("offset", "?"),
                    )
            else:
                body = self._build_ddif_body(session_id)
                self.logger.info(
                    "DDIF '%s' (call #%d): no descriptor found, returning 0 rows",
                    tabname or "?", tabname_call_num,
                )

        header = self._build_appc_header(raw, len(body))
        self.request.send(Raw(header + body))

    # -- Old-style init (F_SAP_INIT 0xca / F_SAP_ALLOCATE 0xc9) ---------

    def _handle_old_style_init(self, raw, func_type, func_name):
        """Handle F_SAP_INIT/F_SAP_ALLOCATE from older RFC clients."""
        data = {"func_type": func_name}

        try:
            rfc = SAPRFC(raw)

            sap_param = getattr(rfc, "sap_param", None)
            if sap_param and isinstance(sap_param, SAPRFCDTStruct):
                val = _strip_field(getattr(sap_param, "user", None))
                if val:
                    data["user"] = val

            sap_ext = getattr(rfc, "sap_ext_header", None)
            if sap_ext and isinstance(sap_ext, SAPRFCEXTEND):
                val = _strip_field(getattr(sap_ext, "short_dest_name", None))
                if val:
                    data["dest"] = val
        except Exception:
            pass

        self.logger.debug("%s from %s", func_name, str(self.client_address))
        self.session.add_event("APPC old-style init/allocate", data=data)

        try:
            # Respond with acceptance
            resp_func = 0x03 if func_type == 0xc9 else 0x01
            response = SAPRFC(version=0x06, func_type=resp_func, appc_rc=0x00)
            self.request.send(response)
        except error:
            pass


class SAPGatewayServerThreaded(Loggeable, SAPNIServerThreaded):

    clients_cls = SAPGatewayClient
    clients_count = 0

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=False, socket_cls=None, keep_alive=True,
                 base_cls=None):
        # base_cls=None prevents pysap from auto-decoding NI payloads as
        # SAPRFC.  pysap's SAPRFC parser crashes on F_SAP_SEND packets
        # (codepage_size2 is None → TypeError).  We parse raw bytes instead.
        SAPNIServerThreaded.__init__(self, server_address, RequestHandlerClass,
                                     bind_and_activate, socket_cls, keep_alive,
                                     base_cls=base_cls)


class SAPGatewayService(BaseTCPService):

    server_cls = SAPGatewayServerThreaded
    handler_cls = SAPGatewayServerHandler

    def setup_server(self):
        super(SAPGatewayService, self).setup_server()
        catalog_path = self.config.get("rfm_catalog")
        if catalog_path:
            self.server.rfm_catalog = load_rfm_catalog(catalog_path)
        else:
            self.server.rfm_catalog = {}

        ddic_path = self.config.get("ddic_catalog")
        if ddic_path:
            self.server.ddic_catalog = load_ddic_catalog(ddic_path)
        else:
            self.server.ddic_catalog = {}

        # Build tabname → INTLENGTH index from RFM catalog.
        # Used to synthesise single-RAW-field DFIES descriptors for structure
        # types not present in the catalog or _BUILTIN_DDIC.
        tabname_intlength = {}
        for fm_info in self.server.rfm_catalog.values():
            for p in fm_info.get("params", []):
                tn = (p.get("tabname") or "").strip()
                il = p.get("intlength", 0) or 0
                if tn and il > 0:
                    tabname_intlength[tn] = max(tabname_intlength.get(tn, 0), il)
        self.server.tabname_intlength = tabname_intlength
        self.logger.info(
            "DDIC catalog: %d types loaded; tabname index: %d entries "
            "[RFCPARAM.INTLENGTH: converted to non-unicode via _nuc_intlength]",
            len(self.server.ddic_catalog),
            len(tabname_intlength),
        )
