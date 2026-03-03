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

# 2-byte start-marker for password — not in pysap's cpic_padd dict.
MARKER_PASSWORD = b"\x01\x17"  # cpic_password (scrambled)

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


def _build_params_row(paramclass, parameter, tabname, fieldname, exid,
                      position, intlength, paramtext):
    """Build a single PARAMS table row (402 bytes = 201 UTF-16LE chars).

    Layout: PARAMCLASS(1) PARAMETER(30) TABNAME(30) FIELDNAME(30) EXID(1)
            POSITION(int4-LE) OFFSET(int4-LE) INTLENGTH(int4-LE)
            DECIMALS(int4-LE) PARAMTEXT(101)
    """
    text = paramclass[0]
    text += parameter.ljust(30)[:30]
    text += tabname.ljust(30)[:30]
    text += fieldname.ljust(30)[:30]
    text += exid[0]
    row = text.encode("utf-16-le")                       # 92 chars = 184 bytes
    row += struct.pack("<IIII", position, 0, intlength, 0)  # 16 bytes
    row += paramtext.ljust(101)[:101].encode("utf-16-le")   # 202 bytes
    return row                                              # total 402 bytes


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

        version = raw[0]

        if version == 0x06:
            # APPC layer — RFC function call protocol
            func_type = raw[1]
            self._handle_appc(raw, func_type)
        else:
            # Gateway layer — connection management, monitor commands
            self._handle_gateway(raw, version)

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
        try:
            resp = bytearray(raw)
            if len(resp) > 41:
                resp[41] = resp[41] | 0x30  # set CODE_PAGE + NIPING bits
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
                    if target == "RFC_SYSTEM_INFO":
                        self._send_rfcgfi_response(raw, "RFC_SYSTEM_INFO")
                    else:
                        self._send_rfc_response(raw)
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

        In the login handshake the TLV sequence is fixed, so we use full
        4-byte cpic_padd entries from pysap for reliable field extraction.
        The password field is not in pysap's cpic_padd dict, so we fall
        back to the 2-byte marker scan for that one.
        """
        # Username (cpic_username1_padd)
        val = _extract_cpic_field_by_padd(raw, CPIC_USERNAME_PADD)
        if val:
            username = val.decode("ascii", errors="replace").strip("\x00 ")
            if username:
                data["username"] = username
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].username = username

        # Client number (cpic_cli_nbr1_padd)
        val = _extract_cpic_field_by_padd(raw, CPIC_CLI_NBR_PADD)
        if val:
            cli_nbr = val.decode("ascii", errors="replace").strip("\x00 ")
            if cli_nbr:
                data["client_number"] = cli_nbr
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].client_nbr = cli_nbr

        # Password (2-byte marker \x01\x17) — SAP XOR-scrambled
        # Not in pysap's cpic_padd dict, so we use marker-based extraction.
        val, _ = _extract_cpic_field_by_marker(raw, MARKER_PASSWORD)
        if val:
            data["password_hash"] = val.hex()
            data["password"] = _descramble_rfc_password(val)

        # Client IP (cpic_ip_padd)
        val = _extract_cpic_field_by_padd(raw, CPIC_IP_PADD)
        if val:
            ip = val.decode("ascii", errors="replace").strip("\x00 ")
            if ip:
                data["client_ip"] = ip

        # Client hostname/SID/instance (cpic_host_sid_inbr_padd)
        val = _extract_cpic_field_by_padd(raw, CPIC_HOSTNAME_PADD)
        if val:
            hostname = val.decode("ascii", errors="replace").strip("\x00 ")
            if hostname:
                data["client_hostname"] = hostname

        # Destination (cpic_dest_padd)
        val = _extract_cpic_field_by_padd(raw, CPIC_DEST_PADD)
        if val:
            dest = val.decode("ascii", errors="replace").strip("\x00 ")
            if dest:
                data["destination"] = dest

        # Program / client library (cpic_program_padd)
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
        fields += _tlv(0x0106, 0x0016, utf16("1100"))
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

    # Function names the honeypot can respond to with full metadata.
    _KNOWN_TARGET_FUNCTIONS = ("RFC_SYSTEM_INFO", "DDIF_FIELDINFO_GET")

    def _extract_target_function(self, raw):
        """Extract the target function name from an RFC_GET_FUNCTION_INTERFACE
        request by searching for known function names in UTF-16LE."""
        for name in self._KNOWN_TARGET_FUNCTIONS:
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

        # PARAMS table — 6 rows describing RFC_SYSTEM_INFO's parameters
        body += _tlv(0x0203, 0x0301, utf16("PARAMS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 1))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 404, 6))

        rows = [
            _build_params_row("E", "CURRENT_RESOURCES", "SYST", "INDEX",
                              "I", 1, 4, "Currently Available Resources"),
            _build_params_row("E", "FAST_SER_VERS", "INT4", "",
                              "I", 0, 4, ""),
            _build_params_row("E", "MAXIMAL_RESOURCES", "SYST", "INDEX",
                              "I", 1, 4, "Maximum Resources Available"),
            _build_params_row("E", "RECOMMENDED_DELAY", "SYST", "INDEX",
                              "I", 1, 4, "Default Value for Delay"),
            _build_params_row("E", "RFCSI_EXPORT", "RFCSI", "",
                              "u", 0, 490, "See structure RFCSI"),
            _build_params_row("E", "S4_HANA", "CHAR1", "",
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
        """Send RFC_GET_FUNCTION_INTERFACE response for a known function."""
        session_id = _extract_session_id(raw)
        if target_func == "RFC_SYSTEM_INFO":
            body = self._build_rfcgfi_sysinfo_body(session_id)
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

    def _send_ddif_response(self, raw):
        """Send a DDIF_FIELDINFO_GET response using pre-captured data.

        The NWRFC SDK makes 3 sequential DDIF_FIELDINFO_GET calls when it
        encounters a structure-type (EXID='u') export parameter.  Each call
        returns different field metadata.  We use compressed response bodies
        captured from a real SAP NW 7.52 system, patching in the session ID.
        """
        session_id = _extract_session_id(raw)
        client = self.server.clients.get(self.client_address)
        if client:
            client.ddif_call_count += 1
            call_num = client.ddif_call_count
        else:
            call_num = 1

        body = get_ddif_body(call_num, session_id)
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
