.. SAP Gateway service

SAP Gateway service
===================

Implementation of the SAP RFC Gateway service (``sapdp<NN>`` / port 3300+).
The gateway emulates the ABAP RFC engine: it handles CPIC/APPC connections,
responds to system-info calls (``RFC_SYSTEM_INFO``, ``RFC_GET_FUNCTION_INTERFACE``,
``DDIF_FIELDINFO_GET``), and records every credential and business function call
that arrives.


Capabilities
------------

**Credential capture**

Every ``F_INITIALIZE_CONVERSATION`` and ``F_SAP_SEND`` (login) packet is
parsed for:

- SAP logon username (cpic_username1, reliable — no size constraint)
- OS / client-side username (from ``SAPRFCDTStruct.user``, 12-byte CPI-C field;
  names longer than 11 characters will be flagged as ``os_user_truncated``)
- SAP client number (mandant)
- XOR-scrambled password (stored as hash and decoded plaintext)
- Client IP address and hostname

**Function call logging**

All incoming RFC function calls are logged. Infrastructure calls
(``RFC_PING``, ``DDIF_FIELDINFO_GET``, ``RFC_SYSTEM_INFO``,
``RFC_GET_FUNCTION_INTERFACE``) are recorded at INFO level.  Business function
calls — including any exploitation attempts — are highlighted at WARNING level.

Where the wire encoding contains XML parameter data (NWRFC SDK serialises
table and structure parameters as ASCII XML), the gateway extracts and logs
each field value inline, including nested ABAP internal table rows.

**RFM catalog-driven responses**

When a ``rfm_catalog`` CSV is configured, the gateway serves accurate
``RFC_GET_FUNCTION_INTERFACE`` responses for every function module present
in the catalog.  Calls for unknown function modules fall back to a synthetic
single-string parameter response so the NWRFC SDK can still complete the call.

**DDIC catalog-driven structure layout**

When a ``ddic_catalog`` CSV is configured, ``DDIF_FIELDINFO_GET`` responses
include the exact field layout (name, type, length, offset) exported from a
real SAP system.  The gateway handles the NWRFC SDK's two-call sequence and
synthesises correct NUC/UC size values, LINES_DESCR XML for nested internal
tables (TTYP), and suppressed sub-type registrations.

**CVE-2025-42957 detection**

Calls to ``/SLOAE/DEPLOY`` are recognised as exploitation attempts for
CVE-2025-42957 (arbitrary ABAP code injection via the Software Lifecycle
Analysis Engine).  The injected ABAP code is extracted from the ``IT_MODULE``
table parameter and logged line-by-line at WARNING level.  A dedicated session
event ``SLOAE deploy payload`` is emitted containing the target report name,
module GUID, and full ABAP source.


Configuration options
---------------------

``hostname``:

SAP application server hostname returned in system-info responses.

``sid``:

SAP System ID (e.g. ``PRD``).

``instance_number``:

Two-digit SAP instance number (e.g. ``"00"``). Used to construct the
system number in system-info responses.

``rfm_catalog``:

Path to the semicolon-delimited RFC function module catalog CSV exported
from SAP using the ``Z_HONEYSAP_EXPORT`` ABAP report (found in ``tools/``).
Required columns: ``FUNCNAME``, ``REMOTE_CALL``, ``UPDATE_TASK``,
``EXCEPTION_CLASSES``, ``SHORT_TEXT``, plus per-parameter columns
``PARAMCLASS``, ``PARAMETER``, ``TABNAME``, ``FIELDNAME``, ``EXID``,
``POSITION``, ``OFFSET``, ``INTLENGTH``, ``DECIMALS``, ``DEFAULT``,
``PARAMTEXT``, ``OPTIONAL``.

When not set, ``RFC_GET_FUNCTION_INTERFACE`` responses use a minimal
synthetic parameter layout.

``ddic_catalog``:

Path to the semicolon-delimited DDIC structure field definition CSV
exported alongside the RFM catalog by ``Z_HONEYSAP_EXPORT``.
Required columns: ``TABNAME``, ``FIELDNAME``, ``POSITION``, ``KEYFLAG``,
``DATATYPE``, ``LENG``, ``OUTPUTLEN``, ``DECIMALS``, ``INTTYPE``,
``INTLEN``, ``OFFSET``, ``OFFSET_UNI``, ``ROLLNAME``, ``REPTEXT``.

When not set, ``DDIF_FIELDINFO_GET`` responses use synthetic single-field
CHAR structures.


Catalog export
--------------

Use the ``Z_HONEYSAP_EXPORT`` ABAP report in ``tools/`` to export both
catalogs from a reference SAP system in one step.  The report writes two
files — ``honeysap_rfm.csv`` and ``honeysap_ddic.csv`` — which can be
placed in the ``data/`` directory and referenced by the profile.

Alternatively, ``tools/ztfdir_rfcint_to_spool_csv.abap`` exports the
``TFDIR`` / ``FUPARAREF`` function module catalog to a spool file for
manual extraction.


Example configuration
---------------------

.. code-block:: yaml

   service: SAPGatewayService
   alias: GatewayService
   enabled: yes
   listener_port: 3300
   listener_address: 0.0.0.0

   hostname: sapnw702
   sid: PRD
   instance_number: "00"

   # Optional: path to catalog CSVs exported with Z_HONEYSAP_EXPORT
   rfm_catalog: data/honeysap_rfm.csv
   ddic_catalog: data/honeysap_ddic.csv
