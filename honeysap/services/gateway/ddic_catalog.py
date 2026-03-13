# HoneySAP - SAP low-interaction honeypot
#
# Loads DDIC structure field definitions exported by Z_HONEYSAP_EXPORT
# (honeysap_ddic.csv) so the gateway can look up which structure types
# are known and what their field layouts look like.
#
# CSV columns (semicolon-delimited, double-quoted, Latin-1):
#   TABNAME;FIELDNAME;POSITION;KEYFLAG;DATATYPE;LENG;OUTPUTLEN;
#   DECIMALS;INTTYPE;INTLEN;OFFSET;OFFSET_UNI;ROLLNAME;REPTEXT

import csv
import logging

logger = logging.getLogger(__name__)

# SAP INTTYPE codes for text-like fields whose UC byte length is 2× NUC.
_UC_DOUBLE_INTYPES = frozenset("CNDTG")


def load_ddic_catalog(path):
    """Load DDIC structure field definitions from the exported CSV.

    Returns a dict mapping TABNAME → list of field dicts, where each dict
    contains the keys: tabname, fieldname, position, keyflag, datatype,
    leng, outputlen, decimals, inttype, intlen, offset, offset_uni,
    rollname, reptext.

    Returns an empty dict on any I/O or parse error.
    """
    catalog = {}

    def _int(val):
        try:
            return int((val or "0").strip() or "0")
        except (ValueError, TypeError):
            return 0

    try:
        with open(path, newline="", encoding="latin-1") as fh:
            reader = csv.DictReader(fh, delimiter=";", quotechar='"', restval="")
            for row in reader:
                tabname = (row.get("TABNAME") or "").strip()
                if not tabname:
                    continue
                if tabname not in catalog:
                    catalog[tabname] = []
                inttype = (row.get("INTTYPE") or "").strip()
                leng    = _int(row.get("LENG"))
                intlen  = _int(row.get("INTLEN"))
                # Some SAP systems export NUC internal lengths (INTLEN = LENG)
                # for text-like field types instead of UC lengths (INTLEN = LENG*2).
                # Normalise to UC so gateway arithmetic is consistent everywhere.
                if inttype in _UC_DOUBLE_INTYPES and leng > 0 and intlen == leng:
                    intlen = leng * 2
                catalog[tabname].append({
                    "tabname":    tabname,
                    "fieldname":  (row.get("FIELDNAME")  or "").strip(),
                    "position":   _int(row.get("POSITION")),
                    "keyflag":    (row.get("KEYFLAG")    or "").strip(),
                    "datatype":   (row.get("DATATYPE")   or "").strip(),
                    "leng":       leng,
                    "outputlen":  _int(row.get("OUTPUTLEN")),
                    "decimals":   _int(row.get("DECIMALS")),
                    "inttype":    inttype,
                    "intlen":     intlen,
                    "offset":     _int(row.get("OFFSET")),
                    "offset_uni": _int(row.get("OFFSET_UNI")),
                    "rollname":   (row.get("ROLLNAME")   or "").strip(),
                    "reptext":    (row.get("REPTEXT")    or "").strip(),
                })
    except (OSError, csv.Error) as exc:
        logger.warning("Cannot load DDIC catalog from %s: %s", path, exc)
        return {}

    total_fields = sum(len(v) for v in catalog.values())
    logger.info("Loaded DDIC catalog: %d types, %d fields total",
                len(catalog), total_fields)
    return catalog
