"""Source-specific EVTX ANSI metadata; never infer from analyst OS locale."""

_CODECS = frozenset("""ascii ibm866 iso-8859-1 iso-8859-2 iso-8859-3 iso-8859-4
iso-8859-5 iso-8859-6 iso-8859-7 iso-8859-8 iso-8859-10 iso-8859-13 iso-8859-14
iso-8859-15 iso-8859-16 koi8-r koi8-u mac-roman windows-874 windows-1250
windows-1251 windows-1252 windows-1253 windows-1254 windows-1255 windows-1256
windows-1257 windows-1258 mac-cyrillic utf-8 windows-949 euc-jp windows-31j
gbk gb18030 hz big5-2003 pua-mapped-binary iso-8859-8-i""".split())
_ALIASES = {"cp936": "gbk", "936": "gbk", "cp1252": "windows-1252", "1252": "windows-1252",
            "cp950": "big5-2003", "big5": "big5-2003", "cp932": "windows-31j",
            "shift-jis": "windows-31j", "cp949": "windows-949"}


def normalize_ansi_codec(value: str | None) -> str:
    if value is None:
        return "windows-1252"
    if not isinstance(value, str):
        raise ValueError("EVTX ansi_codec must name the source Windows code page")
    codec = value.strip().lower().replace("_", "-")
    codec = _ALIASES.get(codec, codec)
    if codec not in _CODECS:
        raise ValueError(f"unsupported EVTX ANSI codec: {value!r}")
    return codec
