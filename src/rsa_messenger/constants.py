import enum

class MessageType(enum.IntEnum):
    SEND_COUNTRY = enum.auto()
    SEND_PROFILE = enum.auto()
    SEND_PUBLIC_KEY = enum.auto()
    SEND_MESSAGE = enum.auto()
    APPROVE_USER = enum.auto()
    BROADCAST_USER = enum.auto()
    BROADCAST_UPDATED_USER = enum.auto()
    ASK_NEW_NAME = enum.auto()
    GET_MESSAGE = enum.auto()
    SEND_READY_USERS = enum.auto()

class ClientWindow(enum.Flag):
    CONNECT = enum.auto()
    WAITING = enum.auto()
    CHAT = enum.auto()
    PROFILE = enum.auto()
    SETTINGS = enum.auto()
    RSA_KEY_GENERATOR = enum.auto()
    PRIME_NUMBERS_FINDER = enum.auto()
    PRIME_FACTORIZATION = enum.auto()
    CIPHER_VIEWER = enum.auto()
    CIPHER_ATTACKER = enum.auto()
    ABOUT = enum.auto()

COUNTRY_TO_LOCALE = {
    "Germany": "de_DE",
    "United Kingdom": "en_GB",
    "United States of America": "en_US",
}


# ------------------------------------------------------
# Mappings for all 256 byte codes, based on the "Symbol"
# column from https://www.ascii-code.com/ (using Windows-1252 for extended).
# --------------------------------------------------------------------------

ASCII_CONTROL_CHARACTERS = {
    i: sym for i, sym in enumerate((
        "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL", "BS", "HT", "LF",
        "VT", "FF", "CR", "SO", "SI", "DLE", "DC1", "DC2", "DC3", "DC4", "NAK",
        "SYN", "ETB", "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS", "US"
    ))
}

ASCII_PRINTABLE_CHARACTERS = {
    i: chr(i) for i in range(0x20, 0x7f)
}

# Standard ASCII (0-127)
ASCII_7_BIT_INT_TO_CHAR = ASCII_CONTROL_CHARACTERS | ASCII_PRINTABLE_CHARACTERS | {127: "DEL"}
ASCII_7_BIT_CHAR_TO_INT = {value: key for key, value in ASCII_7_BIT_INT_TO_CHAR.items()}

# Extended ASCII (128-255)
EXTENDED_ASCII_CHARS_WINDOWS_1252 = {
    i: sym for i, sym in enumerate((
        "€", "\x81", "‚", "ƒ", "„", "…", "†", "‡", "ˆ", "‰", "Š", "‹",
        "Œ", "\x8d", "Ž", "\x8f", "\x90", "‘", "’", "“", "”", "•", "–",
        "—", "˜", "™", "š", "›", "œ", "\x9d", "ž", "Ÿ", "NBSP"
    ), start=128)
} | {
    i: chr(i) for i in range(0xa1, 0xad) 
} | {
    173: "SHY"
} | {
    i: chr(i) for i in range(0xae, 0x100)
}

EXTENDED_ASCII_CHARS_ISO_8859_1 = {
    i: chr(i) for i in range(0x80, 0xa0)
} | {
    i: chr(i) for i in range(0xa1, 0xad) 
} | {
    160: "NBSP",
    173: "SHY"
} | {
    i: chr(i) for i in range(0xae, 0x100)
}

ASCII_8_BIT_INT_TO_CHAR = ASCII_7_BIT_INT_TO_CHAR | EXTENDED_ASCII_CHARS_WINDOWS_1252
ASCII_8_BIT_CHAR_TO_INT = {value: key for key, value in ASCII_8_BIT_INT_TO_CHAR.items()}
