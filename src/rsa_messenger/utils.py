import tkinter as tk
import json
from typing import Literal, Any, overload

class JSONBytesEncoder(json.JSONEncoder):
    """Custom JSON encoder that converts bytes objects to hex strings."""
    
    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return {
                "__type__": "bytes",
                "__value__": obj.hex()
            }
        return super().default(obj)

class JSONBytesDecoder(json.JSONDecoder):
    """Custom JSON decoder that converts hex strings back to bytes objects."""
    
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)
    
    def object_hook(self, obj: dict[str, Any]) -> Any:
        if "__type__" in obj and obj["__type__"] == "bytes":
            return bytes.fromhex(obj["__value__"])
        return obj

def center_window(win: tk.Tk | tk.Toplevel) -> None:
    """Centers a tkinter window."""
    win.update_idletasks() # Update window information
    width = win.winfo_width()
    height = win.winfo_height()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    win.geometry(f'{width}x{height}+{x}+{y}')
    win.deiconify() # Ensure the window is shown

def get_center_coordinates(width: int, height: int, screen_width: int, screen_height: int) -> tuple[int, int]:
    """Calculate the center coordinates for a window."""
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    return x, y

def get_center_geometry(width: int, height: int, screen_width: int, screen_height: int) -> str:
    """Get the geometry string for centering a window."""
    x, y = get_center_coordinates(width, height, screen_width, screen_height)
    return f"{width}x{height}+{x}+{y}"

def shorten_string(string: str, start: int = 5, end: int = 5) -> str:
    """Shortens a string to a maximum length, adding '...' if it exceeds."""
    if len(string) > (start + end):
        string = f"{string[:start]}[{len(string[start:-end])} chars...]{string[-end:]}"
    return string

def format_seconds(seconds: int) -> str:
    """Formats seconds into a string of the form 'DD:HH:MM:SS'."""
    d = seconds // 86400
    h = seconds % 86400 // 3600
    m = seconds % 3600 // 60
    s = seconds % 3600 % 60
    return '{:02d}:{:02d}:{:02d}:{:02d}'.format(d, h, m, s)

# def advanced_format_seconds(seconds: int, *formats: Literal["milleniums", "centuries", "decades", "years", "months", "weeks", "days", "hours", "minutes", "seconds"], auto_detect: bool = False) -> str:
#     """
#     Formats seconds into a string with advanced formatting.
#     Supports milleniums, centuries, decades, years, months, weeks, days, hours, minutes, and seconds.
#     TODO: Introduce an option to specify the calendar system (e.g., Gregorian, Julian).
#     TODO: Add support for leap years.
#     TODO: Handle edge cases like negative seconds or zero.
#     TODO: Introduce relative year/month/day calculations.
#     TODO: Introduce relative time formatting (e.g., "in 2 days", "3 months ago").
#     TODO: Introduce regional formatting options (e.g., using commas or periods as decimal separators).
#     TODO: Add support for different languages/locales.
#     TODO: Support milliseconds and microseconds.
#     """
#     units = {
#         "milleniums": 31536000000,  # 1000 years
#         "centuries": 3153600000,     # 100 years
#         "decades": 315360000,        # 10 years
#         "years": 31536000,           # 1 year
#         "months": 2592000,           # 30 days
#         "weeks": 604800,             # 1 week
#         "days": 86400,               # 1 day
#         "hours": 3600,               # 1 hour
#         "minutes": 60,               # 1 minute
#         "seconds": 1                 # 1 second
#     }

#     if auto_detect:
#         # Automatically detect the largest unit to display
#         formats: list[str] = [unit for unit in units if seconds >= units[unit]]
#         if not formats:
#             return '0 seconds'

#     result: list[str] = []
#     for unit in formats:
#         if unit in units:
#             value = seconds // units[unit]
#             if value > 0:
#                 result.append(f"{value} {unit[:-1] if value == 1 else unit}")
#             seconds %= units[unit]
    
#     return ', '.join(result) if result else '0 seconds'

# Type overloads for format_time function
@overload
def format_time(
    seconds: float, 
    mode: Literal["basic"], 
    *formats: Literal["days", "hours", "minutes", "seconds"], 
    auto_detect: bool = False, 
    precision: int = 3
) -> str: ...

@overload
def format_time(
    seconds: float, 
    mode: Literal["advanced"], 
    *formats: Literal["millenniums", "centuries", "decades", "years", "months", "weeks", "days", "hours", "minutes", "seconds"], 
    auto_detect: bool = False, 
    precision: int = 3
) -> str: ...

@overload
def format_time(
    seconds: float, 
    mode: Literal["esoteric"], 
    *formats: Literal[
        "quettaseconds", "ronnaseconds", "yottaseconds", "zettaseconds", "exaseconds",
        "kalpas", "eons", "galactic years", "petaseconds", "megaannums", "teraseconds",
        "gigaseconds", "jubilees", "indictions", "lustrums", "olympiads", "ages",
        "leap years", "sidereal years", "Gregorian years", "tropical years", "common years", "lunar years",
        "semesters", "hectodays", "quarantines", "lunar months", "fortnights", "megaseconds", "decadays",
        "decidays", "kiloseconds", "centidays", "moments", "millidays", "hectoseconds", "decaseconds",
        "deciseconds", "jiffy electronics", "centiseconds", "milliseconds", "microseconds", "shakes",
        "nanoseconds", "picoseconds", "svedbergs", "femtoseconds", "atomic time", "attoseconds",
        "zeptoseconds", "jiffy physics", "yoctoseconds", "rontoseconds", "quectoseconds", "planck time"
    ], 
    auto_detect: bool = False, 
    precision: int = 3
) -> str: ...

@overload
def format_time(
    seconds: float, 
    mode: Literal["all"], 
    *formats: Literal[
        "quettaseconds", "ronnaseconds", "yottaseconds", "zettaseconds", "exaseconds",
        "kalpas", "eons", "galactic years", "petaseconds", "megaannums", "teraseconds",
        "gigaseconds", "jubilees", "indictions", "lustrums", "olympiads", "ages",
        "leap years", "sidereal years", "Gregorian years", "tropical years", "common years", "lunar years",
        "semesters", "hectodays", "quarantines", "lunar months", "fortnights", "megaseconds", "decadays",
        "decidays", "kiloseconds", "centidays", "moments", "millidays", "hectoseconds", "decaseconds",
        "deciseconds", "jiffy electronics", "centiseconds", "milliseconds", "microseconds", "shakes",
        "nanoseconds", "picoseconds", "svedbergs", "femtoseconds", "atomic time", "attoseconds",
        "zeptoseconds", "jiffy physics", "yoctoseconds", "rontoseconds", "quectoseconds", "planck time"
    ],
    auto_detect: bool = False, 
    precision: int = 3
) -> str: ...

def format_time(seconds: float, mode: Literal["basic", "advanced", "esoteric", "all"] = "basic", *formats: str, auto_detect: bool = False, precision: int = 3) -> str:
    """
    Unified time formatting function with different modes.
    
    Args:
        seconds: Time value in seconds
        mode: Formatting mode - "basic", "advanced", "esoteric", or "all"
        *formats: Specific units to include (when not using auto_detect)
        auto_detect: Automatically select appropriate units
        precision: Decimal precision for small values
    """
    
    # Define all available units
    all_units: dict[str, int | float] = {
        # Extremely large scale
        "quettaseconds": 1e30,
        "ronnaseconds": 1e27,
        "yottaseconds": 1e24,
        "zettaseconds": 1e21,
        "exaseconds": 1e18,
        
        # Cosmic/geological scale
        "kalpas": 4.32e9 * 31536000,        # 4.32 billion years
        "eons": 1e9 * 31536000,             # 1 billion years
        "galactic years": 2.3e8 * 31536000, # 230 million years
        "petaseconds": 1e15,
        "megaannums": 1e6 * 31536000,       # 1 million years
        "teraseconds": 1e12,
        
        # Historical scale
        "millenniums": 31536000000,          # 1000 years
        "centuries": 3153600000,             # 100 years
        "gigaseconds": 1e9,
        "jubilees": 50 * 31536000,           # 50 years
        "indictions": 15 * 31536000,         # 15 years
        "decades": 315360000,                # 10 years
        "lustrums": 5 * 31536000,            # 5 years
        "olympiads": 4 * 31536000,           # 4 years
        "ages": (2 + 148/365.25) * 31536000, # ~2.4 years
        
        # Year variations
        "leap years": 366 * 86400,
        "sidereal years": 365.25636 * 86400,
        "Gregorian years": 365.2425 * 86400,
        "tropical years": 365.24219 * 86400,
        "common years": 365 * 86400,
        "years": 31536000,
        "lunar years": 354.37 * 86400,
        
        # Medium scale
        "semesters": 18 * 604800,            # 18 weeks
        "hectodays": 100 * 86400,            # 100 days
        "quarantines": 40 * 86400,           # 40 days
        "months": 2592000,                   # 30 days
        "lunar months": 29.5 * 86400,        # Average lunar month
        "fortnights": 1209600,               # 14 days
        "megaseconds": 1e6,
        "decadays": 10 * 86400,              # 10 days
        "weeks": 604800,                     # 7 days
        "days": 86400,
        "decidays": 8640,                    # 0.1 day
        "hours": 3600,
        "kiloseconds": 1000,
        "centidays": 864,                    # 0.01 day (ke)
        "moments": 90,                       # 1.5 minutes
        "millidays": 86.4,                   # 0.001 day
        "hectoseconds": 100,
        "minutes": 60,
        "decaseconds": 10,
        
        # Standard and sub-second scale
        "seconds": 1,
        "deciseconds": 0.1,
        "jiffy electronics": 1/60,          # ~16.67 ms (60 Hz)
        "centiseconds": 0.01,
        "milliseconds": 1e-3,
        "microseconds": 1e-6,
        "shakes": 1e-8,                     # 10 nanoseconds
        "nanoseconds": 1e-9,
        "picoseconds": 1e-12,
        "svedbergs": 1e-13,                 # 100 femtoseconds
        "femtoseconds": 1e-15,
        "atomic time": 2.42e-17,            # Atomic theory of hydrogen
        "attoseconds": 1e-18,
        "zeptoseconds": 1e-21,
        "jiffy physics": 3e-24,             # Light travel time over one fermi
        "yoctoseconds": 1e-24,
        "rontoseconds": 1e-27,
        "quectoseconds": 1e-30,
        "planck time": 5.39e-44,
        
        # Legacy units for backward compatibility
        "gigaannums": 3.154e16,
        "ke": 864,
        "jiffys": 1/60,
        "milleniums": 31536000000,
    }
    
    # Select units based on mode
    mode_units = {
        "basic": ["days", "hours", "minutes", "seconds"],
        "advanced": ["millenniums", "centuries", "decades", "years", "months", "weeks", "days", "hours", "minutes", "seconds"],
        "esoteric": [
            "quettaseconds", "ronnaseconds", "yottaseconds", "zettaseconds", "exaseconds",
            "kalpas", "eons", "galactic years", "petaseconds", "megaannums", "teraseconds",
            "gigaseconds", "jubilees", "indictions", "lustrums", "olympiads", "ages",
            "leap years", "sidereal years", "Gregorian years", "tropical years", "common years", "lunar years",
            "semesters", "hectodays", "quarantines", "lunar months", "fortnights", "megaseconds", "decadays",
            "decidays", "kiloseconds", "centidays", "moments", "millidays", "hectoseconds", "decaseconds",
            "deciseconds", "jiffy electronics", "centiseconds", "milliseconds", "microseconds", "shakes",
            "nanoseconds", "picoseconds", "svedbergs", "femtoseconds", "atomic time", "attoseconds",
            "zeptoseconds", "jiffy physics", "yoctoseconds", "rontoseconds", "quectoseconds", "planck time"
        ],
        "all": list(all_units.keys())
    }
    
    # Get available units for the mode
    available_units = {k: v for k, v in all_units.items() if k in mode_units[mode]}
    sorted_units = sorted(available_units.items(), key=lambda x: x[1], reverse=True)
    
    # Determine which formats to use
    if auto_detect:
        formats_to_use = [unit for unit, value in sorted_units if seconds >= value]
        if not formats_to_use and seconds > 0:
            # Find the most appropriate small unit
            formats_to_use = [sorted_units[-1][0]]  # Use smallest available unit
    else:
        formats_to_use = [f for f in formats if f in available_units]
    
    if not formats_to_use:
        return "0 seconds"
    
    # Format the result
    result: list[str] = []
    remaining = seconds
    
    for unit in [u for u, _ in sorted_units if u in formats_to_use]:
        value = available_units[unit]
        if remaining >= value:
            count = remaining // value
            if count >= 1:
                result.append(f"{int(count)} {unit[:-1] if (count == 1 and unit.endswith("s")) else unit}")
                remaining %= value
    
    # Handle fractional remainders for very small values
    if not result and remaining > 0:
        for unit in [u for u, _ in sorted_units if u in formats_to_use]:
            value = available_units[unit]
            count = remaining / value
            result.append(f"{count:.{precision}g} {unit[:-1] if (abs(count - 1) < 1e-10 and unit.endswith('s') and unit not in ['seconds']) else unit}")
            break
    
    return ', '.join(result) if result else "0 seconds"

if __name__ == "__main__":
    # Test the utility functions
    print(shorten_string("This is a very long string that needs to be shortened.", start=5, end=5) == "This [44 chars...]ened.")
    print(shorten_string("Short string", start=6, end=6) == "Short string")
    print(shorten_string("1234567890", start=5, end=5) == "1234567890")
    print(shorten_string("1234567890", start=3, end=3) == "123[4 chars...]890")
    
    # Test time formatting
    print(format_seconds(3661) == "00:01:01:01")  # 1 hour, 1 minute, 1 second
    print(format_time(872647642, "advanced", "years", "months") == "27 years, 8 months")
    print(format_time(872647642, "advanced", auto_detect=True) == "2 decades, 7 years, 8 months, 5 days, 2 hours, 7 minutes, 22 seconds")

    # Test new comprehensive esoteric formatting
    print(
        format_time(9*10**15, "esoteric", auto_detect=True) == 
        "1 galactic year, 1 petasecond, 23 megaannums, 21 teraseconds, 248 jubilees, "
        "2 indictions, 2 quarantines, 70 decidays, 3 kiloseconds, 2 hectoseconds"
    )
    print(format_time(5.39e-44, "esoteric", auto_detect=True) == "1 planck time")  # Planck time
    print(format_time(1e30, "esoteric", auto_detect=True) == "1 quettasecond")     # Quettaseconds
    print(format_time(123.456, "esoteric", "moments", "millidays", "jiffy electronics") == "1 moment, 2007 jiffy electronics")
    
    # Test JSON encoding/decoding
    test_data: dict[str, Any] = {
        "to": "alice",
        "message": [
            b'\x01\x23\x45\x67\x89\xab\xcd\xef',
            b'\xfe\xdc\xba\x98\x76\x54\x32\x10',
            b'\x00\x11\x22\x33\x44\x55\x66\x77'
        ]
    }
    json_str = json.dumps(test_data, cls=JSONBytesEncoder)
    decoded_data = json.loads(json_str, cls=JSONBytesDecoder)
    print(test_data == decoded_data)
