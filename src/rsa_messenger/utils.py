import tkinter as tk
import json
from typing import Literal, Any

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

def advanced_format_seconds(seconds: int, *formats: Literal["milleniums", "centuries", "decades", "years", "months", "weeks", "days", "hours", "minutes", "seconds"], auto_detect: bool = False) -> str:
    """
    Formats seconds into a string with advanced formatting.
    Supports milleniums, centuries, decades, years, months, weeks, days, hours, minutes, and seconds.
    TODO: Improve the formatting to handle different number of days in months and years.
    TODO: Support milliseconds and microseconds.
    """
    units = {
        "milleniums": 31536000000,  # 1000 years
        "centuries": 3153600000,     # 100 years
        "decades": 315360000,        # 10 years
        "years": 31536000,           # 1 year
        "months": 2592000,           # 30 days
        "weeks": 604800,             # 1 week
        "days": 86400,               # 1 day
        "hours": 3600,               # 1 hour
        "minutes": 60,               # 1 minute
        "seconds": 1                 # 1 second
    }

    if auto_detect:
        # Automatically detect the largest unit to display
        formats: list[str] = [unit for unit in units if seconds >= units[unit]]
        if not formats:
            return '0 seconds'

    result: list[str] = []
    for unit in formats:
        if unit in units:
            value = seconds // units[unit]
            if value > 0:
                result.append(f"{value} {unit[:-1] if value == 1 else unit}")
            seconds %= units[unit]
    
    return ', '.join(result) if result else '0 seconds'

if __name__ == "__main__":
    # Test the utility functions
    print(shorten_string("This is a very long string that needs to be shortened.", start=5, end=5) == "This [44 chars...]ened.")
    print(shorten_string("Short string", start=6, end=6) == "Short string")
    print(shorten_string("1234567890", start=5, end=5) == "1234567890")
    print(shorten_string("1234567890", start=3, end=3) == "123[4 chars...]890")
    print(format_seconds(3661) == "00:01:01:01")  # 1 hour, 1 minute, 1 second
    print(advanced_format_seconds(872647642, "years", "months") == "27 years, 8 months")
    print(advanced_format_seconds(872647642, auto_detect=True) == "2 decades, 7 years, 8 months, 5 days, 2 hours, 7 minutes, 22 seconds")
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
