import asyncio
import json
import logging
import random
import secrets
import struct
import traceback
import tkinter as tk
import tkinter.messagebox as messagebox
import tkinter.simpledialog as simpledialog
import tkinter.ttk as ttk
from typing import Any
import tkinter.font as tkFont

from .constants import *
from .crypto import *
from .translations import TRANSLATIONS
from .utils import get_center_geometry, shorten_string, JSONBytesEncoder, JSONBytesDecoder

LOGGING_FORMAT = u"%(asctime)-28s %(filename)-20s %(levelname)s: %(message)s"


logger = logging.getLogger(__name__)
logging.basicConfig(filename='client.log', level=logging.DEBUG, format=LOGGING_FORMAT, filemode="w", encoding="utf-8")


class Profile(object):
    """A class representing a user profile in the client application."""
    def __init__(self, username: str, name: str, public_key: tuple[int, int] | None = None, private_key: tuple[int, int] | None = None) -> None:
        self.username = username
        self.name = name
        self.is_approved = False
        self.has_set_up_key = False
        self.public_key: tuple[int, int] | None = public_key
        self.private_key: tuple[int, int] | None = private_key
        self.keys: dict[str, tuple[tuple[int, int], tuple[int, int]]] = {}

class ClientApp(tk.Tk):
    """The main client application window."""
    def __init__(self, loop: asyncio.AbstractEventLoop, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        self.other_clients: dict[str, Profile] = {}
        self.chats: dict[str, list[str]] = {}

        self.current_window = ClientWindow.CONNECT
        self.loop = loop

        # self.iconbitmap("icon.ico")
        self.title("Client App | Connect Page")
        self.resizable(False, False)
        self.geometry(get_center_geometry(375, 500, self.winfo_screenwidth(), self.winfo_screenheight()))
        # self.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        for widget in ("TLabel", "TButton", "TEntry"):
            for no, font_size in zip(range(1, 8), (32, 24, 18, 16, 13, 11, 8)):
                style.configure(f"h{no}.{widget}", font=("Roboto", font_size)) # type: ignore
                style.configure(f"h{no}.bold.{widget}", font=("Roboto", font_size, "bold")) # type: ignore
                style.configure(f"h{no}.italic.{widget}", font=("Roboto", font_size, "italic")) # type: ignore
                style.configure(f"h{no}.bold.italic.{widget}", font=("Roboto", font_size, "bold", "italic")) # type: ignore

        self.language = tk.StringVar(self, value="en")

        self.menubar = tk.Menu(self)
        self.language_menu = tk.Menu(self.menubar, tearoff=False)
        for name, code in (("English", "en"), ("Deutsch", "de")):
            self.language_menu.add_radiobutton(
                label=name,
                value=code,
                variable=self.language,
                command=lambda: self.update_language()
            )
        self.menubar.add_cascade(menu=self.language_menu, label="Language")
        self.config(menu=self.menubar)

        # Info labels (store references for language switching)
        self.info_labels = [
            ttk.Label(self, style="h3.TLabel"),
            ttk.Label(self, style="h4.bold.italic.TLabel"),
            ttk.Label(self, style="h5.TLabel"),
            ttk.Label(self, style="h5.TLabel", wraplength=325),
            ttk.Label(self, style="h5.TLabel", wraplength=325),
            ttk.Label(self, style="h5.TLabel", wraplength=325),
            ttk.Label(self, style="h5.TLabel", wraplength=325),
            ttk.Label(self, style="h5.TLabel", wraplength=325),
        ]
        for row, label in enumerate(self.info_labels, start=1):
            if row == 1:
                label.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=(20, 0), pady=(15, 0))
            else:
                label.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=(20, 0))
        row = len(self.info_labels) + 1

        self.country_frame = ttk.Frame(self)
        self.country_label = ttk.Label(self.country_frame, style="h5.TLabel")
        self.country = ttk.Combobox(self.country_frame, width=20, height=10, justify="left", values=("Germany", "United Kingdom", "United States of America"))
        self.country.set("Germany")
        self.country_label.grid(row=0, column=0, sticky=tk.W)
        self.country.grid(row=0, column=1, sticky=tk.W)
        self.country_frame.grid(row=row, column=0, columnspan=2, sticky=tk.W, padx=(50, 0), pady=(5, 0))

        self.host_frame = ttk.Frame(self)
        self.host_label = ttk.Label(self.host_frame, style="h5.TLabel")
        self.host_entry = PlaceholderEntry(self.host_frame, placeholder="e.g. 127.0.0.1", font=("Roboto", 11), placeholder_font=("Roboto", 11, "italic"), char_limit=15)
        self.host_label.grid(row=0, column=0, sticky=tk.W) # self.host_label.pack(side=tk.LEFT)
        self.host_entry.grid(row=0, column=1, sticky=tk.W) # self.host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.host_frame.grid(row=(row := row + 1), column=0, columnspan=2, sticky=tk.W, padx=(40, 0), pady=(5, 0))
        
        self.port_frame = ttk.Frame(self)
        self.port_label = ttk.Label(self.port_frame, style="h5.TLabel")
        self.port_entry = PlaceholderEntry(self.port_frame, placeholder="e.g. 8080", font=("Roboto", 11), placeholder_font=("Roboto", 11, "italic"), char_limit=5)
        self.port_label.grid(row=0, column=0, sticky=tk.W)
        self.port_entry.grid(row=0, column=1, sticky=tk.W)
        self.port_frame.grid(row=(row := row + 1), column=0, columnspan=2, sticky=tk.W, padx=(23, 0), pady=(5, 0))

        self.connect_button = ttk.Button(self, width=8, command=self.on_click_connect, style="h5.bold.TButton")
        self.connect_button.grid(row=(row := row + 1), column=0, sticky=tk.W, padx=(115, 0), pady=(10, 0))

        self.update_language()
        self.after(10, self.poll_asyncio) # Start polling the asyncio event loop

    
    def open_settings(self):
        ...

    def on_close(self):
        ...

    def open_prime_factorizator(self):
        win = tk.Toplevel(self)
        win.title("Prime Factorization")
        ttk.Label(win, text="Prime Factorization Tool (Coming Soon)", style="h4.TLabel").pack(padx=20, pady=20)
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def open_prime_numbers_finder(self):
        win = tk.Toplevel(self)
        win.title("Find Prime Numbers")
        win.geometry(get_center_geometry(480, 600, self.winfo_screenwidth(), self.winfo_screenheight()))

        self.current_window |= ClientWindow.PRIME_NUMBERS_FINDER
        
        menubar = tk.Menu(win)
        win.config(menu=menubar)

        self.show_step_by_step = tk.BooleanVar(value=False)

        settings_menu = tk.Menu(menubar, tearoff=False)
        settings_menu.add_checkbutton(
            label="Show step by step",
            variable=self.show_step_by_step,
        )

        menubar.add_cascade(menu=settings_menu, label="Settings")

        content = ttk.Frame(win, padding=(3,3,12,12))
        content.grid(row=0, column=0, sticky="nsew")

        self.key_generator_label = ttk.Label(content, text="Prime Numbers Finder", style="h4.TLabel")
        self.key_generator_label.grid(row=0, column=0, sticky="w")

        self.any_number_frame = ttk.Labelframe(content, text="Any number")
        self.any_number_entry = ttk.Entry(self.any_number_frame, style="h5.TEntry")
        self.any_number_copy = ttk.Button(self.any_number_frame, text="Copy", style="h6.TButton", command=lambda: self.any_number_entry.clipboard_clear() or self.any_number_entry.clipboard_append(self.any_number_entry.get()))
        self.any_number_paste = ttk.Button(self.any_number_frame, text="Paste", style="h6.TButton", command=lambda: self.any_number_entry.insert(tk.END, self.any_number_entry.clipboard_get() if self.any_number_entry.clipboard_get() else ""))
        self.any_number_clear = ttk.Button(self.any_number_frame, text="Clear", style="h6.TButton", command=lambda: self.any_number_entry.delete(0, tk.END))

        self.from_frame = ttk.Labelframe(content, text="From (lower bound)")
        self.from_entry = ttk.Entry(self.from_frame, style="h5.TEntry")
        self.from_copy = ttk.Button(self.from_frame, text="Copy", style="h6.TButton", command=lambda: self.from_entry.clipboard_clear() or self.from_entry.clipboard_append(self.from_entry.get()))
        self.from_paste = ttk.Button(self.from_frame, text="Paste", style="h6.TButton", command=lambda: self.from_entry.insert(tk.END, self.from_entry.clipboard_get() if self.from_entry.clipboard_get() else ""))
        self.from_clear = ttk.Button(self.from_frame, text="Clear", style="h6.TButton", command=lambda: self.from_entry.delete(0, tk.END))

        self.to_frame = ttk.Labelframe(content, text="To (upper bound)")
        self.to_entry = ttk.Entry(self.to_frame, style="h5.TEntry")
        self.to_copy = ttk.Button(self.to_frame, text="Copy", style="h6.TButton", command=lambda: self.to_entry.clipboard_clear() or self.to_entry.clipboard_append(self.to_entry.get()))
        self.to_paste = ttk.Button(self.to_frame, text="Paste", style="h6.TButton", command=lambda: self.to_entry.insert(tk.END, self.to_entry.clipboard_get() if self.to_entry.clipboard_get() else ""))
        self.to_clear = ttk.Button(self.to_frame, text="Clear", style="h6.TButton", command=lambda: self.to_entry.delete(0, tk.END))

        self.control_buttons_frame = ttk.Frame(content)
        self.is_it_prime_button = ttk.Button(self.control_buttons_frame, text="Is it prime?", style="h6.TButton", command=lambda: self.is_it_prime(self.any_number_entry.get()))
        self.random_button = ttk.Button(self.control_buttons_frame, text="Random", style="h6.TButton", command=lambda: self.set_random_prime(self.any_number_entry, self.from_entry.get(), self.to_entry.get()))
        self.next_prime_button = ttk.Button(self.control_buttons_frame, text="Next prime", style="h6.TButton", command=lambda: self.set_next_prime(self.any_number_entry, self.any_number_entry.get()))
        self.prev_prime_button = ttk.Button(self.control_buttons_frame, text="Previous prime", style="h6.TButton", command=lambda: self.set_prev_prime(self.any_number_entry, self.any_number_entry.get()))
    
        self.step_by_step_frame = ttk.Labelframe(content, text="Step by Step:")
        self.step_by_step_text = tk.Text(self.step_by_step_frame, height=10, wrap="word", font=("Consolas", 11))

        # Layout for any_number_frame
        self.any_number_entry.grid(row=0, column=0, sticky="ew")
        self.any_number_copy.grid(row=0, column=1, sticky="ew")
        self.any_number_paste.grid(row=0, column=2, sticky="ew")
        self.any_number_clear.grid(row=0, column=3, sticky="ew")
        self.any_number_frame.grid(row=1, column=0, columnspan=4, sticky="ew")

        # Layout for from_frame
        self.from_entry.grid(row=0, column=0, sticky="ew")
        self.from_copy.grid(row=0, column=1, sticky="ew")
        self.from_paste.grid(row=0, column=2, sticky="ew")
        self.from_clear.grid(row=0, column=3, sticky="ew")
        self.from_frame.grid(row=2, column=0, columnspan=4, sticky="ew")

        # Layout for to_frame
        self.to_entry.grid(row=0, column=0, sticky="ew")
        self.to_copy.grid(row=0, column=1, sticky="ew")
        self.to_paste.grid(row=0, column=2, sticky="ew")
        self.to_clear.grid(row=0, column=3, sticky="ew")
        self.to_frame.grid(row=3, column=0, columnspan=4, sticky="ew")

        # Layout for buttons
        self.is_it_prime_button.grid(row=0, column=0, sticky="ew")
        self.random_button.grid(row=0, column=1, sticky="ew")
        self.next_prime_button.grid(row=0, column=2, sticky="ew")
        self.prev_prime_button.grid(row=0, column=3, sticky="ew")
        self.control_buttons_frame.grid(row=4, column=0, columnspan=4, sticky="ew")

        # Layout for step by step frame
        self.step_by_step_text.grid(row=0, column=0, sticky="nsew")
        self.step_by_step_frame.grid(row=5, column=0, columnspan=4, sticky="nsew")

        # Configure grid weights for resizing
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        self.any_number_frame.columnconfigure(0, weight=1)

        self.from_frame.columnconfigure(0, weight=1)

        self.to_frame.columnconfigure(0, weight=1)

        self.control_buttons_frame.columnconfigure(0, weight=1)
        self.control_buttons_frame.columnconfigure(1, weight=1)
        self.control_buttons_frame.columnconfigure(2, weight=1)
        self.control_buttons_frame.columnconfigure(3, weight=1)

        content.columnconfigure(0, weight=1)
        content.rowconfigure(5, weight=1)

        self.step_by_step_frame.rowconfigure(0, weight=1)
        self.step_by_step_frame.columnconfigure(0, weight=1)


    def open_rsa_key_generator(self):
        # TODO: "Show" button for the already existing keys in the manager.
        win = tk.Toplevel(self)
        win.title("RSA Key Generator")
        win.geometry(get_center_geometry(480, 600, self.winfo_screenwidth(), self.winfo_screenheight()))

        self.current_window |= ClientWindow.RSA_KEY_GENERATOR

        menubar = tk.Menu(win)
        win.config(menu=menubar)

        self.perform_security_checks = tk.BooleanVar(value=True)
        self.show_step_by_step = tk.BooleanVar(value=False)
        self.key_format = tk.StringVar(value="Plain/Raw")
        self.last_public_key = self.last_private_key = None

        settings_menu = tk.Menu(menubar, tearoff=False)
        settings_menu.add_checkbutton(
            label="Perform security checks",
            variable=self.perform_security_checks,
        )
        settings_menu.add_checkbutton(
            label="Show step by step",
            variable=self.show_step_by_step,
        )
        key_format_menu = tk.Menu(settings_menu, tearoff=False)
        for f in ("PEM", "Plain/Raw"):
            key_format_menu.add_radiobutton(
                label=f,
                value=f,
                variable=self.key_format,
            )
        settings_menu.add_separator()
        settings_menu.add_cascade(label="Key Format", menu=key_format_menu)
        menubar.add_cascade(menu=settings_menu, label="Settings")

        content = ttk.Frame(win, padding=(3,3,12,12))
        content.grid(row=0, column=0, sticky=tk.NSEW)

        self.key_generator_label = ttk.Label(content, text="RSA Key Generator", style="h4.TLabel")
        self.key_generator_label.grid(row=0, column=0, sticky=tk.W)

        self.first_prime_frame = ttk.Labelframe(content, text="First Prime Number:")
        self.first_prime_entry = ttk.Entry(self.first_prime_frame, style="h5.TEntry")
        self.first_random_button = ttk.Button(self.first_prime_frame, text="Random", style="h6.TButton", command=lambda: self.set_random_prime(self.first_prime_entry))
        self.first_prime_entry.grid(row=0, column=0, sticky=tk.W)
        self.first_random_button.grid(row=0, column=1, sticky=tk.W)
        self.first_prime_frame.grid(row=1, column=0, sticky=tk.SW)

        self.second_prime_frame = ttk.Labelframe(content, text="Second Prime Number:")
        self.second_prime_entry = ttk.Entry(self.second_prime_frame, style="h5.TEntry")
        self.second_random_button = ttk.Button(self.second_prime_frame, text="Random", style="h6.TButton", command=lambda: self.set_random_prime(self.second_prime_entry))
        self.second_prime_entry.grid(row=0, column=0, sticky=tk.W)
        self.second_random_button.grid(row=0, column=1, sticky=tk.W)
        self.second_prime_frame.grid(row=2, column=0, sticky=tk.W)

        self.key_manager_frame = ttk.Labelframe(content, text="Key Manager:")
        self.key_manager_listbox = ScrollableListboxFrame(self.key_manager_frame)
        if self.profile:
            for key_name in self.profile.keys.keys():
                self.key_manager_listbox.listbox.insert(tk.END, key_name)
        self.key_manager_listbox.listbox.config(selectmode="browse")
        # TODO: Show button that should print the selected key in `self.public_key_text` and `self.private_key_text`
        # TODO: Buttons to temporarily hide and show the private key (should be enabled by default? with some action required?)
        self.key_manager_generate_button = ttk.Button(self.key_manager_frame, text="Generate", style="h6.TButton", command=self.generate_rsa_keys)
        self.key_manager_save_button = ttk.Button(self.key_manager_frame, text="Save", style="h6.TButton", command=lambda: self.save_rsa_keys(win))
        self.key_manager_use_button = ttk.Button(self.key_manager_frame, text="Use", style="h6.TButton", command=lambda: self.use_rsa_keys(win))
        self.key_manager_remove_button = ttk.Button(self.key_manager_frame, text="Remove", style="h6.TButton", command=self.remove_rsa_keys)
        self.key_manager_listbox.grid(row=0, column=0, rowspan=4, sticky=tk.NSEW)
        self.key_manager_generate_button.grid(row=0, column=1, sticky=tk.W)
        self.key_manager_save_button.grid(row=1, column=1, sticky=tk.W)
        self.key_manager_use_button.grid(row=2, column=1, sticky=tk.W)
        self.key_manager_remove_button.grid(row=3, column=1, sticky=tk.W)
        self.key_manager_frame.grid(row=0, column=1, rowspan=3, sticky=tk.W)

        self.public_key_frame = ttk.Labelframe(content, text="Public Key:")
        self.public_key_text = tk.Text(self.public_key_frame, height=10, wrap="word", font=("Consolas", 11))
        self.public_key_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.public_key_frame.grid(row=3, column=0, columnspan=3, sticky=tk.NSEW)

        self.private_key_frame = ttk.Labelframe(content, text="Private Key:")
        self.private_key_text = tk.Text(self.private_key_frame, height=10, wrap="word", font=("Consolas", 11))
        self.private_key_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.private_key_frame.grid(row=4, column=0, columnspan=3, sticky=tk.NSEW)

        self.step_by_step_frame = ttk.Labelframe(content, text="Step by Step:")
        self.step_by_step_text = tk.Text(self.step_by_step_frame, height=10, wrap="word", font=("Consolas", 11))
        self.step_by_step_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.step_by_step_frame.grid(row=5, column=0, columnspan=3, sticky=tk.NSEW)

        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)
        content.columnconfigure(2, weight=1)
        content.rowconfigure(3, weight=1)
        content.rowconfigure(4, weight=1)
        content.rowconfigure(5, weight=1)
        self.public_key_frame.rowconfigure(0, weight=1)
        self.public_key_frame.columnconfigure(0, weight=1)
        self.private_key_frame.rowconfigure(0, weight=1)
        self.private_key_frame.columnconfigure(0, weight=1)
        self.step_by_step_frame.rowconfigure(0, weight=1)
        self.step_by_step_frame.columnconfigure(0, weight=1)

    def open_cipher_viewer(self):
        """Open the Cipher Viewer window."""
        win = tk.Toplevel(self)
        win.title("Cipher Viewer")
        win.geometry(get_center_geometry(1000, 600, self.winfo_screenwidth(), self.winfo_screenheight()))
        
        self.current_window |= ClientWindow.CIPHER_VIEWER

        menubar = tk.Menu(win)
        win.config(menu=menubar)

        # TODO: Add an option to disable automatic updates of the treeviews or highlighting.
        # TODO: Add an option to update the saved personal keys and other users' keys.
        # TODO: Remake the key selection menu to use a combobox instead of a radiobutton menu.
        self.ignore_encoding_errors = tk.BooleanVar(value=False)
        self.use_chunking = tk.BooleanVar(value=True)
        self.current_format = tk.StringVar(value="Unicode")
        self.current_view = tk.StringVar(value="Input")
        self.selected_key_identity = tk.StringVar(value="current_session_key") # Holds the ID of the selected key
        self.output_display_format = tk.StringVar(value="Hex")
        self.input_string = tk.StringVar()

        settings_menu = tk.Menu(menubar, tearoff=False)
        settings_menu.add_checkbutton(
            label="Use chunked encryption/decryption",
            variable=self.use_chunking,
        )
        settings_menu.add_checkbutton(
            label="Ignore encoding errors",
            variable=self.ignore_encoding_errors,
        )
        settings_menu.add_separator()

        output_format_menu = tk.Menu(settings_menu, tearoff=False)
        output_format_menu.add_radiobutton(
            label="Hex (Reversible)",
            value="Hex",
            variable=self.output_display_format,
        )
        output_format_menu.add_radiobutton(
            label="Raw (Display Only)",
            value="Raw",
            variable=self.output_display_format,
        )
        settings_menu.add_cascade(label="Output Format", menu=output_format_menu)
        settings_menu.add_separator()

        key_menu = tk.Menu(settings_menu, tearoff=False)
        
        key_menu.add_radiobutton(
            label="Current session key",
            value="current_session_key", # A unique identifier
            variable=self.selected_key_identity,
        )
        key_menu.add_separator()

        personal_keys_menu = tk.Menu(key_menu, tearoff=False)
        if getattr(self, "profile", None) and self.profile.keys:
            for key_name in self.profile.keys.keys():
                personal_keys_menu.add_radiobutton(
                    label=shorten_string(key_name, 20),
                    value=f"personal_key_{key_name}", # The key name is the unique identifier
                    variable=self.selected_key_identity,
                )
            key_menu.add_cascade(label="My saved keys", menu=personal_keys_menu)
        else:
            key_menu.add_cascade(label="My saved keys", menu=personal_keys_menu, state="disabled")

        other_user_keys_menu = tk.Menu(key_menu, tearoff=False)
        other_users_with_keys = [p for p in self.other_clients.values() if p.username != self.profile.username and p.public_key]
        if other_users_with_keys:
            for profile in other_users_with_keys:
                other_user_keys_menu.add_radiobutton(
                    label=shorten_string(profile.username, 20),
                    value=f"other_user_key_{profile.username}", # The username is the unique identifier
                    variable=self.selected_key_identity,
                )
            key_menu.add_cascade(label="Other users' public keys", menu=other_user_keys_menu)
        else:
            key_menu.add_cascade(label="Other users' public keys", menu=other_user_keys_menu, state="disabled")

        format_menu = tk.Menu(settings_menu, tearoff=False)
        
        for mode in ("Unicode", "ASCII", "Extended ASCII", "HEX", "BIN", "DEC"):
            format_menu.add_radiobutton(
                label=mode,
                value=mode,
                variable=self.current_format,
                command=lambda: on_format_change()
            )
        
        settings_menu.add_cascade(label="Select Key", menu=key_menu)
        settings_menu.add_cascade(label="Select Format", menu=format_menu)
        menubar.add_cascade(menu=settings_menu, label="Settings")

        content = ttk.Frame(win, padding=(3,3,12,12))
        content.grid(row=0, column=0, sticky=tk.NSEW)

        self.cipher_viewer_label = ttk.Label(content, text="Cipher Viewer", style="h4.TLabel")
        self.cipher_viewer_label.grid(row=0, column=0, sticky=tk.W)

        self._syncing_selection = False
        self._syncing_yview = False
        self._handling_text_change = False
        self._last_input_text = ""
        self._last_format = self.current_format.get()
        self._previous_highlights: set[tuple[int, int]] = set()


        # ---------------- DEBUG ---------------------
        public_key, private_key = rsa_generate_keys(rand_prime(3, 2**16), rand_prime(3, 2**16)) # type: ignore
        self.profile = Profile(
            username="test_user",
            name="Test User",
            public_key=public_key,
            private_key=private_key
        )
        # -----------------------------------------------

        # Create a style for the format treeview
        style = ttk.Style()
        style.configure("Format.Treeview", font=("Consolas", 8))

        def synchronize_treeview_selection(event: tk.EventType, treeview: ttk.Treeview):
            if self._syncing_selection:
                return
            self._syncing_selection = True
            try:
                selected_items = treeview.selection()
                if not selected_items:
                    return

                # --- Sync Treeview -> Other Treeview ---
                other_treeview = self.format_treeview if treeview == self.address_treeview else self.address_treeview
                if set(other_treeview.selection()) != set(selected_items):
                    other_treeview.selection_set(selected_items)
                    other_treeview.see(selected_items[-1])

                # --- Sync Treeview -> Text Widget ---
                self.input_text.tag_remove("highlight", "1.0", tk.END)
                
                # Calculate the full text range to select
                start_offset_str = self.address_treeview.item(selected_items[0], 'values')[0]
                end_offset_str = self.address_treeview.item(selected_items[-1], 'values')[0]
                
                try:
                    start_char = int(start_offset_str, 16) - 16
                    end_char = int(end_offset_str, 16)
                    
                    start_index = f"1.0 + {start_char} chars"
                    end_index = f"1.0 + {end_char} chars"
                    
                    self.input_text.tag_add("highlight", start_index, end_index)
                except (ValueError, tk.TclError):
                    pass # Ignore errors if conversion or indexing fails
            finally:
                self._syncing_selection = False

        def sync_yview(*args: Any):
            if self._syncing_yview:
                return
            self._syncing_yview = True
            try:
                # If called from the scrollbar (moveto/scroll), propagate to both
                if args and args[0] in ("moveto", "scroll"):
                    self.address_treeview.yview(*args)
                    self.format_treeview.yview(*args)
                # If called from the widget (yscrollcommand), update both scrollbars
                else:
                    self.address_treeview_frame.vscrollbar.set(*args)
                    self.format_treeview_frame.vscrollbar.set(*args)
                    self.address_treeview.yview("moveto", args[0])
                    self.format_treeview.yview("moveto", args[0])
            finally:
                self._syncing_yview = False

        self.address_labelframe = ttk.Labelframe(content, text="Address")
        self.address_treeview_frame = ScrollableTreeviewFrame(self.address_labelframe, height=10)
        self.address_treeview_frame.treeview.config(columns=("Offset"), show="headings")
        self.address_treeview = self.address_treeview_frame.treeview
        self.address_treeview.bind("<<TreeviewSelect>>", lambda event: synchronize_treeview_selection(event, self.address_treeview))
        self.address_treeview.heading("Offset", text="Offset")
        self.address_treeview.column("Offset", width=50) # stretch=tk.NO
        self.address_treeview_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.address_labelframe.grid(row=1, column=0, rowspan=2, sticky=tk.NSEW)

        self.format_labelframe = ttk.Labelframe(content, text=self.current_format.get())
        self.format_treeview_frame = ScrollableTreeviewFrame(self.format_labelframe, height=10)
        self.format_treeview = self.format_treeview_frame.treeview
        self.format_treeview.bind("<<TreeviewSelect>>", lambda event: synchronize_treeview_selection(event, self.format_treeview))
        self.format_treeview.config(
            columns=("00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F"),
            show="headings",
            style="Format.Treeview",
        )
        for col in self.format_treeview["columns"]:
            self.format_treeview.heading(col, text=col)
            self.format_treeview.column(col, width=39, stretch=tk.NO, anchor="center")
        self.format_treeview.column("#0", width=0, stretch=tk.NO)
        self.format_treeview_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.format_labelframe.grid(row=1, column=1, rowspan=2, sticky=tk.NSEW)

        # Set the yscrollcommand for both treeviews to the sync function
        self.address_treeview.config(yscrollcommand=lambda *args: sync_yview(*args))
        self.format_treeview.config(yscrollcommand=lambda *args: sync_yview(*args))

        # Also, set the scrollbars to control both treeviews
        self.address_treeview_frame.vscrollbar.config(command=lambda *args: sync_yview(*args))
        self.format_treeview_frame.vscrollbar.config(command=lambda *args: sync_yview(*args))

        def _update_highlighting():
            """
            The single source of truth for synchronizing the Text widget's
            cursor and selection state TO the treeviews.
            """
            if self._syncing_selection:
                return

            self._syncing_selection = True
            try:
                info = self.input_text.get_cursor_info()
                children = self.format_treeview.get_children()
                
                clear_previous_highlights(children)
                if not children:
                    return

                if info['selection']:
                    # --- SELECTION HIGHLIGHTING ---
                    select_from, select_to = info["selection"]
                    cursor_position = info["position"]
                    
                    try:
                        count_cursor = self.input_text.count("1.0", cursor_position, "chars")
                        char_distance_cursor = count_cursor[0] if count_cursor else 0
                        count_from = self.input_text.count("1.0", select_from, "chars")
                        char_distance_from = count_from[0] if count_from else 0
                        count_to = self.input_text.count("1.0", select_to, "chars")
                        char_distance_to = count_to[0] if count_to else 0
                    except (IndexError, tk.TclError):
                        return

                    treeview_selection = []
                    for char_distance in range(char_distance_from, char_distance_to):
                        row = char_distance // 16
                        col = char_distance % 16
                        if row >= len(children): continue

                        item = children[row]
                        if item not in treeview_selection:
                            treeview_selection.append(item)

                        values = list(self.format_treeview.item(item, "values"))
                        if col < len(values) and values[col]:
                            values[col] = f"▶{values[col].lstrip('▶')}"
                            self.format_treeview.item(item, values=values)
                            self._previous_highlights.add((row, col))
                    
                    if treeview_selection:
                        self.address_treeview.selection_set(treeview_selection)
                        self.format_treeview.selection_set(treeview_selection)
                        item_to_see = children[min(len(children) - 1, char_distance_cursor // 16)]
                        self.address_treeview.see(item_to_see)
                        self.format_treeview.see(item_to_see)

                else:
                    # --- CURSOR-ONLY HIGHLIGHTING ---
                    try:
                        cursor_position = info["position"]
                        count = self.input_text.count("1.0", cursor_position, "chars")
                        char_distance = count[0] if count else 0
                        
                        row = char_distance // 16
                        col = char_distance % 16
                        if row >= len(children): return

                        item = children[row]
                        values = list(self.format_treeview.item(item, "values"))
                        if col < len(values) and values[col]:
                            values[col] = f"▶{values[col]}"
                            self.format_treeview.item(item, values=values)
                            self._previous_highlights.add((row, col))

                        self.address_treeview.selection_set(item)
                        self.format_treeview.selection_set(item)
                        self.address_treeview.see(item)
                        self.format_treeview.see(item)
                    except (tk.TclError, ValueError, IndexError):
                        pass
            finally:
                self._syncing_selection = False

        def _format_code_for_display(value: int) -> str:
            """Format an integer value for display based on current mode."""
            # FIXME: HEX should show only 2 characters, BIN should show 8 characters, DEC should show at least 3 characters.
            mode = self.current_format.get()
            if mode == "Unicode":
                return chr(value) if 0 <= value <= 0x10ffff else "NaN"
            elif mode == "ASCII":
                return ASCII_7_BIT_INT_TO_CHAR.get(value, "NaN")
            elif mode == "Extended ASCII":
                return ASCII_8_BIT_INT_TO_CHAR.get(value, "NaN")
            elif mode == "HEX":
                return f"{value:02X}"
            elif mode == "BIN":
                return f"{value:08b}"
            elif mode == "DEC":
                return f"{value:d}"
            return "NaN"

        def on_format_change():
            """Callback for when the format changes."""
            # TODO: See FIXME in _format_code_for_display.
            if self.current_format.get() != self._last_format:
                column_width = 65 if self.current_format.get() == "BIN" else 39
                for header in self.format_treeview['columns']:
                    self.format_treeview.column(header, width=column_width, stretch=tk.NO, anchor="center")
                on_text_change(None)
                _update_highlighting()

        def on_text_change(event):
            """Callback for when text is inserted or deleted. Optimized."""
            if self._handling_text_change:
                return
            self._handling_text_change = True
            try:
                new_text = self.input_text.get("1.0", "end-1c") # Get text without trailing newline
                old_text = self._last_input_text

                # Handle a full rebuild, which is necessary for format changes.
                if self._last_format != (format_name := self.current_format.get()):
                    self.format_labelframe.configure(text=format_name)
                    
                    # Clear BOTH treeviews to ensure they are in sync
                    self.address_treeview.delete(*self.address_treeview.get_children())
                    self.format_treeview.delete(*self.format_treeview.get_children())

                    # Rebuild BOTH treeviews from scratch with the new format
                    if new_text:
                        for offset in range(0, len(new_text), 16):
                            row_text = new_text[offset:offset+16]
                            
                            format_values = list(_format_code_for_display(ord(char)) for char in row_text)
                            format_values.extend([''] * (16 - len(format_values)))

                            self.address_treeview.insert("", tk.END, values=(f"{offset+16:08x}",))
                            self.format_treeview.insert("", tk.END, values=tuple(format_values))

                    self._last_format = format_name
                    # We must return here. The on_format_change function, which called us,
                    # is responsible for calling _update_highlighting after the rebuild.
                    return

                if new_text == old_text:
                    return # No actual change

                # Find the first differing character index
                start_char_index = 0
                min_len = min(len(new_text), len(old_text))
                for i in range(min_len):
                    if new_text[i] != old_text[i]:
                        start_char_index = i
                        break
                else:
                    start_char_index = min_len

                # Determine the first row in the treeview to update
                start_row = start_char_index // 16

                # Get all item IDs from the start_row to the end
                address_children = self.address_treeview.get_children()
                format_children = self.format_treeview.get_children()
                
                if start_row < len(address_children):
                    self.address_treeview.delete(*address_children[start_row:])
                if start_row < len(format_children):
                    self.format_treeview.delete(*format_children[start_row:])

                # Re-insert the new/updated rows from the start_row onwards
                rebuild_start_offset = start_row * 16
                text_to_rebuild = new_text[rebuild_start_offset:]

                if text_to_rebuild:
                    for offset in range(rebuild_start_offset, len(new_text), 16):
                        row_text = new_text[offset:offset+16]
                        
                        values = list(_format_code_for_display(ord(char)) for char in row_text)
                        values.extend([''] * (16 - len(values))) # Pad to 16 columns

                        self.address_treeview.insert("", tk.END, values=(f"{offset+16:08x}",))
                        self.format_treeview.insert("", tk.END, values=tuple(values))
                
                self._last_input_text = new_text

                # After updating the content, refresh the highlighting
                _update_highlighting()

            finally:
                self._handling_text_change = False

        def clear_previous_highlights(children: tuple[str, ...]) -> None:
            if self._previous_highlights and children:
                for row, col in self._previous_highlights:
                    if row < len(children):
                        item = children[row]
                        values = list(self.format_treeview.item(item, "values"))
                        if col < len(values) and values[col]:
                            values[col] = values[col].lstrip('▶')
                            self.format_treeview.item(item, values=values)
            self._previous_highlights.clear()

        def on_cursor_change(event):
            """Callback for when the cursor position changes."""
            _update_highlighting()

        def on_selection(event):
            """Callback for when the selection changes."""
            _update_highlighting()

        def copy_input_text():
            """Copy the selected text from the input_text widget to the clipboard."""
            try:
                if self.input_text.tag_ranges("sel"):
                    # If there's a selection, copy it
                    text_to_copy = self.input_text.get(tk.SEL_FIRST, tk.SEL_LAST)
                else:
                    # Otherwise, copy the entire content, excluding the trailing newline
                    text_to_copy = self.input_text.get("1.0", "end-1c")
                
                if text_to_copy:
                    self.clipboard_clear()
                    self.clipboard_append(text_to_copy)
            except tk.TclError:
                pass  # Clipboard may be empty or inaccessible
            

        def paste_input_text():
            """Paste text into the input_text widget."""
            try:
                clipboard_text = self.input_text.clipboard_get()
                if clipboard_text:
                    self.input_text.insert(tk.INSERT, clipboard_text)
            except tk.TclError:
                pass  # Clipboard may be empty or inaccessible

        def delete_input_text():
            """Delete all text in the input_text widget."""
            self.input_text.delete("1.0", tk.END)
            self.address_treeview.delete(*self.address_treeview.get_children())
            self.format_treeview.delete(*self.format_treeview.get_children())

        def encode_cipher_text():
            """Encode the input text using the selected key."""
            text = self.input_text.get("1.0", "end-1c")
            if not text:
                delete_input_text()
                return

            identity = self.selected_key_identity.get()
            public_key = None
            if self.profile:
                if identity == "current_session_key":
                    public_key = self.profile.public_key
                elif identity.startswith("personal_key_"):
                    key_name = identity.removeprefix("personal_key_")
                    key_pair = self.profile.keys.get(key_name)
                    if key_pair:
                        public_key = key_pair[0] # Public key is the first element
                elif identity.startswith("other_user_key_"):
                    username = identity.removeprefix("other_user_key_")
                    profile = self.other_clients.get(username)
                    if profile:
                        public_key = profile.public_key
            
            if not public_key:
                messagebox.showerror("Error", "No valid public key selected or available.")
                return

            errors = "replace" if self.ignore_encoding_errors.get() else "strict"
            try:
                display_format = self.output_display_format.get()
                display_text = ""

                if self.use_chunking.get():
                    # Assuming chunked_rsa_encrypt returns list[bytes]
                    encoded_chunks = chunked_rsa_encrypt(str_to_int(text, errors=errors), public_key)
                    if display_format == "Hex":
                        display_text = "\n".join(chunk.hex() for chunk in encoded_chunks)
                    else: # "Raw"
                        display_text = "".join(chunk.decode("utf-8", errors="replace") for chunk in encoded_chunks)
                else:
                    # Assuming rsa_encrypt returns an int
                    encoded_int = rsa_encrypt(str_to_int(text, errors=errors), public_key)
                    if display_format == "Hex":
                        display_text = hex(encoded_int)
                    else: # "Raw"
                        display_text = int_to_bytes(encoded_int).decode("utf-8", errors="replace")
                
                self.output_text.config(state=tk.NORMAL)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, display_text)
                self.output_text.config(state=tk.DISABLED)
            except Exception as e:
                logging.error(f"Error encoding: {traceback.format_exc()}")
                messagebox.showerror("Encoding Error", f"An error occurred during encoding:\n{e}")

        def decode_cipher_text():
            """Decode the cipher text using the selected key."""
            text = self.input_text.get("1.0", "end-1c")
            if not text:
                delete_input_text()
                return

            identity = self.selected_key_identity.get()
            private_key = None
            if self.profile:
                if identity == "current_session_key":
                    private_key = self.profile.private_key
                elif identity.startswith("personal_key_"):
                    key_name = identity.removeprefix("personal_key_")
                    key_pair = self.profile.keys.get(key_name)
                    if key_pair:
                        private_key = key_pair[1] # Private key is the second element
                elif identity.startswith("other_user_key_"):
                    messagebox.showerror("Error", "Cannot decode using another user's public key.")
                    return

            if not private_key:
                messagebox.showerror("Error", "No valid private key selected or available for decryption.")
                return

            try:
                # Decryption MUST assume a reversible format (Hex).
                if self.use_chunking.get():
                    # Parse hex strings from each line back into bytes objects.
                    chunks_as_bytes = [bytes.fromhex(line) for line in text.splitlines() if line.strip()]
                    decoded_text = chunked_rsa_decrypt(chunks_as_bytes, private_key)
                else:
                    # Parse the single hex string (e.g., "0x...") into an integer.
                    decoded_text = rsa_decrypt(int(text, 16), private_key)
                
                decoded_string = int_to_str(decoded_text, errors="ignore" if self.ignore_encoding_errors.get() else "strict")
                self.output_text.config(state=tk.NORMAL)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, decoded_string)
                self.output_text.config(state=tk.DISABLED)
            except ValueError:
                logging.error(f"Error decoding: {traceback.format_exc()}")
                messagebox.showerror(
                    "Decoding Error",
                    "Invalid input format.\n\n"
                    "Decryption requires hexadecimal input. The 'Raw' output format is for display only and cannot be decoded."
                )
            except Exception as e:
                logging.error(f"Error decoding: {traceback.format_exc()}")
                self.output_text.config(state=tk.NORMAL)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, f"Error decoding the text: {e}")
                self.output_text.config(state=tk.DISABLED)

        self.input_frame = ttk.Labelframe(content, text="Input")
        self.input_text = CustomText(self.input_frame, height=10, wrap="word", font=("Consolas", 11))
        self.input_text.tag_configure("highlight", background="#cceeff")
        self.input_text.bind("<<Selection>>", on_selection)
        self.input_text.bind("<<CursorChange>>", on_cursor_change)
        self.input_text.bind("<<TextInserted>>", on_text_change)
        self.input_text.bind("<<DeleteBefore>>", on_text_change)
        self.input_text.bind("<<DeleteAfter>>", on_text_change)
        self.input_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.input_copy_button = ttk.Button(self.input_frame, text="Copy", style="h6.TButton", command=lambda: copy_input_text())
        self.input_paste_button = ttk.Button(self.input_frame, text="Paste", style="h6.TButton", command=paste_input_text)
        self.input_view_button = ttk.Button(self.input_frame, text="View", style="h6.TButton", command=lambda: self.current_view.set("Input"))
        self.input_encode_button = ttk.Button(self.input_frame, text="Encode", style="h6.TButton", command=lambda: encode_cipher_text()) 
        self.input_decode_button = ttk.Button(self.input_frame, text="Decode", style="h6.TButton", command=lambda: decode_cipher_text())
        self.input_clear_button = ttk.Button(self.input_frame, text="Clear", style="h6.TButton", command=delete_input_text)
        self.input_text.grid(row=0, column=0, columnspan=6, sticky=tk.NSEW)
        self.input_copy_button.grid(row=1, column=0, sticky=tk.EW)
        self.input_paste_button.grid(row=1, column=1, sticky=tk.EW)
        self.input_view_button.grid(row=1, column=2, sticky=tk.EW)
        self.input_encode_button.grid(row=1, column=3, sticky=tk.EW)
        self.input_decode_button.grid(row=1, column=4, sticky=tk.EW)
        self.input_clear_button.grid(row=1, column=5, sticky=tk.EW)
        self.input_frame.grid(row=1, column=2, sticky=tk.NSEW)

        self.output_frame = ttk.Labelframe(content, text="Output")
        self.output_text = tk.Text(self.output_frame, height=10, wrap="word", font=("Consolas", 11), state=tk.DISABLED)
        self.output_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.output_copy_button = ttk.Button(self.output_frame, text="Copy", style="h6.TButton", command=lambda: self.output_text.clipboard_clear() or self.output_text.clipboard_append(self.output_text.get("1.0", "end-1c")))
        self.output_view_button = ttk.Button(self.output_frame, text="View", style="h6.TButton", command=lambda: self.current_view.set("Output"))
        self.output_clear_button = ttk.Button(self.output_frame, text="Clear", style="h6.TButton", command=lambda: self.output_text.config(state=tk.NORMAL) or self.output_text.delete("1.0", tk.END) or self.output_text.config(state=tk.DISABLED))
        self.output_text.grid(row=0, column=0, columnspan=3, sticky=tk.NSEW)
        self.output_copy_button.grid(row=1, column=0, sticky=tk.EW)
        self.output_view_button.grid(row=1, column=1, sticky=tk.EW)
        self.output_clear_button.grid(row=1, column=2, sticky=tk.EW)
        self.output_frame.grid(row=2, column=2, sticky=tk.NSEW)

        # Configure grid weights for resizing
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        content.columnconfigure(0, weight=1, minsize=80)
        # content.columnconfigure(1, weight=1)
        content.columnconfigure(2, weight=1)
        content.rowconfigure(1, weight=1)
        content.rowconfigure(2, weight=1)
        
        self.address_labelframe.rowconfigure(0, weight=1)
        self.address_labelframe.columnconfigure(0, weight=1)
        self.address_treeview_frame.rowconfigure(0, weight=1)
        self.address_treeview_frame.columnconfigure(0, weight=1)

        self.format_labelframe.rowconfigure(0, weight=1)
        self.format_labelframe.columnconfigure(0, weight=1)
        self.format_treeview_frame.rowconfigure(0, weight=1)
        self.format_treeview_frame.columnconfigure(0, weight=1)

        self.input_frame.rowconfigure(0, weight=1)
        self.input_frame.columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.output_frame.rowconfigure(0, weight=1)
        self.output_frame.columnconfigure((0, 1, 2), weight=1)

    def open_cipher_attacker(self):
        win = tk.Toplevel(self)
        win.title("Cipher Attacker")
        ttk.Label(win, text="Cipher Attacker (Coming Soon)", style="h4.TLabel").pack(padx=20, pady=20)
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)

    def show_license(self):
        ...

    def goto_repository(self):
        ...

    def show_about(self):
        ...

    def show_howto(self):
        ...

    def update_all_chats(self):
        ...

    def update_active_chat(self):
        ...

    def show_waiting_panel(self):
        # Destroy all widgets except the root
        for child in self.winfo_children():
            if child not in (self.menubar, self.language_menu):
                # Exclude the menubar and language menu from destruction
                child.destroy()
        self.title("Client App | Waiting for Approval")
        self.geometry(get_center_geometry(375, 205, self.winfo_screenwidth(), self.winfo_screenheight()))
        self.current_window = ClientWindow.WAITING
        self.waiting_label = ttk.Label(self, style="h3.TLabel")
        self.waiting_label.pack(side=tk.TOP, pady=(10, 5))
        self.fact_label = ttk.Label(self, style="h5.TLabel", wraplength=325)
        self.fact_label.pack(fill=tk.Y, side=tk.TOP, expand=True, pady=(0, 5))
        self.just_wait_button = ttk.Button(self, command=self.update_fact, style="h5.bold.TButton")
        self.just_wait_button.pack(side=tk.TOP, pady=(0, 15))
        self.update_fact()
        self.update_language()

    def get_random_fact(self) -> str:
        self.last_fact = random.randint(0, len(TRANSLATIONS["client"]["waiting"][self.language.get()]["facts"]) - 1)
        return TRANSLATIONS["client"]["waiting"][self.language.get()]["facts"][self.last_fact]

    def update_fact(self):
        self.fact_label.config(text=self.get_random_fact())
    
    def show_chats(self):
        # Destroy all widgets except the root
        for child in self.winfo_children():
            if child not in (self.menubar, self.language_menu):
                # Exclude the menubar and language menu from destruction
                child.destroy()

        self.title("Client App | Chats")
        self.geometry(get_center_geometry(900, 600, self.winfo_screenwidth(), self.winfo_screenheight()))
        self.current_window = ClientWindow.CHAT

        self.file_menu = tk.Menu(self.menubar, tearoff=False)
        self.file_menu.add_command(
            label="Settings",
            accelerator="Ctrl+,",
            command=self.open_settings
        )
        self.file_menu.add_separator()
        self.file_menu.add_command(
            label="Exit",
            command=self.on_close
        )
        self.toolkit_menu = tk.Menu(self.menubar, tearoff=False)
        self.toolkit_menu.add_command(
            label="Prime Factorization",
            command=self.open_prime_factorizator
        )
        self.toolkit_menu.add_command(
            label="Find Prime Numbers",
            command=self.open_prime_numbers_finder
        )
        self.toolkit_menu.add_command(
            label="Generate RSA Key",
            command=self.open_rsa_key_generator
        )
        self.toolkit_menu.add_command(
            label="Cipher viewer",
            command=self.open_cipher_viewer
        )
        self.toolkit_menu.add_command(
            label="Cipher attacker",
            command=self.open_cipher_attacker
        )
        self.help_menu = tk.Menu(self.menubar, tearoff=False)
        self.help_menu.add_command(
            label="License",
            command=self.show_license
        )
        self.help_menu.add_command(
            label="Repository",
            command=self.goto_repository
        )
        self.help_menu.add_command(
            label="About",
            command=self.show_about
        )
        self.help_menu.add_command(
            label="How-to",
            command=self.show_howto
        )
        self.menubar.insert_cascade(index=1, menu=self.file_menu, label="File")
        self.menubar.insert_cascade(index=2, menu=self.toolkit_menu, label="Toolkit")
        self.menubar.insert_cascade(index=4, menu=self.help_menu, label="Help")
        
        self.configure(menu=self.menubar)

        # --- Chat UI Layout ---
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)

        # Chat display (read-only)
        self.chat_display = tk.Text(self, state="disabled", wrap="word", font=("Roboto", 12))
        self.chat_display.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=(10, 5))
        # TODO: Chat and chatting should be reworked to support both encoded and decoded messages and
        #       switching between them.

        # User list
        self.user_listbox = tk.Listbox(self, width=20, font=("Roboto", 11))
        for username in self.other_clients.keys():
            self.user_listbox.insert(tk.END, username)
        self.user_listbox.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=(10, 5))
        self.user_listbox.bind("<<ListboxSelect>>", self.update_chat)

        # Message entry and send button
        self.message_entry = ttk.Entry(self, font=("Roboto", 12))
        self.message_entry.grid(row=1, column=0, sticky="ew", padx=(10, 5), pady=(0, 10))
        self.send_button = ttk.Button(self, text="Send", command=self.send_message, style="h5.bold.TButton")
        self.send_button.grid(row=1, column=1, sticky="ew", padx=(5, 10), pady=(0, 10))

    def send_message(self):
        """Send a message to the chat."""
        if not self.profile or not self.profile.has_set_up_key:
            messagebox.showwarning("Warning", "You need to set up your RSA keys before sending messages.") # type: ignore
            return
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No user selected to send the message to.") # type: ignore
        else:
            username = self.user_listbox.get(selection[0])
            message = self.message_entry.get().strip()
            if not message:
                messagebox.showwarning("Warning", "Message cannot be empty.") # type: ignore
            else:
                if self.writer and self.profile:
                    try:
                        encrypted_message = chunked_rsa_encrypt(str_to_int(message), self.other_clients[username].public_key)
                        self.loop.create_task(
                            self.transmit_message(self.writer, MessageType.SEND_MESSAGE, json.dumps(
                                {
                                    "to": username,
                                    "message": encrypted_message,
                                }, cls=JSONBytesEncoder
                            ).encode("utf-8")),
                        )
                        self.message_entry.delete(0, tk.END)
                        logging.info(f"Sent message: {message}")
                        self.chats[username].append(f"{self.profile.username}: {message}\n")
                        self.chat_display.config(state="normal")
                        self.chat_display.insert(tk.END, f"{self.profile.username}: {message}\n")
                        self.chat_display.config(state="disabled")
                        self.chat_display.see(tk.END)
                    except Exception as e:
                        logging.error(f"Failed to send message: {e}")
                        messagebox.showerror("Error", f"Failed to send message: {e}") # type: ignore

    def on_click_connect(self):
        server_host = self.host_entry.get()
        server_port = self.port_entry.get()
        if not server_host or not server_port:
            messagebox.showerror("Error", "Server IP or Port is empty.") # type: ignore
        elif len(octets := server_host.split(".")) != 4 or not all(octet.isdecimal() for octet in octets):
            messagebox.showerror( # type: ignore
                "Error", "[ERROR] - IPv4 should be written in dot-decimal notation and consist of four octets (e.g. `255.255.255.255`)."
            ) 
        elif not server_port.isdecimal():
            messagebox.showerror("Error", "[ERROR] - Port numbers should be decimal integers (e.g. `8080`).") # type: ignore
        else:
            self.loop.create_task(self.start_client(server_host, int(server_port)))

    def poll_asyncio(self):
        try:
            self.loop.call_soon(self.loop.stop)
            self.loop.run_forever()
        except RuntimeError:
            pass
        self.after(10, self.poll_asyncio)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.writer, self.reader = writer, reader
        self.profile = None
        waiting_panel_shown = False
        while True:
            try:
                msg_type, length = struct.unpack('>BI', await reader.readexactly(5))
                data = await reader.readexactly(length)
            except asyncio.exceptions.IncompleteReadError:
                logging.info(f"Server {writer.get_extra_info('peername')} is unreachable")
                break
            logging.info(f"Received message type {MessageType(msg_type).name}: {len(data)} bytes from {writer.get_extra_info('peername')}")
            logging.debug(f"Bytes: {data!r}")

            if msg_type == MessageType.SEND_PROFILE:
                data = json.loads(data)
                self.profile = Profile(data["username"], data["name"])
            elif msg_type == MessageType.SEND_READY_USERS:
                data = json.loads(data)
                for profile in data:
                    self.other_clients[profile["username"]] = Profile(profile["username"], profile["name"], profile["public_key"])
                    self.chats[profile["username"]] = []
            if self.profile:
                if not self.profile.is_approved:
                    if not waiting_panel_shown:
                        self.show_waiting_panel()
                        waiting_panel_shown = True
                    elif msg_type == MessageType.APPROVE_USER:
                        self.profile.is_approved = True
                        self.show_chats()
                else:
                    if msg_type == MessageType.BROADCAST_USER:
                        data = json.loads(data)
                        username, name, public_key = data["username"], data["name"], data["public_key"]
                        if username != self.profile.username and username not in self.other_clients:
                            self.other_clients[username] = Profile(username, name, public_key)
                            self.user_listbox.insert(tk.END, username)
                            self.chats[username] = []
                            logging.info(f"New user connected: {username}")
                    elif msg_type == MessageType.GET_MESSAGE:
                        if not self.profile.has_set_up_key or not self.profile.private_key:
                            continue
                        message_data = json.loads(data, cls=JSONBytesDecoder)
                        username = message_data["from"]
                        message = message_data["message"]
                        if username in self.other_clients:
                            # TODO: Handle situations when the message was encrypted badly (e.g. p=q)
                            #       and throw out error.
                            decrypted_message = int_to_str(chunked_rsa_decrypt(message, self.profile.private_key))
                            self.chats[username].append(f"{username}: {decrypted_message}\n")
                            if (selection := self.user_listbox.curselection()):
                                if self.user_listbox.get(selection[0]) == username:
                                    # NOTE: ONLY IF THE CHAT WITH THE USER IS CURRENTLY ACTIVE, DO FOLLOWING:
                                    self.chat_display.config(state="normal")
                                    self.chat_display.insert(tk.END, f"{username}: {decrypted_message}\n")
                                    self.chat_display.config(state="disabled")
                                    self.chat_display.see(tk.END)
                    

        await self.close_connection(writer)

    async def connect_client(self, server_host: str, server_port: int):
        try:
            self.reader, self.writer = await asyncio.open_connection(server_host, server_port)
        except (OSError, PermissionError, TimeoutError) as err:
            logging.error(f"Failed to connect to the server: {err}")
            messagebox.showerror("Connection Error", f"Failed to connect to the server: {err}") # type: ignore
        else:
            logging.info(f'Client is connected to (\'{server_host}\', {server_port})')
            self.loop.create_task(self.handle_connection(self.reader, self.writer))

    async def start_client(self, server_host: str, server_port: int):
        await self.connect_client(server_host, server_port)

        self.loop.create_task(self.transmit_message(self.writer, MessageType.SEND_COUNTRY, self.country.get().encode("utf-8")))

        # await asyncio.sleep(3600)

    async def transmit_message(self, writer: asyncio.StreamWriter, msg_type: int, data: bytes = b""):
        logging.info(f"Send message type {MessageType(msg_type).name}: {len(data)} bytes to {writer.get_extra_info('peername')}")
        try:
            writer.write(struct.pack('>BI', msg_type, len(data)))  # 1-byte message type and 4-byte big-endian length prefix
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logging.info(f"Failed to send to {writer.get_extra_info('peername')} — server offline")
            await self.close_connection(writer)

    async def transmit(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        logging.info(f"Send: {len(data)} bytes to {writer.get_extra_info('peername')}")
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logging.info(f"Failed to send to {writer.get_extra_info('peername')} — server offline")
            await self.close_connection(writer)

    async def close_connection(self, writer: asyncio.StreamWriter):
        logging.info(f"Closing the connection with {writer.get_extra_info('peername')}")
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

    def update_language(self):
        if self.current_window & ClientWindow.CONNECT:
            t = TRANSLATIONS["client"]["connect"][self.language.get()]
            self.title(t["title"])
            texts: list[str] = [
                "RSA Demonstration Messenger",
                t["welcome"],
                t["info"],
                t["rule1"],
                t["rule2"],
                t["rule3"],
                t["rule4"],
                t["rule5"],
            ]
            for label, text in zip(self.info_labels, texts):
                label.config(text=text)
            self.country_label.config(text=t["country"])
            self.host_label.config(text=t["server_ip"])
            self.port_label.config(text=t["server_port"])
            self.connect_button.config(text=t["connect"])
        elif self.current_window & ClientWindow.WAITING:
            t = TRANSLATIONS["client"]["waiting"][self.language.get()]
            self.title(t["title"])
            self.waiting_label.config(text=t["waiting_for_approval"])
            self.just_wait_button.config(text=t["just_wait"])
            self.fact_label.config(text=t["facts"][self.last_fact])

    def is_it_prime(self, number: int | str) -> None:
        """Check if the given number is prime and display the result."""
        try:
            if isinstance(number, str):
                number = int(number)
            result = is_prime(number)
            if result:
                if result < 2**64:
                    type_str = "prime"
                else:
                    type_str = "probable prime"
            else:
                type_str = "composite"
            messagebox.showinfo("Result", f"{shorten_string(str(number), 10, 10)} is a {type_str} number.") # type: ignore
        except ValueError as err:
            messagebox.showerror("Error", f"Invalid input: {err}") # type: ignore

    def set_random_prime(self, entry: tk.Entry, lower: int | str = 3, upper: int | str = 2**1024) -> None:
        """Set a random prime number in the given entry widget."""
        try:
            if isinstance(lower, str):
                lower = int(lower) 
            if isinstance(upper, str):
                upper = int(upper)
            prime = rand_prime(lower, upper)
            if not prime:
                raise ValueError("No prime number found in the given range.")
            entry.delete(0, tk.END)
            entry.insert(0, str(prime))
        except Exception as err:
            messagebox.showerror("Error", f"Failed to generate a random prime number: {err}") # type: ignore

    def set_next_prime(self, entry: tk.Entry, number: int | str) -> None:
        """Set the next prime number after the given number in the entry widget."""
        try:
            if isinstance(number, str):
                number = int(number)
            prime = next_prime(number, 1)
            entry.delete(0, tk.END)
            entry.insert(0, str(prime))
        except Exception as err:
            messagebox.showerror("Error", f"Failed to find the next prime number: {err}")

    def set_prev_prime(self, entry: tk.Entry, number: int | str) -> None:
        """Set the previous prime number before the given number in the entry widget."""
        try:
            if isinstance(number, str):
                number = int(number)
            prime = prev_prime(number)
            entry.delete(0, tk.END)
            entry.insert(0, str(prime))
        except Exception as err:
            messagebox.showerror("Error", f"Failed to find the previous prime number: {err}")

    def generate_rsa_keys(self):
        """Generate RSA keys based on the provided prime numbers."""
        t1 = TRANSLATIONS["common"][self.language.get()]
        t2 = TRANSLATIONS["client"]["rsa_key_generator"][self.language.get()]
        try:
            p = int(self.first_prime_entry.get())
            q = int(self.second_prime_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Both p and q must be valid integers.") # type: ignore
        else:
            try:
                if self.perform_security_checks.get():
                    self.last_public_key, self.last_private_key = rsa_generate_keys_with_checks(p, q)
                else:
                    self.last_public_key, self.last_private_key = rsa_generate_keys(p, q)
            except ValueError as err:
                # TODO: Error here should be translated. 
                messagebox.showerror("Error", str(err)) # type: ignore
            else:
                self.public_key_text.config(state="normal")
                self.private_key_text.config(state="normal")
                self.step_by_step_text.config(state="normal")
                self.public_key_text.delete(1.0, tk.END)
                self.private_key_text.delete(1.0, tk.END)
                self.step_by_step_text.delete(1.0, tk.END)
                if self.key_format.get() == "Plain/Raw":
                    self.public_key_text.insert(tk.END, f"-----EXPONENT e-----\n{self.last_public_key[0]}\n-----MODULUS n-----\n{self.last_public_key[1]}")
                    self.private_key_text.insert(tk.END, f"-----EXPONENT d-----\n{self.last_private_key[0]}\n-----MODULUS n-----\n{self.last_private_key[1]}")
                elif self.key_format.get() == "PEM":
                    pass
                self.public_key_text.config(state="disabled")
                self.private_key_text.config(state="disabled")
                self.step_by_step_text.config(state="disabled")
    
    def save_rsa_keys(self, parent: tk.Toplevel):
        if not self.last_public_key or not self.last_private_key:
            messagebox.showerror("Error", "No RSA keys generated yet.")
        else:
            name = simpledialog.askstring("Save RSA Keys", "Enter a name for the key pair:", initialvalue="Main Key Pair", parent=parent)
            if not name:
                messagebox.showerror("Error", "Key pair name cannot be empty.") # type: ignore
            else:
                if (self.last_public_key, self.last_private_key) in self.profile.keys.values():
                    messagebox.showerror("Error", "This RSA key pair already exists in the profile.") # type: ignore
                else:
                    if self.profile:
                        self.profile.keys[name] = (self.last_public_key, self.last_private_key)
                        self.key_manager_listbox.listbox.insert(tk.END, name)
                        self.key_manager_listbox.listbox.see(tk.END)
    
    def use_rsa_keys(self, parent: tk.Toplevel):
        """Use the selected RSA keys for encryption/decryption."""
        selected = self.key_manager_listbox.listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "No RSA keys selected.") # type: ignore
            return
        key_name = self.key_manager_listbox.listbox.get(selected[0])
        if self.profile and key_name in self.profile.keys:
            self.profile.public_key, self.profile.private_key = self.profile.keys[key_name]
            self.profile.has_set_up_key = True
            self.loop.create_task(self.transmit_message(self.writer, MessageType.SEND_PUBLIC_KEY, json.dumps({
                        "exponent": self.profile.public_key[0],
                        "modulus": self.profile.public_key[1]
            }).encode("utf-8")))
            messagebox.showinfo("Success", f"Using RSA keys: {key_name}", parent=parent) # type: ignore

    def remove_rsa_keys(self):
        selected = self.key_manager_listbox.listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "No RSA keys selected.") # type: ignore
        else:
            key_name = self.key_manager_listbox.listbox.get(selected[0])
            if self.profile and key_name in self.profile.keys:
                key_public, key_private = self.profile.keys[key_name]
                if (self.profile.public_key == key_public and self.profile.private_key == key_private):
                    messagebox.showerror("Error", "Cannot remove currently used RSA keys.") # type: ignore
                elif len(self.profile.keys) == 1:
                    messagebox.showerror("Error", "Cannot remove the only RSA keys in the profile.") # type: ignore
                else:
                    if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove the RSA keys: {key_name}?"): # type: ignore
                        del self.profile.keys[key_name]
                        self.key_manager_listbox.listbox.delete(selected[0])
                        messagebox.showinfo("Success", f"Removed RSA keys: {key_name}") # type: ignore
            else:
                messagebox.showerror("Error", "Selected RSA keys not found in profile.") # type: ignore

    def update_chat(self, event):
        # TODO: shouldn't it save the current selection in self, for situations
        # when the selections if not active anymore?
        selection = self.user_listbox.curselection()
        if selection:
            username = self.user_listbox.get(selection[0])
            chat = self.chats[username]
            self.chat_display.config(state="normal")
            self.chat_display.delete("1.0", tk.END)
            for message in chat:
                self.chat_display.insert(tk.END, message)
            self.chat_display.config(state="disabled")
            self.chat_display.see(tk.END)


class PlaceholderEntry(ttk.Entry):
    """An Entry widget with a placeholder text feature."""
    def __init__(
        self,
        master: tk.Misc | None = None,
        widget: str | None = None,
        *,
        text: str = "",
        placeholder: str = "",
        placeholder_foreground: str = "#a0a0a0",
        placeholder_font: tuple[Any] | str = "TkTextFont",
        char_limit: int = 0,
        **kwargs: Any
    ):
        # TODO: Add emoji and Ctrl+Del fast deletion support
        # TODO: Functionality to change style for both normal entry and placeholder?
        super().__init__(master, widget, **kwargs)
        self.text = tk.StringVar(self, value=text)
        self.placeholder = tk.StringVar(self, value=placeholder)
        self.default_foreground = str(self.cget('foreground'))
        self.default_font = str(self.cget('font'))

        self.default_char_limit = char_limit
        self.placeholder_foreground = placeholder_foreground
        self.placeholder_font = placeholder_font
        self.is_placeholder_enabled = False
        self.config(textvariable=self.text)
        self.set_char_limit(char_limit)
        self.focus_set_placeholder(None) # type: ignore
        self.bind('<FocusIn>', self.focus_clear_placeholder) # type: ignore
        self.bind('<FocusOut>', self.focus_set_placeholder) # type: ignore

    def set(self, text: str):
        """Set the text."""
        self.text.set(text)

    def get(self):
        """Return the text."""
        if not self.is_placeholder_enabled:
            return super().get()
        return ""

    def set_placeholder(self, text: str):
        """Set the placeholder text."""
        self.placeholder.set(text)

    def get_placeholder(self) -> str:
        """Return the placeholder text."""
        return self.placeholder.get()

    def set_char_limit(self, char_limit: int):
        """Set the number of characters allowed for the text."""
        if char_limit > 0:
            self.char_limit = char_limit
            if not self.text.trace_info():
                self.text.trace_add("write", self._callback_char_limit)

    def remove_char_limit(self):
        if (trace_info := self.text.trace_info()):
            self.text.trace_remove("write", trace_info[0][1])
            self.char_limit = 0

    def focus_clear_placeholder(self, event: tk.EventType):
        if self.is_placeholder_enabled:
            self.set_char_limit(self.default_char_limit)
            self.set("")
            self.configure(foreground=self.default_foreground, font=self.default_font)
            self.is_placeholder_enabled = False

    def focus_set_placeholder(self, event: tk.EventType):
        if not self.get():
            self.remove_char_limit()
            self.set(self.get_placeholder())
            self.configure(foreground=self.placeholder_foreground, font=self.placeholder_font)
            self.is_placeholder_enabled = True

    def _callback_char_limit(self, var: Any, index: Any, mode: Any):
        value = self.text.get()
        if len(value) > self.char_limit:
            self.text.set(value[:self.char_limit])


# TODO: `default` argument in order to pass default values in a list or a tuple
# TODO: direct access to the listbox and it's selection without doing object.listbox.function()
class ScrollableListboxFrame(ttk.Frame):
    """A frame with a scrollable Listbox widget."""
    def __init__(
        self,
        master: tk.Misc | None = None,
        **kwargs: Any
    ):
        super().__init__(master, **kwargs)
        self.hscrollbar = ttk.Scrollbar(self, orient=tk.HORIZONTAL)
        self.vscrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL)
        self.listbox = tk.Listbox(
            self,
            xscrollcommand=self.hscrollbar.set,
            yscrollcommand=self.vscrollbar.set
        )
        self.hscrollbar.config(command=self.listbox.xview) # type: ignore
        self.hscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.vscrollbar.config(command=self.listbox.yview) # type: ignore
        self.vscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(fill=tk.BOTH, expand=True)

class ScrollableTreeviewFrame(ttk.Frame):
    """A frame with a scrollable Treeview widget."""
    def __init__(
        self,
        master: tk.Misc | None = None,
        **kwargs: Any
    ):
        super().__init__(master, **kwargs)
        self.hscrollbar = ttk.Scrollbar(self, orient=tk.HORIZONTAL)
        self.vscrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL)
        self.treeview = ttk.Treeview(
            self,
            xscrollcommand=self.hscrollbar.set,
            yscrollcommand=self.vscrollbar.set
        )
        self.hscrollbar.config(command=self.treeview.xview) # type: ignore
        self.hscrollbar.grid(row=1, column=0, sticky=tk.EW)
        self.vscrollbar.config(command=self.treeview.yview) # type: ignore
        self.vscrollbar.grid(row=0, column=1, sticky=tk.NS)
        self.treeview.grid(row=0, column=0, sticky=tk.NSEW)

class CustomText(tk.Text):
    """A custom Text widget that generates events for cursor and selection changes."""
    def __init__(self, master: tk.Misc | None = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(master, *args, **kwargs)

        self.widget_name = f"{parent_name if (parent_name := self.winfo_parent()) != '.' else ''}.{self.winfo_name()}"
        self.this_widget_name = f"{self.widget_name}_proxied"

        self.cursor_anchor = None
        self.cursor_position = "1.0"
        self.last_selection_range = None # Tracks the last selection to avoid duplicate events

        self.tk.call("rename", self.widget_name, self.this_widget_name)
        self.tk.createcommand(self.widget_name, self._proxy) # type: ignore

    def get_cursor_info(self) -> dict[str, str | Any | tuple[Any, ...]]:
        """Return dictionary with cursor position information"""
        return {
            "position": self.cursor_position,
            "selection": self.tag_ranges("sel") if self.tag_ranges("sel") else None,
            "anchor": self.cursor_anchor
        }

    def _proxy(self, *args: Any) -> Any:
        """
        Proxy method that intercepts calls to the Text widget,
        and generates events for cursor and selection changes.
        """
        try:
            # Get state BEFORE the command runs
            old_pos = self.cursor_position
            old_sel = self.last_selection_range

            command = (self.this_widget_name,) + args
            result = self.tk.call(command)

            # Track the selection anchor. This is the most reliable signal for a mouse-based selection start.
            if args[0:3] == ("mark", "set", "tk::anchor1"):
                self.cursor_anchor = self.index(args[3])

            # This command clears the selection, e.g., by clicking elsewhere.
            elif args == ('tag', 'remove', 'sel', '1.0', 'end'):
                self.cursor_anchor = None

            # This is the definitive command for any cursor movement (arrows, clicks, drags).
            elif args[0:3] == ("mark", "set", "insert"):
                # Get state AFTER the command has run
                new_pos = self.index("insert")
                new_sel = self.tag_ranges("sel")

                # Compare with state BEFORE the command ran
                pos_changed = new_pos != old_pos
                sel_changed = new_sel != old_sel

                # If nothing changed, do nothing. This is the main loop breaker.
                if not pos_changed and not sel_changed:
                    return result

                # Update state for the next check
                self.cursor_position = new_pos
                self.last_selection_range = new_sel

                if new_sel:
                    # It's a selection. Fire the event.
                    if self.cursor_anchor is None:
                        sel_start, sel_end = new_sel
                        if self.compare(self.cursor_position, "==", sel_start):
                            self.cursor_anchor = self.index(sel_end)
                        else:
                            self.cursor_anchor = self.index(sel_start)
                    self.event_generate("<<Selection>>", when="tail")
                else:
                    # No selection. It's a cursor change.
                    self.event_generate("<<CursorChange>>", when="tail")
            
            # Text insertion
            elif args[0] == "insert" and args[1] == "insert":
                self.cursor_position = self.index("insert")
                self.event_generate("<<TextInserted>>", when="tail")
            
            # Text deletion
            elif args[0] == "delete":
                self.cursor_position = self.index("insert")
                delete_type = "DeleteBefore" if "insert-1c" in args[1] else "DeleteAfter"
                self.event_generate(f"<<{delete_type}>>", when="tail")

            return result
        except tk.TclError:
            # This can happen if the widget is destroyed.
            return None

def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = ClientApp(loop)
    app.mainloop()

if __name__ == "__main__":
    main()
