import struct
import asyncio
import logging
import secrets
import json
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as messagebox

from faker import Faker
from typing import Any

from .constants import MessageType, COUNTRY_TO_LOCALE
from .utils import get_center_geometry, JSONBytesEncoder, JSONBytesDecoder
from .translations import TRANSLATIONS

class Profile(object):
    """A class representing a user profile in the server application."""
    def __init__(
            self,
            fake: Faker,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            username: str | None = None,
            name: str | None = None,
        ):
        self.__fake = fake
        self.status = "AWAITS APPROVAL"
        self.reader, self.writer = reader, writer
        self.host, self.port = self.addr = writer.get_extra_info('peername')
        self.username = username if username is not None else fake.user_name()
        self.change_name(name)
        self.public_key: tuple[int, int] | None = None

    def get(self) -> dict[str, str | None | tuple[int, int]]:
        return {
            "username": self.username,
            "name": self.name,
            "public_key": self.public_key,
        }
    
    def get_json(self) -> bytes:
        return json.dumps(self.get()).encode("utf-8")

    def change_name(self, name: str | None = None) -> str:
        self.name = name if name is not None else self.__fake.name()
        return self.name

LOGGING_FORMAT = u"%(asctime)-28s %(filename)-20s %(lineno)d %(levelname)s: %(message)s"
logger = logging.getLogger(__name__)
logging.basicConfig(filename='server.log', level=logging.DEBUG, format=LOGGING_FORMAT, filemode="w", encoding="utf-8")

class TextWidgetHandler(logging.Handler):
    " A logging handler that writes log messages to a Tkinter Text widget."
    def __init__(self, text_widget: tk.Text):
        super().__init__()
        self.text_widget = text_widget
        self.text_widget.tag_configure("INFO", foreground="green")
        self.text_widget.tag_configure("ERROR", foreground="red")
        self.text_widget.tag_configure("DEBUG", foreground="blue")
        self.text_widget.tag_configure("WARNING", foreground="orange")
        self.text_widget.tag_configure("CRITICAL", foreground="purple")

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record to the text widget."""
        msg = self.format(record)
        # Insert log message in the widget in the main thread
        self.text_widget.after(0, self._append, msg, record.levelname)

    def _append(self, msg: str, levelname: str) -> None:
        """Append a message to the text widget with appropriate styling."""
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, msg + "\n")
        start = self.text_widget.search(levelname, index="end-2c linestart", stopindex="end")
        stop = f"{start}+{len(levelname)}c"
        self.text_widget.tag_add(levelname, start, stop)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")

class ServerApp(tk.Tk):
    """A simple server application with a control panel for managing connected clients."""
    def __init__(self, loop: asyncio.AbstractEventLoop, host: str, port: int, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        self.clients: dict[str, Profile] = {}
        self.ready_clients: set[str] = set()
        self.banned_clients: set[str] = set() # TODO: ?
        self.chats: dict[tuple[str, str], list[str]] # TODO: ?

        self.server = None
        self.loop = loop
        self.host, self.port = host, port
        self.shutdown_in_progress = False

        self.MAX_CONNECTIONS = 10
        
        self.title("Server App | Control Panel")
        # self.resizable(False, False)
        self.geometry(get_center_geometry(450, 600, self.winfo_screenwidth(), self.winfo_screenheight()))
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        for widget in ("TLabel", "TButton", "TEntry", "TCheckbutton"):
            for no, font_size in zip(range(1, 7), (32, 24, 18, 16, 13, 11)):
                style.configure(f"h{no}.{widget}", font=("Roboto", font_size)) # type: ignore
                style.configure(f"h{no}.bold.{widget}", font=("Roboto", font_size, "bold")) # type: ignore
                style.configure(f"h{no}.italic.{widget}", font=("Roboto", font_size, "italic")) # type: ignore
                style.configure(f"h{no}.bold.italic.{widget}", font=("Roboto", font_size, "bold", "italic")) # type: ignore

        self.language = tk.StringVar(self, value="en")
        self.current_online = tk.IntVar(self)

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

        self.content = ttk.Frame(self, padding=(3,3,12,12))
        self.content.grid(row=0, column=0, sticky=tk.NSEW)

        server_panel_label = ttk.Label(self.content, text="Server Control Panel", style="h4.bold.TLabel")
        server_panel_label.grid(row=0, column=0, sticky=tk.W)

        self.current_online_frame = ttk.Frame(self.content)
        self.current_online_label = ttk.Label(self.current_online_frame, text="Current Online Users:", style="h5.TLabel")
        self.current_online_number = ttk.Label(self.current_online_frame, textvariable=self.current_online, style="h5.TLabel")
        self.current_online_label.grid(row=1, column=0, sticky=tk.W)
        self.current_online_number.grid(row=1, column=1, sticky=tk.W)
        self.current_online_frame.grid(row=1, column=0, sticky=tk.W)

        self.search_frame = ttk.Frame(self.content)
        self.search_label = ttk.Label(self.search_frame, text="Search Users:", style="h5.TLabel")
        self.search_entry = ttk.Entry(self.search_frame, style="h5.TEntry")
        self.search_label.grid(row=2, column=0, sticky=tk.W)
        self.search_entry.grid(row=2, column=1, sticky=tk.W)
        self.search_frame.grid(row=2, column=0, sticky=tk.W)

        self.users_panel = ScrollableListboxFrame(self.content, borderwidth=5, relief="ridge")
        self.users_panel.grid(row=3, column=0, columnspan=4, sticky=tk.NSEW)

        self.buttons_frame = ttk.Frame(self.content)
        self.approve_button = ttk.Button(self.buttons_frame, text="Approve", command=self.approve_user)
        self.kick_button = ttk.Button(self.buttons_frame, text="Kick", command=self.kick_user)
        self.ban_button = ttk.Button(self.buttons_frame, text="Ban", command=self.ban_user)
        self.unban_button = ttk.Button(self.buttons_frame, text="Unban", command=self.ban_user)
        self.info_button = ttk.Button(self.buttons_frame, text="Info", command=self.info_user)
        self.approve_button.grid(row=4, column=0, sticky=tk.NW)
        self.kick_button.grid(row=4, column=1, sticky=tk.NW)
        self.ban_button.grid(row=4, column=2, sticky=tk.NW)
        self.unban_button.grid(row=4, column=3, sticky=tk.NW)
        self.info_button.grid(row=4, column=4, sticky=tk.NW)
        self.buttons_frame.grid(row=4, column=0, sticky=tk.W)

        self.logging_boolvar = tk.BooleanVar(self, value=True)
        self.logging_checkbutton = ttk.Checkbutton(self.content, text="Display logs", variable=self.logging_boolvar, style="h5.TCheckbutton")
        self.logging_checkbutton.grid(row=5, column=0, sticky=tk.W)

        self.log_frame = ttk.Labelframe(self.content, text="Server Log")
        self.log_text = tk.Text(self.log_frame, height=15, state="disabled", font=("Consolas", 10))
        self.log_text_handler = TextWidgetHandler(self.log_text)
        self.log_text_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logging.getLogger().addHandler(self.log_text_handler)
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.log_frame.grid(row=6, column=0, columnspan=4, sticky=tk.NSEW)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(3, weight=1)
        self.content.rowconfigure(6, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        self.log_frame.columnconfigure(0, weight=1)

        self.after(10, self.poll_asyncio) # Start polling the asyncio event loop
        self.loop.create_task(self.start_server(self.host, self.port))

    def approve_user(self):
        for index in self.users_panel.listbox.curselection():
            item = self.users_panel.listbox.get(index)
            status, username, name = item.split(" | ")
            if status == "AWAITS APPROVAL":
                self.clients[username].status = "ONLINE"
                self.users_panel.listbox.delete(index)
                self.users_panel.listbox.insert(index, f"ONLINE | {username} | {name}")
                self.loop.create_task(self.transmit_message(self.clients[username].writer, MessageType.APPROVE_USER, b""))

    def ban_user(self):
        for index in self.users_panel.listbox.curselection():
            item = self.users_panel.listbox.get(index)
            status, username, name = item.split(" | ")
            profile = self.clients[username]
            if username in self.clients:
                self.loop.create_task(self.close_connection(self.clients[username].writer))
                self.clients[username].status = "BANNED"
                self.users_panel.listbox.delete(index)
                self.users_panel.listbox.insert(index, f"BANNED | {username} | {name}")
                self.banned_clients.add(profile.host)
                logging.info(f"User {username} was banned.")

    def kick_user(self):
        for index in self.users_panel.listbox.curselection():
            item = self.users_panel.listbox.get(index)
            status, username, name = item.split(" | ")
            if username in self.clients:
                self.loop.create_task(self.close_connection(self.clients[username].writer))
                self.users_panel.listbox.delete(index)
                del self.clients[username]
                logging.info(f"User {username} was kicked.")

    def info_user(self):
        for index in self.users_panel.listbox.curselection():
            item = self.users_panel.listbox.get(index)
            status, username, name = item.split(" | ")
            profile = self.clients[username]
            messagebox.showinfo(
                "User Info", 
                f"Address: {profile.addr}\n"
                f"Username: {username}\n"
                f"Name: {name}\n"
                f"Status: {status}\n"
                f"Public Key: {profile.public_key if profile.public_key else 'Not set'}"
            )

    def on_close(self):
        self.loop.create_task(self.shutdown())

    async def shutdown(self):
        self.shutdown_in_progress = True
        logging.info("Server shutdown started...")

        await self.close_all_connections()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self.loop.stop()
        self.destroy()

    def poll_asyncio(self):
        try:
            self.loop.call_soon(self.loop.stop)
            self.loop.run_forever()
        except RuntimeError:
            pass
        self.after(10, self.poll_asyncio)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self.shutdown_in_progress:
            await self.close_connection(writer)
            logging.info("Rejected client connection due to server shutdown")
            return

        # Enforce MAX_CONNECTIONS
        if len(self.clients) >= self.MAX_CONNECTIONS:
            logging.info(f"Rejected client connection: max connections reached ({self.MAX_CONNECTIONS})")
            await self.close_connection(writer)
            return
        elif writer.get_extra_info('peername')[0] in self.banned_clients:
            logging.info(f"Rejected client connection: {writer.get_extra_info('peername')[0]} is banned")
            await self.close_connection(writer)
            return

        logging.info(f"Client {(client_address := writer.get_extra_info('peername'))} was connected")
        
        profile = None

        try:
            while True:
                try:
                    msg_type, length = struct.unpack('>BI', await reader.readexactly(5))
                    data = await reader.readexactly(length)
                except asyncio.exceptions.IncompleteReadError:
                    logging.info(f"Client {client_address} disconnected")
                    break
                logging.info(f"Received message type {MessageType(msg_type).name}: {len(data)} bytes from {client_address}")
                logging.debug(f"Bytes: {data!r}")

                if msg_type == MessageType.SEND_COUNTRY:
                    profile = Profile(Faker(COUNTRY_TO_LOCALE[data.decode("utf-8")]), reader, writer)
                    self.clients[profile.username] = profile
                    index = self.users_panel.listbox.index("end")
                    self.users_panel.listbox.insert(index, f"{profile.status} | {profile.username} | {profile.name}")
                    self.loop.create_task(self.transmit_message(profile.writer, MessageType.SEND_PROFILE, profile.get_json()))
                    ready_profiles = json.dumps([self.clients[username].get() for username in self.ready_clients]).encode("utf-8")
                    self.loop.create_task(self.transmit_message(profile.writer, MessageType.SEND_READY_USERS, ready_profiles)) 
                
                if profile:
                    if profile.status == "ONLINE":
                        if msg_type == MessageType.SEND_PUBLIC_KEY:
                            public_key = json.loads(data.decode("utf-8"))
                            profile.public_key = (public_key["exponent"], public_key["modulus"])
                            logging.info(f"Received public key from {profile.username}: {profile.public_key}")
                            self.ready_clients.add(profile.username)
                            await self.broadcast_message(MessageType.BROADCAST_USER, profile.get_json())
                        elif msg_type == MessageType.SEND_MESSAGE:
                            data = json.loads(data.decode("utf-8"), cls=JSONBytesDecoder)
                            to_username: str = data["to"]
                            encrypted_message = data["message"]  # This is now list[bytes]
                            if to_username in self.clients:
                                to_profile = self.clients[to_username]
                                logging.info(f"Received message from {profile.username} to {to_username}: {encrypted_message}")
                                await self.transmit_message(to_profile.writer, MessageType.GET_MESSAGE, json.dumps(
                                    {
                                        "from": profile.username,
                                        "message": encrypted_message,
                                    }, cls=JSONBytesEncoder
                                ).encode("utf-8"))
                            # await self.broadcast_message(MessageType.GET_MESSAGE, f"{profile.username}: {message}".encode("utf-8"))
                    
        except Exception as err:
            logging.error(f"Error with {client_address}: {err}")
        finally:
            if profile and profile.username in self.clients:
                del self.clients[profile.username]
            # del nicknames[client_id]
            if not self.shutdown_in_progress:
                await self.close_connection(writer)

    async def start_server(self, host: str, port: int):
        try:
            self.server = await asyncio.start_server(self.handle_connection, host, port)
        except (OSError, PermissionError) as err:
            logging.error(f"Failed to start server: {err}")
            return

        addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        logging.info(f'Server is serving on {addrs}')

        try:
            await self.server.serve_forever()
        except asyncio.CancelledError:
            logging.info("Server shutdown requested")

    async def transmit_message(self, writer: asyncio.StreamWriter, msg_type: int, data: bytes) -> None:
        logging.info(f"Send message type {MessageType(msg_type).name}: {len(data)} bytes to {(client_address := writer.get_extra_info('peername'))}")
        try:
            # 1-byte message type and 4-byte big-endian length prefix and then - data
            writer.write(struct.pack('>BI', msg_type, len(data)))
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logging.info(f"Failed to send to {client_address} — client disconnected")
            await self.close_connection(writer)

    async def broadcast_message(self, msg_type: int, data: bytes) -> None:
        logging.info(f"Send message type {MessageType(msg_type).name}: {len(data)} bytes to everyone")
        for profile in self.clients.values():
            await self.transmit_message(profile.writer, msg_type, data)

    async def transmit(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        logging.info(f"Send: {len(data)} bytes to {(client_address := writer.get_extra_info('peername'))}")
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logging.info(f"Failed to send to {client_address} — client disconnected")
            await self.close_connection(writer)

    async def broadcast(self, data: bytes) -> None:
        logging.info(f"Send: {len(data)} bytes to everyone")
        for profile in self.clients.values():
            await self.transmit(profile.writer, data)

    async def close_connection(self, writer: asyncio.StreamWriter):
        logging.info(f"Closing the connection with {writer.get_extra_info('peername')}")
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

    async def close_all_connections(self) -> None:
        logging.info(f"Closing all existing connections")
        for profile in tuple(self.clients.values()):
            await self.close_connection(profile.writer)

    def update_language(self):
        t = TRANSLATIONS["server"][self.language.get()]
        self.title(t["title"])
        self.current_online_label.config(text=t["current_online"])
        self.search_label.config(text=t["search"])
        self.approve_button.config(text=t["buttons"]["approve"])
        self.kick_button.config(text=t["buttons"]["kick"])
        self.ban_button.config(text=t["buttons"]["ban"])
        self.unban_button.config(text=t["buttons"]["unban"])
        self.kick_button.config(text=t["buttons"]["kick"])
        self.info_button.config(text=t["buttons"]["info"])        
        self.logging_checkbutton.config(text=t["logging"])

class ScrollableListboxFrame(ttk.Frame):

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

def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app = ServerApp(loop, "127.0.0.1", 8080)
    app.mainloop()

if __name__ == "__main__":
    main()
