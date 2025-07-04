import tkinter as tk
import tkinter.ttk as ttk
from typing import Any


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


class ChatMessageFrame(ttk.Frame):
    """A frame to display a chat message."""
    def __init__(
        self,
        master: tk.Misc | None = None,
        message: str = "",
        sender: str = "",
        timestamp: str = "",
        **kwargs: Any
    ):
        super().__init__(master, **kwargs)
        self.message_label = ttk.Label(self, text=message, font=("Helvetica", 11), background="#f0f0f0", wraplength=300, justify=tk.LEFT, padding=(1, 1))
        self.sender_label = ttk.Label(self, text=sender, font=("Helvetica", 10, "bold"), foreground="#555", background="#f0f0f0", padding=(1, 1))
        self.timestamp_label = ttk.Label(self, text=timestamp, font=("Helvetica", 8), foreground="#999", background="#f0f0f0", padding=(5, 1))
        self.edit_entry = ttk.Entry(self, font=("Helvetica", 11), foreground="#000", background="#fff", justify=tk.LEFT)

        # TODO: Add a custom style for the message label to make it look like a chat bubble
        # TODO: Utilize FocusIn and FocusOut events to change the style of the message label when hovered or clicked
        # TODO: Add a context menu for the message label to copy the message, reply, or delete it, or encode/decode with RSA
        # TODO: (?) Add a feature to edit the message by clicking on it, which will turn it into an Entry widget
        # TODO: (?) Add a feature to copy the message text partially utilizing the selection feature of the Text widget
        # TODO: (?) Add logic to update the timestamp label to accurately reflect the time of the message, e.g., using `datetime` module and relative time
        # FIXME: Timestamp clapping with the border of the frame
        self.configure(borderwidth=1, relief=tk.RAISED)

        # Set up bindings
        self.message_label.bind("<Enter>", lambda e: self.message_label.configure(background="#e0e0e0"))
        self.message_label.bind("<Leave>", lambda e: self.message_label.configure(background="#f0f0f0"))
        self.message_label.bind("<Button-1>", lambda e: self.message_label.configure(background="#d0d0d0"))
        self.message_label.bind("<ButtonRelease-1>", lambda e: self.message_label.configure(background="#e0e0e0"))
        self.message_label.bind("<Button-3>", lambda e: self.show_context_menu(e))
        self.message_label.bind("<Double-Button-1>", lambda e: self.edit_message())
        self.edit_entry.bind("<Return>", lambda e: self.save_edit())
        self.edit_entry.bind("<FocusOut>", lambda e: self.cancel_editing())

        # Configure the grid layout
        self.message_label.grid(row=1, column=0, sticky=tk.W)
        self.sender_label.grid(row=0, column=0, sticky=tk.W)
        self.timestamp_label.grid(row=1, column=1, sticky=tk.E, padx=(0, 1))

    def show_context_menu(self, event: tk.Event):
        """Show a context menu with options for the message."""
        context_menu = tk.Menu(self, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: self.copy_message())
        context_menu.add_command(label="Reply", command=lambda: self.reply_to_message())
        context_menu.add_command(label="Delete", command=lambda: self.delete_message())
        context_menu.add_separator()
        context_menu.add_command(label="Encode with RSA", command=lambda: self.encode_message())
        context_menu.add_command(label="Decode with RSA", command=lambda: self.decode_message())
        context_menu.add_separator()
        context_menu.add_command(label="Edit", command=lambda: self.edit_message())
        context_menu.add_command(label="Close", command=context_menu.unpost)
        # Show the context menu at the mouse position
        context_menu.post(event.x_root, event.y_root)

    def copy_message(self):
        """Copy the message text to the clipboard."""
        self.master.clipboard_clear()
        self.master.clipboard_append(self.message_label.cget("text"))
        self.master.update()
    
    def reply_to_message(self):
        """Reply to the message."""
        pass

    def delete_message(self):
        """Delete the message."""
        pass

    def encode_message(self):
        """Encode the message with RSA."""
        pass

    def decode_message(self):
        """Decode the message with RSA."""
        pass

    def edit_message(self):
        """Edit the message by turning it into an Entry widget."""
        self.message_label.grid_forget()
        self.edit_entry.delete(0, tk.END)
        self.edit_entry.grid(row=1, column=0, sticky=tk.W)

    def save_edit(self):
        """Save the edited message."""
        # TODO: Logic to save the edited message, e.g., send it to the server or update the local state
        # TODO: Check if the message is not empty or not the same before saving
        new_text = self.edit_entry.get()
        self.message_label.configure(text=new_text)
        self.edit_entry.grid_forget()
        self.message_label.grid(row=1, column=0, sticky=tk.W)

    def cancel_editing(self):
        """Cancel editing and restore the original message."""
        self.edit_entry.grid_forget()
        self.message_label.grid(row=1, column=0, sticky=tk.W)

if __name__ == "__main__":
    # Example usage of the widgets
    root = tk.Tk()
    root.title("Example Widgets")

    chat_message = ChatMessageFrame(root, message="Hello, this is a test message.", sender="User1", timestamp="12:00 PM")
    chat_message.pack()
    
    root.mainloop()