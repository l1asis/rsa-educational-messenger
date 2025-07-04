import asyncio
import logging
import struct
from .constants import MessageType
from typing import Any

class NetworkClient:
    def __init__(self, incoming_queue: asyncio.Queue[Any], loop: asyncio.AbstractEventLoop):
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.incoming_queue = incoming_queue
        self.loop = loop

    async def connect(self, host: str, port: int) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(host, port)
        except (OSError, PermissionError, TimeoutError) as err:
            logging.error(f"Failed to connect to the server: {err}")
            await self.incoming_queue.put(("connection_error", err))
            return False
        else:
            logging.info(f'Client is connected to (\'{host}\', {port})')
            self.loop.create_task(self.handle_connection())
            return True

    async def handle_connection(self):
        if not self.reader or not self.writer:
            return

        while True:
            try:
                header = await self.reader.readexactly(5)
                msg_type, length = struct.unpack('>BI', header)
                data = await self.reader.readexactly(length)
                
                logging.info(f"Received message type {MessageType(msg_type).name}: {len(data)} bytes")
                # Put the received message onto the queue for the UI to process
                await self.incoming_queue.put((msg_type, data))

            except (asyncio.IncompleteReadError, ConnectionResetError):
                logging.info(f"Connection to server lost.")
                await self.incoming_queue.put(("connection_lost", None))
                break
        
        await self.close()

    async def transmit_message(self, msg_type: int, data: bytes = b""):
        if not self.writer or self.writer.is_closing():
            logging.warning("Cannot send message, writer is not available.")
            return

        logging.info(f"Send message type {MessageType(msg_type).name}: {len(data)} bytes")
        try:
            self.writer.write(struct.pack('>BI', msg_type, len(data)))
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            logging.info(f"Failed to send to server — server offline")
            await self.close()

    async def close(self):
        if self.writer and not self.writer.is_closing():
            logging.info(f"Closing the connection with {self.writer.get_extra_info('peername')}")
            self.writer.close()
            await self.writer.wait_closed()