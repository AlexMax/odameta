#  Emacs style mode select   -*- C++ -*-
# -----------------------------------------------------------------------------
#
#  Copyright (C) 2006-2023 by The Odamex Team.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  DESCRIPTION:
#   Packet abstraction.
#
# -----------------------------------------------------------------------------

import inspect
import io
import struct
from typing import Optional, Tuple, cast


class Packet:
    data: io.BytesIO
    length: int

    def __init__(self, data: Optional[bytes] = None) -> None:
        if not data is None:
            self.data = io.BytesIO(data)
            self.length = len(data)
        else:
            self.data = io.BytesIO()
            self.length = 0

    def read_byte(self) -> int:
        data = self.data.read(1)
        if len(data) == 1:
            return cast(Tuple[int], struct.unpack("B", data))[0]
        else:
            raise PacketException(self)

    def read_short(self) -> int:
        data = self.data.read(2)
        if len(data) == 2:
            return cast(Tuple[int], struct.unpack("<h", data))[0]
        else:
            raise PacketException(self)

    def read_long(self) -> int:
        data = self.data.read(4)
        if len(data) == 4:
            return cast(Tuple[int], struct.unpack("<i", data))[0]
        else:
            raise PacketException(self)

    def read_string(self) -> bytes:
        string = b""
        while True:
            if self.left() == 0:
                raise PacketException(self)

            ch = self.data.read(1)
            if ch == b"\0":
                return string
            string += ch

    def write_byte(self, val: int) -> None:
        self.data.write(struct.pack("<B", val))
        self.length += 1

    def write_short(self, val: int) -> None:
        self.data.write(struct.pack("<h", val))
        self.length += 2

    def write_long(self, val: int) -> None:
        self.data.write(struct.pack("<i", val))
        self.length += 4

    def left(self) -> int:
        return self.length - self.data.tell()


class PacketException(Exception):

    packet: Packet
    caller: inspect.FrameInfo

    def __init__(self, packet: Packet):
        self.packet = packet
        self.caller = inspect.getouterframes(inspect.currentframe())[1]
