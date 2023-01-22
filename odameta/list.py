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
#   Server List.
#
# -----------------------------------------------------------------------------


import weakref
from typing import Dict, Optional, ValuesView

from odameta.server import *

MAX_SERVERS = 1024
MAX_SERVERS_PER_IP = 64


class ServerList:

    list: Dict[str, Server]
    addresses: Dict[str, weakref.WeakValueDictionary[int, Server]]

    def __init__(self) -> None:
        self.list = {}
        self.addresses = {}

    def __len__(self) -> int:
        return len(self.list)

    def values(self) -> ValuesView[Server]:
        return self.list.values()

    def add(self, server: Server) -> None:
        """Add server to all server lists."""
        addr = server.addr
        self.list[address_str(addr)] = server
        ports = self.addresses.get(addr[0])
        if ports is None:
            self.addresses[addr[0]] = weakref.WeakValueDictionary({addr[1]: server})
        else:
            ports[addr[1]] = server

    def remove(self, server: Server) -> None:
        """Remove server from all server lists."""
        addr = server.addr
        del self.list[address_str(addr)]
        ports = self.addresses.get(addr[0])
        if not ports is None and len(ports) == 0:
            del self.addresses[addr[0]]

    def get(self, addr: Address) -> Optional[Server]:
        """Get a server from the list by address."""
        ports = self.addresses.get(addr[0])
        if not ports is None:
            server = ports.get(addr[1])
            if not server is None:
                return server
        return None

    def servers_reached_limit(self) -> bool:
        """Return True if no more servers can be added to the metaserver."""
        return len(self.list) >= MAX_SERVERS

    def ip_reached_limit(self, ip: str) -> bool:
        """Return True if no more servers can be added for this IP."""
        ports = self.addresses.get(ip)
        if ports is None:
            return False
        return len(ports) >= MAX_SERVERS_PER_IP
