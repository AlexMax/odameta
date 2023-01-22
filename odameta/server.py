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
#   Server class.
#
# -----------------------------------------------------------------------------

from dataclasses import dataclass, field
from typing import List, Tuple

Address = Tuple[str, int]


def address_str(addr: Address) -> str:
    """Turn an address into a string representation."""
    return f"{addr[0]}:{addr[1]}"


@dataclass
class Player:
    names: str = ""
    frags: int = 0
    ping: int = 0
    team: int = 0


@dataclass
class Server:
    addr: Address
    age: float = 0.0

    # from server itself
    hostname: str = ""
    curplayers: int = 0
    maxplayers: int = 0
    map: str = ""
    pwads: List[str] = field(default_factory=list)
    gametype: int = 0
    skill: int = 0
    teamplay: int = 0
    ctfmode: int = 0
    players: List[Player] = field(default_factory=list)
    key_sent: int = 0
    pinged: bool = False
    verified: bool = False
