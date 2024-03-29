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
# 	Main loop
#
# -----------------------------------------------------------------------------

import csv
import ipaddress
import logging
import random
import selectors
import socket
import time
from typing import List, Optional

from odameta.server import *
from odameta.packet import *
from odameta.list import *

METAPORT = 15000
METALATEST = "latest.csv"
SERVER_CHALLENGE = 5560020  # doomsv challenge
LAUNCHER_CHALLENGE = 777123  # csdl challenge

MAX_SERVER_AGE = 300.0  # 5 minutes
MAX_UNVERIFIED_SERVER_AGE = 60.0  # 60 seconds

_meta_socket: Optional[socket.socket] = None
meta_list = ServerList()


def meta_socket() -> socket.socket:
    """Return the metaserver socket singleton - initialize it if it doesn't exist yet."""
    global _meta_socket
    if _meta_socket is None:
        _meta_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _meta_socket.bind(("", METAPORT))
    return _meta_socket


def send_packet(packet: Packet, addr: Address) -> None:
    """Send a packet to a remote address."""
    meta_socket().sendto(packet.data.getbuffer(), addr)


def add_server(addr: Address) -> None:
    """Add a server to the server list from an initial contact."""
    # Check for existing address:port combination
    server = meta_list.get(addr)
    if not server is None:
        # Found existing server, reset the age
        server.age = time.monotonic()
        server.pinged = False
        logging.debug(f"refreshed address:{address_str(server.addr)}")
        return

    if not meta_list.servers_reached_limit():
        if meta_list.ip_reached_limit(addr[0]):
            logging.debug(f"too many servers for address:{address_str(addr)}")
            return

        server = Server(addr=addr)
        server.age = time.monotonic()

        meta_list.add(server)

        logging.info(f"Server registered: {address_str(addr)}, {len(meta_list)} total.")
    else:
        logging.warn(f"Failed to add server: {address_str(addr)}, no slots left")


def add_server_info(packet: Packet, addr: Address) -> None:
    """Add detailed information for a server."""
    server = meta_list.get(addr)
    if server is None:
        logging.debug(f"got info from alien server at address: {address_str(addr)}")
        return

    if not server.key_sent:
        logging.debug(f"key was not sent to server at address: {address_str(addr)}")
        return

    packet.read_long()

    key_sent = packet.read_long()
    if key_sent != server.key_sent:
        logging.debug(
            f"incorrect key from server at address: {address_str(addr)}, expected:{server.key_sent}, actual:{key_sent}"
        )
        return

    if meta_list.ip_reached_limit(addr[0]):
        logging.debug(f"too many servers from ip: {addr[0]}")
        return

    logging.info(f"Server info from {address_str(addr)}.")

    server.verified = True
    server.age = time.monotonic()

    server.hostname = packet.read_string().decode(encoding="ascii", errors="ignore")
    server.curplayers = packet.read_byte()
    server.maxplayers = packet.read_byte()
    server.map = packet.read_string().decode(encoding="ascii", errors="ignore")

    pwad_count = packet.read_byte()
    server.pwads.clear()
    for _ in range(pwad_count):
        server.pwads.append(
            packet.read_string().decode(encoding="ascii", errors="ignore")
        )

    server.gametype = packet.read_byte()
    server.skill = packet.read_byte()
    server.teamplay = packet.read_byte()
    server.ctfmode = packet.read_byte()

    server.players.clear()
    for _ in range(server.curplayers):
        player = Player()

        player.names = packet.read_string().decode(encoding="ascii", errors="ignore")
        player.frags = packet.read_short()
        player.ping = packet.read_long()
        player.team = packet.read_byte()

        server.players.append(player)


def cull_servers() -> None:
    """Cull servers that we haven't heard from in a while."""

    to_cull: List[Server] = []

    for server in meta_list.values():
        if server.verified is True:
            if time.monotonic() - server.age > MAX_SERVER_AGE:
                to_cull.append(server)
                logging.info(
                    f"Remote server timed out at {address_str(server.addr)}, {len(meta_list)} total."
                )
        else:
            if time.monotonic() - server.age > MAX_UNVERIFIED_SERVER_AGE:
                to_cull.append(server)
                logging.info(
                    f"Unverified remote server timed out at {address_str(server.addr)}, {len(meta_list)} total."
                )

    for server in to_cull:
        meta_list.remove(server)


def dump_servers_to_file() -> None:
    "Dump current list of servers to a file in CSV format."
    with open(METALATEST, "w", newline="") as fp:
        csvp = csv.writer(fp)
        csvp.writerow(
            ["Name", "Map", "Players/Max", "WADs", "Gametype", "Address:Port"]
        )

        for server in meta_list.values():
            if server.verified == False:
                continue

            gametype = "UNKNOWN"
            if server.gametype == 0:
                gametype = "COOP"
            else:
                gametype = "DM"
            if server.gametype == 1 and server.teamplay == 1:
                gametype = "TEAM DM"
            if server.ctfmode == 1:
                gametype = "CTF"

            csvp.writerow(
                [
                    server.hostname,
                    server.map,
                    f"{len(server.players)}/{server.maxplayers}",
                    " ".join(server.pwads),
                    gametype,
                    address_str(server.addr),
                ]
            )


def write_server_data(packet: Packet) -> None:
    """Write out server data to a packet."""
    verified_count = 0
    for server in meta_list.values():
        if server.verified:
            verified_count += 1
    packet.write_short(verified_count)

    for server in meta_list.values():
        if not server.verified:
            continue

        ip = ipaddress.ip_address(server.addr[0])
        for octet in range(4):
            packet.write_byte(ip.packed[octet])
        packet.write_short(server.addr[1])


def send_server_data(addr: Address) -> None:
    """Send out (possibly cached) launcher challenge."""
    packet = Packet()
    packet.write_long(LAUNCHER_CHALLENGE)
    write_server_data(packet)
    send_packet(packet, addr)


def ping_servers() -> None:
    """Ping all servers, so we can verify their presence."""
    for server in meta_list.values():
        if server.pinged and not server.verified:
            continue  # have already asked and got no answer

        server.key_sent = random.randrange(0x7FFFFFFF)

        packet = Packet()
        packet.write_long(LAUNCHER_CHALLENGE)
        packet.write_long(server.key_sent)

        send_packet(packet, server.addr)
        server.pinged = True

        logging.debug(f"pinging {address_str(server.addr)}")


def get_packet(sock: socket.socket) -> None:
    """Read a packet sent to the metaserver."""
    try:
        data, address = sock.recvfrom(65535)
    except socket.error:
        # Socket errors are usually caused by unresponsive servers.
        return

    packet = Packet(data)

    try:
        challenge = packet.read_long()
        logging.debug(
            f"got packet from address:{address_str(address)} datalen:{len(data)} challenge:{challenge}"
        )

        if challenge == 0 or challenge == SERVER_CHALLENGE:
            if packet.left() > 2:
                # full reply with deathmatch, wad, etc
                add_server_info(packet, address)
            else:
                # plain contact
                if packet.left() == 2:
                    address = (address[0], packet.read_short())

                add_server(address)
        elif challenge == LAUNCHER_CHALLENGE:
            if packet.left() > 0:
                logging.warn(
                    f"Metaserver syncing server list (ignored), IP:{address_str(address)}."
                )
                return

            logging.info(f"Client request, IP:{address_str(address)}")
            send_server_data(address)

    except PacketException as e:
        raise
        # logging.debug(f"discarded invalid packet from address:{address_str(address)}")


def main() -> None:
    sel = selectors.DefaultSelector()
    sel.register(meta_socket(), selectors.EVENT_READ, get_packet)

    logging.basicConfig(level=logging.DEBUG)
    logging.info("Odamex Metaserver Started.")

    next_ping = time.monotonic() + 5.0  # every 5 seconds

    while True:
        events = sel.select(0.05)  # every 50ms
        for key, _ in events:
            callback = key.data
            callback(key.fileobj)

        cull_servers()

        current_time = time.monotonic()
        if current_time > next_ping:
            dump_servers_to_file()
            ping_servers()
            next_ping = time.monotonic() + 5.0  # every 5 seconds


if __name__ == "__main__":
    main()
