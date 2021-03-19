import argparse
import asyncio
import fcntl
import functools
import logging
import os
import signal
import socket
import subprocess
import sys
import types
from struct import Struct, unpack, unpack_from

from aiodns import DNSResolver
from aiodns.error import DNSError

import datetime
from collections import deque

__version__ = "v0.0.1"
__project__ = "dns-outage-fallback"
__description__ = "A transparent DNS proxy with fallback to LRU cache for DNS outages"
__author__ = "Zac Medico"
__email__ = "<zmedico@gmail.com>"
__copyright__ = "Copyright 2021 Zac Medico"
__license__ = "Apache-2.0"


def get_resolvers():
    resolvers = []
    try:
        with open( '/etc/resolv.conf', 'r' ) as resolvconf:
            for line in resolvconf.readlines():
                line = line.split('#', 1)[0]
                line = line.split()
                if len(line) == 1 and line[0] == "nameserver":
                    resolvers.append(line[1])
    except FileNotFoundError:
        pass
    return resolvers


def _hex(x: int) -> str:
    return '0x{0:04x}'.format(x)


class DnsQuery(types.SimpleNamespace):
    struct = Struct("!6H")
    def load(self, dgram):
        self.id, self.flags, self.questions, self.answer_rrs, self.authority_rrs, self.additional_rrs = map(
            _hex, unpack("!6H", dgram[:12]))


class DnsQname(types.SimpleNamespace):
    def load(self, dgram, offset):
        parts = []
        size = ord(unpack("!c", dgram[offset:offset+1])[0])
        offset += 1
        while size != 0:
            parts.append(b''.join(unpack("!%sc" % size, dgram[offset:offset+size])))
            offset += size
            size = ord(unpack("!c", dgram[offset:offset+1])[0])
            offset += 1

        self.qname = b".".join(parts).decode('idna')


class Daemon:
    def __init__(self, args):
        self.args = args
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(False)

    async def run(self):
        loop = asyncio.get_event_loop()
        self._sock.bind((self.args.address, self.args.port))
        fd = self._sock.fileno()
        exclude = set(self.args.exclude_resolver or [])
        include = set(self.args.include_resolver or [])
        resolvers = []
        for resolver in get_resolvers():
            if resolver not in exclude:
                resolvers.append(resolver)
        resolver = DNSResolver(servers=resolvers, loop=loop)
        while True:
            try:
                data, addr = self._sock.recvfrom(4096)
            except BlockingIOError:
                future = loop.create_future()
                loop.add_reader(fd, future.set_result, None)
                try:
                    await future
                finally:
                    if not loop.is_closed():
                        future.done() or future.cancel()
                    loop.remove_reader(fd)
            else:
                logging.info("%s %s %s", datetime.datetime.now(), addr, data)
                if len(data) < DnsQuery.struct.size:
                    continue
                header = DnsQuery()
                header.load(data)
                logging.info("query: %s", header)
                if header.questions == "0x0001":
                    qname = DnsQname()
                    qname.load(data, offset=DnsQuery.struct.size)
                    logging.info("qname: %s", qname)

                try:
                    result = await resolver.gethostbyname(qname.qname, socket.AF_INET)
                except DNSError as e:
                    logging.error("host: %s gethostbyname: %s", qname.qname, e)
                else:
                    logging.info("result: %s", result)


                # bytes_sent = self._sock.sendto(data, "router.bittorrent.com", 6881))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        return False


def main():
    args = parse_args()
    loop = asyncio.get_event_loop()
    try:
        with Daemon(args) as daemon:
            loop.run_until_complete(asyncio.ensure_future(daemon.run(), loop=loop))
    except KeyboardInterrupt:
        loop.stop()
    finally:
        loop.close()


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(
        prog=os.path.basename(argv[0]),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="  {} {}\n  {}".format(__project__, __version__, __description__),
    )

    parser.add_argument(
        "--address",
        action="store",
        metavar="ADDRESS",
        default="127.0.0.1",
        help="bind to the specified address",
    )

    parser.add_argument(
        "--exclude-resolver",
        action="append",
        help="exclude upstream nameserver found in resolv.conf",
    )

    parser.add_argument(
        "--include-resolver",
        action="append",
        help="include upstream nameserver",
    )

    parser.add_argument(
        "--ipv4",
        action="store_true",
        default=None,
        help="prefer IPv4",
    )

    parser.add_argument(
        "--ipv6",
        action="store_true",
        default=None,
        help="prefer IPv6",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        help="verbose logging (each occurence increases verbosity)",
        default=0,
    )

    parser.add_argument(
        "--port",
        action="store",
        metavar="PORT",
        type=int,
        default=53,
        help="listen on the given port number",
    )

    args = parser.parse_args(argv[1:])

    logging.basicConfig(
        level=(logging.getLogger().getEffectiveLevel() - 10 * args.verbosity),
        format="[%(levelname)-4s] %(message)s",
    )

    logging.debug("args: %s", args)

    if args.ipv6 and not socket.has_ipv6:
        logging.warning("the platform has IPv6 support disabled")

    return args


if __name__ == "__main__":
    sys.exit(main())
