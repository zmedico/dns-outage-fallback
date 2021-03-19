import asyncio
import unittest

from dns_resiliency_proxy import Daemon, parse_args


class DnsOutageFallbackTest(unittest.TestCase):
    def test_socket_burst_dampener(self):
        args = parse_args(
            [
                "dns-resiliency-proxy",
                "--help",
            ]
        )
        loop = asyncio.get_event_loop()

        try:
            with Daemon(args) as daemon:
                loop.run_until_complete(self._test_daemon(loop, daemon))
        except KeyboardInterrupt:
            loop.stop()
        finally:
            loop.close()

    async def _test_daemon(self, loop, daemon):
        pass
