"""UDP relay that records the SNMPv3 messages an agent sends back.

Tests point the manager at the relay port; the relay forwards datagrams to
the agent and back, keeping a decoded copy of every agent -> manager message
so tests can assert on wire-level fields (msgFlags, Report OIDs).
"""

import asyncio

from pyasn1.codec.ber import decoder

from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message


class _AgentSide(asyncio.DatagramProtocol):
    def __init__(self, relay: "UdpRelay"):
        self.relay = relay

    def datagram_received(self, data, addr):
        self.relay.agent_messages.append(
            decoder.decode(data, asn1Spec=SNMPv3Message())[0]
        )
        if self.relay.manager_address is not None:
            self.relay.manager_side.sendto(data, self.relay.manager_address)


class _ManagerSide(asyncio.DatagramProtocol):
    def __init__(self, relay: "UdpRelay"):
        self.relay = relay

    def datagram_received(self, data, addr):
        self.relay.manager_address = addr
        self.relay.agent_side.sendto(data)


class UdpRelay:
    """Async context manager relaying ``listen`` <-> ``agent``."""

    def __init__(self, listen: tuple, agent: tuple):
        self.listen = listen
        self.agent = agent
        self.agent_messages = []
        self.manager_address = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        self.manager_side, _ = await loop.create_datagram_endpoint(
            lambda: _ManagerSide(self), local_addr=self.listen
        )
        self.agent_side, _ = await loop.create_datagram_endpoint(
            lambda: _AgentSide(self), remote_addr=self.agent
        )
        return self

    async def __aexit__(self, *exc):
        self.manager_side.close()
        self.agent_side.close()

    def reports(self):
        """Return (msgFlags, report OID) for each Report-PDU the agent sent.

        Reports are sent at noAuthNoPriv here, so the scoped PDU is plaintext.
        """
        reports = []
        for msg in self.agent_messages:
            data = msg["msgData"]
            if data.getName() != "plaintext":
                continue
            pdus = data["plaintext"]["data"]
            if pdus.getName() != "report":
                continue
            (flags,) = msg["msgGlobalData"]["msgFlags"].asNumbers()
            oid = pdus["report"]["variable-bindings"][0]["name"]
            reports.append((flags, tuple(oid)))
        return reports
