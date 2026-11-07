"""Report-PDUs must never carry the reportableFlag (RFC 3412 6.4, 7.1.7d).

When the agent cannot authenticate a request, USM downgrades the Report to
noAuthNoPriv (RFC 3412 7.1.3d.1). Only the auth/priv bits may be cleared then:
a Report with reportableFlag set invites the receiver to answer it with
another Report, and two pysnmp engines can bounce Reports forever. #207
"""

import pytest

from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_SHA,
    USM_PRIV_CFB128_AES,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)
from pysnmp.proto.errind import WrongDigest
from tests.agent_context import AGENT_PORT, AgentContextManager
from tests.udp_relay import UdpRelay

RELAY_PORT = 1641
USM_STATS_WRONG_DIGESTS = (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0)


@pytest.mark.asyncio
async def test_downgraded_report_is_not_reportable():
    async with AgentContextManager():
        async with UdpRelay(
            ("127.0.0.1", RELAY_PORT), ("127.0.0.1", AGENT_PORT)
        ) as relay:
            with SnmpEngine() as snmpEngine:
                errorIndication, _, _, _ = await get_cmd(
                    snmpEngine,
                    UsmUserData(
                        "usr-sha-aes",
                        "wrongauthkey",
                        "privkey1",
                        authProtocol=USM_AUTH_HMAC96_SHA,
                        privProtocol=USM_PRIV_CFB128_AES,
                    ),
                    await UdpTransportTarget.create(
                        ("127.0.0.1", RELAY_PORT), timeout=1, retries=0
                    ),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                )

    assert isinstance(errorIndication, WrongDigest)

    wrongDigestReports = [
        flags for flags, oid in relay.reports() if oid == USM_STATS_WRONG_DIGESTS
    ]
    assert wrongDigestReports
    # noAuthNoPriv and not reportable
    assert all(flags == 0x00 for flags in wrongDigestReports)
