"""SNMPv3 exchanges across an agent restart with a new snmpEngineID.

A long-lived manager SnmpEngine keeps addressing the agent by the engine ID
it discovered first. After the agent is re-initialized with a new
snmpEngineID, the agent must answer such requests with an unauthenticated
usmStatsUnknownEngineIDs Report (RFC 3414 3.2.3b), like net-snmp does.
"""

import asyncio

import pytest

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
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
from pysnmp.proto import rfc1902
from tests.udp_relay import UdpRelay

AGENT_PORT = 1631
RELAY_PORT = 1632
USER, AUTH_KEY, PRIV_KEY = "usr-sha-aes", "authkey1", "privkey1"
OLD_ENGINE_ID = bytes.fromhex("8000000001aa")
NEW_ENGINE_ID = bytes.fromhex("8000000001bb")
USM_STATS_UNKNOWN_ENGINE_IDS = (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)


def start_agent(engine_id: bytes, boots: int = 1) -> engine.SnmpEngine:
    snmpEngine = engine.SnmpEngine(rfc1902.OctetString(engine_id))

    (snmpEngineBoots,) = snmpEngine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    snmpEngineBoots.syntax = snmpEngineBoots.syntax.clone(boots)

    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(("127.0.0.1", AGENT_PORT)),
    )
    config.add_v3_user(
        snmpEngine,
        USER,
        config.USM_AUTH_HMAC96_SHA,
        AUTH_KEY,
        config.USM_PRIV_CFB128_AES,
        PRIV_KEY,
    )
    config.add_vacm_user(snmpEngine, 3, USER, "authPriv", (1, 3, 6))

    cmdrsp.GetCommandResponder(snmpEngine, context.SnmpContext(snmpEngine))
    snmpEngine.open_dispatcher()
    return snmpEngine


async def get_sysdescr(snmpEngine: SnmpEngine, port: int = AGENT_PORT):
    return await get_cmd(
        snmpEngine,
        UsmUserData(
            USER,
            AUTH_KEY,
            PRIV_KEY,
            authProtocol=USM_AUTH_HMAC96_SHA,
            privProtocol=USM_PRIV_CFB128_AES,
        ),
        await UdpTransportTarget.create(("127.0.0.1", port), timeout=1, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )


async def restart_and_get(new_engine_id: bytes, new_boots: int, port: int):
    """Poll, restart the agent, poll again from the same manager engine."""
    agent = start_agent(OLD_ENGINE_ID)
    try:
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, _, _ = await get_sysdescr(snmpEngine, port)
            assert errorIndication is None
            assert errorStatus == 0

            agent.close_dispatcher()
            await asyncio.sleep(0.1)
            agent = start_agent(new_engine_id, new_boots)

            return await get_sysdescr(snmpEngine, port)
    finally:
        agent.close_dispatcher()


@pytest.mark.asyncio
async def test_agent_reports_unknown_engine_id_after_restart():
    async with UdpRelay(("127.0.0.1", RELAY_PORT), ("127.0.0.1", AGENT_PORT)) as relay:
        await restart_and_get(NEW_ENGINE_ID, new_boots=1, port=RELAY_PORT)

    reports = relay.reports()
    assert reports
    # noAuthNoPriv, not reportable, usmStatsUnknownEngineIDs
    assert all(
        (flags, oid) == (0x00, USM_STATS_UNKNOWN_ENGINE_IDS) for flags, oid in reports
    )
