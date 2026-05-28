"""Unit tests for the pure Sysmon-XML -> Syscall* translator (PRD §9.2.2).

Cross-platform: imports only the translator (stdlib + auditor), never pywin32, so it runs on Windows
now and on Linux/CI. Feeds rendered Sysmon event XML (file fixtures + inline samples) through
``parse_event_data`` and ``translate`` and asserts the correct schema and field mapping.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from auditor.events.schemas import (
    DnsQueryEvent,
    SyscallConnect,
    SyscallExecve,
    SyscallOpenat,
)
from involuntary.windows_sysmon.translator import parse_event_data, translate

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sysmon"
RUN_ID = uuid4()
TENANT_ID = uuid4()


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# --------------------------------- parse_event_data ---------------------------------


def test_parse_event_data_process_create() -> None:
    data = parse_event_data(_load("process_create_eid1.xml"))
    assert data["event_id"] == 1
    assert data["process_id"] == 7344  # decimal ProcessId, parsed to int
    assert data["image"] == r"C:\Windows\System32\curl.exe"
    # Every EventData Data Name -> text is flattened in.
    assert data["CommandLine"].startswith("curl.exe -X POST")
    assert data["UtcTime"] == "2026-05-27 18:30:01.123"


def test_parse_event_data_strips_namespace_and_handles_missing_processid() -> None:
    # A System-only event with no EventData/ProcessId still parses; process_id is None.
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4</EventID></System></Event>"
    )
    data = parse_event_data(xml)
    assert data["event_id"] == 4
    assert data["process_id"] is None
    assert data["image"] is None


# ------------------------------------ translate -------------------------------------


def test_translate_process_create_to_execve() -> None:
    event = translate(_load("process_create_eid1.xml"), run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallExecve)
    assert event.event_type == "syscall.execve"
    assert event.channel == "INVOLUNTARY"
    assert event.binary == r"C:\Windows\System32\curl.exe"
    assert event.pid == 7344
    assert event.run_id == RUN_ID
    assert event.tenant_id == TENANT_ID
    # CommandLine split into argv.
    assert event.argv[0] == "curl.exe"
    assert "https://evil.example.com/exfil" in event.argv
    # UtcTime parsed (not "now").
    assert event.ts.year == 2026 and event.ts.month == 5 and event.ts.day == 27


def test_translate_network_connect_to_connect_ipv4() -> None:
    event = translate(_load("network_connect_eid3.xml"), run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallConnect)
    assert event.event_type == "syscall.connect"
    assert event.family == "AF_INET"  # SourceIsIpv6 == "false"
    assert event.addr == "203.0.113.66"  # DestinationIp preferred over hostname
    assert event.port == 443
    assert event.pid == 7344


def test_translate_network_connect_ipv6_family() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>3</EventID></System><EventData>"
        '<Data Name="ProcessId">9001</Data>'
        '<Data Name="SourceIsIpv6">true</Data>'
        '<Data Name="DestinationIp">2606:4700:4700::1111</Data>'
        '<Data Name="DestinationPort">853</Data>'
        "</EventData></Event>"
    )
    event = translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallConnect)
    assert event.family == "AF_INET6"
    assert event.addr == "2606:4700:4700::1111"
    assert event.port == 853
    assert event.pid == 9001


def test_translate_connect_falls_back_to_hostname_when_no_ip() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>3</EventID></System><EventData>"
        '<Data Name="ProcessId">42</Data>'
        '<Data Name="SourceIsIpv6">false</Data>'
        '<Data Name="DestinationHostname">api.anthropic.com</Data>'
        '<Data Name="DestinationPort">443</Data>'
        "</EventData></Event>"
    )
    event = translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallConnect)
    assert event.addr == "api.anthropic.com"


def test_translate_file_create_to_openat() -> None:
    event = translate(_load("file_create_eid11.xml"), run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallOpenat)
    assert event.event_type == "syscall.openat"
    assert event.path == r"C:\Users\agent\AppData\Local\Temp\exfil_payload.bin"
    assert event.flags == 0
    assert event.pid == 7344


def test_translate_dns_query_to_dns_event() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>22</EventID></System><EventData>"
        '<Data Name="ProcessId">7344</Data>'
        '<Data Name="QueryName">evil.example.com</Data>'
        '<Data Name="QueryStatus">0</Data>'
        '<Data Name="QueryResults">::ffff:203.0.113.66;203.0.113.66;</Data>'
        "</EventData></Event>"
    )
    event = translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, DnsQueryEvent)
    assert event.event_type == "syscall.dns"
    assert event.query_name == "evil.example.com"
    # Trailing empty token after the final ';' is filtered out.
    assert event.results == ["::ffff:203.0.113.66", "203.0.113.66"]
    assert event.pid == 7344


def test_translate_file_delete_to_openat_touch() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>23</EventID></System><EventData>"
        '<Data Name="ProcessId">7344</Data>'
        '<Data Name="TargetFilename">C:\\Users\\agent\\.ssh\\id_rsa</Data>'
        "</EventData></Event>"
    )
    event = translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID)
    assert isinstance(event, SyscallOpenat)  # delete mapped to a file touch (documented)
    assert event.path == r"C:\Users\agent\.ssh\id_rsa"
    assert event.pid == 7344


def test_translate_unmapped_eventid_returns_none() -> None:
    # EventID 10 (ProcessAccess) and 13 (RegistryValueSet) are intentionally unmapped for now.
    for eid in (10, 13, 255):
        xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f"<System><EventID>{eid}</EventID></System>"
            '<EventData><Data Name="ProcessId">7344</Data></EventData></Event>'
        )
        assert translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID) is None


def test_translate_no_eventid_returns_none() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System></System></Event>"
    )
    assert translate(xml, run_id=RUN_ID, tenant_id=TENANT_ID) is None
