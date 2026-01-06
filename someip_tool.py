"""
SOME/IP & SOME/IP-SD debugging toolkit.

This script focuses on:
- Service Discovery monitoring.
- Subscription monitoring.
- Custom packet crafting and injection (UDP/TCP).
- Subscribe/verify/replay helper flows.

Python 3.10 compatible.
"""
from __future__ import annotations

import argparse
import binascii
import ipaddress
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from scapy.all import (
    AsyncSniffer,
    Ether,
    IPv6,
    TCP,
    UDP,
    conf,
    get_if_hwaddr,
    get_if_list,
    in6_getifaddr,
    send,
    sendp,
)
import scapy.contrib.automotive.someip as someip


DEFAULT_SD_PORT = 30490
DEFAULT_SD_MC_PORT = 30491
DEFAULT_FIND_METHOD = 0x8100
DEFAULT_SUBSCRIBE_METHOD = 0x8101


@dataclass
class InterfaceProfile:
    name: str
    mac: str
    ipv6: str


@dataclass
class ScapyComponents:
    SOMEIP: type
    SOMEIPSD: type
    sd_entry_service: type
    sd_entry_eventgroup: type
    sd_option_ipv6_endpoint: type


def resolve_ipv6_address(iface: str) -> str:
    addresses = [x for x in in6_getifaddr() if x.ifname == iface]
    for addr in addresses:
        if not addr.addr.startswith("fe80"):
            return addr.addr.split("%")[0]
    if addresses:
        return addresses[0].addr.split("%")[0]
    raise ValueError(f"No IPv6 address found for interface {iface}")


def choose_interface(preferred: Optional[str]) -> InterfaceProfile:
    available = get_if_list()
    if preferred:
        iface = preferred
    elif conf.iface:
        iface = conf.iface
    else:
        print("Available interfaces:")
        for idx, name in enumerate(available):
            print(f"[{idx}] {name}")
        choice = input("Select interface index: ").strip()
        iface = available[int(choice)]
    mac = get_if_hwaddr(iface)
    ipv6 = resolve_ipv6_address(iface)
    return InterfaceProfile(name=iface, mac=mac, ipv6=ipv6)


def load_scapy_components() -> ScapyComponents:
    components = ScapyComponents(
        SOMEIP=someip.SOMEIP,
        SOMEIPSD=getattr(someip, "SOMEIPSD"),
        sd_entry_service=None,
        sd_entry_eventgroup=None,
        sd_option_ipv6_endpoint=None,
    )
    entry_service_candidates = [
        "SOMEIPSDEntry_Service",
        "SOMEIPSDEntryService",
    ]
    entry_eventgroup_candidates = [
        "SOMEIPSDEntry_Eventgroup",
        "SOMEIPSDEntryEventgroup",
        "SOMEIPSDEntry_EventGroup",
    ]
    ipv6_endpoint_candidates = [
        "SOMEIPSDOptionIPv6Endpoint",
        "SOMEIPSDOptionIP6Endpoint",
    ]

    for cand in entry_service_candidates:
        candidate = getattr(someip, cand, None)
        if candidate:
            components.sd_entry_service = candidate
            break
    if not components.sd_entry_service:
        raise RuntimeError("SOMEIPSDEntry Service class not found in scapy")

    for cand in entry_eventgroup_candidates:
        candidate = getattr(someip, cand, None)
        if candidate:
            components.sd_entry_eventgroup = candidate
            break
    if not components.sd_entry_eventgroup:
        raise RuntimeError("SOMEIPSDEntry Eventgroup class not found in scapy")

    for cand in ipv6_endpoint_candidates:
        candidate = getattr(someip, cand, None)
        if candidate:
            components.sd_option_ipv6_endpoint = candidate
            break
    if not components.sd_option_ipv6_endpoint:
        raise RuntimeError("SOMEIPSD IPv6 endpoint option class missing")

    return components


def format_someip_header(layer: someip.SOMEIP) -> str:
    return (
        f"ServiceID=0x{int(layer.service_id):04x} "
        f"Method/EventID=0x{int(layer.method_id):04x} "
        f"ClientID=0x{int(layer.client_id):04x} "
        f"SessionID=0x{int(layer.session_id):04x} "
        f"ProtoVer={int(layer.protocol_version)} "
        f"IfaceVer={int(layer.interface_version)} "
        f"MsgType=0x{int(layer.message_type):02x} "
        f"ReturnCode=0x{int(layer.return_code):02x}"
    )


def sniff_service_discovery(iface: InterfaceProfile, duration: Optional[int]) -> None:
    def printer(pkt):
        if someip.SOMEIP not in pkt:
            return
        layer = pkt[someip.SOMEIP]
        ipv6_src = pkt[IPv6].src if IPv6 in pkt else ""
        mac_src = pkt[Ether].src if Ether in pkt else ""
        header_info = format_someip_header(layer)
        print(f"[SD] MAC={mac_src} IPv6={ipv6_src} {header_info}")
        sd_layer = pkt.getlayer(getattr(someip, "SOMEIPSD", someip.SOMEIP))
        if sd_layer and hasattr(sd_layer, "entries"):
            for idx, entry in enumerate(getattr(sd_layer, "entries", [])):
                summary = entry.summary() if hasattr(entry, "summary") else str(entry)
                print(f"    Entry[{idx}]: {summary}")

    sniff_args = {
        "iface": iface.name,
        "prn": printer,
        "store": False,
        "filter": f"udp port {DEFAULT_SD_PORT} or udp port {DEFAULT_SD_MC_PORT}",
    }
    sniffer = AsyncSniffer(**sniff_args)
    sniffer.start()
    try:
        if duration:
            time.sleep(duration)
        else:
            print("Press Ctrl+C to stop...")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()


def sniff_subscription_requests(iface: InterfaceProfile, duration: Optional[int]) -> None:
    def printer(pkt):
        sd_layer = pkt.getlayer(getattr(someip, "SOMEIPSD", someip.SOMEIP))
        if not sd_layer or not hasattr(sd_layer, "entries"):
            return
        header = pkt[someip.SOMEIP] if someip.SOMEIP in pkt else None
        if header and int(header.method_id) not in (DEFAULT_FIND_METHOD, DEFAULT_SUBSCRIBE_METHOD):
            return
        mac_src = pkt[Ether].src if Ether in pkt else ""
        ip_src = pkt[IPv6].src if IPv6 in pkt else ""
        for entry in getattr(sd_layer, "entries", []):
            entry_type = getattr(entry, "type", None)
            if entry_type is None and hasattr(entry, "options_flags"):
                entry_type = getattr(entry, "options_flags", None)
            name = entry.__class__.__name__
            if entry_type in (5, 6) or "Subscribe" in name or "SUBSCRIBE" in name:
                sid = getattr(entry, "service_id", None)
                egid = getattr(entry, "eventgroup_id", None)
                print(
                    f"[SUBSCRIBE] MAC={mac_src} IPv6={ip_src} "
                    f"ServiceID={sid} EventGroupID={egid} EntryType={entry_type}"
                )

    sniffer = AsyncSniffer(
        iface=iface.name,
        prn=printer,
        store=False,
        filter=f"udp port {DEFAULT_SD_PORT} or udp port {DEFAULT_SD_MC_PORT}",
    )
    sniffer.start()
    try:
        if duration:
            time.sleep(duration)
        else:
            print("Press Ctrl+C to stop subscription monitor...")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()


def build_someip_payload(args, components: ScapyComponents):
    payload_bytes = bytes.fromhex(args.payload) if args.payload else b""
    layer = components.SOMEIP(
        service_id=args.service_id,
        method_id=args.method_id,
        client_id=args.client_id,
        session_id=args.session_id,
        protocol_version=args.protocol_version,
        interface_version=args.interface_version,
        message_type=args.message_type,
        return_code=args.return_code,
    ) / payload_bytes
    return layer


def send_custom_packet(args, iface: InterfaceProfile, components: ScapyComponents) -> None:
    layer = build_someip_payload(args, components)
    dst_ip = str(ipaddress.ip_address(args.dst_ip))
    src_ip = args.src_ip or iface.ipv6
    if args.transport.upper() == "UDP":
        pkt = IPv6(src=src_ip, dst=dst_ip) / UDP(sport=args.src_port, dport=args.dst_port) / layer
    else:
        pkt = IPv6(src=src_ip, dst=dst_ip) / TCP(sport=args.src_port, dport=args.dst_port, flags="PA") / layer
    send_func = send
    if args.use_layer2:
        pkt = Ether(src=iface.mac) / pkt
        send_func = sendp
    interval = args.period_ms / 1000.0 if args.period_ms else None
    if interval:
        print(f"Sending every {args.period_ms} ms. Press Ctrl+C to stop...")
        try:
            while True:
                send_func(pkt, iface=iface.name, verbose=False)
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
    else:
        send_func(pkt, iface=iface.name, verbose=True)


def build_find_service_packet(components: ScapyComponents, iface: InterfaceProfile, service_id: int, instance_id: int, major: int, minor: int):
    entry = components.sd_entry_service(
        type=1,
        index_1=0,
        index_2=0,
        service_id=service_id,
        instance_id=instance_id,
        major_version=major,
        ttl=0,
        minor_version=minor,
    )
    sd_layer = components.SOMEIPSD(entries=[entry], options=[])
    header = components.SOMEIP(
        service_id=0xffff,
        method_id=DEFAULT_FIND_METHOD,
        client_id=0x0001,
        session_id=0x0001,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=0x02,
        return_code=0x00,
    )
    pkt = IPv6(src=iface.ipv6, dst="ff02::1") / UDP(sport=DEFAULT_SD_PORT, dport=DEFAULT_SD_PORT) / header / sd_layer
    return pkt


def build_subscribe_packet(
    components: ScapyComponents,
    iface: InterfaceProfile,
    service_id: int,
    instance_id: int,
    eventgroup_id: int,
    major: int,
    ttl: int,
    remote_ip: str,
    remote_port: int,
) -> someip.SOMEIP:
    entry = components.sd_entry_eventgroup(
        type=6,
        index_1=0,
        index_2=0,
        service_id=service_id,
        instance_id=instance_id,
        major_version=major,
        ttl=ttl,
        eventgroup_id=eventgroup_id,
    )
    endpoint_option = components.sd_option_ipv6_endpoint(address=iface.ipv6, l4proto=17, port=remote_port)
    sd_layer = components.SOMEIPSD(entries=[entry], options=[endpoint_option])
    header = components.SOMEIP(
        service_id=service_id,
        method_id=DEFAULT_SUBSCRIBE_METHOD,
        client_id=0x0001,
        session_id=0x0002,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=0x02,
        return_code=0x00,
    )
    pkt = IPv6(src=iface.ipv6, dst=remote_ip) / UDP(sport=DEFAULT_SD_PORT, dport=DEFAULT_SD_PORT) / header / sd_layer
    return pkt


def await_ack(iface: InterfaceProfile, components: ScapyComponents, service_id: int, timeout: int) -> bool:
    ack_received = False

    def handler(pkt):
        nonlocal ack_received
        if someip.SOMEIP not in pkt:
            return
        layer = pkt[someip.SOMEIP]
        if int(layer.service_id) != service_id:
            return
        ttl = None
        sd_layer = pkt.getlayer(components.SOMEIPSD)
        if sd_layer and getattr(sd_layer, "entries", None):
            entry = sd_layer.entries[0]
            ttl = getattr(entry, "ttl", None)
        if ttl is None:
            return
        if ttl > 0:
            print(f"ACK received with TTL={ttl}")
            ack_received = True
        else:
            print(f"NACK received (TTL={ttl})")
            ack_received = False

    sniffer = AsyncSniffer(
        iface=iface.name,
        prn=handler,
        store=False,
        filter=f"udp port {DEFAULT_SD_PORT} or udp port {DEFAULT_SD_MC_PORT}",
    )
    sniffer.start()
    sniffer.join(timeout=timeout)
    sniffer.stop()
    return ack_received


def subscribe_flow(args, iface: InterfaceProfile, components: ScapyComponents) -> None:
    if args.scenario == "find":
        find_pkt = build_find_service_packet(
            components,
            iface,
            args.service_id,
            args.instance_id,
            args.major_version,
            args.minor_version,
        )
        print("Sending FindService request...")
        send(find_pkt, iface=iface.name, verbose=False)
        print("Waiting for OfferService...")
    else:
        print("Waiting for OfferService before subscribing...")

    offer = capture_offer(
        iface=iface,
        components=components,
        service_id=args.service_id,
        instance_id=args.instance_id,
        timeout=args.timeout,
    )
    if not offer:
        print("OfferService not received before timeout")
        return
    remote_ip = offer[IPv6].src if IPv6 in offer else args.remote_ip
    remote_port = offer[UDP].sport if UDP in offer else DEFAULT_SD_PORT

    subscribe_pkt = build_subscribe_packet(
        components,
        iface,
        args.service_id,
        args.instance_id,
        args.eventgroup_id,
        args.major_version,
        args.ttl,
        remote_ip,
        remote_port,
    )
    print(f"Sending SubscribeEventgroup to {remote_ip}:{remote_port}...")
    send(subscribe_pkt, iface=iface.name, verbose=False)
    print("Waiting for ACK/NACK...")
    if not await_ack(iface, components, args.service_id, args.timeout):
        print("Subscription failed or timed out")
        return
    print("Subscription acknowledged. Listening for service traffic...")
    sniff_service_traffic(iface, args.service_id)


def capture_offer(iface: InterfaceProfile, components: ScapyComponents, service_id: int, instance_id: int, timeout: int):
    offer_pkt = None

    def handler(pkt):
        nonlocal offer_pkt
        if components.SOMEIPSD not in pkt or offer_pkt is not None:
            return
        sd_layer = pkt[components.SOMEIPSD]
        for entry in getattr(sd_layer, "entries", []):
            if getattr(entry, "service_id", None) == service_id and getattr(entry, "instance_id", None) == instance_id:
                offer_pkt = pkt
                break

    sniffer = AsyncSniffer(
        iface=iface.name,
        prn=handler,
        store=False,
        filter=f"udp port {DEFAULT_SD_PORT} or udp port {DEFAULT_SD_MC_PORT}",
    )
    sniffer.start()
    sniffer.join(timeout=timeout)
    sniffer.stop()
    return offer_pkt


def sniff_service_traffic(iface: InterfaceProfile, service_id: int):
    def printer(pkt):
        if someip.SOMEIP not in pkt:
            return
        layer = pkt[someip.SOMEIP]
        if int(layer.service_id) != service_id:
            return
        mac_src = pkt[Ether].src if Ether in pkt else ""
        ipv6_src = pkt[IPv6].src if IPv6 in pkt else ""
        header_info = format_someip_header(layer)
        payload_hex = binascii.hexlify(bytes(layer.payload)).decode() if layer.payload else ""
        print(f"[REPLAY] MAC={mac_src} IPv6={ipv6_src} {header_info} Payload={payload_hex}")

    sniffer = AsyncSniffer(
        iface=iface.name,
        prn=printer,
        store=False,
    )
    sniffer.start()
    try:
        print("Press Ctrl+C to stop listening...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()


def int_hex(value: str) -> int:
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOME/IP & SOME/IP-SD diagnostic toolkit")
    parser.add_argument("--iface", help="Network interface to use")

    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Service Discovery listener")
    discover.add_argument("--duration", type=int, help="Optional capture duration in seconds")

    monitor = subparsers.add_parser("monitor-subscriptions", help="Monitor subscription requests")
    monitor.add_argument("--duration", type=int, help="Optional capture duration in seconds")

    inject = subparsers.add_parser("inject", help="Custom SOME/IP packet injection")
    inject.add_argument("--transport", choices=["UDP", "TCP"], default="UDP")
    inject.add_argument("--src-ip", dest="src_ip", help="Source IPv6 address (default: interface IPv6)")
    inject.add_argument("--dst-ip", dest="dst_ip", required=True, help="Destination IPv6 address")
    inject.add_argument("--src-port", dest="src_port", type=int, default=30490)
    inject.add_argument("--dst-port", dest="dst_port", type=int, default=30490)
    inject.add_argument("--service-id", type=int_hex, required=True)
    inject.add_argument("--method-id", type=int_hex, required=True)
    inject.add_argument("--client-id", type=int_hex, required=True)
    inject.add_argument("--session-id", type=int_hex, required=True)
    inject.add_argument("--protocol-version", type=int_hex, default=1)
    inject.add_argument("--interface-version", type=int_hex, default=1)
    inject.add_argument("--message-type", type=int_hex, default=0x02)
    inject.add_argument("--return-code", type=int_hex, default=0)
    inject.add_argument("--payload", default="", help="Hex payload without spaces")
    inject.add_argument("--period-ms", type=int, default=0, help="Periodic send interval in milliseconds")
    inject.add_argument("--use-layer2", action="store_true", help="Send with Ethernet layer (sets source MAC)")

    subscribe = subparsers.add_parser("subscribe", help="Subscribe, verify & replay flow")
    subscribe.add_argument("--scenario", choices=["find", "offer"], default="find")
    subscribe.add_argument("--service-id", type=int_hex, required=True)
    subscribe.add_argument("--instance-id", type=int_hex, required=True)
    subscribe.add_argument("--eventgroup-id", type=int_hex, required=True)
    subscribe.add_argument("--major-version", type=int, default=1)
    subscribe.add_argument("--minor-version", type=int, default=1)
    subscribe.add_argument("--ttl", type=int, default=3)
    subscribe.add_argument("--timeout", type=int, default=10, help="Timeout waiting for offer/ack")
    subscribe.add_argument("--remote-ip", default="ff02::1", help="Remote IPv6 for SD messages")
    subscribe.add_argument("--remote-port", type=int, default=DEFAULT_SD_PORT)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    iface = choose_interface(args.iface)
    components = load_scapy_components()

    if args.command == "discover":
        sniff_service_discovery(iface, args.duration)
    elif args.command == "monitor-subscriptions":
        sniff_subscription_requests(iface, args.duration)
    elif args.command == "inject":
        send_custom_packet(args, iface, components)
    elif args.command == "subscribe":
        subscribe_flow(args, iface, components)
    else:
        parser.error("Unknown command")
    return 0


if __name__ == "__main__":
    sys.exit(main())
