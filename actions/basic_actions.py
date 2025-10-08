import asyncio
import json
import os

import pyshark

from consts import consts
from structs.basic_structs import Packet


### Ensures that an asyncio event loop is available in the current thread; creates one if necessary.
def _ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


### Reads packets from a PCAP file, filters by IPv4 and supported protocols, and returns valid packets and errors.
def get_packets(filepath: str) -> dict:
    pcklist: list[Packet] = []
    errlist: list = []

    try:
        _ensure_event_loop()
        capture = pyshark.FileCapture(filepath)
        try:
            for packet in capture:
                if not hasattr(packet, "ip"):
                    print(f"Line {getattr(packet, 'number', '?')}: no IP layer")
                    errlist.append(packet)
                    continue

                if getattr(packet.ip, "version", None) != "4":
                    print(f"Line {getattr(packet, 'number', '?')}: non-IPv4")
                    errlist.append(packet)
                    continue

                pro = packet.highest_layer
                if pro not in consts.Supported_Protocols:
                    print(f"Line {getattr(packet, 'number', '?')}: unsupported protocol {pro}")
                    errlist.append(packet)
                    continue

                accessors = consts.Supported_Protocols[pro]
                try:
                    src_port = accessors["src"](packet) if callable(accessors.get("src")) else None
                    dst_port = accessors["dst"](packet) if callable(accessors.get("dst")) else None
                except Exception as e:
                    print(f"Line {getattr(packet, 'number', '?')}: port extract failed: {e}")
                    errlist.append(packet)
                    continue

                ip_src = getattr(packet.ip, "src", None)
                ip_dst = getattr(packet.ip, "dst", None)
                ts = getattr(getattr(packet, "frame_info", None), "time_utc", None) \
                     or getattr(getattr(packet, "frame_info", None), "time", None)

                new_pckt = Packet(
                    Num=int(getattr(packet, "number", 0)),
                    Timestamp=str(ts) if ts is not None else "" and print(f"packet {packet.Num} doesnt have TimeStamp"),
                    Source=str(ip_src) if ip_src is not None else "" and print(
                        f"packet {packet.Num} doesnt have SourceIP"),

                    Destination=str(ip_dst) if ip_dst is not None else "" and print(
                        f"packet {packet.Num} doesnt have DestinationIP"),
                    SourcePort=str(src_port) if src_port is not None else None and print(
                        f"packet {packet.Num} doesnt have SRCPort"),
                    DestinationPort=str(dst_port) if dst_port is not None else None and print(
                        f"packet {packet.Num} doesnt have DSTPort"),
                    Protocol=str(pro) if pro is not None else None and print(
                        f"packet {packet.Num} doesnt have Protocol", ),
                )
                pcklist.append(new_pckt)
        finally:
            try:
                capture.close()
            except Exception as e:
                print(e)
                pass

        return {consts.Output: pcklist, consts.Errors: errlist}

    except Exception as e:
        print(consts.GetPacketF.format(filepath))
        return {consts.Output: [], consts.Errors: [e]}


### Counts occurrences of each source and destination IP address in the packet list.
def ip_count(pcklist: list[Packet]) -> dict[str, int]:
    ipdic: dict[str, int] = {}
    for pck in pcklist:
        src = pck.Source
        dst = pck.Destination
        ipdic[src] = ipdic.get(src, 0) + 1
        ipdic[dst] = ipdic.get(dst, 0) + 1
    return ipdic


### Prints a formatted report of packet details and IP appearance counts.
def finished_report(pcklist: list[Packet], count: dict[str, int]):
    for pck in pcklist:
        output = consts.Output_Report.format(
            pck.Num,
            pck.Timestamp,
            pck.Source,
            pck.SourcePort,
            pck.Destination,
            pck.DestinationPort,
            pck.Protocol
        )
        print(output)

    for ip in count:
        print(consts.IPCount.format(ip, count[ip]))


### Converts packet and error lists into a dictionary format suitable for JSON serialization.
def convert_pck_to_dict(pcklist: list[Packet], errlist: list) -> dict[int, dict]:
    output_dict: dict[int, dict] = {}
    for pck in pcklist:
        try:
            data = pck.model_dump()
        except AttributeError:
            data = pck.model_dump()
        output_dict[pck.Num] = data

    for err in errlist:
        if hasattr(err, "number") and hasattr(err, "highest_layer"):
            output_dict[int(getattr(err, "number", 0))] = f"packet protocol - {getattr(err, 'highest_layer')}"
        else:
            output_dict[len(output_dict) + 1] = f"error - {repr(err)}"
    return output_dict


### Saves packet data and IP count summary to a JSON file in the specified location.
def save_to_pc(file_location: str, files_name: str, data: dict[int, dict], count: dict[str, int]):
    path = os.path.expanduser(file_location)
    os.makedirs(path, exist_ok=True)
    full_path = os.path.join(path, files_name)
    combined = {
        "packets": data,
        "IP appearances": count
    }
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(combined, f, indent=4, ensure_ascii=False)
        print(f"JSON data successfully saved to: {full_path}")
    except IOError as e:
        print(f"Error saving JSON data: {e}")


### Wrapper function that retrieves packets and errors from a file, with type checks and fallbacks.
def pck_lists(file_location: str):
    output = get_packets(file_location)
    if not isinstance(output, dict):
        return [], [f"unexpected producer type: {type(output).__name__}"]
    pcklst = output.get(consts.Output, [])
    errlist = output.get(consts.Errors, [])
    if not isinstance(pcklst, list):
        errlist = list(errlist) if isinstance(errlist, list) else []
        errlist.append(f"invalid {consts.Output} type: {type(pcklst).__name__}")
        pcklst = []
    if not isinstance(errlist, list):
        errlist = [f"invalid {consts.Errors} type: {type(errlist).__name__}"]
    return pcklst, errlist


### Main pipeline to extract, analyze, and print packet info and IP counts from a PCAP file.
def report(file_location: str):
    pcklst, errlst = pck_lists(file_location)
    count = ip_count(pcklst)
    finished_report(pcklst, count)
