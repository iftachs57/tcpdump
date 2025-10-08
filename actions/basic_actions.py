import asyncio
import json
import logging
import os

import pyshark

from consts import consts
from structs.basic_structs import Packet


def _ensure_event_loop():
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


def GetPackets(filepath: str) -> dict:
    pcklist: list[Packet] = []
    errlist: list = []

    try:
        _ensure_event_loop()
        capture = pyshark.FileCapture(filepath)
        try:
            for packet in capture:
                # Require IP and IPv4
                if not hasattr(packet, consts.Protocol):
                    logging.info("Line %s: no IP layer", getattr(packet, "number", "?"))
                    errlist.append(packet)
                    continue

                if getattr(packet.ip, consts.IP_Field, None) != consts.IP_Version:
                    logging.info("Line %s: non-IPv4", getattr(packet, "number", "?"))
                    errlist.append(packet)
                    continue

                pro = packet.highest_layer
                if pro not in consts.Supported_Protocols:
                    logging.info("Line %s: unsupported protocol %s", getattr(packet, "number", "?"), pro)
                    errlist.append(packet)
                    continue

                accessors = consts.Supported_Protocols[pro]
                try:
                    src_port = accessors["src"](packet) if callable(accessors.get("src")) else None
                    dst_port = accessors["dst"](packet) if callable(accessors.get("dst")) else None
                except Exception as e:
                    logging.info("Line %s: port extract failed: %s", getattr(packet, "number", "?"), e)
                    errlist.append(packet)
                    continue

                ip_src = getattr(packet.ip, "src", None)
                ip_dst = getattr(packet.ip, "dst", None)
                # timestamp fields can vary; fall back gracefully
                ts = getattr(getattr(packet, "frame_info", None), "time_utc", None) \
                     or getattr(getattr(packet, "frame_info", None), "time", None)

                new_pckt = Packet(
                    Num=int(getattr(packet, "number", 0)),
                    Timestamp=str(ts) if ts is not None else "",
                    Source=str(ip_src) if ip_src is not None else "",
                    Destination=str(ip_dst) if ip_dst is not None else "",
                    SourcePort=str(src_port) if src_port is not None else None,
                    DestinationPort=str(dst_port) if dst_port is not None else None,
                    Protocol=str(pro) if pro is not None else None,
                )
                pcklist.append(new_pckt)
        finally:
            try:
                capture.close()
            except Exception:
                pass

        return {consts.Output: pcklist, consts.Errors: errlist}

    except Exception as e:
        logging.exception("GetPackets failed for %s", filepath)
        return {consts.Output: [], consts.Errors: [e]}


def PrintSrcIPCount(pcklist: list[Packet]):
    ipdic: dict[str, int] = {}
    for pck in pcklist:
        src = pck.Source
        ipdic[src] = ipdic.get(src, 0) + 1
    print(ipdic)


def FinishedReport(pcklist: list[Packet], errlist: list):
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

    for err in errlist:
        if hasattr(err, "number") and hasattr(err, "highest_layer"):
            err_output = consts.Error_Output.format(err.number, err.highest_layer)
        else:
            err_output = f"\n[Error] {repr(err)}\n"
        print(err_output)


def ConvertToDict(pcklist: list[Packet], errlist: list) -> dict[int, dict]:
    output_dict: dict[int, dict] = {}
    for pck in pcklist:
        try:
            data = pck.model_dump()
        except AttributeError:
            data = pck.dict()
        output_dict[pck.Num] = data

    for err in errlist:
        if hasattr(err, "number") and hasattr(err, "highest_layer"):
            output_dict[int(getattr(err, "number", 0))] = f"packet protocol - {getattr(err, 'highest_layer')}"
        else:
            output_dict[len(output_dict) + 1] = f"error - {repr(err)}"
    return output_dict


def SaveToPC(file_location: str, files_name: str, data: dict[int, dict]):
    path = os.path.expanduser(file_location)
    os.makedirs(path, exist_ok=True)
    full_path = os.path.join(path, files_name)
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"JSON data successfully saved to: {full_path}")
    except IOError as e:
        print(f"Error saving JSON data: {e}")


def PckLists(file_location: str):
    output = GetPackets(file_location)
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


def Report(file_location: str):
    pcklst, errlst = PckLists(file_location)
    PrintSrcIPCount(pcklst)
    FinishedReport(pcklst, errlst)
