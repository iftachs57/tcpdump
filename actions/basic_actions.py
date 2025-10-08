import logging

import pyshark

from consts import consts
from structs.basic_structs import Packet


def GetPackets(filepath: str) -> list[Packet]:
    try:
        pcklist = []
        for packet in pyshark.FileCapture(filepath):
            src_port = consts.SRC_Port
            dst_port = consts.DST_Port
            ip_src = consts.IP_SRC
            ip_dst = consts.IP_DST
            pro = packet.highest_layer
            if not hasattr(packet, consts.Protocol) or getattr(packet.ip, consts.IP_Field, None) != consts.IP_Version:
                logging.info(f"Line {packet.number} unsupported version")
            elif packet.highest_layer in consts.Supported_Protocols:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                src_port = packet["tcp"]["port"]
                dst_port = packet.str(consts.Supported_Protocols.get(packet.highest_layer)).dstport
                pro = packet.highest_layer
            new_pckt = Packet(Num=packet.number, Timestamp=packet.frame_info.time_utc, Source=ip_src,
                              Destination=ip_dst,
                              SourcePort=src_port,
                              DestinationPort=dst_port,
                              Protocol=pro)
            pcklist.append(new_pckt)
        return pcklist
    except Exception as e:
        logging.error(e)


def CountSrcIP(pcklist: list[Packet]) -> dict[str, int]:
    ipdic = {}
    for pck in pcklist:
        src = pck.Source
        ipdic[src] = ipdic.get(src, 0) + 1
    return ipdic


def FinishingReport(pcklist: list[Packet]):
    for pck in pcklist:
        if pck.DestinationPort != "0":
            output = f"""
            ___________________________________________
            Packet Num - {pck.Num}
            Timestamp - {pck.Timestamp}
            Source IP - {pck.Source} - SRCPort - {pck.SourcePort} 
            Destination - {pck.Destination} - DSCPort - {pck.DestinationPort}
            Protocol - {pck.Protocol}
            ___________________________________________
            """
        else:
            output = f"""
            ___________________________________________
            "Line {pck.Num} unsupported version"
            ___________________________________________
            """
        print(output)
