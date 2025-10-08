import logging
import sys

import pyshark
import json
import os
from consts import consts
from structs.basic_structs import Packet


def GetPackets(filepath: str):
    try:
        pcklist = []
        errlist = []
        output = {}
        capture = pyshark.FileCapture(filepath)
        for packet in capture:
            if not hasattr(packet, consts.Protocol) or getattr(packet.ip, consts.IP_Field, None) != consts.IP_Version:
                logging.info(f"Line {packet.number} unsupported protocol")
                errlist.append(packet)
                continue
            elif not packet.highest_layer in consts.Supported_Protocols:
                logging.info(f"Line {packet.number} unsupported protocol")
                errlist.append(packet)
                continue
            else:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                pro = packet.highest_layer
                accessors = consts.Supported_Protocols[pro]
                src_port = accessors.get("src")(packet) if callable(accessors.get("src")) else accessors.get("src")
                dst_port = accessors.get("dst")(packet) if callable(accessors.get("dst")) else accessors.get("dst")
                new_pckt = Packet(Num=packet.number, Timestamp=packet.frame_info.time_utc, Source=ip_src,
                                  Destination=ip_dst,
                                  SourcePort=src_port,
                                  DestinationPort=dst_port,
                                  Protocol=pro)
                pcklist.append(new_pckt)
        output[consts.Output] = pcklist
        output[consts.Errors] = errlist
        capture.close()
        return output
    except Exception as e:
        logging.error(e)


def PrintSrcIPCount(pcklist: list[Packet]):
    ipdic = {}
    for pck in pcklist:
        src = pck.Source
        ipdic[src] = ipdic.get(src, 0) + 1
    print(ipdic)


def FinishedReport(pcklist: list[Packet], errlist: list[Packet]):
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
        err_output = consts.Error_Output.format(
            err.number,
            err.highest_layer
        )
        print(err_output)


def ConvertToDict(pcklist: list[Packet], errlist: list) -> dict[int, dict]:
    output_dict = {}
    for pck in pcklist:
        output_dict[pck.Num] = pck.__dict__
    for err in errlist:
        output_dict[err.number] = "packets protocol- "+str(err.highest_layer)
    return output_dict

def SaveToPC(file_location: str,files_name: str, data: dict[int, dict]):
    path = os.path.expanduser(file_location)
    full_path = os.path.join(path, files_name)
    try:
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(data,f, indent=4)
        print(f"JSON data successfully saved to: {full_path}")
    except IOError as e:
        print(f"Error saving JSON data: {e}")

def PckLists(file_location: str):
    output = GetPackets(file_location)
    pcklst = output[consts.Output]
    errlist = output[consts.Errors]
    return pcklst, errlist

def Report(file_location: str):
    pcklst, errlst = PckLists(file_location)
    PrintSrcIPCount(pcklst)
    FinishedReport(pcklst, errlst)