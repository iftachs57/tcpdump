Supported_Protocols = {
    "TCP": {
        "src": lambda p: p.tcp.srcport,
        "dst": lambda p: p.tcp.dstport,
    },
    "UDP": {
        "src": lambda p: p.udp.srcport,
        "dst": lambda p: p.udp.dstport,
    },
    "ICMP": {
        "src": lambda p: getattr(p.icmp, "type", "0"),
        "dst": lambda p: getattr(p.icmp, "code", "0"),
    },
    "TLS": {
        "src": lambda p: p.tcp.srcport,
        "dst": lambda p: p.tcp.dstport,
    },
    "DNS": {
        "src": lambda p: getattr(p, "udp", getattr(p, "tcp")).srcport,
        "dst": lambda p: getattr(p, "udp", getattr(p, "tcp")).dstport,
    },
}

Output_Report = """
            ___________________________________________
            Packet Num - {}
            Timestamp - {}
            Source IP - {} - SRCPort - {} 
            Destination - {} - DSCPort - {}
            Protocol - {}
            ___________________________________________
            """

Output = "PckList"
Errors = "Errors"

Main_Menu = """
    Enter your choice:
    1) Enter pcap/pcapng file
    2) Print report on current file
    3) Export current Report as Json file
    4) Exit
    """
Enter_File_Location = "Please enter your pcap/pcapng file location"
Exit_Massage = "Thank you and goodbye"
Input_Error = "Input Error"
Saving_Location = "Please enter your saving location"
Enter_Files_Name = "give a name to your file:"
Not_File_Path = "you didnt add file path"
Press = "press enter to continue"
IPCount = "IP - {} ,appeared - {} times"
GetPacketF = "GetPackets failed for {}"
