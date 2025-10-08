Supported_Protocols = {
    "TCP": {
        "src": lambda packet: packet.tcp.port,
        "dst": lambda packet: packet.tcp.dstport,
    },
    "UDP": {
        "src": lambda packet: packet.udp.port,
        "dst": lambda packet: packet.udp.dstport,
    },
    "ICMP": {
        "src": "0",
        "dst": "0"
    },
    "TLS": {
        "src": lambda packet: packet.tcp.port,
        "dst": lambda packet: packet.tcp.dstport,
    },
    "DNS": {
        "src": lambda packet: packet.tcp.port,
        "dst": lambda packet: packet.tcp.dstport,
    }
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
Error_Output = """
            ___________________________________________
            Line {} unsupported protocol
            Packet type {}
            ___________________________________________
            """
Protocol = "ip"
IP_Version = "4"
IP_Field = "version"
Output="PckList"
Errors="Errors"
Main_Menu="""
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