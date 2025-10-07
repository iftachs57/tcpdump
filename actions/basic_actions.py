import pyshark

def GetPackets(filepath : str):
    capture = pyshark.FileCapture(filepath)
    for packet in capture:
        print(packet)