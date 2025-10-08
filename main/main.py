from actions.basic_actions import GetPackets, CountSrcIP, FinishingReport

if __name__=='__main__':
    pcklst = GetPackets(r'C:\Users\Navot Shiener\Desktop\test2.pcap')
    dirpck = CountSrcIP(pcklst)
    FinishingReport(pcklst)
    #for packet in stream:
    #    GetIP(packet)