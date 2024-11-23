from scapy.all import *
interface = 'wlan0'
probeReqs = []

def sniffProves(p):

    if p.haslayer(DotllProbeReq):
        netName = p.getlayer(DotllProbeReq).info
        if netName not in probeReqs:
            probeReqs.append(netName)
            print('[+] Detected New Probre Request:'+ netName)

sniff(iface=interface,prn=sniffProves)            