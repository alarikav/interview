import pyshark
import os
import pickle

# driver method main
def main():
        capture = pyshark.FileCapture(os.path.join(os.getcwd(),'example_pcap.pcapng'))
        action = input("D for DNS Analysis | S for PCAP Analysis: ")

        if action is 'D': 
                dnsAnalysis(capture)
        elif action is 'S':
                packetAnalysis(capture)

# packet analysis
# total TCP, UDP, # packets, set of src addresses
def packetAnalysis(capture):
        packetCount = 0
        sourceAddressSet = set()
        udp = 0
        tcp = 0

        for packet in capture:
                sourceAddressSet.add(packet.ip.src)
                packetCount+=1
                if packet.transport_layer is 'TCP':
                        tcp+=1
                elif packet.transport_layer is 'UDP':
                        udp+=1

        print("TCP Packets: ", tcp)
        print("UDP Packets: ", udp)
        print("Set of IP Addresses", sourceAddressSet)
        print("Packet Count", packetCount)

        action = input('Y for DNS Analysis on same file') 
        if action is 'Y':
                dnsAnalysis(capture)

# dnsAnalysis driver 
# what OS is most likely to have this capture
def dnsAnalysis(capture):
        dnsPackets = set()
        for packet in capture:
                destination_address = packet.ip.dst
                if destination_address:
                        dnsPackets.add(destination_address)

        # DNS destinations not unique to Operating System
        file = open('/Users/alarikavoora/PycharmProjects/broadwayTechnology/dnsDestinations.txt', 'rb')
        commonDNSDestinations = pickle.load(file)
        file.close()
        
        #remove common hostnames from DNS list
        uniqueDNSList = set([x for x in dnsPackets if x not in commonDNSDestinations])
        
        # dictionary of Operating System and list of hostnames associated with the OS
        file = open('/Users/alarikavoora/PycharmProjects/broadwayTechnology/osProfiles.txt', 'rb')
        osDictionary = pickle.load(file)
        file.close()

        # comparing known OS hostnames against unique hostnames of unknown PCAP file
        analyzedList = []
        for operatingSystem, address_list in osDictionary.items():
                overlap = set(address_list) & uniqueDNSList
                percentage = float(len(overlap)) / len(address_list) * 100
                analyzedList.append([operatingSystem, percentage])

        finalList = (sorted(analyzedList, key=lambda x:x[1]))
        print(finalList)
       
        action = input('Y for PCAP Analysis on same file') 
        if action is 'Y':
                packetAnalysis(capture)

if __name__ == '__main__':
    main()
