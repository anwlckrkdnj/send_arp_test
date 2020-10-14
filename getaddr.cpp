#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

struct EthArpPacket {
        EthHdr eth_;
        ArpHdr arp_;
};

// https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
int getAtkMac(Mac* atk_mac) {
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) /* handle error*/
                return -1;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) /* handle error */
                return -1;

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		}
		else /* handle error */
                	return -1;
    	}

	if (success)
	       	memcpy(atk_mac, ifr.ifr_hwaddr.sa_data, sizeof(Mac));
	else
		return -1;

	return 0;
}

// https://technote.kr/176
int getAtkIp(Ip* atk_ip){
	struct ifreq ifr;
	int s;
 
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ);
 
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
        	return -1;
	else
		memcpy(atk_ip, ifr.ifr_addr.sa_data + 2, sizeof(Ip));
	close(s);

	return 0;
}



int sndArpRequest(char* argv, Ip* snd_ip, Mac* atk_mac, Ip* atk_ip) {
        char* dev = argv;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr)
                return -1;

        EthArpPacket packet;

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        memcpy(&packet.eth_.smac_, atk_mac, sizeof(Mac));
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        memcpy(&packet.arp_.smac_, atk_mac, sizeof(Mac));
        memcpy(&packet.arp_.sip_, atk_ip, sizeof(Ip));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        memcpy(&packet.arp_.tip_, snd_ip, sizeof(Ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0)
                return -1;

        pcap_close(handle);
        return 0;
}

int findAddr(const u_char* packet, Mac* snd_mac, Ip* snd_ip) {  // catch sender mac addr
        ArpHdr arp_;
        memcpy(&arp_, packet + sizeof(EthHdr), sizeof(ArpHdr));
        if(arp_.op_ != htons(ArpHdr::Reply))                    // determine whether arp reply
                return -1;
        if(memcmp(snd_ip, &arp_.sip_, sizeof(Ip)))              // check sender ip
                return -1;
        memcpy(snd_mac, &arp_.smac_, sizeof(Mac));
        return 0;
}

int isArpPkt(const u_char* packet) {            // determine whether arp packet
        EthHdr eth_;
        memcpy(&eth_, packet, sizeof(EthHdr));
        if(eth_.type_ != htons(ETHERTYPE_ARP))  // not arp packet
                return -1;
        return 0;                               // arp packet
}

int getSndMac(char* interface, Mac* snd_mac, Ip* snd_ip, Mac* atk_mac, Ip* atk_ip) {
        char* dev = interface;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
                return -1;
        }

        int det = 0;
        while (true) {
                if(sndArpRequest(interface, snd_ip, atk_mac, atk_ip))        // to know sender mac
                        return -1;
                for(int i = 0 ; i < 5 ; i++) {
                        struct pcap_pkthdr* header;
                        const u_char* packet;
                        int res = pcap_next_ex(handle, &header, &packet);
                        if (res == 0) continue;
                        if (res == -1 || res == -2)
                                return -1;
                        if(isArpPkt(packet))
                                continue;
                        if(!findAddr(packet, snd_mac, snd_ip)){
                                det = 1;
                                break;
                        }
                }
                if(det)
                        break;
        }

        pcap_close(handle);
        return 0;
}

