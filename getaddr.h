#pragma once

#include "mac.h"
#include "ip.h"

int getAtkMac(Mac* atk_mac);
int getAtkIp(Ip* atk_ip);
int getSndMac(char* argv, Mac* arp_smac, Ip* arp_sip, Mac* arp_tmac, Ip* arp_tip);
