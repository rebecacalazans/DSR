#pragma once
#include <map>

unsigned int create_routerqt (char *packet, unsigned int target, unsigned int saddr);
unsigned int addaddr_routerqt (char *packet, unsigned int saddr);
void addroute (std::map<unsigned int, struct route*> &routes, unsigned int* addrs, int n);
void addroute (std::map<unsigned int, struct route*> &routes, char *packet, unsigned int laddr);
unsigned int create_routereply (char *packet, char *packetrcv);
