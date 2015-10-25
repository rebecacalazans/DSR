#include <netinet/ip.h>
#include <dsr.h>
#include <utils.h>
#include <routediscovery.h>
#include <arpa/inet.h>

unsigned int create_routerqt (char *packet, unsigned int target, unsigned int saddr) {
  struct iphdr* ip = (struct iphdr*) packet;

  unsigned int packet_len = sizeof(struct iphdr) + sizeof(struct routerqt_hdr) + sizeof(unsigned int);

  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(packet_len);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 1;
  ip->protocol = 48;
  ip->saddr = saddr;
  ip->daddr = inet_addr("255.255.255.255");

  struct routerqt_hdr *routerqt = (struct routerqt_hdr*) (packet + sizeof(struct iphdr));

  routerqt->next_hdr = 0;
  routerqt->f = 0;
  routerqt->payload_len = 12;
  routerqt->type = 1;
  routerqt->data_len = 10;
  routerqt->identification = generate_identification(saddr);
  routerqt->taddr = target;

  unsigned int *addr = (unsigned int*) (packet + sizeof(struct iphdr) + sizeof(struct routerqt_hdr));
  *addr = saddr;

  return packet_len;
}

unsigned int addaddr_routerqt (char *packet, unsigned int saddr) {
  struct iphdr* ip = (struct iphdr*) packet;

  ip->tot_len += 4;
  ip->saddr = saddr;

  struct routerqt_hdr *routerqt = (struct routerqt_hdr*) (packet + sizeof(struct iphdr));

  unsigned int *addr = (unsigned int*) (packet + sizeof(struct iphdr) + sizeof(struct routerqt_hdr) + routerqt->data_len-6);
  *addr = saddr;

  routerqt->payload_len += 4;
  routerqt->data_len += 4;

  unsigned int packet_len = sizeof(struct iphdr) + sizeof(struct routerqt_hdr) + routerqt->data_len - 6;

  return packet_len;
}
