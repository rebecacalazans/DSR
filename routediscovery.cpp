#include <dsr.h>
#include <utils.h>
#include <netinet/ip.h>
#include <routediscovery.h>
#include <arpa/inet.h>
#include <time.h>

#include <map>

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

void addroute (std::map<unsigned int, struct route*> &routes, unsigned int* addrs, int n) {
  struct route* ptr;
  ptr = (struct route*) malloc (sizeof(struct route) + n * sizeof(unsigned int));
  ptr->t = clock();
  ptr->route_len = n;
  ptr->hosts = (unsigned int*) (ptr + 1);
  for (int i = 0; i < n; i++) {
    ptr->hosts[i] = addrs[i];
  }
  routes[ptr->hosts[n-1]]=ptr;
}

//Essa função obtém, a partir da route request, a rota até o nó que enviou a requisição
void addroute (std::map<unsigned int, struct route*> &routes, char *packet, unsigned int laddr) {
  struct route* ptr;

  struct routerqt_hdr *routerqt = (struct routerqt_hdr*) (packet + sizeof(struct iphdr));
  //O ponteiro abaixo aponta para o primeiro endereço contido no pacote
  unsigned int *addr = (unsigned int*) (packet + sizeof(struct iphdr) + sizeof(struct routerqt_hdr));
  int pos = 0;
  while (*addr != laddr) {
    addr++;
    pos++;
  }
  int n = pos + 1;

  ptr = (struct route*) malloc (sizeof(struct route) + n * sizeof(unsigned int));
  ptr->t = clock();
  ptr->route_len = n;
  ptr->hosts = (unsigned int*) (ptr + 1);

  for (int i = 0; i < n; i++) {
    ptr->hosts[i] = *addr;
    addr--;
  }
  routes[ptr->hosts[n-1]]=ptr;
}
