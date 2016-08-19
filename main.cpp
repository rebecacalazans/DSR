#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

//Blibliotecas responsáveis pelo multiprocessamento
#include <thread>
#include <mutex>

//Bibliotecas das estruturas de dados utilizadas
#include <vector>
#include <queue>
#include <utility>

//Bibliotecas próprias
#include <utils.h>
#include <dsr.h>
#include <routediscovery.h>
using std::pair;
using std::make_pair;

const unsigned int MAX_LEN = 2000;

std::mutex mutrcv, mutqwerty;
std::queue <pair<unsigned char*, unsigned int> > rcv_buffer;

std::map<unsigned int, struct route*> routes;
std::map<unsigned short, int> routerqt_id;

void rcv_thread(unsigned int sockfd) {
  while(1) {
    unsigned int pcklen;
    unsigned int addrlen = 0;
    unsigned char *packet = (unsigned char*) malloc(MAX_LEN);
    pcklen = recvfrom(sockfd, packet, MAX_LEN, 0, NULL, &addrlen);

    mutrcv.lock();
    rcv_buffer.push( make_pair(packet, pcklen));
    mutrcv.unlock();
    mutqwerty.unlock();
  }
}

void process_thread(unsigned int sockfd) {

  while(1) {
    mutqwerty.lock();
    while(!rcv_buffer.empty()) {
      //printf("processando mensagem\n");
      struct sockaddr_in servaddr;

      mutrcv.lock();
      char* packet = (char*) rcv_buffer.front().first;
      unsigned int len = rcv_buffer.front().second;
      rcv_buffer.pop();
      mutrcv.unlock();

      struct iphdr* ip = (struct iphdr*) packet;
      if(ip->protocol != 48) continue;
      struct dsr_hdr* dsr = (struct dsr_hdr*) (packet + sizeof(struct iphdr));

      if(dsr->type == 1) {
        struct routerqt_hdr* dsr = (struct routerqt_hdr*) (packet + sizeof(struct iphdr));
        if(routerqt_id[dsr->identification]++) continue;

        printf("Mensagem recebida: route request:\n\n");
        printpacket((unsigned char*) packet, len);
        printf("\n\n");

        {
          struct in_addr addr;
          addr.s_addr = dsr->taddr;

          printf("Target: %s\n", inet_ntoa(addr));
        }

        char a[20], b[20];
        FILE *f;
        unsigned int addr, mask;
        int ok = 0;

        f = fopen("redes.txt", "r");

        while(fscanf(f, "%s%s", a, b)!= EOF) {
          addr = inet_addr(a), mask = inet_addr(b);
          if(addr == dsr->taddr) {
            printf("ok\n");
            ok = 1;
            break;
          }
        }
        fclose(f);

        if(ok) {
          addaddr_routerqt(packet, addr);
          addroute(routes, packet, addr);
          char* packet2 = (char*) malloc(MAX_LEN);
          int packet_size = create_routereply(packet2, packet);
          ip = (struct iphdr*) packet2;
          ip->saddr = addr;
          unsigned int *daddr = (unsigned int*) (packet2 + sizeof(struct iphdr) + sizeof(struct routereply_hdr));
          while(*daddr != addr) daddr++;
          daddr--;
          ip->daddr = *daddr;

          servaddr.sin_family = AF_INET;
          servaddr.sin_addr.s_addr = *daddr;
          memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

          ip->check = checksum((unsigned short*) packet, sizeof(struct iphdr));
          if (sendto(sockfd, packet2, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
          {
            perror("send failed");
            return;
          }
          printf("Resposta enviada:\n\n");
          printpacket((unsigned char*) packet2, packet_size);
          printf("\n\n");

          free(packet2);
        }
        else {
          f = fopen("redes.txt", "r");

          while(fscanf(f, "%s%s", a, b)!= EOF) {
            addr = inet_addr(a), mask = inet_addr(b);
            int packet_size = addaddr_routerqt(packet, addr);
            ip = (struct iphdr*) packet;
            ip->saddr = addr;
            ip->daddr = (~mask)|addr;

            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = ip->daddr;
            memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

            ip->check = checksum((unsigned short*) packet, sizeof(struct iphdr));
            if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
            {
              perror("send failed");
              return;
            }
            printf("Route request encaminhado\n\n");
            rmaddr_routerqt(packet);
          }
          fclose(f);
        }
      }
      else if(dsr->type == 2) {
        printf("Mensagem recebida: route reply:\n\n");
        struct routereply_hdr* dsr = (struct routereply_hdr*) (packet + sizeof(struct iphdr));

        unsigned int *addr = (unsigned int*) (packet + sizeof(struct iphdr) + sizeof(struct routereply_hdr)) + 1;

        if((*addr) == ip->saddr) {
          printf("Route reply recebido com sucesso\n\n");
          printpacket((unsigned char*) packet, len);
          printf("\n\n");
        }
        else {
          while((*addr) != ip->saddr) addr++;
          addr--;
          addr--;
          ip->daddr = *addr;

          printf("Route reply encaminhado\n\n");
          printpacket((unsigned char*) packet, len);
          printf("\n\n");

          char a[20], b[20];
          FILE *f;
          f = fopen("redes.txt", "r");
          unsigned int addr2, mask;

          while(fscanf(f, "%s%s", a, b)!= EOF) {
            addr2 = inet_addr(a), mask = inet_addr(b);
            if((addr2 & mask) == (ip->daddr & mask)) {
              break;
            }
          }
          fclose(f);

          ip->saddr = addr2;
          addr++;
          (*addr) = addr2;

          servaddr.sin_family = AF_INET;
          servaddr.sin_addr.s_addr = ip->daddr;
          memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

          ip->check = checksum((unsigned short*) packet, sizeof(struct iphdr));
          if (sendto(sockfd, packet, len, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
          {
            perror("send failed");
            return;
          }
        }

      }
      free(packet);
    }
  }
}

int main() {
  std::thread trcv, tprocess;

  int on = 1;

  int sockrcv = socket(AF_INET, SOCK_RAW, 48),
      socksend = socket(AF_INET, SOCK_RAW, 48);

  if(sockrcv < 0 || socksend < 0) {
    perror("could not create socket");
    return 0;
  }

  if ((setsockopt(sockrcv, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) |
       setsockopt(socksend, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) ) == -1) {
    perror("setsockopt");
    return 0;
  }
  if ((setsockopt (sockrcv, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(on))|
       setsockopt (socksend, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(on))) == -1) {
    perror("setsockopt");
    return 0;
  }

  trcv = std::thread(rcv_thread, sockrcv);
  tprocess = std::thread(process_thread, socksend);

  trcv.join();
  tprocess.join();
  return 0;
}
