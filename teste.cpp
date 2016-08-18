#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include <dsr.h>
#include <utils.h>
#include <routediscovery.h>

unsigned int MAX_LEN = 2000;

int main (int argc, char **argv) {

  unsigned int daddr = inet_addr(argv[1]); // transforma o segundo parametro no formato de endereço de IP

  int sockfd = socket(AF_INET, SOCK_RAW, 48); //Cria file descriptor do socket

  if (sockfd < 0){ //Verifica criação do file descriptor
    perror("could not create socket");
    return 0;
  }

  int on = 1;//Variável auxiliar na definição de opções
  //Seleciona opção HDRINCL, que significa que o header IP estará incluso no pacote
  if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) == -1){
    perror("setsockopt");
    return 0;
  }
  if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof(on)) == -1){
    perror("setsockopt");
    return 0;
  }

  //source ip
  struct ifreq ifr;//interface usada para configurar network devices
  ifr.ifr_addr.sa_family = AF_INET;//Usaremos da estrutura if_addr dentro da estrutura ifreq

  ioctl(sockfd, SIOCGIFADDR, &ifr);

  char* packet = (char*) malloc(MAX_LEN);//Aloca espaço para o pacote

  //Cria ponteiros das estruturas utilizadas no pacote e ajusta suas localizações
  struct iphdr* ip = (struct iphdr*) packet;

  memset(packet, 0, MAX_LEN);//Inicia pacote
  int packet_size = create_routerqt(packet, daddr, inet_addr("0.0.0.0"));

  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(packet_size);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 10;
  ip->protocol = 48;

  FILE* f;

  struct sockaddr_in servaddr;

  char a[20], b[20];
  f = fopen("redes.txt", "r");
  unsigned int addr, mask;
  while(fscanf(f, "%s%s", a, b)!= EOF) {
    rmaddr_routerqt(packet);
    addr = inet_addr(a), mask = inet_addr(b);
    int packet_size = addaddr_routerqt(packet, addr);
    ip = (struct iphdr*) packet;
    ip->saddr = addr;
    ip->daddr = (~mask)|addr;
    ip->check = checksum((unsigned short*) packet, sizeof(struct iphdr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip->daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

    printf("\n\n");
    printpacket((unsigned char*) packet, packet_size);

    if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
    {
      perror("send failed");
    }
  }
  fclose(f);
  free(packet);

  printf("enviada\n");

  memset(packet, 0, MAX_LEN);//Inicia pacote

  unsigned int addrlen = 0;
  int bytesrecv = recvfrom(sockfd, packet, packet_size, 0, NULL, &addrlen);//Recebe a resposta
  printf("recebida\n");

  if (bytesrecv < 1){
    perror("recv failed\n");
  }
  else{
    printf("\n\n");
    printpacket((unsigned char*) packet, bytesrecv);
  }

  free(packet);
  close(sockfd);
  return 0;
}
