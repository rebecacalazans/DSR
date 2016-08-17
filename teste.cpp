#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include <dsr.h>
#include <utils.h>
#include <routediscovery.h>

unsigned int MAX_LEN = 2000;

int main (int argc, char **argv) {

  unsigned int daddr = inet_addr("10.0.0.2"); // transforma o segundo parametro no formato de endereço de IP

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); //Cria file descriptor do socket

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

  //source ip
  struct ifreq ifr;//interface usada para configurar network devices
  ifr.ifr_addr.sa_family = AF_INET;//Usaremos da estrutura if_addr dentro da estrutura ifreq

  ioctl(sockfd, SIOCGIFADDR, &ifr);

  char* packet = (char*) malloc(MAX_LEN);//Aloca espaço para o pacote

  //Cria ponteiros das estruturas utilizadas no pacote e ajusta suas localizações
  struct iphdr* ip = (struct iphdr*) packet;

  memset(packet, 0, MAX_LEN);//Inicia pacote
  int packet_size = create_routerqt(packet, daddr, daddr);

  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(packet_size);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 1;
  ip->protocol = htons(48);
  ip->saddr = daddr;
  ip->daddr = daddr;
  ip->check = checksum((unsigned short*) packet, sizeof(struct iphdr));
  printf("\n\n");
  printpacket((unsigned char*) packet, packet_size);


  //Estrutura utilizada para endereçamento no envio do pacote
  struct sockaddr_in servaddr;
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = daddr;
  memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));


  if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr)) < 1)//Envia pacote e verifica envio
  {
    perror("send failed");
    return 0;
  }
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
