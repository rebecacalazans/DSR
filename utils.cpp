#include <arpa/inet.h>
#include <stdio.h>

unsigned short checksum(unsigned short* ptr, int nbytes) {
  int sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1)
    sum += (unsigned short)(*((unsigned char*)ptr));

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}
unsigned short generate_identification(unsigned int saddr) {
  static unsigned char c;
  return (htonl(saddr) << 8) | c++;
}
void printcharb(unsigned char c) {
  unsigned char aux = 128;
  for (int i = 0; i < 8; i++) {
    printf("%d", (c & aux)? 1: 0);
    aux >>=1;
  }
}
void printpacket(unsigned char* ptr, unsigned int nbytes) {
  while (nbytes) {
    for (int i = 0; i < 4; i++) {
      printcharb(*ptr);
      printf(" ");
      ptr++;
      if (--nbytes <= 0)
        break;
    }
    printf("\n");
  }
}

