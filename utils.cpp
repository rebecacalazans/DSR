#pragma once

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
  return (saddr << 8) | c++;
}
