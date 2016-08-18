#pragma once
#include <time.h>

struct dsr_hdr {
  unsigned char next_hdr;
  unsigned char f;
  unsigned short payload_len;
  unsigned char type;
};

struct routerqt_hdr {
  unsigned char next_hdr;
  unsigned char f;
  unsigned short payload_len;

  unsigned char type;
  unsigned char data_len;
  unsigned short identification;
  unsigned int taddr;
};

struct routereply_hdr {
  unsigned char next_hdr;
  unsigned char f;
  unsigned short payload_len;

  unsigned char type;
  unsigned char data_len;
  unsigned char l;
  unsigned char reserved;
};

struct route {
  time_t t;
  unsigned short route_len;
  unsigned int *hosts;
};
