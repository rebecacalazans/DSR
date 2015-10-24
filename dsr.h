#pragma once

#define MAX_LEN = 1024;

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

  unsigned char reserved;
  unsigned char type;
  unsigned char data_len;
  unsigned char l;
};
