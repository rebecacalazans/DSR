#pragma once

unsigned short checksum(unsigned short* ptr, int nbytes);
unsigned short generate_identification(unsigned int saddr);
void printcharb(unsigned char c);
void printpacket(unsigned char* ptr, unsigned int nbytes);
