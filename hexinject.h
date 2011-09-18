/*
 * hexinject.h
 *
 *  Created on: 08/mag/2010
 *      Author: Acri Emanuele
 */

#ifndef HEXINJECTION_H_
#define HEXINJECTION_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192

/*
 * Convert a 2-bytes string to a short integer.
 */
char str_to_hex(char *str) {

	assert(str != NULL);

	char hex = '\0';

	if(isdigit(str[0])) {
		hex |= (str[0] & 0x0F) << 4;
	} else {
		hex |= ((str[0]+0x09) & 0x0F) << 4;
	}

	if(isdigit(str[1])) {
		hex |= (str[1] & 0x0F);
	} else {
		hex |= ((str[1]+0x09) & 0x0F);
	}

	return hex;
}

/*
 * Convert a 2-bytes string to a short integer.
 */
void hex_to_str(char hex, char *str) {

	assert(str != NULL);

	str[0] = (hex & 0xF0) >> 4;
	str[1] = (hex & 0x0F);
	str[2] = '\0';

	if(str[0]<0x0A) {
		str[0] |= 0x30;
	} else {
		str[0] |= 0x40;
		str[0] -= 0x09;
	}

	if(str[1]<0x0A) {
		str[1] |= 0x30;
	} else {
		str[1] |= 0x40;
		str[1] -= 0x09;
	}
}

/*
 * Check if the character is hex.
 */
int is_hex(char c) {
	if ((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		return 1;
	return 0;
}

/*
 * Return the length of the hexstring.
 */
int hexstr_size(char *hexstr) {

	assert(hexstr != NULL);

	int size = 0;
	char *p = hexstr;

	/*
	 * Parse an hexstring and calculate it's size.
	 * Analyze three bytes at a time, in this format: HEX HEX (SPACE|NULL)
	 * (Ex. "FF ", "2A ", "EE")
	 */
	while ( is_hex(p[0]) && is_hex(p[1]) && (p[2] == ' ' || p[2] == '\n' || p[2] == '\0') ) {
		//printf("p[0] = %c, p[1] = %c, p[2] = %c\n", p[0], p[1], p[2] == '\0' ? 'N' : p[2]);

		size++;
		p += 3;
	}

	return size;
}

/*
 * Create a raw buffer from an hexstring.
 * The buffer must be manually free()d.
 */
char *hexstr_to_raw(char *hexstr, int *size) {

	assert(hexstr != NULL);
	assert(size != NULL);

	char *raw = NULL;
	char *p  = hexstr;

	*size = hexstr_size(hexstr);
	raw = (char *) malloc(*size); // malloc the raw buffer

	char hex[3];
	int i = 0;

	/*
	 * Parse an hexstring.
	 * Analyze three bytes at a time, in this format: HEX HEX (SPACE|NULL)
	 * (Ex. "FF ", "2A ", "EE")
	 */
	while ( is_hex(p[0]) && is_hex(p[1]) && (p[2] == ' ' || p[2] == '\n' || p[2] == '\0') ) {
		//printf("p[0] = %c, p[1] = %c, p[2] = %c\n", p[0], p[1], p[2] == '\0' ? 'N' : p[2]);

		// extract a single byte
		hex[0] = p[0];
		hex[1] = p[1];
		hex[2] = '\0';

		raw[i] = str_to_hex(hex);

		i++;
		p += 3;
	}

	//hex_dump(raw, size);

	return raw;
}

/*
 * Create an hexstring from a raw buffer.
 * The buffer must be manually free()d.
 */
char *raw_to_hexstr(char *raw, int size) {

	assert(raw != NULL);
	if(size == 0) return NULL;

	char *hexstr = NULL;

	hexstr = (char *) malloc(size*3); // malloc the hexstring

	char hex[3];
	int i = 0;
	char *p = hexstr;

	/*
	 * Parse an hexstring.
	 * Analyze three bytes at a time, in this format: HEX HEX (SPACE|NULL)
	 * (Ex. "FF ", "2A ", "EE")
	 */
	for (i=0; i<size; i++, p+=3) {

		// extract a single byte
		hex_to_str(raw[i], hex);

		p[0] = hex[0];
		p[1] = hex[1];
		p[2] = ' ';
	}


	hexstr[(size*3)-1] = '\0';
	return hexstr;
}

/*
 * Checksum IP
 */

uint16_t ip_cksum (uint16_t *buff, size_t len) {
    
    uint32_t sum = 0;
    uint16_t answer = 0;

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Checksum TCP
 */
uint16_t tcp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, uint16_t len) {

    uint32_t sum = 0;
    uint16_t answer = 0;

    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x6);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Checksum UDP
 */
uint16_t udp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, size_t len) {
   
    uint32_t sum = 0;
    uint16_t answer = 0;
    
    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x11);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Do checksum (if the packet requires it...)
 */
void do_cksum (char *raw, size_t size) {
    
    uint16_t *cksum = NULL;

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip checksum
        cksum = (uint16_t *) &raw[24];
        *cksum = 0;

        *cksum = ip_cksum((uint16_t *) &raw[14], 20);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                cksum = (uint16_t *) &raw[50];
                *cksum = 0;
                *cksum = tcp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[40];
                *cksum = 0;
                *cksum = udp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // icmp
            case 0x01:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[36];
                *cksum = 0;
                *cksum = ip_cksum((uint16_t *) &raw[34], (size-34));
                break;
        }
    }
}

/*
 * Adjust packet size fields (if the packet requires it...)
 */
void do_size (char *raw, size_t size) {
    
    uint16_t *len_field = NULL;

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip total length
        len_field = (uint16_t *) &raw[16];

        *len_field = size - 14; // size - ethernet header
        *len_field = htons(*len_field);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                // tcp uses header length field
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                len_field = (uint16_t *) &raw[38];
                *len_field = size - 14 - ((raw[14] & 0xF) * 4); // size - ethernet header - ip header
                *len_field = htons(*len_field);
                break;

            // icmp
            case 0x01:
                if (size < 42) return; // size check
                // no size field
                break;
        }
    }
}

/*
 * Inject a raw buffer to the network
 */
int inject_raw(pcap_t *fp, char *raw, size_t size) {

	assert(fp != NULL);
	assert(raw != NULL);

	int err = 0;
    
    /* packet size (if enabled) */
    do_size (raw, size);

    /* checksum */
    do_cksum (raw, size);

	/* Send down the packet */
	err = pcap_sendpacket(fp, (unsigned char *) raw, size);

	return err;
}

/*
 * Inject an hexstring to the network
 */
int inject_hexstr(pcap_t *fp, char *hexstr) {

	assert(fp != NULL);
	assert(hexstr != NULL);

	int err = 0;
	int size = 0;
	char *raw = NULL;

	raw = hexstr_to_raw(hexstr, &size);

	/* Send down the packet */
	err = inject_raw(fp, raw, size);

	free(raw);

	return err;
}

/*
 * Sniff a packet from the network. Hexstring mode.
 */
char *sniff_hexstr(pcap_t *fp) {

	assert(fp != NULL);

	struct pcap_pkthdr hdr;
	char *hexstr = NULL;
	char *raw    = NULL;

	/* Sniff the packet */
	raw = (char *) pcap_next(fp, &hdr);

    if(raw == NULL)
    	return NULL;

    hexstr = raw_to_hexstr(raw, hdr.len);

    return hexstr;
}

/*
 * Sniff a packet from the network. Raw mode.
 */
char *sniff_raw(pcap_t *fp, size_t *size) {

	assert(fp != NULL);
	assert(size != NULL);

	struct pcap_pkthdr hdr;
	char *raw = NULL;

	/* Sniff the packet */
	raw = (char *) pcap_next(fp, &hdr);

	*size = hdr.len;

    return raw;
}

#endif /* HEXINJECTION_H_ */
