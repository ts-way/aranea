#ifndef DNS_PROCESSING_H_
#define DNS_PROCESSING_H_

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <pcap.h>

#pragma pack (1)

uint16_t ipid = 0;

/*
 * Ethernet header
 */
#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
        uint8_t  ether_dhost[ETHER_ADDR_LEN];  /* destination host address */
        uint8_t  ether_shost[ETHER_ADDR_LEN];  /* source host address */
        uint16_t ether_type;                   /* IP? ARP? RARP? etc */
};
#define SIZE_ETHERNET 14

/*
 * IP header
 */
struct sniff_ip {
        uint8_t  ip_vhl;                /* version << 4 | header length >> 2 */
        uint8_t  ip_tos;                /* type of service */
        uint16_t ip_len;                /* total length */
        uint16_t ip_id;                 /* identification */
        uint16_t ip_off;                /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        uint8_t  ip_ttl;                /* time to live */
        uint8_t  ip_p;                  /* protocol */
        uint16_t ip_sum;                /* checksum */
        in_addr_t ip_src,ip_dst;        /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/*
 * UDP header
 */
struct sniff_udp {
    uint16_t uh_sport;  /* source port      */
    uint16_t uh_dport;  /* destination port */
    uint16_t uh_ulen;  /* udp length       */
    uint16_t uh_sum;   /* udp checksum     */
};

/*
 * DNS header
 */
struct sniff_dns { 
    uint16_t id;         /* identification number */
    uint16_t flags;      /* dns flags */ 
    uint16_t q_count;    /* number of question entries */
    uint16_t ans_count;  /* number of answer entries */
    uint16_t auth_count; /* number of authority entries */
    uint16_t add_count;  /* number of resource entries */
};
#define DNS_QUERY 0x8000

/*
 * DNS Query structure
 */
struct dns_query {
    uint8_t     *name_first_byte; // name, complete
    char        *name_string;     // name, string part
    uint16_t    *type;            // query type
    uint16_t    *class;           // query class
};

/*
 * DNS Answer structure
 */
struct dns_answer {
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t addr_len;
    uint32_t addr;
};

/*
 * Basic packet structure
 */
struct basic_packet {
    struct sniff_ethernet eth;  /* ethernet header */
    struct sniff_ip ip;         /* ip header */
    struct sniff_udp udp;       /* tcp header */
    struct sniff_dns dns;       /* dns header */
};

/*
 * Prepare Ethernet header
 */
void prep_ethernet_header(struct basic_packet *packet, uint8_t *dmac, uint8_t *smac)
{
    memcpy(packet->eth.ether_dhost, dmac, ETHER_ADDR_LEN); /* destination host address */
    memcpy(packet->eth.ether_shost, smac, ETHER_ADDR_LEN); /* source host address */
    packet->eth.ether_type = htons(0x0800); /* IP */
}

/*
 * Prepare IP header
 */
void prep_ip_header(struct basic_packet *packet, in_addr_t srcip, in_addr_t dstip)
{
    packet->ip.ip_vhl = 0x45;          /* version 4, header length 20 bytes */
    packet->ip.ip_id  = htons(ipid++); /* identification */
    packet->ip.ip_ttl = 0x40;          /* time to live 60 */
    packet->ip.ip_p   = 0x11;          /* protocol udp */
    packet->ip.ip_src = srcip;         /* source ip */
    packet->ip.ip_dst = dstip;         /* dest ip */
}

/*
 * Prepare UDP header
 */
void prep_udp_header(struct basic_packet *packet, uint16_t sport, uint16_t dport)
{
    packet->udp.uh_sport = sport;         /* source port */
    packet->udp.uh_dport = dport;         /* destination port */
}

/*
 * Prepare DNS header
 */
void prep_dns_header(struct basic_packet *packet, uint16_t id)
{
    packet->dns.id = id;               /* identification number */
    packet->dns.flags = htons(0x8180); /* dns flags */
    packet->dns.q_count = htons(1);    /* number of question entries */
    packet->dns.ans_count = htons(1);  /* number of answer entries */
}

/*
 * Prepare DNS answer
 */
void prep_dns_answer(struct dns_answer *answer, in_addr_t addr)
{
    answer->name     = htons(0xc00c);
    answer->type     = htons(0x0001);
    answer->class    = htons(0x0001);
    answer->ttl      = htonl(3600); /* 1 hour */
    answer->addr_len = htons(4);
    answer->addr     = addr;
}

/*
 * Process a received DNS packet
 */
int process_dns_packet(pcap_t *fp, char *packet, int size, char *errbuf)
{
    struct sniff_ethernet *eth_header = NULL;
    struct sniff_ip *ip_header  = NULL;
    struct sniff_udp *udp_header = NULL;
    struct sniff_dns *dns_header = NULL;

    struct dns_query query;
    char name[BUFFER_SIZE];
    int name_len = 0;

    in_addr_t addr;

    uint8_t *dns_answer_buffer;
    struct basic_packet *dns_answer;
    int dns_query_len, dns_answer_buffer_size;

    int err;

    /*
     * PARSE DNS QUERY
     */
    
    // check len
    if(size < (sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) +
               sizeof(struct sniff_udp) + sizeof(struct sniff_dns)) + 6) {
        sprintf(errbuf, "Invalid DNS query size.\n");
        return 0;
    }

    // set structure pointers
    eth_header = (struct sniff_ethernet *) packet;
    ip_header  = (struct sniff_ip *)  (packet + sizeof(struct sniff_ethernet));    
    udp_header = (struct sniff_udp *) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip));
    dns_header = (struct sniff_dns *) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) +
                                                sizeof(struct sniff_udp));

    // extract query
    query.name_first_byte = (uint8_t *) (packet + sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip) +
                                                  sizeof(struct sniff_udp) + sizeof(struct sniff_dns));
    query.name_string     = (char *) (query.name_first_byte + 1);
    
    // check dns header
    if ((dns_header->flags & htons(DNS_QUERY)) !=0 || ntohs(dns_header->q_count) != 1 ||
        dns_header->ans_count || dns_header->auth_count || dns_header->add_count) {
        sprintf(errbuf, "Not a DNS query.\n");
        return 0;
    }
    
    // expand dns name
    if ((name_len = dn_expand((unsigned char *) dns_header, (unsigned char *) (packet + size),
                       (unsigned char *) query.name_first_byte, name, sizeof(name))) < 0) {
        sprintf(errbuf, "DNS name expansion failed.\n");
        return 0;
    }
    
    // get type and class
    query.type  = (uint16_t *) (packet + size - sizeof(uint32_t));
    query.class = (uint16_t *) (packet + size - sizeof(uint16_t));
    
    // check class
    if (ntohs(*query.class) != C_IN) {
        sprintf(errbuf, "Invalid DNS query class: %d\n", ntohs(*query.class));
        return 0;
    }
    
    // check type
    if (ntohs(*query.type) != T_A) {
        sprintf(errbuf, "Invalid DNS query type: %d\n", ntohs(*query.type));
        return 0;
    }
    
    /*
     * PREPARE DNS ANSWER
     */

    // resolv dns name
    addr = name_resolv(name);
    if (addr == 0) {
        sprintf(errbuf, "DNS name not in the list.\n");
        return 0;
    }

    // length of the dns query part
    dns_query_len = size - sizeof(struct basic_packet);

    // allocate the answer packet
    dns_answer_buffer_size = sizeof(struct basic_packet) + dns_query_len + sizeof(struct dns_answer);
    dns_answer_buffer = (uint8_t *) calloc(dns_answer_buffer_size, sizeof(uint8_t));
    dns_answer = (struct basic_packet *) dns_answer_buffer;

    // prepare packet: Ethernet header 
    prep_ethernet_header(dns_answer, eth_header->ether_shost, eth_header->ether_dhost);
    
    // prepare packet: IP header
    prep_ip_header(dns_answer, ip_header->ip_dst, ip_header->ip_src);

    // prepare packet: UDP header
    prep_udp_header(dns_answer, udp_header->uh_dport, udp_header->uh_sport);
 
    // prepare packet: DNS header
    prep_dns_header(dns_answer, dns_header->id);

    // copy the query
    memcpy(((uint8_t *) dns_answer) + sizeof(struct basic_packet), query.name_first_byte, dns_query_len);

    // prepare the answer
    prep_dns_answer((struct dns_answer *) (((uint8_t *) dns_answer) + sizeof(struct basic_packet) + dns_query_len), addr);
    
    // inject the answer
    err = inject_raw(fp, (char *) dns_answer_buffer, dns_answer_buffer_size);

    // cleanup
    free(dns_answer_buffer);

    // check injection
    if(err !=0) {
        sprintf(errbuf, "Error writing packet: %s\n", pcap_geterr(fp));
        return 0;
    }

    return 1;
}


#endif /* DNS_PROCESSING_H_ */
