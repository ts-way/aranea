/*
 * aranea.c
 *
 *  Created on: Sat, 04 Jun 2011 08:40:50 GMT
 *      Author: Acri Emanuele
 */

#include "aranea.h"
#include "argparser.h"
#include "hexinject.h"
#include "resolver.h"
#include "dns_processing.h"

/*
 * Thread parameters
 */
struct thread_param {
    pcap_t *fp;
    char *packet;
    size_t size;
};

/*
 * Thread: process a single DNS query
 */
void *thread_dns_processor(void *param)
{
    // Cast the cookie pointer to the right type.
    struct thread_param* p = (struct thread_param *) param;

    char errbuf[PCAP_ERRBUF_SIZE];
    int result;

    if(options.verbose > 1) {
        fprintf(stderr, "%s\n", raw_to_hexstr(p->packet, p->size));
    }

    // process dns packet
    result = process_dns_packet(p->fp, p->packet, p->size, errbuf);

    if(options.verbose) {
        fprintf(stderr, "Packet processing %s", result ? "positive" : "negative");
        if(!result) {
            fprintf(stderr, ": %s", errbuf);
        } else {
            fprintf(stderr, ".\n");
        }
    }

    // cleanup
    free(param);

    return NULL;
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
    pcap_t *fp, *injfp;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *packet;
    size_t size;

    char *dev;

    struct thread_param *dns_processor_param;
    pthread_t thread_id;
    pthread_attr_t attr;

    /* Parse cmdline options */
    parseopt(argc, argv);

    /* find a device if not specified */
    if(!options.device) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr,"\nUnable to find a network adapter: %s.\n", errbuf);
            return 1;
        }
    }
    else {
        dev = options.device;
    }

    /* Open the input device */
    if ( (fp = pcap_open_live( dev, // name of the device
                    BUFSIZ,         // portion of the packet to capture
                    1,              // promiscuous mode
                    -1,             // read timeout
                    errbuf          // error buffer
                    )) == NULL)

    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported.\n", dev);
        return 1;
    }

    /* Apply filter */
    if ( options.filter ) {

        if(pcap_compile(fp, &bpf, options.filter, 0, 0) != 0) {
            fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(fp));
            return 0;
        }

        if(pcap_setfilter(fp, &bpf) != 0) {
            fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(fp));
            return 0;
        }

    }

    /* Open the output device */
    if ( (injfp = pcap_open_live( dev, // name of the device
                    BUFSIZ,         // portion of the packet to capture
                    1,              // promiscuous mode
                    -1,             // read timeout
                    errbuf          // error buffer
                    )) == NULL)

    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported.\n", dev);
        return 1;
    }


    /* Initialize name resolver */
    if(!resolver_init(options.file, errbuf)) {
        fprintf(stderr,"\nUnable to initialize name resolver:%s", errbuf);
        return 1;
    }

#ifndef USE_FORK

    /* Set thread attributes */
    pthread_attr_init (&attr);
    pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED); // no need to join the thread

#else

    /* To avoid zombies */
    signal(SIGCHLD, SIG_IGN);

#endif

    /* DNS Spoofing loop */
    while ( 1 ) {

        size = BUFFER_SIZE;

        /* Sniff a packet */
        if ((packet = sniff_raw(fp, &size))) {

            dns_processor_param = (struct thread_param *) malloc(sizeof(struct thread_param));

            dns_processor_param->fp = injfp;
            dns_processor_param->packet = packet;
            dns_processor_param->size = size;

#ifndef USE_FORK

            // start a new DNS query processor
            pthread_create(&thread_id, NULL, &thread_dns_processor, dns_processor_param);

#else
            
            // start a new DNS query processor
            if(fork()==0) {
                thread_dns_processor(dns_processor_param);
                exit(0);
            }

#endif

        }

        usleep(100);
    }

    /* cleanup */
    pthread_attr_destroy (&attr);
    pcap_close(fp);
    pcap_close(injfp);

    return 0;
}

