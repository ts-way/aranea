#ifndef __ARGPARSER_H__
#define __ARGPARSER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#define VERSION "1.0"

/*
 * Cmdline options
 */
struct prog_options {
    char *file;   // hosts file
    char *device; // interface
    char *filter; // custom pcap filter
    int verbose;  // verbosity level
} options;

/*
 * Program usage template
 */
const char usage_template[] =
    "Aranea " VERSION " [fast dns spoofing tool]\n"
    "written by: Emanuele Acri <crossbower@gmail.com>\n\n"
    "Usage:\n"
    "   aranea -f hosts_file <options>\n"
    "Options:\n"
    "  -f file: hosts file (see hosts.txt)\n"
    "  -i device: network device to use\n"
    "  -F filter: custom pcap filter\n"
    "  -v verbose: verbosity level\n"
    "  -h help screen\n";

/*
 * Program usage
 */
void usage(FILE *out, const char *error)
{
    fputs(usage_template, out);

    if(error)
        fputs(error, out);

    exit(1);
}

/*
 * Parser for command line options
 * See getopt(3)...
 */
int parseopt(int argc, char **argv)
{
    char ch;
    
    // cleaning
    memset(&options, 0, sizeof(options));
    
    
    const char *shortopt = "f:i:F:vh"; // short options
    
    while ((ch = getopt (argc, argv, shortopt)) != -1) {
        switch (ch) {

            case 'f': // hosts file
                options.file = optarg;
                break;
        
            case 'i': // interface
                options.device = optarg;
                break;
            
            case 'F': // custom filter
                options.filter = optarg;
                break;
                
            case 'v': // verbosity level
                options.verbose++;
                break;
            
            case 'h': //help
                usage(stdout, NULL);

            case '?':
            default:
                usage(stderr, NULL);
        }
    }

    // check required options
    if ( !options.file ) {
        usage(stderr, "\nError: no hosts file selected, see -f option...\n");
    }
    
    return 1;
}

#endif /* __ARGPARSER_H__ */

