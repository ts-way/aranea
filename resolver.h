#ifndef RESOLVER_H_
#define RESOLVER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <regex.h>

/*
 * DNS name list structure
 */
struct resolv_dns_list {
    char      *name;
    in_addr_t ip;
    struct resolv_dns_list *next;
} dns_list;

/*
 * Glob expression matching function
 * Returns:
 *    -1  error on pattern compilation
 *     0  don't match
 *     1  match
 */
int regmatch(const char *str, const char *regex)
{
    regex_t re;

    // Compile the regex pattern.
    if (regcomp(&re, regex, REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(stderr, "Error on regex pattern compilation: %s.\n", regex);
        return -1;
    }

    // Use the pattern on the passed string
    if (regexec(&re, str, 0, NULL, 0))  {
        return 0;
    }

    regfree(&re);
    return 1;
}

/*
 * DNS name list append
 */
struct resolv_dns_list *dns_list_append(struct resolv_dns_list *list, char *name, in_addr_t ip)
{
    if(list->name) {
        list->next = calloc(sizeof(struct resolv_dns_list), sizeof(uint8_t));
        list = list->next;
    }

    list->name = name;
    list->ip = ip;

    return list;
}

/*
 * DNS name list find
 */

/*
 * Prepare host list
 */
int resolver_init(char *filename, char *errbuf)
{
    FILE *file;
    char *ip, *name, buf[1024];

    struct resolv_dns_list *list = &dns_list;

    // clear dns list structure
    memset(&dns_list, 0, sizeof(dns_list));

    // open hosts file
    if ((file = fopen(filename, "r")) == NULL) {
        sprintf(errbuf, "Error opening %s.\n", filename);
        return 0;
    }

    // read entries
    while (fgets(buf, sizeof(buf), file) != NULL) {
        if (buf[0] == '#' || buf[0] == '\n')
            continue;

        if ((ip = strtok(buf, "\t ")) == NULL ||
                (name = strtok(NULL, "\n\t ")) == NULL)
            continue;

        if (!inet_addr(ip)) {
            sprintf(errbuf, "Invalid entry: %s.\n", buf);
            return 0;
        }

        // append dns entry
        list = dns_list_append(list, strdup(name), inet_addr(ip));
    }

    fclose(file);

    return 1;
}

/*
 * Resolv query name
 */
in_addr_t name_resolv (const char *name)
{
    struct resolv_dns_list *list;

    // search host
    for(list = &dns_list; list; list=list->next) {
        if(regmatch(name, list->name)) {
            return list->ip;
        }
    }

    return 0;
}


#endif /* RESOLVER_H_ */

