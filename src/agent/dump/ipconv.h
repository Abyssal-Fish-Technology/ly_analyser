
#ifndef _IPCONV_H
#define _IPCONV_H 1

int parse_ip(int *af, const char *src, uint64_t *dst, int *bytes, int lookup, uint32_t *num_ip );

int set_nameserver(char *ns);

#define MAXHOSTS 512

#define STRICT_IP 	 0
#define ALLOW_LOOKUP 1

#endif //_IPCONV_H
