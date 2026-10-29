/*
 * Frama-C Header Stub for <netinet/ip_icmp.h>
 *
 * Provides standard Linux/BSD ICMP header structures and constants missing
 * from Frama-C's POSIX __fc_libc when -nostdinc is active.
 */

#ifndef FRAMAC_NETINET_IP_ICMP_H
#define FRAMAC_NETINET_IP_ICMP_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

struct icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t __glibc_reserved;
            uint16_t mtu;
        } frag;
        uint8_t reserved[4];
    } un;
};

struct icmp_ra_addr {
    uint32_t ira_addr;
    uint32_t ira_preference;
};

struct icmp {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
    union {
        uint8_t ih_pptr;
        struct in_addr ih_gwaddr;
        struct ih_idseq {
            uint16_t icd_id;
            uint16_t icd_seq;
        } ih_idseq;
        uint32_t ih_void;
        struct ih_pmtu {
            uint16_t ipm_void;
            uint16_t ipm_nextmtu;
        } ih_pmtu;
        struct ih_rtradv {
            uint8_t irt_num_addrs;
            uint8_t irt_wpa;
            uint16_t irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
    union {
        struct {
            uint32_t its_otime;
            uint32_t its_rtime;
            uint32_t its_ttime;
        } id_ts;
        struct {
            uint8_t idi_ip[20];
        } id_ip;
        struct icmp_ra_addr id_radv;
        uint32_t id_mask;
        uint8_t id_data[1];
    } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};

#define ICMP_MINLEN         8
#define ICMP_ECHOREPLY      0
#define ICMP_DEST_UNREACH   3
#define ICMP_SOURCE_QUENCH  4
#define ICMP_REDIRECT       5
#define ICMP_ECHO           8
#define ICMP_TIME_EXCEEDED  11
#define ICMP_PARAMETERPROB  12
#define ICMP_TIMESTAMP      13
#define ICMP_TIMESTAMPREPLY 14
#define ICMP_INFO_REQUEST   15
#define ICMP_INFO_REPLY     16
#define ICMP_ADDRESS        17
#define ICMP_ADDRESSREPLY   18

#endif /* FRAMAC_NETINET_IP_ICMP_H */
