#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t ether_dhost[ETHER_ADDR_LEN];
    u_int8_t ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int8_t th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

