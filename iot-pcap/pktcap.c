
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "log.h"
#include "pktcap.h"

#define container_of(ptr, type, member) ({               \
    const typeof(((type *)0)->member) *__mptr = (ptr);   \
    (type *)((char *)__mptr - offsetof(type, member));   \
})

static int *s_signo = NULL;

/**
 * @brief 信号处理函数
 * @param signo 信号编号
 */
static void signal_handler(int signo) {

    *s_signo = signo;
    struct pcap_private *priv = container_of(s_signo, struct pcap_private, signo);
    if (priv->ph)
        pcap_breakloop(priv->ph);

    log_info("received exit signal");

}

int pcap_init(void **priv, void *opts) {

    struct pcap_private *p;

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    struct pcap_option *cfg = (struct pcap_option *)opts;
    pcap_t *ph = pcap_open_live(cfg->iface, 0xffff, 1, 100, errbuf);
    if (ph == NULL) {
      pcap_if_t *devs, *d;
      log_error("failed to open interface %s, available interfaces:", cfg->iface);
      if (pcap_findalldevs(&devs, errbuf) == 0) {
        for (d = devs; d != NULL; d = d->next) {
            log_error("%s (%s)", d->name, d->description ? d->description : "");
        }
        pcap_freealldevs(devs);
      }
      return -1;
    }
    pcap_setdirection(ph, PCAP_D_INOUT);

    if (cfg->bpf != NULL) {
        struct bpf_program bpfp;
        if (pcap_compile(ph, &bpfp, cfg->bpf, 1, 0))
            log_error("bpf compile failed\n");
        pcap_setfilter(ph, &bpfp);
        pcap_freecode(&bpfp);
    }

    *priv = NULL;
    p = calloc(1, sizeof(struct pcap_private));
    if (!p) {
        pcap_close(ph);
        return -1;
    }
    if (strcmp(cfg->iface, "any") == 0) {
        p->is_sll = true;
    }

    s_signo = &p->signo;
    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM 

    p->cfg.opts = opts;
    log_set_level(p->cfg.opts->debug_level);

    p->ph = ph;

    *priv = p;

    return 0;

}

void print_hex_binary(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);  // 大写十六进制，用%02x可输出小写
    }
    printf("\n");
}

// SLL 头部结构（Linux Cooked Capture）
struct sll_header {
    uint16_t pkt_type;
    uint16_t arphrd_type;
    uint16_t addr_len;
    uint8_t  src_addr[8];
    uint16_t protocol;
};

static void packet_handler(unsigned char *handle, const struct pcap_pkthdr *header, const unsigned char *bytes) {

    struct pcap_private *priv = (struct pcap_private *)handle;
    struct sll_header *sll = NULL;
    struct ether_header *eth = NULL;
    uint16_t pkt_type = 0;
    size_t offset = 0;
    struct iphdr *ipv4 = NULL;
    //struct ip6_hdr *ipv6 = NULL;

    if ( priv->is_sll ) {
        sll = (struct sll_header *)bytes;
        pkt_type = ntohs(sll->protocol);
        offset = sizeof(struct sll_header);
    } else {
        eth = (struct ether_header *)bytes;
        pkt_type = ntohs(eth->ether_type);
        offset = sizeof(struct ether_header);
    }

    print_hex_binary(bytes, header->len);
    log_info("packet length: %d, caplen: %d, type: 0x%04X", header->len, header->caplen, pkt_type);  // 输出数据包实际长度
    switch (pkt_type) {
    case ETHERTYPE_IP:
        ipv4 = (struct iphdr *)(bytes + offset);
        log_info("ipv4 packet from %d to %d", ipv4->saddr, ipv4->daddr);
        break;
    case ETHERTYPE_IPV6:
        //ipv6 = (struct ip6_hdr *)(bytes + offset);
        log_info("ipv6 packet");
        break;
    }
}

void pcap_run(void *handle) {

    struct pcap_private *priv = (struct pcap_private *)handle;

    pcap_loop(priv->ph, 0, packet_handler, handle);

}

void pcap_exit(void *handle) {
    struct pcap_private *priv = (struct pcap_private *)handle;
    if (priv->ph)
        pcap_close(priv->ph);
    free(handle);
}

int pcap_main(void *user_options) {

    struct pcap_option *opts = (struct pcap_option *)user_options;
    void *pcap_handle;
    int ret;

    ret = pcap_init(&pcap_handle, opts);
    if (ret)
        exit(1);

    pcap_run(pcap_handle);

    pcap_exit(pcap_handle);

    return 0;

}