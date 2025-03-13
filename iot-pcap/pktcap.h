#ifndef __PKTCAP_H__
#define __PKTCAP_H__

#include <pcap.h>

struct pcap_option {

    int debug_level;                  /**< 调试日志级别(0-4) */
    const char *iface;                /**< 网卡接口 */
    const char *bpf;                  /**< BPF过滤规则 */
};

struct pcap_config {
    struct pcap_option *opts;    /**< 配置选项指针 */
};

struct pcap_private {
    struct pcap_config cfg;      /**< 配置信息 */

    pcap_t *ph;                   /**< 网卡句柄 */

    int signo;                  /**< 退出信号 */

    bool is_sll;               /**< 是否为SLL */

};

int pcap_main(void *user_options);

#endif // __PKTCAP_H__
// End of file