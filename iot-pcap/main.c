#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "pktcap.h"

#define APP_VERSION "0.1.0"

static void usage(const char *prog, struct pcap_option *default_opts) {
    struct pcap_option *opts = default_opts;
    fprintf(stderr,
        "IoT-SDK v.%s\n"
        "Usage: %s OPTIONS\n"
        "  -i   NAME   - network interface name, default: '%s'\n"
        "  -bpf rules  - bpf filter, default: '%s'\n"
        "  -v   LEVEL  - debug level, from 0 to 4, default: %d\n",
        APP_VERSION, prog, opts->iface,  opts->bpf ? opts->bpf : "", opts->debug_level);

    exit(1);
}

static void parse_args(int argc, char *argv[], struct pcap_option *opts) {
    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            opts->iface = argv[++i];
        } else if (strcmp(argv[i], "-bpf") == 0) {
            opts->bpf = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            opts->debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0], opts);
        }
    }
}

int main(int argc, char *argv[]) {

    struct pcap_option opts = {
        .debug_level = LOG_INFO,
        .iface = "eth0",
        .bpf = NULL,
    };

    parse_args(argc, argv, &opts);

    log_info("iot-pcap version         : v%s", APP_VERSION);

    pcap_main(&opts);

    return 0;
}
