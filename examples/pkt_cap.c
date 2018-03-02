#include "nf_pktgen.h"

#include <poll.h>
#include <strings.h>

int main(int argc, char *argv[])
{
    int i, fd, ret;
    uint32_t start;
    int32_t pkt_gap = 1000000000;
    /*fd_set fds;*/
    struct pollfd poll_set[1];
    char* filename = "../pkt.pcap";

    int count = 0;
    const uint8_t *data;
    struct pcap_pkthdr h;

    if (argc == 2) {
        filename = argv[1];
    }

    //enable padding
    nf_init(1, 0, 0);
    nf_gen_set_number_iterations (1, 1, 0);
    struct nf_cap_t *cap1 = nf_cap_enable("nf1", 1024);
    if(cap1 == NULL) {
        perror("nf_cap_enable");
    }

    //load the pcap capture file
    nf_gen_load_pcap("../pkt.pcap", 0,  10000);
    nf_cap_add_rule(1, 0, 0, 0, 0, 0, 0, 0, 0);
    nf_start(0);
    printf("trying to get data\n");

    fd = nf_cap_fileno(cap1);
    while( (count < 100)){

        bzero(poll_set, sizeof(struct pollfd));
        poll_set[0].fd = fd;
        poll_set[0].events |= POLLIN;
        ret = poll(poll_set, 1, 1);

        if(!ret) {
            continue;
        }
        data = nf_cap_next(cap1, &h);
        if (data)
            printf("packet %d,%u.%06u \n", ++count, (uint32_t)h.ts.tv_sec, (uint32_t)h.ts.tv_usec);
        else
            fprintf(stderr, "[WARNING] packet %d not captured\n", ++count);

    }
    // Wait until the correct number of packets is sent
    nf_finish();
    usleep(10);
    return 0;
}
