#include "nf_pktgen.h"

#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/queue.h>

FILE *out = NULL;

struct packet {
	uint32_t seq, rec_sec, rec_usec, trans_sec, trans_usec;
	TAILQ_ENTRY(packet) entries;
};

TAILQ_HEAD(pcap_packet_h, pcap_packet_t) cap_pkts;

void session_terminate(int signum) {
	struct packet *pkt = TAILQ_FIRST(&cap_pkts), *tmp;

	while (pkt) {
		fprintf(out, "%d;%u.%09u;%u.%09u\n", pkt->seq,
				(uint32_t)pkt->rec_sec, (uint32_t)pkt->rec_usec,
				(uint32_t)pkt->trans_sec, (uint32_t)pkt->trans_usec);
		tmp = TAILQ_NEXT(pkt, entries);
		TAILQ_REMOVE(&cap_pkts, pkt, entries);
		pkt = tmp;
	}

	


    fclose(out);
    nf_finish();
    usleep(10);
    printf("terminating session\n");
    exit(0);
}


void print_help(int argc, char *argv[]) {
    printf("error using command options\n");
    printf("usage: ./%s -i input_trace -d interpkt_delay_nsec -o output_file -c iterations -v\n", argv[0]);
}

int main(int argc, char *argv[]) {	//capture session parameters
    char *filename = "data.pcap";
    uint32_t pkt_gap = 1000000000;
    uint32_t iterations = 1;
    struct pktgen_hdr *pktgen;
    int valid = 0;
    int debug = 0;
    int i;
    struct nf_cap_t * cap1;
    struct pollfd poll_set[1];
    int ret, missed = 0;

    //captured packets data.
    struct pcap_pkthdr h;
    const uint8_t *data;
    // getopt parameters
    int c, count = 0;
    uint32_t max_receive = 0;
    // polling informations
	TAILQ_INIT(&cap_pkts);
	struct packet *pkt;
    int fd;
    struct nf_gen_stats stat_before, stat_after;

    while((c = getopt(argc, argv, "i:d:o:c:vh")) != -1) {
        switch (c) {
            case 'i':
                filename = malloc(strlen(optarg) + 1);
                strcpy(filename, optarg);
                break;
            case 'd':
                pkt_gap = atol(optarg);
                break;
            case 'o':
                out = fopen(optarg, "w");
                break;
            case 'c':
                iterations = atol(optarg);
                break;
            case 'v':
                debug=1;
                break;
            default:
                print_help(argc, argv);
                exit(1);
        }
    }

    if (out == NULL) {
        printf("Invalid output file\n");
        print_help(argc, argv);
        exit(1);
    }
    printf("pkt_gap = %u, filename = %s, iterations = %u\n", pkt_gap, filename, iterations);

    if (iterations <= 0) {
        printf("invalid iteration number %d\n", iterations);
        print_help(argc, argv);
        exit(1);
    }

    printf("Initiating packet generator\n");
    signal(SIGINT, session_terminate);

    //enable padding
    nf_init(1, 0, 0);

    //capture packets on port 1
    cap1 = nf_cap_enable("nf1", 2048);

    if(cap1 == NULL) {
        perror("nf_cap_enable");
    }

    nf_enable_rx_measurement("nf1");

    //send packet from nf0.
    nf_gen_set_number_iterations (iterations, 1, 0);

    nf_reset_stats();
    nf_port_cnt_reset();
    nf_gen_stat(0, &stat_before);
    //load the pcap capture file
    nf_gen_load_pcap(filename, 0, pkt_gap);
    nf_cap_add_rule(1, 0, 0, 0, 0, 0, 0, 0, 0);
    nf_start(0);
    printf("starting capture\n");
    fd = nf_cap_fileno(cap1);
    max_receive = nf_get_max_packet();
    fprintf(stdout, "Max iteration %d.\n", max_receive);
    while(1) {
        bzero(poll_set, sizeof(struct pollfd));
        poll_set[0].fd = fd;
        poll_set[0].events |= POLLIN;
        ret = poll(poll_set, 1, 1);

        if(!ret) {
            continue;
        }
        data = nf_cap_next(cap1, &h);
        if (data == (const u_char*)-1) {
            printf("No packet to receive\n");
            continue;
        }
        if (data) {
            if (count++ % 100000 == 0)
				printf("captured %d pkts...\n", count);
            valid++;
			pktgen = nf_gen_extract_header(cap1, data, h.len);
			if (pktgen) {
				if (debug)
					printf("packet with  cnt:%d,seq_num:%d,caplen:%u,ts:%u.%u,snt:%u.%09u\n",
                            count, htonl(pktgen->seq_num), h.caplen,
                            pktgen->tv_rcv_sec, pktgen->tv_rcv_usec,
							pktgen->tv_sec, pktgen->tv_usec);

				pkt = (struct packet *) malloc(sizeof(struct packet));
				pkt->seq = htonl(pktgen->seq_num);
				pkt->trans_usec = pktgen->tv_usec;
				pkt->trans_sec = pktgen->tv_sec;
				pkt->rec_sec = pktgen->tv_rcv_sec;
				pkt->rec_usec = pktgen->tv_rcv_usec;
				TAILQ_INSERT_TAIL(&cap_pkts, pkt, entries);
			} 
			else {
                printf("packet %d malformed\n", count++);
            }
        } else {
            printf("packet %d not captured\n", ++count);
            missed++;
        }
        if (count == max_receive ) {
            break;
        }
    }
    nf_gen_stat(0, &stat_after);

    fprintf(stdout, "==========================[ Received %d valid packets ]==========================\n", valid);

    fprintf(stdout, "XXXXXXXXXXXXXXXXXXXXXXXXXX[ Board transmitted %d packets ]XXXXXXXXXXXXXXXXXXXXXXX\n",
            stat_after.pkt_snd_cnt - stat_before.pkt_snd_cnt);
    session_terminate(SIGINT);
    return 0;

}
