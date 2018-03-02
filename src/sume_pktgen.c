/*
# Copyright (c) 2017 University of Cambridge
# Copyright (c) 2017 Rémi Oudin
# All rights reserved.
#
# This software was developed by University of Cambridge Computer Laboratory
# under the ENDEAVOUR project (grant agreement 644960) as part of
# the European Union's Horizon 2020 research and innovation programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA Open Systems C.I.C. (NetFPGA) under one or more
# contributor license agreements. See the NOTICE file distributed with this
# work for additional information regarding copyright ownership. NetFPGA
# licenses this file to you under the NetFPGA Hardware-Software License,
# Version 1.0 (the License); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at:
#
# http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
*/
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <net/if.h>

#include <sched.h>

#include "global.h"
#include "util.h"
#include "sume_pktgen_data.h"


struct str_nf_pktgen sume;


#define SUME_IOCTL_CMD_READ_STAT (SIOCDEVPRIVATE+0)
#define SUME_IOCTL_CMD_WRITE_REG (SIOCDEVPRIVATE+1)
#define SUME_IOCTL_CMD_READ_REG (SIOCDEVPRIVATE+2)

#define SUME_IOCTL_CMD_INIT (SIOCDEVPRIVATE+3)

/**
 * Default interface for the NetFPGA SUME board.
 * It is the first interface, and is used by default for ifreq ioctl.
 * see netdevice(7) for more information.
 */
#define SUME_IFNAM_DEFAULT "nf0"


/* PREPROCESSOR definitions for message logging. */
#define WHERESTR "[file %s, line %d]:"
#define WHEREARG __FILE__, __LINE__
#define MESSAGE "%s"
#define LOG(...) fprintf(__VA_ARGS__)
#define LOG_ERROR2(...) LOG(stderr, __VA_ARGS__)
#define LOG_WARNING2(...) LOG(stdout, __VA_ARGS__)
#define LOG_ERROR(_fmt, ...) LOG_ERROR2(WHERESTR MESSAGE _fmt, WHEREARG, "[ERROR]", ##__VA_ARGS__)
#define LOG_WARNING(_fmt, ...) LOG_WARNING2(MESSAGE _fmt, "[WARNING]", ##__VA_ARGS__)
#define LOG_INFO(_fmt, ...) LOG_WARNING2(MESSAGE _fmt, "[INFO]", ##__VA_ARGS__)

/**
 * @brief: read the data at the given address, and stores it into ret
 * @param addr: The address to read on.
 * @param ret : A pointer to the variable in which data should be stored.
 * @description: If there is an error in setting up the socket, or in reading
 * the data, it will return -1, and will return 0 either.
 */
int rdaxi(uint32_t addr, uint32_t *ret) {
    char *ifnam;
    struct sume_ifreq sifr;
    struct ifreq ifr;
    size_t ifnamlen;
    int fd, rc;

    ifnam = SUME_IFNAM_DEFAULT;
    ifnamlen = strlen(ifnam);

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
               LOG_ERROR("Socket failed for both AF_INET6 and AF_INET.\n");
            return -1;
        }
    }

    memset(&sifr, 0, sizeof(sifr));
    sifr.addr = addr;

    memset(&ifr, 0, sizeof(ifr));
    if (ifnamlen >= sizeof(ifr.ifr_name)) {
        LOG_ERROR("Interface name too long.\n");
        return -1;
    }
    memcpy(ifr.ifr_name, ifnam, ifnamlen);
    ifr.ifr_name[ifnamlen] = '\0';
    ifr.ifr_data = (char *)&sifr;

    rc = ioctl(fd, SUME_IOCTL_CMD_READ_REG, &ifr);
    if (rc < 0) {
        LOG_ERROR("ioctl read failed.\n");
        return -1;
    }
    close(fd);
    *ret = (uint32_t)(sifr.val & 0xffffffffL);
    return 0;
}

/**
 * @brief: write the value val at the adress addr
 * @param addr: The address to write on.
 * @param val : The value to write.
 * @description: If there is an error in setting up the socket, or in writing
 * the data, it will return -1, and will return 0 either.
 */
int wraxi(uint32_t addr, uint32_t val) {
    char *ifnam;
    struct sume_ifreq sifr;
    struct ifreq ifr;
    size_t ifnamlen;
    int fd, rc;

    ifnam = SUME_IFNAM_DEFAULT;
    ifnamlen = strlen(ifnam);

    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOG_ERROR("Socket failed for both AF_INET6 and AF_INET\n");
            return -1;
        }
    }

    memset(&sifr, 0, sizeof(sifr));
    sifr.addr = addr;
    sifr.val = val;
    memset(&ifr, 0, sizeof(ifr));
    if (ifnamlen >= sizeof(ifr.ifr_name)) {
        LOG_ERROR("Interface name too long.\n");
        return -1;
    }
    memcpy(ifr.ifr_name, ifnam, ifnamlen);
    ifr.ifr_name[ifnamlen] = '\0';
    ifr.ifr_data = (char *)&sifr;

    rc = ioctl(fd, SUME_IOCTL_CMD_WRITE_REG, &ifr);
    if (rc < 0) {
        LOG_ERROR("ioctl write failed: %d\n", rc);
        return -1;
    }
    close(fd);

    return 0;
}


//function to load data
// TODO pcap_pkthdr is probably not required
int nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data,
		int port, uint64_t delay) {
	uint32_t len = h->len, word_len = (uint32_t)ceil(((float)len)/32.0) + 1;

	// Check if there is room in the queue for the entire packet
	// 	If there is no room return 1

	if ( (word_len + sume.total_words) > MEM_HIGH_ADDR) {
		LOG_ERROR("Warning: unable to load all packets from pcap file. SRAM queues are full.\n");
		LOG_ERROR("Total output queue size: %u words\n", MEM_HIGH_ADDR);
		LOG_ERROR("Current queue occupancy: %u words\n", sume.total_words);
		LOG_ERROR("Packet size:%u words\n", word_len);
		return -1;
	} else {
		sume.total_words += word_len;
		sume.queue_pages[port] += word_len;
		sume.queue_bytes[port] += len;
		sume.queue_pkts[port]++;
	}

	//Save packet in RAM
	sume.queue_data[port] = realloc(sume.queue_data[port], sume.queue_bytes[port]);
	memcpy(sume.queue_data[port] + sume.queue_bytes[port] - len, data, len);
	sume.pkt_len[port] = realloc(sume.pkt_len[port], sume.queue_pkts[port]*sizeof(uint32_t));
	sume.pkt_len[port][sume.queue_pkts[port] - 1] = len;

	sume.queue_delay[port] = (delay*DATAPATH_FREQUENCY)/1000000000L;
	return 0;
}

int nf_gen_load_pcap(const char *filename, int port, uint64_t ns_delay) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr h;
    const uint8_t *pkt;

    if ((pcap = pcap_open_offline(filename, errbuf)) == NULL) {
        LOG_ERROR("[sume] error: %s\n", errbuf);
        perror("pcap_open_offline");
        return -1;
    }

    while((pkt = pcap_next(pcap, &h)) != NULL) {
        if (nf_gen_load_packet(&h, pkt,  port, ns_delay) < 0) {
            break;
        }
    }

    //pcap_close(pcap);
    return 0;
}

#define PCAP_ENGINE_BASE_ADDR  0x76000000
#define PCAP_ENGINE_RESET      0x0
#define PCAP_ENGINE_REPLAY     0x4
#define PCAP_ENGINE_REPLAY_CNT 0x14
#define PCAP_ENGINE_MEM_LOW    0x24
#define PCAP_ENGINE_MEM_HIGH   0x28
#define PCAP_ENGINE_ENABLE     0x44
#define PCAP_LOAD_PCAP_ONLY    0x76000054
#define INTER_PKT_DELAY_BASE_ADDR   0x76600000
#define INTER_PKT_DELAY             0xc
#define INTER_PKT_DELAY_ENABLE      0x4
#define INTER_PKT_DELAY_USE_REG     0x8
#define INTER_PKT_DELAY_RST         0x0

#define TX_TIMESTAMP_BASE_ADDR 0x79001054
#define TX_TIMESTAMP_OFFSET 0x2000
#define RX_TIMESTAMP_BASE_ADDR 0x79001050
#define RX_TIMESTAMP_OFFSET 0x2000


int
generator_rst(uint32_t val) {
    int ret = wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_RESET, val);
    return ret;
}

int
rst_gen_mem() {
    int i;
    for (i=0;i<NUM_PORTS;i++)
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_LOW + i*0x8, 0L) < 0) ||
            (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_HIGH + i*0x8, 0L) < 0) ||
            (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, 0L) < 0) ||
            (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, 0L) < 0) ||
            (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY_CNT + i*0x4, 0L) < 0) ||
            (wraxi(TX_TIMESTAMP_BASE_ADDR + TX_TIMESTAMP_OFFSET * i, 0) < 0) ||
            (wraxi(RX_TIMESTAMP_BASE_ADDR + RX_TIMESTAMP_OFFSET * i, 0) < 0)) {
            perror("rst_gen_mem");
            return -1;
        }
    return 0;
}

int
stop_gen() {
    int i;
    for (i=0;i<NUM_PORTS;i++) {
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, 0L) < 0) ||
                (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, 0L) < 0) ) {
            perror("stop_gen");
            return -1;
        }
    }
    return 0;
}

int
start_gen() {
    int i;
    uint32_t enable = 0;
    uint64_t en_tmstmp = PKTGEN_HDR_OFFSET;
    for (i=0;i<NUM_PORTS;i++) {
        // enabling tx timestamp measurement
        if ((wraxi(TX_TIMESTAMP_BASE_ADDR + TX_TIMESTAMP_OFFSET * i, en_tmstmp)) < 0) {
            LOG_ERROR("Couldn't set timestamp measurement on port %d.\n", i);
            return -1;
        }
        if (sume.obj_cap[i].rx_measurement == 1) {
            if (wraxi(RX_TIMESTAMP_BASE_ADDR + RX_TIMESTAMP_OFFSET * i, en_tmstmp + 2) < 0) {
                LOG_ERROR("Couldn't set rx timestamp measurement on port %d.\n", i);
                return -1;
            }
        }
    }
    for(i=0; i<NUM_PORTS; i++) {
        enable = (int32_t)(sume.queue_bytes[i] > 0);
        if (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY + i*0x4, enable) < 0) {
            LOG_ERROR("Could't enable the PCAP replay");
            return -1;
        }
        usleep(5);
    }
    return 0;
}

int
set_gen_mem() {
    int i;
    uint32_t offset = 0;
    for (i=0;i<NUM_PORTS;i++) {
//        printf("port %d: %d-%d iter %d\n", i, offset, offset + sume.queue_pages[i], sume.queue_iter[i]);
        if ((wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_LOW + i*0x8, offset) < 0)) {
            perror("set_gen_mem");
            return -1;
        }
        if (wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_MEM_HIGH + i*0x8,
					(offset + sume.queue_pages[i])) < 0) {
            perror("set_gen_mem");
            return -1;
        }
		offset +=  sume.queue_pages[i];
    }

    for (i=0;i<NUM_PORTS;i++) {
		if(wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_REPLAY_CNT + i*0x4, sume.queue_iter[i]) < 0) {
            perror("set_gen_mem");
            return -1;
        }
    }

    for (i=0;i<NUM_PORTS;i++) {
		uint32_t enable = (sume.queue_bytes[i] > 0);
		wraxi(PCAP_ENGINE_BASE_ADDR + PCAP_ENGINE_ENABLE + i*0x4, enable);
    }

    for (i=0;i<NUM_PORTS;i++) {
        if (sume.queue_delay[i] > 0) {
            if ((wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY, sume.queue_delay[i]) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_ENABLE, 1) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_USE_REG, 1) < 0) ) {
                perror("set_gen_mem");
                return -1;
            }
        } else {
            if ((wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY, 0) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_ENABLE, 0) < 0) ||
                    (wraxi(INTER_PKT_DELAY_BASE_ADDR + 0x10*i + INTER_PKT_DELAY_USE_REG, 0) < 0) ) {
                perror("set_gen_mem");
                return -1;
            }
        }
    }
    return 0;
}


#define DELAY_HEADER_EXTRACTOR_BASE_ADDR 0x76e00000
#define DELAY_HEADER_EXTRACTOR_RST       0x0
#define DELAY_HEADER_EXTRACTOR_SET       0x4

int nf_init(int pad, int nodrop,int resolve_ns) {
    int i;
    // Sets everything to zero, to be sure.
    memset(&sume, 0, sizeof(struct str_nf_pktgen));

    sume.pad = pad;
    sume.nodrop = nodrop;
    sume.resolve_ns = resolve_ns;

	for (i=0;i<NUM_PORTS;i++) {
        sume.obj_cap[i].cap_fd = -1;
        sume.obj_cap[i].if_ix = i;
        sume.obj_cap[i].name = malloc(sizeof("nfX"));
        if (!sume.obj_cap[i].name) {
            LOG_ERROR("Malloc failed: sume.obj_cap[%d].name.\n", i);
            exit(1);
        }
        sprintf(sume.obj_cap[i].name, "nf%i", i);
        sume.obj_cap[i].h = malloc(sizeof(struct pcap_pkthdr));
        if (!sume.obj_cap[i].h) {
            LOG_ERROR("Malloc failed: sume.obj_cap[%d].h.\n", i);
            exit(1);
        }
        memset(&sume.obj_cap[i].h, 0, sizeof(sume.obj_cap[i].h));
        sume.obj_cap[i].packet_cache = NULL;
        sume.obj_cap[i].caplen = 0;
        sume.obj_cap[i].caplen = 0;
	}

	sem_init(&sume.osnt_sem, 0, 0);

    if (pthread_mutex_init(&sume.pkt_lock, NULL) != 0)
    {
        LOG_ERROR("Mutex init failed\n");
        exit(1);
    }


    wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_RST, 0);
    wraxi(DELAY_HEADER_EXTRACTOR_BASE_ADDR + DELAY_HEADER_EXTRACTOR_SET, 0);

    nf_cap_clear_rules();

    return 0;
}

int nf_start(int wait) {
    int if_fd, i;
	uint32_t j;
    uint32_t ix;
    char if_name[IFNAMSIZ];
    struct sockaddr_ll socket_address;
    struct ifreq ifr;

    pthread_attr_t attr; // thread attribute
    // set thread detachstate attribute to DETACHED
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	cpu_set_t cpu;
    socket_address.sll_halen = ETH_ALEN;

    stop_gen();
    generator_rst(1);
    rst_gen_mem();
    generator_rst(0);
    set_gen_mem();
    for ( i = 0; i < NUM_PORTS; i++) {
        sprintf(if_name, "nf%d", i);

        if_fd = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ALL));
        if (if_fd < 0) {
            perror("socket");
            return -1;
        }

        memset(&ifr, 0, sizeof(struct ifreq));
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
        if (ioctl(if_fd, SIOCGIFINDEX, &ifr) < 0) {
            perror("SIOCGIFINDEX");
            return -1;
        }
        socket_address.sll_ifindex = ifr.ifr_ifindex;
        socket_address.sll_family = PF_PACKET;
        socket_address.sll_protocol = htons(ETH_P_IP);

        /*target is another host*/
        socket_address.sll_pkttype  = PACKET_OTHERHOST;

        /*address length*/
        socket_address.sll_halen    = ETH_ALEN;

        ix = 0;
        printf("adding %d packet on port %s\n", sume.queue_pkts[i], if_name);
        for (j = 0; j < sume.queue_pkts[i]; j++) {
            if (sendto(if_fd, sume.queue_data[i] + ix, sume.pkt_len[i][j], 0,
                        (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
                perror("Send failed");
            ix += sume.pkt_len[i][j];
            if (j%10 == 0) {
                sleep(0.1);
                printf("sleeping\n");
            }
            usleep(50);
        }
        close(if_fd);
    }
    usleep(wait);
    for (i=0; i < NUM_PORTS; i++) {
        wraxi(PCAP_LOAD_PCAP_ONLY + 0x4*i, 0x1);
        sleep(0.5);
        wraxi(PCAP_LOAD_PCAP_ONLY + 0x4*i, 0x0);
    }

	CPU_ZERO(&cpu);
	CPU_SET(2, &cpu);
    sume.gen_start = ((double)time(NULL));
    pthread_yield();
    printf("Finished sending the packets to the board...\n");
    start_gen();

    return 0;
}

int nf_gen_reset_queue(int port) {
    LOG_ERROR("unimplemented nf_gen_reset_queue for queue %d\n", port);
    return 0;
}

int nf_gen_set_number_iterations(int number_iterations, int iterations_enable,
        int queue) {
    if (iterations_enable < 0) {
        LOG_ERROR("Negative iteration number.\n");
        return -1;
    }
    sume.queue_iter[queue] = number_iterations;
    return 0;
}


#define RATE_LIMITER_BASE_ADDR 0x77e00000
#define RATE_LIMITER           0x8
#define RATE_LIMITER_ENABLE    0x4
#define RATE_LIMITER_RST       0x0

int nf_gen_rate_limiter_enable(int port, int cpu) {
    if ( wraxi(RATE_LIMITER_BASE_ADDR + RATE_LIMITER_ENABLE + 0xC * port, 0x1) < 0) {
        LOG_ERROR("Failed to enable rate limiter on port %d.\n", port);
        return -1;
    };
    return 0;
}

int nf_gen_rate_limiter_disable(int port, int cpu) {
    if (wraxi(RATE_LIMITER_BASE_ADDR + RATE_LIMITER_ENABLE + 0xC * port, 0x0) < 0) {
        LOG_ERROR("Failed to disable rate limiter on port %d.\n", port);
        return -1;
    }
    return 0;
}

int nf_gen_rate_limiter_set(int port, int cpu, float rate) {
    if (wraxi(RATE_LIMITER_BASE_ADDR + RATE_LIMITER + 0xC * port, (uint64_t)rate) < 0) {
        LOG_ERROR("Failed to set rate limit to %f on port %d.\n", rate, port);
        return -1;
    }
    LOG_INFO("Set rate limiter to %f on port %d.\n", rate, port);
    return 0;
}

int nf_gen_rate_limiter_reset(int port) {
    if (wraxi(RATE_LIMITER_BASE_ADDR + RATE_LIMITER_RST + 0xC*port, 0x1) < 0) {
        LOG_ERROR("Failed to reset rate limiter\n");
        return -1;
    }
    if (nf_gen_rate_limiter_disable(port, -1) < 0) {
        LOG_ERROR("Failed to disable rate limiter\n");
        return -1;
    }
    if (nf_gen_rate_limiter_set(port, -1, 0) < 0) {
        LOG_ERROR("Failed to reset rate.\n");
        return -1;
    }
    return 0;
}

int nf_gen_wait_end() {
    int i;
    double last_pkt = 0, delta = 0, queue_last;
    for (i = 0; i < NUM_PORTS; i++) {
        if (sume.queue_data_len[i]) {
            queue_last = sume.queue_pkts[i] * sume.queue_delay[i] * pow(10,-9) * sume.queue_iter[i];
            if (queue_last > last_pkt) {
                last_pkt = queue_last;
            }
        }
    }

    printf("delta : %f, last_pkt: %.09f\n", delta, last_pkt);
    // Wait the requesite number of seconds
    while (delta <= last_pkt) {
        printf("\r%1.3f seconds elapsed...\n", delta);
        pthread_yield();
        delta = ((double)time(NULL)) - sume.gen_start;
    }
    return 0;
}

int nf_gen_finished() {
    int i;
    double last_pkt = 0, queue_last;
    for (i = 0; i < NUM_PORTS; i++) {
        if (sume.queue_data_len[i]) {
            queue_last = ((double)sume.queue_delay[i]) / (double)(10*DATAPATH_FREQUENCY);
            queue_last *= sume.queue_pkts[i] * sume.queue_iter[i];
            if (queue_last > last_pkt) {
                last_pkt = queue_last;
           }
        }
    }

    //  printf("finished? %e %e < %ld %ld %ld %e\n", ((double)time(NULL)), sume.gen_start, sume.queue_delay[i], sume.queue_pkts[i],
    //      sume.queue_iter[i], last_pkt);
    //  return (((double)time(NULL) - sume.gen_start) > last_pkt);
    return 0;

}

int nf_restart() {
    stop_gen();
    start_gen();
    return 0;
}

#define CUTTER_BASE_ADDR 0x77a00000
#define CUTTER_ENABLE 0x0
#define CUTTER_WORDS  0x4
#define CUTTER_OFFSET 0x8
#define CUTTER_BYTES  0xc


/**
 * @brief: Enable packet capturing on the given interface.
 * @param dev_name: The device to sniff on.
 * @param: caplen The number of bytes of the packet that are available from the
 * capture.
 **/
struct nf_cap_t *nf_cap_enable(char *dev_name, int caplen) {
    // Errbuf for pcap.
    char errbuf[PCAP_ERRBUF_SIZE];
    struct nf_cap_t *ret = NULL;
    int ix;

    // Safety check in order to avoid malformed data.
    if ((!dev_name) || (caplen <= 0)) {
        LOG_ERROR("Invalid data");
        return NULL;
    }

    uint32_t words = ceil(((float)caplen)/32) - 2;
    uint32_t offset = 32 - (caplen % 32);
    uint32_t bytes = (0xffffffff << offset) & 0xffffffff;

    wraxi(CUTTER_BASE_ADDR + CUTTER_WORDS, words);
    wraxi(CUTTER_BASE_ADDR + CUTTER_OFFSET, bytes);
    wraxi(CUTTER_BASE_ADDR + CUTTER_BYTES, caplen);
    wraxi(CUTTER_BASE_ADDR + CUTTER_ENABLE, 1);

    for(ix = 0; ix < NUM_PORTS; ix++) {
        if(strcmp(sume.obj_cap[ix].name, dev_name) == 0) break;
    }

    ret = malloc(sizeof(struct nf_cap_t));
    if (!ret) {
        LOG_ERROR("Malloc failed: ret.\n");
        return NULL;
        exit(1);
    }

    if (ix == NUM_PORTS) {
        LOG_ERROR("Invalid device name %s.\n", dev_name);
        return NULL;
    } else {
        ret = &sume.obj_cap[ix];
    }

    ret->pcap_handle = pcap_create(dev_name, errbuf);
    if (ret->pcap_handle == NULL) {
        LOG_ERROR("Couldn't open device %s: %s.\n",
                dev_name, errbuf);
        return NULL;
    }
    if ((pcap_set_snaplen(ret->pcap_handle, caplen)) < 0) {
        LOG_ERROR("setup_channel: pcap_set_snaplen: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if ((pcap_set_promisc(ret->pcap_handle, PROMISC)) < 0) {
        LOG_ERROR("setup_channel: pcap_set_promisc: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if ((pcap_set_timeout(ret->pcap_handle, 1000)) < 0) {
        LOG_ERROR("setup_channel: pcap_set_timeout: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if (pcap_set_buffer_size(ret->pcap_handle, 2048000) < 0) {
        LOG_ERROR("setup_channel: pcap_set_buffer_size: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if ((pcap_activate(ret->pcap_handle)) < 0) {
        LOG_ERROR("Couldn't activate pcap_handle: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if (pcap_setdirection(ret->pcap_handle, PCAP_D_IN) < 0) {
        LOG_ERROR("setup_channel: pcap_setdirection: %s.\n",
                pcap_geterr(ret->pcap_handle));
        return NULL;
    }
    if (pcap_setnonblock(ret->pcap_handle, 1, errbuf) < 0) {
        LOG_ERROR("setup_channel: pcap_setnonblock: %s.\n",
                errbuf);
        return NULL;
    }

    ret->cap_fd = pcap_get_selectable_fd(ret->pcap_handle);
    if (ret->cap_fd == -1) {
        LOG_ERROR("Selectable fd are not supported");
    }

    // Allocate memory for the incoming packet.
    ret->caplen = caplen;
    ret->packet_cache = malloc(caplen);
    if(!ret->packet_cache) {
        // Malloc failed.
        LOG_ERROR("Malloc failed.\n");
        return NULL;
    }

    //TODO fix caplen
    return ret;
}



/**
 * Utility function that returns the file descriptor associated to the
 * cap handle.
 * It checks that the given structure exists, in order to avoid issues.
 **/
int nf_cap_fileno(struct nf_cap_t *cap) {
    if(cap) {return cap->cap_fd;}
    else {return -1;}
}

/**
 *  Utility function that returns the maximum number of packets that can be sent by the board.
 **/
uint32_t nf_get_max_packet() {
    int i;
    uint32_t max = 0;
    for (i=0; i<NUM_PORTS; i++) {
        max += sume.queue_pkts[i]*sume.queue_iter[i];
    }
    return max;
}

/**
 * @name: nf_finish
 * @brief: This function is called after the last packet has been sent.
 **/
int nf_finish() {
    stop_gen();
    sume.terminate = 1;
    printf("XXXXXXXX terminating generation thread XXXXXXXX\n");
    pthread_mutex_destroy(&sume.pkt_lock);
    return 0;
}

void nf_kill_pcap() {
    int i;
    for (i=0; i<NUM_PORTS; i++) {
        if (sume.obj_cap[i].pcap_handle != NULL) {
            fprintf(stderr, "Closing pcap handle for interface %s\n", sume.obj_cap[i].name);
            pcap_close(sume.obj_cap[i].pcap_handle);
            sume.obj_cap[i].pcap_handle = NULL;
        }
        free(sume.obj_cap[i].h);
        free(sume.obj_cap[i].name);
    }
}


// These counters are after the filtering modules that
// can drop some packets. Useful if you know how many packets
// should arrive.
#define SUME_STATS_RCV_BASE_ADDR  0x75000000
#define SUME_STATS_RCV_RST        0x0
#define SUME_STATS_RCV_FREEZE     0x4
#define SUME_STATS_RCV_PKT_CNT    0x8
#define SUME_STATS_RCV_BYTE_CNT   0x18

// These counters are directly on the ports of the board.
// This is the raw number of packets that arrived on
// the physical port.
#define SUME_STATS_RAW_BASE_ADDR  0x75000000
#define SUME_STATS_RAW_OFFSET     0x2000
#define SUME_STATS_RAW_RST        0x0
#define SUME_STATS_RAW_RX_OFFSET  0x8
#define SUME_STATS_RAW_TX_OFFSET  0xc

/**
 * @brief: Get the number of transmitted packets by the board for the given queue.
 * @param queue: The queue to look on.
 * @param stat: the structure to fill.
 **/
int nf_gen_stat(int queue, struct nf_gen_stats *stat) {
    assert (queue < NUM_PORTS);
    if(rdaxi(SUME_STATS_RAW_BASE_ADDR + SUME_STATS_RAW_OFFSET*queue + SUME_STATS_RAW_TX_OFFSET,
             &stat->pkt_snd_cnt ) < 0) {
        LOG_ERROR("Couldn't read pkt counter for channel %d", queue);
        return -1;
    }
    return 0;
}

/**
 * @brief: Reset the raw counters that are before any modules
 **/
int nf_port_cnt_reset() {
    if (wraxi(SUME_STATS_RAW_BASE_ADDR + SUME_STATS_RAW_RST, 1) < 0) {
        LOG_ERROR("Couldn't freeze raw packet counting for reset.\n");
        return -1;
    }
    if (wraxi(SUME_STATS_RAW_BASE_ADDR + SUME_STATS_RAW_RST, 0) < 0) {
        LOG_ERROR("Couldn't reset raw packet counter.\n");
        return -1;
    }
    fprintf(stdout, "Raw counter reset completed.\n");
    return 0;
}

/**
 * @brief: Get the stats from the counter after the filtering step.
 * @param queue: The port number to look on.
 * @param stat: The structure to fill.
 * @description: This returns the values after the filtering module, which
 * means that it is the number of packets that have passed the filtering module
 * since the last reset of this counter
 **/
int nf_cap_stat(int queue, struct nf_cap_stats *stat) {
    int succeed = 0;
    if (wraxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_FREEZE, 1) < 0) {
        LOG_ERROR("Unable to freeze rcv counter.\n");
        return -1;
    }
    if ((rdaxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_PKT_CNT + queue*0x4, &stat->pkt_cnt) <0) ||
        (rdaxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_BYTE_CNT + queue*0x4, &stat->byte_cnt) <0)) {
        LOG_ERROR("Couldn't read statistics from the board for channel %d.\n", queue);
        succeed = -1;
    }
    if (wraxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_FREEZE, 0) < 0) {
        LOG_ERROR("Unable to unfreeze rcv counter.\n");
    }
    return succeed;
}


/**
 * @brief: Resets the statistics counters.
 **/
int nf_reset_stats() {
    if (wraxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_RST, 1) < 0) {
        LOG_ERROR("Couldn't freeze packet counting for reset.\n");
        return -1;
    }
    if (wraxi(SUME_STATS_RCV_BASE_ADDR + SUME_STATS_RCV_RST, 0) < 0) {
        LOG_ERROR("Couldn't reset packet counter.\n");
        return -1;
    }
    fprintf(stdout, "Stats counter reset completed.\n");
    return 0;
}

/**
 * @brief: Enables the rx measurement on device dev_name
 **/
int nf_enable_rx_measurement(char* dev_name) {
    int i;
    if(!dev_name) {
        LOG_ERROR("Invalid data: No device given.");
        return -1;
    }
    for(i=0; i < NUM_PORTS; i++) {
        if(strcmp(sume.obj_cap[i].name, dev_name) == 0) {
            sume.obj_cap[i].rx_measurement = 1;
            printf("Enabled rx_measurement on device %s\n", dev_name);
            return 0;
        }
    }
    LOG_ERROR("No device found.\n");
    return -1;
}

#define SUME_TIMER_ADDR 0x78a00000
#define SUME_TIME_LOW_REG   0x24
#define SUME_TIME_HIGH_REG  0x28

void nf_cap_timeofday(struct timeval *now) {
    uint32_t low, high;
    rdaxi(SUME_TIMER_ADDR + SUME_TIME_LOW_REG, &low);
    rdaxi(SUME_TIMER_ADDR + SUME_TIME_HIGH_REG, &high);
    now->tv_sec = (high & 0xffffffff);
    now->tv_usec = ((( ((uint64_t)low) & 0xffffffffL)*1000000000L)>>32);
    if (INFO) {
        LOG_INFO("Board timeofday is %ld.%.6ld\n", now->tv_sec, now->tv_usec);
    }
    return;
}

inline void free_wrap(pcap_event* pe) {
    if (pe != NULL) {
        free(pe->data);
        free(pe);
    }
}


const u_char* nf_cap_next(struct nf_cap_t *cap, struct pcap_pkthdr *h) {
    int len, rc;
    const u_char* packet;
    struct pcap_pkthdr *rcv;

    if (!sume.obj_cap[cap->if_ix].pcap_handle) {
        LOG_ERROR("No pcap handle enabled for device %s", cap->name);
        return NULL;
    }

    rc = pcap_next_ex(sume.obj_cap[cap->if_ix].pcap_handle, &rcv, &packet);
    if (rc == 0) {
        if (INFO) {
            LOG_WARNING("No packet available on device %s.\n",
                        sume.obj_cap[cap->if_ix].name);
        }
        return (const u_char*)-1;
    } else if (rc < 0) {
        LOG_ERROR("pcap_next_ex failed : %d :: %s.\n",
                  rc, pcap_geterr(sume.obj_cap[cap->if_ix].pcap_handle));
        return NULL;
    }
    memcpy(h, rcv, sizeof(*rcv));
    sume.pkt_count++;
    sume.byte_count += h->len;
    len = h->len;
    memcpy(cap->packet_cache, packet, len);
    return cap->packet_cache;
}

static inline int
metadata_to_port(uint32_t meta) {
	/* decode */
	int port_enc = (meta >> 16) & 0xff;
	switch (port_enc) {
		case 0x02:	return 0;
		case 0x08:	return 1;
		case 0x20:	return 2;
		case 0x80:	return 3;
		default:	return -1;
	}
	return -1;
}




// int
// display_xmit_metrics(int queue, struct nf_gen_stats *stat) {
//     printf("Unimplemented function display_xmit_metrics\n");
//     return 0;
//     // readReg(&nf_pktgen.nf2,
//     //     OQ_QUEUE_0_NUM_PKTS_REMOVED_REG+(queue+8)*nf_pktgen.queue_addr_offset,
//     //     &stat->pkt_snd_cnt);
// }

struct str_nf_pktgen nf_pktgen;

struct pktgen_hdr *
nf_gen_extract_header(struct nf_cap_t *cap, const uint8_t *b, int len) {
    uint32_t swap;
    struct pktgen_hdr *ret;
    int ix = (PKTGEN_HDR_OFFSET -2)*8;
    struct timeval now;
    int offset = 0;

    // sanity check
    if( (b == NULL) || (len < PKTGEN_HDR_OFFSET*8 + 16)) {
		LOG_ERROR("error buf %p, len %d\n", b, len);
        return NULL;
	}

    //constant distance
    ret = (struct pktgen_hdr *)(b + ix);
    if (cap->rx_measurement == 1) {

        if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) { //sometimes the 1st byte is messed up
            //if the vlan tag is stripped move the translation by 4 bytes.
#if DEBUG == 1
            printf("Packet gen packet received %08x\n",ntohl(ret->magic));
#endif
            offset = -4;
            ret = (struct pktgen_hdr *)((uint8_t *)b + ix + offset);
            if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) {
#if DEBUG == 1
                printf("reading header %08x\n", 0xFFFFFFFF & ntohl(ret->magic));
#endif
                offset = 4;
                ret = (struct pktgen_hdr *)((uint8_t *)b + ix + offset);
                if((0xFFFFFFFF & ntohl(ret->magic)) != 0xdeadbeef) {
#if DEBUG == 1
                    printf("reading header %08x\n", 0xFFFFFFFF & ntohl(ret->magic));
#endif
                    return NULL;
                }
            }
        }

        // Warning: Big Hack here.
        // In the data retrieved from the board, we have
        //  0               32          64
        //  |  < magic >    |    <seq_num>  |
        //  |  <tv_usec>    |    <tv_sec>   |
        //  [ ...     padding 0 bytes   ... ]
        //  | <tv_rcv_usec> | <tv_rcv_usec> |
        //  but the struct is { magic ; seq_num; tv_sec: tv_usec; tv_rcv_sec;
        //  tv_rcv_usec } aka
        //  0              32              64
        //  |   < magic >  |   <seq_num>   |
        //  |   <tv_sec >  |   <tv_usec>   |
        //  | <tv_rcv_sec> | <tv_rcv_usec> |
        //  However, in order to be compliant with the nf_pktgen.h file, I prefer
        //  swapping the values.
        swap = ret->tv_sec;
        ret->tv_sec = ret->tv_usec;
        ret->tv_usec = (((uint64_t)swap) * 1000000000L) >> 32;

        ret->seq_num = ntohl(ret->seq_num);
        offset = 8 - offset;
        memcpy(&ret->tv_rcv_usec, ((uint8_t *)ret + 16 + offset ), 4);
        memcpy(&ret->tv_rcv_sec, ((uint8_t *)ret + 16 + offset + 4), 4);
        ret->tv_rcv_usec = (((uint64_t)ret->tv_rcv_usec) * 1000000000L) >> 32;
    } else {
        gettimeofday(&now, NULL);
        ret->seq_num = ntohl(ret->seq_num);
        ret->tv_rcv_sec = now.tv_sec;
        ret->tv_rcv_usec = now.tv_usec;
    }

#if INFO == 1
    printf("packet time %x %d %u.%09u\n", ntohl(ret->magic), htonl(ret->seq_num),
            ret->tv_sec, ret->tv_usec);
#endif
    return ret;
}

/* Definitions for peripheral OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0 */
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH       16
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BASEADDR            0x72220000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_HIGHADDR            0x7222FFFF
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_RESET         0x72220000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_FREEZE        0x72220004
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF0     0x72220008
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF1     0x7222000c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF2     0x72220010
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_PKT_COUNT_INTF3     0x72220014
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF0   0x72220018
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF1   0x7222001c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF2   0x72220020
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_BYTES_COUNT_INTF3   0x72220024
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF0    0x72220028
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF1    0x7222002c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF2    0x72220030
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_VLAN_COUNT_INTF3    0x72220034
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF0      0x72220038
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF1      0x7222003c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF2      0x72220040
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_IP_COUNT_INTF3      0x72220044
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF0     0x72220048
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF1     0x7222004c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF2     0x72220050
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_UDP_COUNT_INTF3     0x72220054
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF0     0x72220058
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF1     0x7222005c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF2     0x72220060
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_TCP_COUNT_INTF3     0x72220064
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_TIME_LOW      0x72220068
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR0_STATS_TIME_HIGH     0x7222006c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_BASEADDR            0x75008000
//#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_HIGHADDR 0x7220FFFF
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP                 0x75008000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_BASEADDR 0x75000000
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_OFFSET   0x0
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_VALUE    0x00000100
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK            0x75008004
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP              0x75008008
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK            0x7500800c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS            0x75008010
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK       0x75008014
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO               0x75008018
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK          0x7500801c
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR             0x75008020
#define XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_RD_ADDR             0x75008024

void nf_cap_clear_rule(int entry) {
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK, 0xffffffff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK);
  if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO, 0xff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO);
  if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK, 0xff))
	  LOG_ERROR("Clearing rule 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK);
}

void nf_cap_clear_rules() {
    int i;
    uint32_t rd_value;
    if (rdaxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_BASEADDR +
                XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_OFFSET, &rd_value) < 0) {
        LOG_ERROR("Couldn't read force drop register");
        return;
    }
    if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_BASEADDR +
                XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_OFFSET,
                rd_value  | XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_VALUE ) < 0) {
        LOG_ERROR("Couldn't write the force drop value.");
    }
    for (i = 0; i < XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH; i++) {
        nf_cap_clear_rule(i);
    }
}

void nf_cap_add_rule(int entry, uint8_t proto, uint32_t src_ip, uint32_t dest_ip,
		uint16_t l4ports, uint8_t proto_mask, uint32_t src_ip_mask,
		uint32_t dest_ip_mask,  uint16_t l4ports_mask) {
    uint32_t rd_value;
    printf("Adding filtering rule on the board\n");
    if ( (entry >= 0)  && (entry < XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH)) {
        if (rdaxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_BASEADDR +
                    XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_OFFSET, &rd_value) < 0) {
            LOG_ERROR("Couldn't read force drop register");
            return;
        }
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_BASEADDR +
                    XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_OFFSET,
                    rd_value  & ~XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_FORCE_DROP_VALUE ) < 0) {
            LOG_ERROR("Couldn't write the accept packets value.");
        }
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP, src_ip))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK, src_ip_mask))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_SIP_MASK);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP, dest_ip))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_IP);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK, dest_ip_mask))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_DIP_MASK);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS, l4ports))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK, l4ports_mask))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_L4_PORTS_MASK);
        if(wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO, (uint32_t)proto))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK, proto_mask))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_PROTO_MASK);
        if (wraxi(XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR, entry))
            LOG_ERROR("Setting rule on 0x%08x.\n", XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_BAR1_WR_ADDR);
    } else {
        LOG_ERROR("At most %d rules can be set. The present rule has been ignored.\n",
                XPAR_OSNT_MONITORING_OUTPUT_PORT_LOOKUP_0_FILTER_TABLE_DEPTH);
    }
}
