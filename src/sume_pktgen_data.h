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
#include <pcap/pcap.h>
#include <sys/queue.h>
#include <nf10_lbuf_api.h>
#include <semaphore.h>

//#include "ringbuffers.h"

#define PKTGEN_HDR_OFFSET 10

#define NUM_PORTS 4
#define MEM_HIGH_ADDR 512*1024

#define DATAPATH_FREQUENCY 160000000L
#define DEBUG 0
#define INFO  0

#define FILTER_RULE_COUNT 8

#define PAGE_SIZE 4096

#undef PKTGEN_HDR
#include "nf_pktgen.h"


#define PROMISC 1


//struct __attribute__((packed)) osnt_cap_t {
//    uint32_t metadata;
//	uint32_t pkt_len;
//	uint64_t timestamp;
//    uint8_t pkt[PKTGEN_HDR_OFFSET*8 + 16];
//};

struct nf_cap_t {
    pcap_t * pcap_handle;
    int cap_fd;
	sem_t sem;
    int if_ix;
    char* name;
	struct pcap_pkthdr* h;
    u_char *packet_cache;
    int caplen;
    uint8_t rx_measurement;
};

struct sume_ifreq {
    uint32_t addr;
    uint32_t val;
};

struct str_nf_pktgen {
    int dev_fd;
    uint32_t queue_pages[NUM_PORTS];
    uint32_t queue_bytes[NUM_PORTS];
    uint32_t queue_pkts[NUM_PORTS];
    uint32_t queue_delay[NUM_PORTS];
    uint32_t num_pkts[NUM_PORTS];
    uint32_t queue_iter[NUM_PORTS];

    uint8_t *queue_data[NUM_PORTS];
    uint32_t *pkt_len[NUM_PORTS];
    uint32_t queue_data_len[NUM_PORTS];
	uint32_t pkt_snd_count;
	uint32_t pkt_dropped_count;

    uint32_t total_words;
    uint8_t pad, nodrop, resolve_ns;
    double gen_start;

    int terminate;

    struct nf_cap_t obj_cap[NUM_PORTS];
	sem_t osnt_sem;

	sem_t *pcap_sem[NUM_PORTS];

    pthread_t osnt_tid, pcap_tid;  // thread ID
    pthread_mutex_t pkt_lock;
    void *buf[NR_LBUF];
	uint32_t pkt_count;
	uint32_t byte_count;
};

struct pcap_event;

typedef struct pcap_event {
    struct pcap_pkthdr pcaphdr;
    unsigned char * data;
} pcap_event;

struct pcap_event_wrapper
{
    pcap_event *pe;
};

uint32_t nf_get_max_packet();
void nf_kill_pcap();
int nf_reset_stats();
int nf_port_cnt_reset();
int nf_enable_rx_measurement(char*);
