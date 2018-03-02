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
#include "nf_pktgen.h"

#include <sys/time.h>
#include <strings.h>
#include <math.h>
#include <stdio.h>
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>

////////////////////////////////////////////////////////////////////////////////
// This small example calculates the average time necessary to make a         //
// timestamp register on the board, when there is no other strain on it.      //
// Keep in mind that  when there are other operations running, it can be      //
// longer (my tests made it increase up to 200µs                              //
////////////////////////////////////////////////////////////////////////////////

uint64_t timediff(struct timeval* now, struct timeval* then) {
    return ((now->tv_sec - then->tv_sec)*1000000L +now->tv_usec) - then->tv_usec;
}

int main(int argc, char *argv[])
{
    FILE* out;
    int count = 0;
    char msg[1024];
    double* data;
    uint32_t mean, median, variance;
    data = malloc(10000*sizeof(double));

    out = fopen("timestamp.log", "w");

    struct timeval before[10000];
    struct timeval after[10000];
    struct timeval garbage;
    //enable padding
    nf_init(1, 0, 0);
    while( (count < 10000)){
        gettimeofday(&before[count], NULL);
        nf_cap_timeofday(&garbage);
        gettimeofday(&after[count++], NULL);
    }
    count=0;
    while( (count < 10000)) {
        snprintf(msg, 1024, "ts:before:%lu.%06lu:after:%lu.%06lu\n",
                before[count].tv_sec, before[count].tv_usec,
                after[count].tv_sec, after[count].tv_usec);
        fprintf(out, "%s", msg);
        fflush(out);
        data[count] = timediff(&after[count], &before[count]);
        count++;
    }
    gsl_sort(data+1, 1, 10000);
    mean = (uint32_t)gsl_stats_mean(data, 1, 10000);
    variance = (uint32_t)gsl_stats_variance(data, 1, 10000);
    median = (uint32_t)gsl_stats_median_from_sorted_data (data, 1, 10000);

    snprintf(msg, 1024, "mean:%lu, devt:%lu, med:%lu\n", (long unsigned)mean,
            (long unsigned)sqrt(variance), (long unsigned)median);
    fprintf(out, "%s", msg);
    fflush(out);
    printf("mean:%lu, devt:%lu, med:%lu\n", (long unsigned)mean,
            (long unsigned)sqrt(variance), (long unsigned)median);
    fclose(out);
    return 0;
}
