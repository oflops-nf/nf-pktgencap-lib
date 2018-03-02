# NF-PktgenCap-Lib

NF-PktgenCap-Lib is a library dedicated to packet generation and capturing
for the NetFPGA boards.

For now, it is compatible with the 1G, 10G and SUME boards.
This library provide an API to setup communication, packet sending, packet
capture and packet parsing.

For the SUME board, it relies on the Pcap library.

## Installation

1. Make sure that the following libraries are installed on your device:
    * `libpcap` (development library)

   For the documentation, you will need `doxygen` and `doxygen-latex`.

To install on:
* Debian/Ubuntu: `sudo apt install libpcap-dev`
* Fedora/CentOS: `sudo yum install libpcap-devel`

2. Clone the git repository : `git clone https://github.com/Gu1nness/nf-pktgencap-lib/tree/devel`

3. Run `./autogen.sh` to bootstrap the project

4. Run `./configure`

5. Run `make` to compile the library.

6. Run `make docs` to compile the documentation (both pdf and html)
   Run `make html` to compile only the html version.

## Basic API usage

More information can be found in the documentation.

### Init the library

```
int nf_init(int pad, int nodrop, int resolve_ns)
```
Usually, it is called with 1, 0, 0.

### Rate limiter, Interpacket gap delay

```
int nf_gen_rate_limiter_set(int port, int cpu, float rate) 
```

In boards other than NetFPGA 1G, `cpu` is unused.
`port` is the queue on which the rate limitation should be set
and rate is the rate in B/s


### Load data on the board

```
int nf_gen_load_packet(struct pcap_pkthdr *h, const unsigned char *data, int port, uint64_t delay)
int nf_gen_load_pcap(const char *filename, int port, uint64_t ns_delay)
```

`nf_gen_load_pcap` loads into memory the content of the pcap file `filename`.
It will use a delay (in nanoseconds) of `delay` between each packet.

`nf_gen_load_packet` loads one packet into memory, and appends it to the
formerly loaded packets.  It add a delay of `ns_delay` (in nanoseconds) between
the last packet of the queue and this one.
`h` is the pcap packet header, and `data` the payload of the packet.

### Enabling/Disabling rate limiters

```
int nf_gen_rate_limiter_enable(int port, int cpu)
int nf_gen_rate_limiter_disable(int port, int cpu)
```

On boards after NetFGPA 1G `cpu` is unused.

### Capturing packets

```
struct nf_cap_t *nf_cap_enable(char *dev_name, int caplen)
```

Enable packet capture on device `dev_name`, with caplen (length of data
captured in the packet of `caplen`.

Returns a struct `nf_cap_t *` that contains the handler, a selectable file
descriptor and other metadata.

```
int nf_enable_rx_measurements(char *dev_name)
```

Enables the rx timestamping of the packets on device `dev_name`.

### Enable packet generation and capturing

```
int nf_start(int wait)
```

Loads the packets on the board, wait for `wait` microseconds and start sending
the packets and the packet capture.

### Wait until generation is finished

```
int nf_gen_finished{}
```

### Terminate the packet generator

```
void nf_finish()
```

## For the SUME board only

### Destroy pcap\_handlers and free memory

```
void nf_kill_pcap()
```

### Examples of use.

1. Pkt\_cap: The source code is [here](./examples/pkt_cap.c)

```
./examples/pkt_cap
```

Reads packets from the pcap file, sends it on interface `nf0` and  here on interface `nf1`.


2. Blueswitch: The source code is [here](./examples/blueswitch_test.c)

```
./examples/blueswitch_test -i <input file> -o <output file> -c <iteration number> -d <delay > -v
```

The input file should be a pcap file.
Loads packets from the file, sends it on `nf0`, receive it on `nf1` and checks the hardware timestamping.
