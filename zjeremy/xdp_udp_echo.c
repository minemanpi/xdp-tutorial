#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <stdint.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ENSURE(pointer, data_end) if ((pointer) + 1 > (data_end)) return XDP_PASS

// See: https://docs.cilium.io/en/v1.8/bpf/
#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

struct memcached_udp_header {
    __be16 request_id;
    __be16 seq_num;
    __be16 num_dgram;
    __be16 unused;
    char data[];
} __attribute__((__packed__));

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

static inline __u16 compute_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *next_ip_u16 = (__u16 *)ip;

    ip->check = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp_sock")
int udp_server_rx_filter_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    void *transp = data + sizeof(*eth) + sizeof(*ip);
    struct udphdr *udp;
    char *payload;
    __be16 dport;

    if (ip + 1 > data_end) return XDP_PASS;

    switch (ip->protocol) {
        case IPPROTO_UDP:
            udp = (struct udphdr *)transp;
            if (udp + 1 > data_end) return XDP_PASS;
            dport = udp->dest;
            payload =
                transp + sizeof(*udp) + sizeof(struct memcached_udp_header);
            break;
        default:
            return XDP_PASS;
    }

    // Is this a memcached GET request?
    if (dport == bpf_htons(11211) && payload + 4 <= data_end) {
        if (ip->protocol == IPPROTO_UDP && payload[0] == 'g' &&
            payload[1] == 'e' && payload[2] == 't' && payload[3] == ' ') {
            // Prepare payload:

            // 1. Swap MAC addresses
            uint8_t swap_eth[ETH_ALEN];
            memcpy(swap_eth, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, swap_eth, ETH_ALEN);

            // 2. Swap IP addresses
            uint32_t swap_ip = ip->daddr;
            ip->daddr = ip->saddr;
            ip->saddr = swap_ip;

            // 3. Swap UDP ports
            uint16_t swap_port;
            swap_port = udp->dest;
            udp->dest = udp->source;
            udp->source = swap_port;

            //char server_resp[] =
            //"VALUE 0123456789012345 0 32\n"
            //"01234567890123450123456789012345\n"
            //"END";

            // 4. Copy response
            int extra_bytes_needed = 0;
            //    sizeof(server_resp) - (ctx->data_end - (__u32)payload);
            //bpf_printk("Payload size: %lu\n", ctx->data_end - (__u32)payload);
            //bpf_printk("Size of server response: %lu\n", sizeof(server_resp));
            //bpf_printk("Extra bytes needed: %d\n", extra_bytes_needed);

            //if (bpf_xdp_adjust_tail(ctx, extra_bytes_needed)) {
            //    bpf_printk("XDP adjust tail failed! :'(");
            //    return XDP_PASS;
            //}
            // After running bpf_xdp_adjust_tail, all checks are void, must
            // reset all pointers.
            data_end = (void *)(long)ctx->data_end;
            data = (void *)(long)ctx->data;
            eth = data;
            ip = data + sizeof(*eth);
            transp = data + sizeof(*eth) + sizeof(*ip);
            udp = (struct udphdr *)transp;
            payload = transp + sizeof(*udp) + sizeof(struct memcached_udp_header);

            //if (payload + sizeof(server_resp) <= (void *)(long)ctx->data_end) {
            //    memcpy(payload, server_resp, sizeof(server_resp));
            //}

            ENSURE(ip, (void *)(long)ctx->data_end);
            ENSURE(udp, (void *)(long)ctx->data_end);
            ENSURE(payload, (void *)(long)ctx->data_end);

            // 5. Adjust IP and UDP length fields
            ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + extra_bytes_needed);
            udp->len = bpf_htons(bpf_ntohs(udp->len) + extra_bytes_needed);

            // 6. Calculate IP checksum
            ip->check = compute_ip_checksum(ip);
            udp->check = 0;


            // do AF_XDP swap
            int index = ctx->rx_queue_index;
            if (bpf_map_lookup_elem(&xsks_map, &index)){
                //bpf_printk("sent to af_xdp!\n");
                return bpf_redirect_map(&xsks_map, index, 0);
            }



            // Send packet back
            bpf_printk("bad bad bad\n");
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
