#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <libgen.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "iscsi_stats.skel.h"
#include "iscsi.h"

static bool exiting = false;

void print_stats(struct iscsi_stats *stats) {

	printf("RW: Count [%lu] total bytes [%lu]\n\n",
		stats->count, stats->total_bytes);

	printf("Toal Interval\n");
	printf("Waiting			Sending			Complete\n");
	printf("-----------------------------------------------------------\n");
	printf("%lu(%lu)		%lu(%lu)		%lu(%lu)\n",
		stats->waiting,	stats->waiting_cycle,
		stats->sending, stats->send_cycle,
		stats->complete, stats->complete_cycle);
	printf("-----------------------------------------------------------\n\n");

	printf("Max Interval\n");
	printf("Waiting			Sending			Complete\n");
	printf("-----------------------------------------------------------\n");
	printf("%lu			%lu			%lu\n",
		stats->max_waiting,
		stats->max_sending,
		stats->max_complete);
	printf("-----------------------------------------------------------\n\n\n");

}

static void sig_handler(int sig)
{
	exiting = true;
}


int main() {
    struct bpf_map *map = NULL;
    struct iscsi_stats stats = {};
    __u64 key;
    __u64 next_key;
    int err;
    int map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    struct iscsi_stats_bpf *skel;

    // open skeleton
    skel = iscsi_stats_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // load BPF 
    err = iscsi_stats_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // attach BPF
    err = iscsi_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    printf("BPF program loaded and attached successfully.\n");
    
    map_fd = bpf_map__fd(skel->maps.stats_map);
    while (true) {
	    sleep(1);
	    key = 0;
        while (true) {
            err = bpf_map_get_next_key(map_fd, &key, &next_key);
	    if (err) {
	        if (errno == ENOENT)
			err = 0;
		break;
	    }
            err = bpf_map_lookup_elem(map_fd, &next_key, &stats);
            if (err == 0) {
                print_stats(&stats);
            } else {
                fprintf(stderr, "Failed to lookup map element\n");
            }
        }
        key = next_key;
	if (exiting)
		break;
    }

cleanup:

    iscsi_stats_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

