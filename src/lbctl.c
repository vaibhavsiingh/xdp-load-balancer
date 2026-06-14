// SPDX-License-Identifier: GPL-2.0
/*
 * Control plane for the XDP load balancer.
 *
 * The data plane (bpf/xdp_lb.bpf.c) only reads BPF maps. This process owns
 * everything slow: loading and attaching the program, health-checking
 * backends, learning their MACs, rebuilding the Maglev table and pushing
 * changes into the live maps. The XDP program is never reloaded.
 *
 *   lbctl run -c lb.conf [--stats-interval SEC] [--pin-dir DIR]
 *   lbctl stats [--json] [--pin-dir DIR]
 *   lbctl detach -c lb.conf [--pin-dir DIR]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "balancer.h"
#include "log.h"
#include "maglev.h"
#include "xdp_lb.skel.h"

#define DEFAULT_PIN_DIR "/sys/fs/bpf/xdp_lb"

/* -- configuration -------------------------------------------------------- */

struct config {
	char     iface[IFNAMSIZ];
	uint32_t vip_be;
	uint32_t xdp_flags;		/* XDP_FLAGS_*_MODE, 0 = auto */
	bool     flow_cache;
	int      interval_ms, timeout_ms, rise, fall;
	struct bal_backend backends[LB_MAX_BACKENDS];
	size_t   nb;
};

static int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned int m[6];
	char tail;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &tail) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (m[i] > 0xff)
			return -1;
		mac[i] = m[i];
	}
	return 0;
}

static int parse_bool(const char *s, bool *out)
{
	if (!strcmp(s, "on") || !strcmp(s, "true") || !strcmp(s, "1"))
		*out = true;
	else if (!strcmp(s, "off") || !strcmp(s, "false") || !strcmp(s, "0"))
		*out = false;
	else
		return -1;
	return 0;
}

/*
 * Line-based config ('#' starts a comment):
 *   iface eth0
 *   vip 10.0.0.100
 *   xdp_mode auto|generic|native|offload
 *   flow_cache on|off
 *   health interval=1000 timeout=500 rise=2 fall=2      (times in ms)
 *   backend 10.0.0.11 8080 [aa:bb:cc:dd:ee:ff]
 */
static int load_config(const char *path, struct config *c)
{
	char line[256];
	FILE *f = fopen(path, "r");
	int lineno = 0;

	if (!f) {
		LOG_ERROR("%s: %s", path, strerror(errno));
		return -1;
	}
	memset(c, 0, sizeof(*c));
	c->flow_cache = true;
	c->interval_ms = 1000;
	c->timeout_ms = 500;
	c->rise = c->fall = 2;

	while (fgets(line, sizeof(line), f)) {
		char *save, *tok, *hash = strchr(line, '#');

		lineno++;
		if (hash)
			*hash = 0;
		tok = strtok_r(line, " \t\r\n", &save);
		if (!tok)
			continue;

		if (!strcmp(tok, "iface")) {
			char *v = strtok_r(NULL, " \t\r\n", &save);

			if (!v || strlen(v) >= IFNAMSIZ)
				goto bad;
			strcpy(c->iface, v);
		} else if (!strcmp(tok, "vip")) {
			char *v = strtok_r(NULL, " \t\r\n", &save);

			if (!v || inet_pton(AF_INET, v, &c->vip_be) != 1)
				goto bad;
		} else if (!strcmp(tok, "xdp_mode")) {
			char *v = strtok_r(NULL, " \t\r\n", &save);

			if (!v)
				goto bad;
			if (!strcmp(v, "auto"))
				c->xdp_flags = 0;
			else if (!strcmp(v, "generic"))
				c->xdp_flags = XDP_FLAGS_SKB_MODE;
			else if (!strcmp(v, "native"))
				c->xdp_flags = XDP_FLAGS_DRV_MODE;
			else if (!strcmp(v, "offload"))
				c->xdp_flags = XDP_FLAGS_HW_MODE;
			else
				goto bad;
		} else if (!strcmp(tok, "flow_cache")) {
			char *v = strtok_r(NULL, " \t\r\n", &save);

			if (!v || parse_bool(v, &c->flow_cache) < 0)
				goto bad;
		} else if (!strcmp(tok, "health")) {
			while ((tok = strtok_r(NULL, " \t\r\n", &save))) {
				int v;

				if (sscanf(tok, "interval=%d", &v) == 1)
					c->interval_ms = v;
				else if (sscanf(tok, "timeout=%d", &v) == 1)
					c->timeout_ms = v;
				else if (sscanf(tok, "rise=%d", &v) == 1)
					c->rise = v;
				else if (sscanf(tok, "fall=%d", &v) == 1)
					c->fall = v;
				else
					goto bad;
			}
			if (c->interval_ms <= 0 || c->timeout_ms <= 0 || c->rise < 1 || c->fall < 1)
				goto bad;
		} else if (!strcmp(tok, "backend")) {
			struct bal_backend *b;
			char *ip = strtok_r(NULL, " \t\r\n", &save);
			char *port = strtok_r(NULL, " \t\r\n", &save);
			char *mac = strtok_r(NULL, " \t\r\n", &save);
			int p;

			if (c->nb >= LB_MAX_BACKENDS || !ip || !port)
				goto bad;
			b = &c->backends[c->nb];
			p = atoi(port);
			if (inet_pton(AF_INET, ip, &b->ip_be) != 1 || p < 1 || p > 65535)
				goto bad;
			b->port = p;
			if (mac) {
				if (parse_mac(mac, b->mac) < 0)
					goto bad;
				b->has_mac = true;
			}
			c->nb++;
		} else {
			goto bad;
		}
		continue;
bad:
		LOG_ERROR("%s:%d: invalid line", path, lineno);
		fclose(f);
		return -1;
	}
	fclose(f);

	if (!c->iface[0] || !c->vip_be || !c->nb) {
		LOG_ERROR("%s: iface, vip and at least one backend are required", path);
		return -1;
	}
	return 0;
}

/* -- host plumbing -------------------------------------------------------- */

static int iface_mac(const char *iface, uint8_t mac[6])
{
	struct ifreq ifr = {};
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), rc;

	if (fd < 0)
		return -1;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
	rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (rc == 0)
		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return rc;
}

/* Kernel neighbour table; populated by the ARP exchange a TCP probe triggers. */
static bool arp_lookup(int fd, const char *iface, uint32_t ip_be, uint8_t mac[6])
{
	struct arpreq r = {};
	struct sockaddr_in *sin = (struct sockaddr_in *)&r.arp_pa;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip_be;
	snprintf(r.arp_dev, sizeof(r.arp_dev), "%s", iface);
	if (ioctl(fd, SIOCGARP, &r) < 0 || !(r.arp_flags & ATF_COM))
		return false;
	memcpy(mac, r.arp_ha.sa_data, 6);
	return true;
}

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static volatile sig_atomic_t stop_requested;

static void on_signal(int sig)
{
	(void)sig;
	stop_requested = 1;
}

/*
 * Probe every backend at once: non-blocking connects, one poll() loop, a
 * shared deadline. No threads, and a round takes at most timeout_ms.
 */
static void probe_all(const struct config *c, struct probe_result *res)
{
	struct pollfd pfd[LB_MAX_BACKENDS];
	int pending = 0, arp_fd;
	int64_t deadline = now_ms() + c->timeout_ms;

	for (size_t i = 0; i < c->nb; i++) {
		struct sockaddr_in sa = {.sin_family = AF_INET,
					 .sin_port = htons(c->backends[i].port),
					 .sin_addr.s_addr = c->backends[i].ip_be};
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

		memset(&res[i], 0, sizeof(res[i]));
		pfd[i] = (struct pollfd){.fd = -1, .events = POLLOUT};
		if (fd < 0)
			continue;
		if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			res[i].ok = true;
			close(fd);
		} else if (errno == EINPROGRESS) {
			pfd[i].fd = fd;
			pending++;
		} else {
			close(fd);
		}
	}

	while (pending > 0) {
		int64_t left = deadline - now_ms();

		if (left <= 0 || poll(pfd, c->nb, left) < 0)
			break;
		for (size_t i = 0; i < c->nb; i++) {
			int err = 0;
			socklen_t len = sizeof(err);

			if (pfd[i].fd < 0 || !pfd[i].revents)
				continue;
			if (getsockopt(pfd[i].fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
				res[i].ok = true;
			close(pfd[i].fd);
			pfd[i].fd = -1;
			pending--;
		}
	}
	for (size_t i = 0; i < c->nb; i++)
		if (pfd[i].fd >= 0)
			close(pfd[i].fd);

	arp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (arp_fd < 0)
		return;
	for (size_t i = 0; i < c->nb; i++)
		if (res[i].ok && !c->backends[i].has_mac)
			res[i].mac_known = arp_lookup(arp_fd, c->iface, c->backends[i].ip_be, res[i].mac);
	close(arp_fd);
}

/* -- bpffs / pinning ------------------------------------------------------ */

static int rm_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
	(void)sb; (void)type; (void)ftw;
	return remove(path);
}

static void remove_tree(const char *dir)
{
	nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static int mkdir_p(const char *path)
{
	char tmp[PATH_MAX];

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = 0;
		if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}
	return mkdir(tmp, 0755) < 0 && errno != EEXIST ? -1 : 0;
}

static void ensure_bpffs(void)
{
	struct statfs sfs;

	if (statfs("/sys/fs/bpf", &sfs) == 0 && sfs.f_type == BPF_FS_MAGIC)
		return;
	if (mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL) < 0)
		LOG_WARN("could not mount bpffs on /sys/fs/bpf: %s", strerror(errno));
}

static int pin_map(const char *pin_dir, const char *name, struct bpf_map *map)
{
	char path[300];

	snprintf(path, sizeof(path), "%s/maps/%s", pin_dir, name);
	return bpf_map__pin(map, path);
}

static int open_pinned(const char *pin_dir, const char *name)
{
	char path[300];

	snprintf(path, sizeof(path), "%s/maps/%s", pin_dir, name);
	return bpf_obj_get(path);
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* -- stats ---------------------------------------------------------------- */

/* Sum a per-CPU array element made of `nfields` u64s across all CPUs. */
static int read_percpu(int fd, uint32_t key, size_t nfields, uint64_t *sum)
{
	int ncpu = libbpf_num_possible_cpus();
	uint64_t *buf;

	if (ncpu < 0)
		return -1;
	buf = calloc((size_t)ncpu * nfields, sizeof(uint64_t));
	if (!buf)
		return -1;
	if (bpf_map_lookup_elem(fd, &key, buf) < 0) {
		free(buf);
		return -1;
	}
	memset(sum, 0, nfields * sizeof(uint64_t));
	for (int cpu = 0; cpu < ncpu; cpu++)
		for (size_t f = 0; f < nfields; f++)
			sum[f] += buf[(size_t)cpu * nfields + f];
	free(buf);
	return 0;
}

static int print_stats(int stats_fd, int be_fd, bool json)
{
	struct lb_stats st;
	struct be_stats bs;
	bool first = true;

	if (read_percpu(stats_fd, 0, sizeof(st) / 8, (uint64_t *)&st) < 0) {
		LOG_ERROR("cannot read stats map: %s", strerror(errno));
		return -1;
	}
	if (json)
		printf("{\"rx_vip\":%llu,\"forwarded\":%llu,\"flow_cache_hits\":%llu,"
		       "\"dropped_no_backend\":%llu,\"bytes_forwarded\":%llu,\"backends\":[",
		       (unsigned long long)st.rx_vip, (unsigned long long)st.forwarded,
		       (unsigned long long)st.flow_hits, (unsigned long long)st.no_backend,
		       (unsigned long long)st.bytes);
	else
		printf("rx_vip=%llu forwarded=%llu flow_cache_hits=%llu dropped_no_backend=%llu "
		       "bytes_forwarded=%llu\n",
		       (unsigned long long)st.rx_vip, (unsigned long long)st.forwarded,
		       (unsigned long long)st.flow_hits, (unsigned long long)st.no_backend,
		       (unsigned long long)st.bytes);

	for (uint32_t i = 0; i < LB_MAX_BACKENDS; i++) {
		if (read_percpu(be_fd, i, sizeof(bs) / 8, (uint64_t *)&bs) < 0 || !bs.packets)
			continue;
		if (json) {
			printf("%s{\"idx\":%u,\"packets\":%llu,\"bytes\":%llu}", first ? "" : ",", i,
			       (unsigned long long)bs.packets, (unsigned long long)bs.bytes);
			first = false;
		} else {
			printf("backend[%u] packets=%llu bytes=%llu\n", i,
			       (unsigned long long)bs.packets, (unsigned long long)bs.bytes);
		}
	}
	if (json)
		printf("]}\n");
	return 0;
}

/* -- map sink for the balancer ------------------------------------------- */

struct map_fds {
	int backends, table;
};

static int put_backend(void *ctx, uint32_t idx, bool healthy, const uint8_t mac[6])
{
	struct map_fds *m = ctx;
	struct backend v = {.healthy = healthy};

	memcpy(v.mac, mac, 6);
	return bpf_map_update_elem(m->backends, &idx, &v, BPF_ANY);
}

static int put_slot(void *ctx, uint32_t slot, uint32_t value)
{
	struct map_fds *m = ctx;

	return bpf_map_update_elem(m->table, &slot, &value, BPF_ANY);
}

/* -- commands ------------------------------------------------------------- */

struct opts {
	const char *config, *pin_dir;
	double stats_interval;
	bool json;
};

static void detach_and_clean(int ifindex, uint32_t flags, const char *pin_dir)
{
	bpf_xdp_detach(ifindex, flags, NULL);
	remove_tree(pin_dir);
}

static int cmd_run(const struct opts *o)
{
	static struct balancer bal;	/* ~20 KB: keep off the stack */
	struct probe_result res[LB_MAX_BACKENDS];
	struct config cfg;
	struct sigaction sa = {.sa_handler = on_signal};	/* no SA_RESTART: poll() must wake */
	struct xdp_lb_bpf *skel;
	struct map_fds fds;
	uint8_t lb_mac[6] = {0};
	unsigned int ifindex;
	int64_t next_stats = 0;
	int rc = 1;

	if (load_config(o->config, &cfg) < 0)
		return 1;
	if (!maglev_is_prime(LB_TABLE_SIZE)) {
		LOG_ERROR("LB_TABLE_SIZE %d is not prime", LB_TABLE_SIZE);
		return 1;
	}
	ifindex = if_nametoindex(cfg.iface);
	if (!ifindex || iface_mac(cfg.iface, lb_mac) < 0) {
		LOG_ERROR("interface %s: %s", cfg.iface, strerror(errno));
		return 1;
	}

	libbpf_set_print(libbpf_print);
	ensure_bpffs();
	detach_and_clean(ifindex, cfg.xdp_flags, o->pin_dir);	/* stale state from a crashed run */

	skel = xdp_lb_bpf__open();
	if (!skel) {
		LOG_ERROR("open BPF object: %s", strerror(errno));
		return 1;
	}
	skel->rodata->cfg_vip = cfg.vip_be;
	skel->rodata->cfg_flow_cache = cfg.flow_cache;
	memcpy(&skel->rodata->cfg_mac_hi, lb_mac, 4);
	memcpy(&skel->rodata->cfg_mac_lo, lb_mac + 4, 2);
	if (xdp_lb_bpf__load(skel)) {
		LOG_ERROR("load BPF object: %s", strerror(errno));
		goto out_destroy;
	}

	{
		char dir[300];

		snprintf(dir, sizeof(dir), "%s/maps", o->pin_dir);
		if (mkdir_p(dir) < 0) {
			LOG_ERROR("create %s: %s", dir, strerror(errno));
			goto out_destroy;
		}
	}
	if (pin_map(o->pin_dir, "stats", skel->maps.stats) ||
	    pin_map(o->pin_dir, "backend_stats", skel->maps.backend_stats) ||
	    pin_map(o->pin_dir, "backends", skel->maps.backends) ||
	    pin_map(o->pin_dir, "lookup_table", skel->maps.lookup_table) ||
	    pin_map(o->pin_dir, "flow_cache", skel->maps.flow_cache)) {
		LOG_ERROR("pin maps under %s: %s", o->pin_dir, strerror(errno));
		goto out_clean;
	}

	fds.backends = bpf_map__fd(skel->maps.backends);
	fds.table = bpf_map__fd(skel->maps.lookup_table);
	if (balancer_init(&bal, cfg.backends, cfg.nb, cfg.rise, cfg.fall,
			  (struct sink){&fds, put_backend, put_slot}) < 0 ||
	    balancer_reset_table(&bal) < 0) {
		LOG_ERROR("initialising maps: %s", strerror(errno));
		goto out_clean;
	}

	if (bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_lb), cfg.xdp_flags, NULL) < 0) {
		LOG_ERROR("attach XDP to %s: %s", cfg.iface, strerror(errno));
		goto out_clean;
	}
	LOG_INFO("XDP program attached to %s, VIP %s, %zu backend(s), flow cache %s", cfg.iface,
		 inet_ntoa(*(struct in_addr *)&cfg.vip_be), cfg.nb, cfg.flow_cache ? "on" : "off");

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	while (!stop_requested) {
		int64_t t0 = now_ms(), wait;

		probe_all(&cfg, res);
		if (balancer_apply(&bal, res) < 0)
			LOG_WARN("map update failed (%s); will retry next round", strerror(errno));
		if (o->stats_interval > 0 && t0 >= next_stats) {
			next_stats = t0 + (int64_t)(o->stats_interval * 1000);
			print_stats(bpf_map__fd(skel->maps.stats), bpf_map__fd(skel->maps.backend_stats), false);
		}
		wait = cfg.interval_ms - (now_ms() - t0);
		if (wait > 0 && !stop_requested)
			poll(NULL, 0, wait);	/* interrupted by SIGINT/SIGTERM */
	}
	rc = 0;

out_clean:
	detach_and_clean(ifindex, cfg.xdp_flags, o->pin_dir);
	LOG_INFO("detached from %s", cfg.iface);
out_destroy:
	xdp_lb_bpf__destroy(skel);
	return rc;
}

static int cmd_stats(const struct opts *o)
{
	int sfd = open_pinned(o->pin_dir, "stats"), bfd = open_pinned(o->pin_dir, "backend_stats"), rc;

	if (sfd < 0 || bfd < 0) {
		LOG_ERROR("no running instance under %s (%s)", o->pin_dir, strerror(errno));
		return 1;
	}
	rc = print_stats(sfd, bfd, o->json);
	close(sfd);
	close(bfd);
	return rc ? 1 : 0;
}

static int cmd_detach(const struct opts *o)
{
	struct config cfg;
	unsigned int ifindex;

	if (load_config(o->config, &cfg) < 0)
		return 1;
	ifindex = if_nametoindex(cfg.iface);
	if (!ifindex) {
		LOG_ERROR("interface %s: %s", cfg.iface, strerror(errno));
		return 1;
	}
	detach_and_clean(ifindex, cfg.xdp_flags, o->pin_dir);
	return 0;
}

static int usage(void)
{
	fprintf(stderr,
		"usage: lbctl run -c CONFIG [--stats-interval SEC] [--pin-dir DIR]\n"
		"       lbctl stats [--json] [--pin-dir DIR]\n"
		"       lbctl detach -c CONFIG [--pin-dir DIR]\n");
	return 2;
}

int main(int argc, char **argv)
{
	struct opts o = {.pin_dir = DEFAULT_PIN_DIR};

	if (argc < 2)
		return usage();
	for (int i = 2; i < argc; i++) {
		if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc)
			o.config = argv[++i];
		else if (!strcmp(argv[i], "--pin-dir") && i + 1 < argc)
			o.pin_dir = argv[++i];
		else if (!strcmp(argv[i], "--stats-interval") && i + 1 < argc)
			o.stats_interval = atof(argv[++i]);
		else if (!strcmp(argv[i], "--json"))
			o.json = true;
		else
			return usage();
	}

	if (!strcmp(argv[1], "run") && o.config)
		return cmd_run(&o);
	if (!strcmp(argv[1], "stats"))
		return cmd_stats(&o);
	if (!strcmp(argv[1], "detach") && o.config)
		return cmd_detach(&o);
	return usage();
}
