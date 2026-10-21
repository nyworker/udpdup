/*
 * udpdup - bidirectional UDP packet duplicator / de-duplicator over N legs.
 *
 * Every datagram received on the local socket is tagged with a sequence
 * number and sent out on ALL legs. Datagrams arriving on any leg are
 * de-duplicated by sequence number and the first copy is forwarded to the
 * local application. Runs the same way on both ends, so SRT's return
 * traffic (ACK/NAK/keepalive) is protected too.
 *
 *   app (SRT) <-udp-> udpdup ==leg1==> udpdup <-udp-> app (SRT)
 *                            ==leg2==>
 *
 * Build: gcc -O2 -Wall -o udpdup udpdup.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_LEGS   8
#define MAX_PKT    65536
#define HDR_LEN    16
#define MAGIC      0x5544u   /* "UD" */
#define VERSION    1
#define WIN_BITS   16
#define WIN_SIZE   (1u << WIN_BITS)

struct hdr {
	uint16_t magic;
	uint8_t  version;
	uint8_t  flags;
	uint32_t session;
	uint64_t seq;
} __attribute__((packed));

struct leg {
	int fd;
	struct sockaddr_storage local, remote;
	socklen_t remote_len;
	char spec[256];
	char dev[IFNAMSIZ];
	int loss_pct;                 /* simulated tx loss, for testing */
	uint64_t tx, tx_err, rx, rx_new, rx_dup, rx_old, rx_bad;
};

static struct leg legs[MAX_LEGS];
static int nlegs;

static int local_fd = -1;
static struct sockaddr_storage local_peer;
static socklen_t local_peer_len;
static int local_peer_fixed;      /* --local-connect: peer is configured */

static uint32_t my_session;
static uint64_t tx_seq;
static uint64_t local_rx, local_tx;

/* receive-side dedup state */
static uint32_t rx_session;
static int rx_have_session;
static uint64_t rx_highest;
static uint64_t *rx_win;          /* slot = seq + 1 if seen, 0 if empty */

static volatile sig_atomic_t stop;

static void on_signal(int s) { (void)s; stop = 1; }

static void die(const char *fmt, const char *arg)
{
	fprintf(stderr, "udpdup: ");
	fprintf(stderr, fmt, arg);
	fprintf(stderr, "\n");
	exit(1);
}

static uint64_t htonll(uint64_t v)
{
	return ((uint64_t)htonl((uint32_t)v) << 32) | htonl((uint32_t)(v >> 32));
}
#define ntohll htonll

/* Parse "host:port" or "[v6]:port" into a sockaddr. */
static socklen_t parse_addr(const char *s, struct sockaddr_storage *out, int passive)
{
	char buf[256], *host, *port;
	struct addrinfo hints = {0}, *res;
	socklen_t len;

	snprintf(buf, sizeof buf, "%s", s);
	if (buf[0] == '[') {
		host = buf + 1;
		char *e = strchr(host, ']');
		if (!e || e[1] != ':')
			die("bad address '%s'", s);
		*e = 0;
		port = e + 2;
	} else {
		port = strrchr(buf, ':');
		if (!port)
			die("address '%s' needs a port", s);
		*port++ = 0;
		host = buf;
	}
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = passive ? AI_PASSIVE : 0;
	if (getaddrinfo(*host ? host : NULL, port, &hints, &res) != 0)
		die("cannot resolve '%s'", s);
	memcpy(out, res->ai_addr, res->ai_addrlen);
	len = res->ai_addrlen;
	freeaddrinfo(res);
	return len;
}

static const char *fmt_addr(const struct sockaddr_storage *a)
{
	static char out[INET6_ADDRSTRLEN + 8];
	char ip[INET6_ADDRSTRLEN];
	int port;

	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *s = (const void *)a;
		inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
		port = ntohs(s->sin6_port);
		snprintf(out, sizeof out, "[%s]:%d", ip, port);
	} else {
		const struct sockaddr_in *s = (const void *)a;
		inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
		port = ntohs(s->sin_port);
		snprintf(out, sizeof out, "%s:%d", ip, port);
	}
	return out;
}

static int make_socket(const struct sockaddr_storage *bind_addr, socklen_t len,
		       const char *dev, int bufsz)
{
	int fd = socket(bind_addr->ss_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	int one = 1;

	if (fd < 0)
		die("socket: %s", strerror(errno));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz);
	if (dev && *dev &&
	    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) < 0)
		die("SO_BINDTODEVICE (needs root/CAP_NET_RAW): %s", strerror(errno));
	if (bind(fd, (const struct sockaddr *)bind_addr, len) < 0) {
		fprintf(stderr, "udpdup: bind %s: %s\n", fmt_addr(bind_addr), strerror(errno));
		exit(1);
	}
	return fd;
}

/* "--leg LOCAL_IP:PORT,REMOTE_IP:PORT[,dev=IFACE][,loss=PCT]" */
static void add_leg(const char *spec)
{
	char buf[256], *tok, *save;
	struct leg *l;
	int i = 0;

	if (nlegs == MAX_LEGS)
		die("too many legs (max %s)", "8");
	l = &legs[nlegs++];
	snprintf(l->spec, sizeof l->spec, "%s", spec);
	snprintf(buf, sizeof buf, "%s", spec);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save), i++) {
		if (i == 0)
			parse_addr(tok, &l->local, 1);
		else if (i == 1)
			l->remote_len = parse_addr(tok, &l->remote, 0);
		else if (!strncmp(tok, "dev=", 4))
			snprintf(l->dev, sizeof l->dev, "%s", tok + 4);
		else if (!strncmp(tok, "loss=", 5))
			l->loss_pct = atoi(tok + 5);
		else
			die("unknown leg option '%s'", tok);
	}
	if (i < 2)
		die("leg '%s' needs LOCAL,REMOTE", spec);
}

/* Returns 1 if seq is new (and records it), 0 if duplicate / too old. */
static int dedup_accept(struct leg *l, uint32_t session, uint64_t seq)
{
	if (!rx_have_session || session != rx_session) {
		/* peer (re)started: forget everything */
		if (rx_have_session)
			fprintf(stderr, "udpdup: peer session changed %08x -> %08x, resetting window\n",
				rx_session, session);
		memset(rx_win, 0, WIN_SIZE * sizeof *rx_win);
		rx_session = session;
		rx_have_session = 1;
		rx_highest = seq;
	}
	if (seq + WIN_SIZE <= rx_highest) {
		l->rx_old++;
		return 0;
	}
	uint64_t *slot = &rx_win[seq & (WIN_SIZE - 1)];
	if (*slot == seq + 1) {
		l->rx_dup++;
		return 0;
	}
	*slot = seq + 1;
	if (seq > rx_highest)
		rx_highest = seq;
	l->rx_new++;
	return 1;
}

static void handle_local(void)
{
	static uint8_t buf[MAX_PKT];
	struct sockaddr_storage from;
	socklen_t fromlen;
	ssize_t n;

	for (;;) {
		fromlen = sizeof from;
		n = recvfrom(local_fd, buf + HDR_LEN, sizeof buf - HDR_LEN, 0,
			     (struct sockaddr *)&from, &fromlen);
		if (n < 0)
			return;
		local_rx++;
		if (!local_peer_fixed &&
		    (fromlen != local_peer_len || memcmp(&from, &local_peer, fromlen))) {
			memcpy(&local_peer, &from, fromlen);
			local_peer_len = fromlen;
			fprintf(stderr, "udpdup: local app is %s\n", fmt_addr(&local_peer));
		}

		struct hdr h = {
			.magic = htons(MAGIC), .version = VERSION, .flags = 0,
			.session = htonl(my_session), .seq = htonll(tx_seq++),
		};
		memcpy(buf, &h, HDR_LEN);
		for (int i = 0; i < nlegs; i++) {
			struct leg *l = &legs[i];
			if (l->loss_pct && (rand() % 100) < l->loss_pct)
				continue;
			if (sendto(l->fd, buf, n + HDR_LEN, 0,
				   (struct sockaddr *)&l->remote, l->remote_len) < 0)
				l->tx_err++;
			else
				l->tx++;
		}
	}
}

static void handle_leg(struct leg *l)
{
	static uint8_t buf[MAX_PKT];
	struct hdr h;
	ssize_t n;

	for (;;) {
		n = recv(l->fd, buf, sizeof buf, 0);
		if (n < 0)
			return;
		l->rx++;
		if (n < HDR_LEN) {
			l->rx_bad++;
			continue;
		}
		memcpy(&h, buf, HDR_LEN);
		if (ntohs(h.magic) != MAGIC || h.version != VERSION) {
			l->rx_bad++;
			continue;
		}
		if (!dedup_accept(l, ntohl(h.session), ntohll(h.seq)))
			continue;
		if (!local_peer_len)
			continue;   /* no local app known yet */
		if (sendto(local_fd, buf + HDR_LEN, n - HDR_LEN, 0,
			   (struct sockaddr *)&local_peer, local_peer_len) >= 0)
			local_tx++;
	}
}

static double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void print_stats(void)
{
	fprintf(stderr, "udpdup: local rx %llu tx %llu |",
		(unsigned long long)local_rx, (unsigned long long)local_tx);
	for (int i = 0; i < nlegs; i++) {
		struct leg *l = &legs[i];
		fprintf(stderr, " leg%d tx %llu err %llu rx %llu new %llu dup %llu old %llu bad %llu |",
			i + 1, (unsigned long long)l->tx, (unsigned long long)l->tx_err,
			(unsigned long long)l->rx, (unsigned long long)l->rx_new,
			(unsigned long long)l->rx_dup, (unsigned long long)l->rx_old,
			(unsigned long long)l->rx_bad);
	}
	fprintf(stderr, "\n");
}

static void usage(void)
{
	fprintf(stderr,
"usage: udpdup (--local-listen ADDR | --local-connect ADDR) --leg SPEC --leg SPEC ...\n"
"\n"
"  --local-listen  IP:PORT   bind here; the local app sends to it (peer is learned)\n"
"  --local-connect IP:PORT   local app is listening here; forward to it\n"
"  --local-bind    IP:PORT   source addr for --local-connect (default 127.0.0.1:0)\n"
"  --leg LOCAL_IP:PORT,REMOTE_IP:PORT[,dev=IFACE][,loss=PCT]\n"
"                            one path to the peer udpdup (repeat per NIC)\n"
"  --stats SECONDS           print counters periodically (default 10, 0=off)\n"
"  --bufsize BYTES           socket buffer size (default 4 MiB)\n");
	exit(2);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{"local-listen",  required_argument, 0, 'l'},
		{"local-connect", required_argument, 0, 'c'},
		{"local-bind",    required_argument, 0, 'b'},
		{"leg",           required_argument, 0, 'g'},
		{"stats",         required_argument, 0, 's'},
		{"bufsize",       required_argument, 0, 'B'},
		{"help",          no_argument,       0, 'h'},
		{0}
	};
	const char *listen_s = NULL, *connect_s = NULL, *bind_s = NULL;
	double stats_iv = 10;
	int bufsz = 4 << 20, c;

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 'l': listen_s = optarg; break;
		case 'c': connect_s = optarg; break;
		case 'b': bind_s = optarg; break;
		case 'g': add_leg(optarg); break;
		case 's': stats_iv = atof(optarg); break;
		case 'B': bufsz = atoi(optarg); break;
		default: usage();
		}
	}
	if (!!listen_s == !!connect_s || nlegs == 0)
		usage();

	rx_win = calloc(WIN_SIZE, sizeof *rx_win);
	if (getrandom(&my_session, sizeof my_session, 0) != sizeof my_session)
		my_session = (uint32_t)time(NULL) ^ (uint32_t)getpid();
	srand(my_session);

	struct sockaddr_storage a;
	socklen_t alen;
	if (listen_s) {
		alen = parse_addr(listen_s, &a, 1);
	} else {
		local_peer_len = parse_addr(connect_s, &local_peer, 0);
		local_peer_fixed = 1;
		alen = parse_addr(bind_s ? bind_s
				  : local_peer.ss_family == AF_INET6 ? "[::1]:0" : "127.0.0.1:0",
				  &a, 1);
	}
	local_fd = make_socket(&a, alen, NULL, bufsz);

	for (int i = 0; i < nlegs; i++) {
		struct leg *l = &legs[i];
		socklen_t ll = l->local.ss_family == AF_INET6 ? sizeof(struct sockaddr_in6)
							       : sizeof(struct sockaddr_in);
		l->fd = make_socket(&l->local, ll, l->dev, bufsz);
		fprintf(stderr, "udpdup: leg%d %s -> ", i + 1, fmt_addr(&l->local));
		fprintf(stderr, "%s%s%s\n", fmt_addr(&l->remote),
			*l->dev ? " dev " : "", l->dev);
	}
	fprintf(stderr, "udpdup: local %s %s, session %08x\n",
		listen_s ? "listen" : "connect", listen_s ? listen_s : connect_s, my_session);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct pollfd pfd[MAX_LEGS + 1];
	pfd[0] = (struct pollfd){ .fd = local_fd, .events = POLLIN };
	for (int i = 0; i < nlegs; i++)
		pfd[i + 1] = (struct pollfd){ .fd = legs[i].fd, .events = POLLIN };

	double next_stats = now_s() + stats_iv;
	while (!stop) {
		if (poll(pfd, nlegs + 1, 500) < 0 && errno != EINTR)
			die("poll: %s", strerror(errno));
		if (pfd[0].revents & POLLIN)
			handle_local();
		for (int i = 0; i < nlegs; i++)
			if (pfd[i + 1].revents & POLLIN)
				handle_leg(&legs[i]);
		if (stats_iv > 0 && now_s() >= next_stats) {
			print_stats();
			next_stats += stats_iv;
		}
	}
	print_stats();
	return 0;
}
