/*
 * Copyright (C) 2020 John Crispin <john@phrozen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <glob.h>
#include <fcntl.h>

#include <linux/rtnetlink.h>
#include <linux/nl80211.h>

#include <net/if.h>
#include <netinet/ether.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/vlist.h>
#include <libubox/ulog.h>

#include <uci.h>
#include <uci_blob.h>

#define  ESSID_MAX_SIZE	32

#define IWINFO_80211_A		(1 << 0)
#define IWINFO_80211_B		(1 << 1)
#define IWINFO_80211_G		(1 << 2)
#define IWINFO_80211_N		(1 << 3)
#define IWINFO_80211_AC		(1 << 4)
#define IWINFO_80211_AD		(1 << 5)

#define IWINFO_CIPHER_NONE	(1 << 0)
#define IWINFO_CIPHER_WEP40	(1 << 1)
#define IWINFO_CIPHER_TKIP	(1 << 2)
#define IWINFO_CIPHER_WRAP	(1 << 3)
#define IWINFO_CIPHER_CCMP	(1 << 4)
#define IWINFO_CIPHER_WEP104	(1 << 5)
#define IWINFO_CIPHER_AESOCB	(1 << 6)
#define IWINFO_CIPHER_CKIP	(1 << 7)
#define IWINFO_CIPHER_COUNT	8

#define IWINFO_KMGMT_NONE	(1 << 0)
#define IWINFO_KMGMT_8021x	(1 << 1)
#define IWINFO_KMGMT_PSK	(1 << 2)
#define IWINFO_KMGMT_SAE	(1 << 3)
#define IWINFO_KMGMT_OWE	(1 << 4)
#define IWINFO_KMGMT_COUNT	5

#define IWINFO_AUTH_OPEN	(1 << 0)
#define IWINFO_AUTH_SHARED	(1 << 1)
#define IWINFO_AUTH_COUNT	2

struct ip_node {
	struct avl_node avl;
	uint8_t *ip;
	uint8_t *mac;
	int ip_len;
	int iface;
};

struct nl_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	int bufsize;
};

struct family_data {
	const char *group;
	int id;
};

struct config {
	uint16_t rssi_low;
	uint16_t rssi_high;
	uint32_t tx_rate_low;
	uint32_t tx_rate_high;
	uint32_t tx_retries;
	uint32_t station_status;
	uint32_t station_poll;
	uint32_t scan_phy;
	char scan_iface[IF_NAMESIZE];
	uint32_t scan_period;
	uint32_t scan_delay;
	uint8_t scan_ap_force;
	char *country;
};

enum metric_state {
	METRIC_NORMAL = 0,
	METRIC_LOW,
	METRIC_HIGH,
};

struct wifi_iface {
	struct avl_node avl;
	uint8_t addr[6];
	char ifname[IF_NAMESIZE];
	int idx;
	struct uloop_timeout assoc;
	struct blob_attr *info;
	int scanning;
	struct blob_attr *scan_result;
	uint32_t phy;
	uint32_t freq;
	uint32_t chan_freq1;
	uint32_t chan_freq2;
	uint32_t chan_width;
	uint32_t chan_type;
};

struct wifi_station {
	struct avl_node avl;
	struct blob_attr *info;
	char ifname[IF_NAMESIZE];
	uint8_t addr[6];
	uint16_t rssi;
	uint32_t tx_rate;
	uint32_t tx_retries;
	uint32_t tx_bytes;
	enum metric_state rssi_state;
	enum metric_state tx_rate_state;
	struct uloop_timeout status;
};

struct crypto_entry {
	uint8_t enabled;
	uint8_t wpa_version;
	uint8_t group_ciphers;
	uint8_t pair_ciphers;
	uint8_t auth_suites;
	uint8_t auth_algs;
};

extern struct avl_tree wif_tree;
extern struct avl_tree sta_tree;

extern struct config config;

extern bool nl_socket(struct nl_socket *ev, int protocol,
			    int (*cb)(struct nl_msg *msg, void *arg), void *priv);
extern void nl_handler_nl_status(struct uloop_fd *u, unsigned int statuss);
extern int genl_send_and_recv(struct nl_socket *ev, struct nl_msg * msg);
int genl_get_multicast_id(struct nl_socket *ev, const char *family, const char *group);

extern uint8_t nl80211_arg[4096];
extern struct nl_socket nl80211_status;
extern int nl80211_init(void);
extern void nl80211_deinit(void);
extern int nl80211_init_scan(void);
extern void nl80211_deinit_scan(void);
extern int nl80211_trigger_scan(struct wifi_iface *wif, int on_channel, int scan_flags);
extern void nl80211_handle_new_scan_result(struct nlattr **tb, int iface);
extern void nl80211_handle_trigger_scan(int iface, int start);
extern int nl80211_reg_get(void);
extern int nl80211_reg_set(char *alpha2);
extern int nl80211_iface_add(int phy, char *ifname, uint32_t iftype);
extern int nl80211_iface_del(char *ifname);
extern int nl80211_get_survey(char *ifname);

extern struct wifi_iface *find_wif(char *ifname);

extern struct nl_sock *create_socket(int protocol, int groups);
extern void handler_nl_status(struct uloop_fd *u, unsigned int statuss);

extern struct ubus_object ubus_object;
extern struct ubus_auto_conn conn;
extern void ubus_init(void);
extern void ubus_uninit(void);

extern struct blob_buf b;
extern struct blob_buf s;
extern void blobmsg_add_iface(struct blob_buf *bbuf, char *name, int index);
extern void blobmsg_add_iftype(struct blob_buf *bbuf, const char *name, const uint32_t iftype);
extern void blobmsg_add_ipv4(struct blob_buf *bbuf, const char *name, const uint8_t* addr);
extern void blobmsg_add_ipv6(struct blob_buf *bbuf, const char *name, const uint16_t* addr);
extern void blobmsg_add_mac(struct blob_buf *bbuf, const char *name, const uint8_t* addr);

extern int iface_up(const char *ifname);

extern void config_load(void);
