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

#include "u80211d.h"

#include <libubox/avl-cmp.h>
#include <net/if.h>
#include <syslog.h>

static char *rssi_string[] = {
	"wifi.normal.rssi",
	"wifi.low.rssi",
	"wifi.high.rssi",
};

static char *tx_rate_string[] = {
	"wifi.normal.tx_rate",
	"wifi.low.tx_rate",
	"wifi.high.tx_rate",
};

struct nl_socket nl80211_status;
uint8_t nl80211_arg[4096];
struct uloop_timeout nl80211_enum_timer;
static struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
static struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
	[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32    },
	[NL80211_STA_INFO_RX_PACKETS]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_PACKETS]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_RX_BITRATE]    = { .type = NLA_NESTED },
	[NL80211_STA_INFO_TX_BITRATE]    = { .type = NLA_NESTED },
	[NL80211_STA_INFO_SIGNAL]        = { .type = NLA_U8     },
	[NL80211_STA_INFO_RX_BYTES]      = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_BYTES]      = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_RETRIES]    = { .type = NLA_U32    },
	[NL80211_STA_INFO_TX_FAILED]     = { .type = NLA_U32    },
	[NL80211_STA_INFO_T_OFFSET]      = { .type = NLA_U64    },
	[NL80211_STA_INFO_STA_FLAGS] =
		{ .minlen = sizeof(struct nl80211_sta_flag_update) },
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
	[NL80211_RATE_INFO_BITRATE]      = { .type = NLA_U16    },
	[NL80211_RATE_INFO_MCS]          = { .type = NLA_U8     },
	[NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG   },
	[NL80211_RATE_INFO_SHORT_GI]     = { .type = NLA_FLAG   },
};

static int avl_addrcmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 6);
}

struct avl_tree wif_tree = AVL_TREE_INIT(wif_tree, avl_strcmp, false, NULL);
struct avl_tree sta_tree = AVL_TREE_INIT(sta_tree, avl_addrcmp, false, NULL);

int nl80211_get_survey(char *ifname)
{
	int idx = if_nametoindex(ifname);
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0) ||
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx)) {
		nlmsg_free(msg);
		goto out;
	}

	blob_buf_init(&s, 0);
	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

static void nl80211_list_wif(void)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, 0)) {
		nlmsg_free(msg);
		return;
	}

	genl_send_and_recv(&nl80211_status, msg);
}

static void nl80211_assoc_list(struct uloop_timeout *t)
{
	struct wifi_iface *wif = container_of(t, struct wifi_iface, assoc);
	int idx = if_nametoindex(wif->ifname);
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0) ||
		nla_put_u32(msg, NL80211_ATTR_IFINDEX, idx)) {
		nlmsg_free(msg);
		goto out;
	}

	genl_send_and_recv(&nl80211_status, msg);

out:
	uloop_timeout_set(t, config.station_poll * 1000);
}

static void nl80211_parse_rateinfo(struct nlattr **ri, char *table)
{
	int mhz = 0;
	void *cookie = blobmsg_open_table(&b, table);

	if (ri[NL80211_RATE_INFO_BITRATE32])
		blobmsg_add_u32(&b, "bitrate", nla_get_u32(ri[NL80211_RATE_INFO_BITRATE32]) * 100);
	else if (ri[NL80211_RATE_INFO_BITRATE])
		blobmsg_add_u16(&b, "bitrate", nla_get_u16(ri[NL80211_RATE_INFO_BITRATE]) * 100);

	if (ri[NL80211_RATE_INFO_VHT_MCS]) {
		blobmsg_add_u8(&b, "vht", 1);
		blobmsg_add_u8(&b, "mcs", nla_get_u8(ri[NL80211_RATE_INFO_VHT_MCS]));

		if (ri[NL80211_RATE_INFO_VHT_NSS])
			blobmsg_add_u8(&b, "nss", nla_get_u8(ri[NL80211_RATE_INFO_VHT_NSS]));
	} else if (ri[NL80211_RATE_INFO_MCS]) {
		blobmsg_add_u8(&b, "ht", 1);
		blobmsg_add_u8(&b, "mcs", nla_get_u8(ri[NL80211_RATE_INFO_MCS]));
	}

	if (ri[NL80211_RATE_INFO_5_MHZ_WIDTH])
		mhz = 5;
	else if (ri[NL80211_RATE_INFO_10_MHZ_WIDTH])
		mhz = 10;
	else if (ri[NL80211_RATE_INFO_40_MHZ_WIDTH])
		mhz = 40;
	else if (ri[NL80211_RATE_INFO_80_MHZ_WIDTH])
		mhz = 80;
	else if (ri[NL80211_RATE_INFO_80P80_MHZ_WIDTH] ||
		 ri[NL80211_RATE_INFO_160_MHZ_WIDTH])
		mhz = 160;
	else
		mhz = 20;
	blobmsg_add_u32(&b, "mhz", mhz);

	if (ri[NL80211_RATE_INFO_SHORT_GI])
		blobmsg_add_u8(&b, "short_gi", 1);
	blobmsg_close_table(&b, cookie);
}

static void nl80211_to_blob(struct nlattr **tb, char *ifname)
{
	memset(sinfo, 0, sizeof(sinfo));
	memset(rinfo, 0, sizeof(rinfo));

	blob_buf_init(&b, 0);

	if (tb[NL80211_ATTR_MAC]) {
		uint8_t *addr = nla_data(tb[NL80211_ATTR_MAC]);
		blobmsg_add_mac(&b, "mac", addr);
	}

	if (tb[NL80211_ATTR_IFINDEX]) {
		int idx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
		if (ifname)
			if_indextoname(idx, ifname);
		blobmsg_add_iface(&b, "interface", idx);
	} else if (tb[NL80211_ATTR_IFNAME]) {
		if (ifname)
			ifname = nla_get_string(tb[NL80211_ATTR_IFNAME]);
		blobmsg_add_string(&b, "interface", nla_get_string(tb[NL80211_ATTR_IFNAME]));
	}

	if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL])
		blobmsg_add_u32(&b, "dbm", nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) / 100);

	if (tb[NL80211_ATTR_IFTYPE])
		blobmsg_add_iftype(&b, "iftype", nla_get_u32(tb[NL80211_ATTR_IFTYPE]));

	if (tb[NL80211_ATTR_WIPHY_FREQ])
		blobmsg_add_u32(&b, "frequency", nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]));

	if (tb[NL80211_ATTR_CENTER_FREQ1])
		blobmsg_add_u32(&b, "center_freq1", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]));

	if (tb[NL80211_ATTR_CENTER_FREQ2])
		blobmsg_add_u32(&b, "center_freq2", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]));

	if (tb[NL80211_ATTR_CHANNEL_WIDTH])
		blobmsg_add_u32(&b, "channel_width", nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]));

	if (tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
		blobmsg_add_u32(&b, "channel_type", nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]));

	if (tb[NL80211_ATTR_WIPHY])
		blobmsg_add_u32(&b, "phy", nla_get_u32(tb[NL80211_ATTR_WIPHY]));

	if (tb[NL80211_ATTR_STA_INFO] != NULL &&
	    !nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			      tb[NL80211_ATTR_STA_INFO], stats_policy))
	{
		if (sinfo[NL80211_STA_INFO_SIGNAL])
			blobmsg_add_u32(&b, "signal", (signed char)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));
		if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
			blobmsg_add_u32(&b, "inactive", nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
		if (sinfo[NL80211_STA_INFO_RX_PACKETS])
			blobmsg_add_u32(&b, "rx_pkt", nla_get_u32(sinfo[NL80211_STA_INFO_RX_PACKETS]));
		if (sinfo[NL80211_STA_INFO_TX_PACKETS])
			blobmsg_add_u32(&b, "tx_pkt", nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]));
		if (sinfo[NL80211_STA_INFO_RX_BITRATE] &&
		    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE],
				      rate_policy))
			nl80211_parse_rateinfo(rinfo, "rx_rate");
		if (sinfo[NL80211_STA_INFO_TX_BITRATE] &&
		    !nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE],
				      rate_policy))
			nl80211_parse_rateinfo(rinfo, "tx_rate");
		if (sinfo[NL80211_STA_INFO_RX_BYTES])
			blobmsg_add_u32(&b, "rx_bytes", nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
		if (sinfo[NL80211_STA_INFO_TX_BYTES])
			blobmsg_add_u32(&b, "tx_bytes", nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));
		if (sinfo[NL80211_STA_INFO_TX_RETRIES])
			blobmsg_add_u32(&b, "tx_retries", nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]));
		if (sinfo[NL80211_STA_INFO_TX_FAILED])
			blobmsg_add_u32(&b, "tx_failed", nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]));
		if (sinfo[NL80211_STA_INFO_T_OFFSET])
			blobmsg_add_u32(&b, "tx_offset", nla_get_u32(sinfo[NL80211_STA_INFO_T_OFFSET]));
	}

	if (tb[NL80211_ATTR_REG_ALPHA2])
		blobmsg_add_string(&b, "country", nla_get_string(tb[NL80211_ATTR_REG_ALPHA2]));

	if (tb[NL80211_ATTR_DFS_REGION])
		blobmsg_add_u16(&b, "dfs-region", nla_get_u8(tb[NL80211_ATTR_DFS_REGION]));
}

static void nl80211_notify(struct nlattr **tb, char *status)
{
	nl80211_to_blob(tb, NULL);
	ubus_notify(&conn.ctx, &ubus_object, status, b.head, -1);
}

static void nl80211_status_station(struct uloop_timeout *t)
{
	struct wifi_station *sta = container_of(t, struct wifi_station, status);

	ubus_notify(&conn.ctx, &ubus_object, "wifi.status.station", sta->info, -1);

	uloop_timeout_set(t, config.station_status * 1000);
}

static void nl80211_add_station(struct nlattr **tb)
{
	struct wifi_station *sta;
	uint8_t *addr;
	int notify = 0;
	uint32_t tx_rate = 0, tx_retries = 0, tx_bytes = 0;
	char ifname[IF_NAMESIZE];

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	nl80211_to_blob(tb, ifname);
	addr = nla_data(tb[NL80211_ATTR_MAC]);

	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (!sta) {
		sta = malloc(sizeof(*sta));
		if (!sta)
			return;

		memset(sta, 0, sizeof(*sta));
		memcpy(sta->addr, addr, 6);
		memcpy(sta->ifname, ifname, IF_NAMESIZE);
		sta->avl.key = sta->addr;
		avl_insert(&sta_tree, &sta->avl);
		notify = 1;
		if (config.station_status) {
			sta->status.cb = nl80211_status_station;
			uloop_timeout_set(&sta->status, config.station_status * 1000);
		}
	}
	if (sta->info)
		free(sta->info);
	sta->info = malloc(blob_pad_len(b.head));
	memcpy(sta->info, b.head, blob_pad_len(b.head));

	if (sinfo[NL80211_STA_INFO_TX_RETRIES])
		tx_retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);

	if (sinfo[NL80211_STA_INFO_TX_BYTES])
		tx_bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

	if (sinfo[NL80211_STA_INFO_SIGNAL]) {
		if (sta->rssi) {
			sta->rssi += nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
			sta->rssi /= 2;
		} else {
			sta->rssi = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
		}
	}

	if (sta->rssi)
		blobmsg_add_u32(&b, "rssi", sta->rssi);

	if (rinfo[NL80211_RATE_INFO_BITRATE32])
		tx_rate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]) * 100;
	else if (rinfo[NL80211_RATE_INFO_BITRATE])
		tx_rate = nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]) * 100;

	if (tx_rate) {
		if (sta->tx_rate) {
			sta->tx_rate += tx_rate;
			sta->tx_rate /= 2;
		} else {
			sta->tx_rate += tx_rate;
		}
	}

	if (notify)
		ubus_notify(&conn.ctx, &ubus_object, "wifi.new.station", b.head, -1);

	if (sta->rssi) {
		enum metric_state metric_state = METRIC_NORMAL;

		if (sta->rssi < config.rssi_low)
			metric_state = METRIC_LOW;
		else if (sta->rssi > config.rssi_high)
			metric_state = METRIC_HIGH;

		if (sta->rssi_state != metric_state) {
			sta->rssi_state = metric_state;
			blob_buf_init(&b, 0);
			blobmsg_add_mac(&b, "mac", sta->addr);
			blobmsg_add_u32(&b, "rssi", sta->rssi);
			ubus_notify(&conn.ctx, &ubus_object, rssi_string[metric_state], b.head, -1);
		}
	}

	if (sta->tx_rate) {
		enum metric_state metric_state = METRIC_NORMAL;

		if (sta->tx_rate < config.tx_rate_low)
			metric_state = METRIC_LOW;
		else if (sta->tx_rate > config.tx_rate_high)
			metric_state = METRIC_HIGH;

		if (sta->tx_rate_state != metric_state) {
			sta->tx_rate_state = metric_state;
			blob_buf_init(&b, 0);
			blobmsg_add_mac(&b, "mac", sta->addr);
			blobmsg_add_u32(&b, "tx_rate", sta->tx_rate);
			ubus_notify(&conn.ctx, &ubus_object, tx_rate_string[metric_state], b.head, -1);
		}
	}

	if (sta->tx_retries) {
		uint32_t retries = tx_retries - sta->tx_retries;

		if (retries)
			retries = (tx_bytes - sta->tx_bytes) / retries;

		if (retries > config.tx_retries) {
			blob_buf_init(&b, 0);
			blobmsg_add_mac(&b, "mac", sta->addr);
			blobmsg_add_u32(&b, "tx_retries", retries);
			ubus_notify(&conn.ctx, &ubus_object, "wifi.rps", b.head, -1);
		}
	}
	sta->tx_retries = tx_retries;
	sta->tx_bytes = tx_bytes;
}

static void _nl80211_del_station(struct wifi_station *sta)
{
	avl_delete(&sta_tree, &sta->avl);
	if (sta->info)
		free(sta->info);
	free(sta);
	uloop_timeout_cancel(&sta->status);
}

static void nl80211_del_station(struct nlattr **tb)
{
	struct wifi_station *sta;
	uint8_t *addr;

	if (tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	sta = avl_find_element(&sta_tree, addr, sta, avl);
	if (!sta)
		return;
	nl80211_notify(tb, "wifi.del.station");
	_nl80211_del_station(sta);
}

static void nl80211_handle_survey(struct nlattr **tb)
{
	struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
	char tmp[20];
	void *c;

	static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
		[NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
	};

	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), tmp);
	if (!tb[NL80211_ATTR_SURVEY_INFO])
                return;

	if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                             tb[NL80211_ATTR_SURVEY_INFO],
                             survey_policy))
                return;

        if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY] ||
	    !sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME] ||
	    !sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY])
		return;

	sprintf(tmp, "%u", nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]));
	c = blobmsg_open_table(&s, tmp);

	if (sinfo[NL80211_SURVEY_INFO_NOISE]) {
		sprintf(tmp, "%d", (int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]));
		blobmsg_add_string(&s, "noise", tmp);
	}

	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME])
		blobmsg_add_u64(&s, "active", nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]));

	if (sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY])
		blobmsg_add_u64(&s, "busy", nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]));

	blobmsg_add_u8(&s, "in_use", (sinfo[NL80211_SURVEY_INFO_IN_USE]) ? nla_get_u8(sinfo[NL80211_SURVEY_INFO_IN_USE]) : false);

	blobmsg_close_table(&s, c);
}

static void nl80211_add_iface(struct nlattr **tb)
{
	struct wifi_iface *wif;
	uint8_t *addr;
	char *ifname;

	if (tb[NL80211_ATTR_IFNAME] == NULL || tb[NL80211_ATTR_MAC] == NULL)
		return;

	addr = nla_data(tb[NL80211_ATTR_MAC]);
	ifname = nla_get_string(tb[NL80211_ATTR_IFNAME]);

	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif) {
		wif = malloc(sizeof(*wif));
		if (!wif)
			return;

		memset(wif, 0, sizeof(*wif));
		memcpy(wif->ifname, ifname, IF_NAMESIZE);
		wif->avl.key = wif->ifname;
		wif->idx = if_nametoindex(wif->ifname);
		wif->assoc.cb = nl80211_assoc_list;
		nl80211_assoc_list(&wif->assoc);
		avl_insert(&wif_tree, &wif->avl);
		nl80211_notify(tb, "wifi.new.iface");
		wif->info = NULL;
		if (!strncmp(wif->ifname, "scan", 4))
			iface_up(wif->ifname);
	} else
		nl80211_to_blob(tb, NULL);
	memcpy(wif->addr, addr, 6);
	if (wif->info)
		free(wif->info);
	wif->info = malloc(blob_pad_len(b.head));
	memcpy(wif->info, b.head, blob_pad_len(b.head));

	if (tb[NL80211_ATTR_WIPHY])
		wif->phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);

	if (tb[NL80211_ATTR_WIPHY_FREQ])
		wif->freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);

	if (tb[NL80211_ATTR_CENTER_FREQ1])
		wif->chan_freq1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);

	if (tb[NL80211_ATTR_CENTER_FREQ2])
		wif->chan_freq2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);

	if (tb[NL80211_ATTR_CHANNEL_WIDTH])
		wif->chan_width = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);

	if (tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
		wif->chan_type = nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
}

static void _nl8011_del_iface(struct wifi_iface *wif)
{
	avl_delete(&wif_tree, &wif->avl);
	uloop_timeout_cancel(&wif->assoc);
	if (wif->info)
		free(wif->info);
	if (wif->scan_result)
		free(wif->scan_result);
	free(wif);
}

static void nl80211_del_iface(struct nlattr **tb)
{
	struct wifi_iface *wif;
	char *ifname;

	if (tb[NL80211_ATTR_IFNAME] == NULL)
		return;

	ifname = nla_get_string(tb[NL80211_ATTR_IFNAME]);
	wif = avl_find_element(&wif_tree, ifname, wif, avl);
	if (!wif)
		return;
	nl80211_notify(tb, "wifi.del.iface");
	_nl8011_del_iface(wif);
}

static void nl80211_handle_cqm(struct nlattr **tb, int iface)
{
	static struct nla_policy cqm_policy[NL80211_ATTR_CQM_MAX + 1] = {
		[NL80211_ATTR_CQM_RSSI_THOLD] = { .type = NLA_U32 },
		[NL80211_ATTR_CQM_RSSI_HYST] = { .type = NLA_U8 },
		[NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT] = { .type = NLA_U32 },
		[NL80211_ATTR_CQM_PKT_LOSS_EVENT] = { .type = NLA_U32 },
	};
	struct nlattr *cqm[NL80211_ATTR_CQM_MAX + 1];

	if (tb[NL80211_ATTR_CQM] == NULL)
		return;
	if (nla_parse_nested(cqm, NL80211_ATTR_CQM_MAX, tb[NL80211_ATTR_CQM], cqm_policy))
		return;
	if (cqm[NL80211_ATTR_CQM_PKT_LOSS_EVENT]) {
		uint8_t *addr;
		if (!tb[NL80211_ATTR_MAC])
			return;
		addr = nla_data(tb[NL80211_ATTR_MAC]);
		blob_buf_init(&b, 0);
		blobmsg_add_iface(&b, "interface", iface);
		blobmsg_add_mac(&b, "mac", addr);
		ubus_notify(&conn.ctx, &ubus_object, "packet.loss", b.head, -1);
		return;
	} else if (cqm[NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT]) {
		switch (nla_get_u32(cqm[NL80211_ATTR_CQM_RSSI_THRESHOLD_EVENT])) {
		case NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH:
			break;
		case NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW:
			break;
		}
	}
}

static int nl80211_mcast_grp(struct nlattr **tb, struct family_data *res)
{
	struct nlattr *mcgrp;
	int i;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
		nla_len(mcgrp), NULL);

		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]), res->group, nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;
		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}

	return NL_SKIP;
}

static int cb_nl80211_status(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	int ifidx = -1;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		return nl80211_mcast_grp(tb, arg);

	} else if (tb[NL80211_ATTR_IFINDEX]) {
		ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
	}

	switch (gnlh->cmd) {
	case NL80211_CMD_NEW_STATION:
		nl80211_add_station(tb);
		break;
	case NL80211_CMD_DEL_STATION:
		nl80211_del_station(tb);
		break;
	case NL80211_CMD_NEW_INTERFACE:
		nl80211_add_iface(tb);
		break;
	case NL80211_CMD_NEW_SURVEY_RESULTS:
		nl80211_handle_survey(tb);
		break;
	case NL80211_CMD_DEL_INTERFACE:
		nl80211_del_iface(tb);
		break;
	case NL80211_CMD_NOTIFY_CQM:
		nl80211_handle_cqm(tb, ifidx);
		break;
	case NL80211_CMD_FRAME_TX_STATUS:
		break;
	case NL80211_CMD_TRIGGER_SCAN:
		nl80211_handle_trigger_scan(ifidx, 1);
		break;
	case NL80211_CMD_NEW_SCAN_RESULTS:
		nl80211_handle_new_scan_result(tb, ifidx);
		break;
	case NL80211_CMD_SCAN_ABORTED:
		nl80211_handle_trigger_scan(ifidx, 0);
		break;
	case NL80211_CMD_GET_REG:
		nl80211_to_blob(tb, NULL);
		break;
	default:
		break;
	}

	return NL_SKIP;
}

int nl80211_reg_get(void)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_GET_REG, 0))
		goto out;

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

int nl80211_reg_set(char *alpha2)
{
	struct nl_msg *msg;

	if (strlen(alpha2) != 2)
		return -EINVAL;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_REQ_SET_REG, 0))
		goto out;

	if (nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, alpha2))
		goto out;

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

int nl80211_iface_del(char *ifname)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_DEL_INTERFACE, 0))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname)))
		goto out;

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

int nl80211_iface_add(int phy, char *ifname, uint32_t iftype)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_NEW_INTERFACE, 0))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY, phy))
		goto out;

	if (nla_put_string(msg, NL80211_ATTR_IFNAME, ifname))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_IFTYPE, iftype))
		goto out;

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

static void nl80211_enum_tout(struct uloop_timeout *t)
{
	nl80211_list_wif();
	uloop_timeout_set(&nl80211_enum_timer, 2 * 1000);
}

int nl80211_init(void)
{
	int id;

	if (!nl_socket(&nl80211_status, NETLINK_GENERIC, cb_nl80211_status, &nl80211_arg))
		return -1;

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "config");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "mlme");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "vendor");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	id = genl_get_multicast_id(&nl80211_status, "nl80211", "scan");
	if (id >= 0)
		nl_socket_add_membership(nl80211_status.sock, id);

	nl80211_enum_timer.cb = nl80211_enum_tout;
	uloop_timeout_set(&nl80211_enum_timer, 2 * 1000);
	if (config.country)
		nl80211_reg_set(config.country);

	nl80211_init_scan();

	return 0;
}

void nl80211_deinit(void)
{
	struct wifi_iface *wif;
	struct wifi_station *sta;

	nl80211_deinit_scan();
	nl_socket_free(nl80211_status.sock);

	while (!avl_is_empty(&wif_tree) && (wif = avl_first_element(&wif_tree, wif, avl)))
		_nl8011_del_iface(wif);
	while (!avl_is_empty(&sta_tree) && (sta = avl_first_element(&sta_tree, sta, avl)))
		_nl80211_del_station(sta);
}
