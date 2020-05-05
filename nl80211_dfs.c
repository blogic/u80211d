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

static uint32_t chwidth[] =  { NL80211_CHAN_WIDTH_20,
			       NL80211_CHAN_WIDTH_40,
			       NL80211_CHAN_WIDTH_80 };
static struct dfs_channels {
	int freq;
	int channel;
	int center_freq[3];
} dfs_channels[] = {
	{
		.freq = 5260,
		.channel = 52,
		.center_freq = { 5260, 5270, 5290},
	}, {
		.freq = 5280,
		.channel = 56,
		.center_freq = { 5280, 5270, 5290},
	}, {

		.freq = 5300,
		.channel = 60,
		.center_freq = { 5300, 5310, 5290},
	}, {

		.freq = 5320,
		.channel = 64,
		.center_freq = { 5320, 5310, 5290},
	}, {

		.freq = 5500,
		.channel = 100,
		.center_freq = { 5500, 5510, 5300},
	}, {

		.freq = 5520,
		.channel = 104,
		.center_freq = { 5520, 5510, 5300},
	}, {

		.freq = 5540,
		.channel = 108,
		.center_freq = { 5540, 5550, 5300},
	}, {

		.freq = 5560,
		.channel = 112,
		.center_freq = { 5560, 5550, 5300},
	}, {

		.freq = 5580,
		.channel = 116,
		.center_freq = { 5580, 5590, 5610},
	}, {

		.freq = 5600,
		.channel = 120,
		.center_freq = { 5600, 5590, 5610},
	}, {

		.freq = 5620,
		.channel = 124,
		.center_freq = { 5620, 56300, 5610},
	}, {

		.freq = 5640,
		.channel = 128,
		.center_freq = { 5640, 5630, 5610},
	}, {

		.freq = 5660,
		.channel = 132,
		.center_freq = { 5660, 5670, 5690},
	}, {

		.freq = 5680,
		.channel = 136,
		.center_freq = { 5680, 5670, 5690},
	}, {

		.freq = 5700,
		.channel = 140,
		.center_freq = { 5700, 5710, 5690},
	}, {

		.freq = 5720,
		.channel = 144,
		.center_freq = { 5720, 5710, 5690},
	}
};

int nl80211_trigger_cac(struct wifi_iface *wif, int channel, int width)
{
	struct nl_msg *msg;
	struct dfs_channels *dfs = dfs_channels;
	int i;

	for (i = 0; i < 16; i++, dfs++) {
		if (dfs->channel == channel)
			break;
	}

	if (i == 16)
		return -EINVAL;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_RADAR_DETECT, 0))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, wif->idx))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, dfs->freq))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, chwidth[width]))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, dfs->center_freq[width]))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, 0))
		goto out;

	wif->cac = 1;

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

void nl80211_handle_radar_event(struct nlattr **tb, int iface)
{
	char ifname[IF_NAMESIZE];
	struct wifi_iface *wif;
	enum nl80211_radar_event event_type;
	uint32_t freq;

	if (!if_indextoname(iface, ifname))
		return;
	wif = find_wif(ifname);
	if (!wif)
		return;

	if (!tb[NL80211_ATTR_RADAR_EVENT] ||
	    !tb[NL80211_ATTR_WIPHY_FREQ]) {
		printf("BAD radar event\n");
		return;
	}
	wif->cac = 0;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", ifname);

	freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
	event_type = nla_get_u32(tb[NL80211_ATTR_RADAR_EVENT]);

	blobmsg_add_u32(&b, "control_frequency", freq);
	if (tb[NL80211_ATTR_CENTER_FREQ1])
		blobmsg_add_u32(&b, "center_frequency1", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]));
	if (tb[NL80211_ATTR_CENTER_FREQ2])
		blobmsg_add_u32(&b, "center_frequency2", nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]));
	if (tb[NL80211_ATTR_CHANNEL_WIDTH])
		blobmsg_add_u32(&b, "width", nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]));

	switch (event_type) {
	case NL80211_RADAR_DETECTED:
		blobmsg_add_u32(&b, "detected", 1);
		ULOG_WARN("%d MHz: radar detected\n", freq);
		break;
	case NL80211_RADAR_CAC_FINISHED:
		blobmsg_add_u32(&b, "finished", 1);
		ULOG_INFO("%d MHz: CAC finished\n", freq);
		break;
	case NL80211_RADAR_CAC_ABORTED:
		blobmsg_add_u32(&b, "abort", 1);
		ULOG_ERR("%d MHz: CAC was aborted\n", freq);
		break;
	case NL80211_RADAR_NOP_FINISHED:
		blobmsg_add_u32(&b, "nop", 1);
		ULOG_INFO("%d MHz: NOP finished\n", freq);
		break;
	default:
		blobmsg_add_u32(&b, "error", 1);
		ULOG_ERR("%d MHz: unknown radar event\n", freq);
		break;
	}

	ubus_notify(&conn.ctx, &ubus_object, "wifi.cac", b.head, -1);
}
