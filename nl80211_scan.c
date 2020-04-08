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

static struct nl_socket nl80211_scan;
static uint8_t nl80211_scan_arg[4096];
struct blob_buf s = { 0 };
struct uloop_timeout nl80211_scan_timer;

#define min(a,b) (((a) < (b)) ? (a) : (b))

static int nl80211_freq2channel(int freq)
{
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else
		return (freq - 5000) / 5;
}

int nl80211_trigger_scan(struct wifi_iface *wif, int on_channel)
{
	struct nl_msg *msg;

	if (wif->scanning)
		return 0;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, 0, NL80211_CMD_TRIGGER_SCAN, 0))
		goto out;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, wif->idx))
		goto out;

	if (on_channel) {
		if (wif->freq)
			nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, wif->freq);
		if (wif->chan_freq1)
			nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, wif->chan_freq1);
		if (wif->chan_freq1)
			nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, wif->chan_freq2);
		if (wif->chan_width)
			nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, wif->chan_width);
		if (wif->chan_type)
			nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, wif->chan_type);
	}

	return genl_send_and_recv(&nl80211_status, msg);
out:
	nlmsg_free(msg);
	return -EINVAL;
}

void nl80211_handle_trigger_scan(int iface, int start)
{
	char ifname[IF_NAMESIZE];
	struct wifi_iface *wif;

	if (!if_indextoname(iface, ifname))
		return;
	wif = find_wif(ifname);
	if (!wif)
		return;
	wif->scanning = !!start;
}

void nl80211_handle_new_scan_result(struct nlattr **tb, int iface)
{
	char ifname[IF_NAMESIZE];
	struct wifi_iface *wif;
	struct nl_msg *msg;

	if (!if_indextoname(iface, ifname))
		return;
	wif = find_wif(ifname);
	if (!wif)
		goto out;

	msg = nlmsg_alloc();
	if (!msg)
		return;

	if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl80211_status.sock, "nl80211"),
			 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0))
		goto err_out;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, iface))
		goto err_out;

	blob_buf_init(&s, 0);
	genl_send_and_recv(&nl80211_scan, msg);
	if (wif->scan_result)
		free(wif->scan_result);
	wif->scan_result = malloc(blob_pad_len(s.head));
	memcpy(wif->scan_result, s.head, blob_pad_len(s.head));
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", ifname);
	ubus_notify(&conn.ctx, &ubus_object, "wifi.scan.done", b.head, -1);
out:
	wif->scanning = 0;
	return;

err_out:
	nlmsg_free(msg);
}

static void iwinfo_parse_rsn_cipher(uint8_t idx)
{
	switch (idx)
	{
		case 0:
			blobmsg_add_string(&s, "cipher", "none");
			break;

		case 1:
			blobmsg_add_string(&s, "cipher", "wep40");
			break;

		case 2:
			blobmsg_add_string(&s, "cipher", "tkip");
			break;

		case 3:  /* WRAP */
			break;

		case 4:
	//		blobmsg_add_string(&s, "cipher", "ccmp");
			break;

		case 5:
			blobmsg_add_string(&s, "cipher", "wep104");
			break;

		case 6:  /* AES-128-CMAC */
		case 7:  /* No group addressed */
		case 8:  /* GCMP */
		case 9:  /* GCMP-256 */
		case 10: /* CCMP-256 */
		case 11: /* BIP-GMAC-128 */
		case 12: /* BIP-GMAC-256 */
		case 13: /* BIP-CMAC-256 */
			break;
	}
}

static void iwinfo_parse_rsn(uint8_t *data, uint8_t len, char *defcipher, char *defauth)
{
	uint16_t i, count;
	uint8_t wpa_version = 0;

	static unsigned char ms_oui[3]        = { 0x00, 0x50, 0xf2 };
	static unsigned char ieee80211_oui[3] = { 0x00, 0x0f, 0xac };

	data += 2;
	len -= 2;

	if (!memcmp(data, ms_oui, 3))
		wpa_version |= 1;
	else if (!memcmp(data, ieee80211_oui, 3))
		wpa_version |= 2;

	if (len < 4) {
		blobmsg_add_string(&s, "group_ciphers", defcipher);
		blobmsg_add_string(&s, "pair_ciphers", defcipher);
		blobmsg_add_string(&s, "auth_suites", defauth);
		return;
	}

	if (!memcmp(data, ms_oui, 3) || !memcmp(data, ieee80211_oui, 3))
		iwinfo_parse_rsn_cipher(data[3]);

	data += 4;
	len -= 4;

	if (len < 2)
	{
		blobmsg_add_string(&s, "pair_ciphers", defcipher);
		blobmsg_add_string(&s, "auth_suites", defauth);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		return;

	for (i = 0; i < count; i++)
		if (!memcmp(data + 2 + (i * 4), ms_oui, 3) ||
		    !memcmp(data + 2 + (i * 4), ieee80211_oui, 3))
			iwinfo_parse_rsn_cipher(data[2 + (i * 4) + 3]);

	data += 2 + (count * 4);
	len -= 2 + (count * 4);

	if (len < 2)
	{
		blobmsg_add_string(&s, "auth_suites", defauth);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		return;

	for (i = 0; i < count; i++)
	{
		if (!memcmp(data + 2 + (i * 4), ms_oui, 3) ||
			!memcmp(data + 2 + (i * 4), ieee80211_oui, 3))
		{
			switch (data[2 + (i * 4) + 3])
			{
				case 1:  /* IEEE 802.1x */
					blobmsg_add_u16(&s, "wpa_version", wpa_version);
					blobmsg_add_string(&s, "auth_suites", "8021x");
					break;

				case 2:  /* PSK */
					blobmsg_add_u16(&s, "wpa_version", wpa_version);
					blobmsg_add_string(&s, "auth_suites", "psk");
					break;

				case 3:  /* FT/IEEE 802.1X */
				case 4:  /* FT/PSK */
				case 5:  /* IEEE 802.1X/SHA-256 */
				case 6:  /* PSK/SHA-256 */
				case 7:  /* TPK Handshake */
					break;

				case 8:  /* SAE */
					blobmsg_add_u16(&s, "wpa_version", 4);
					blobmsg_add_string(&s, "auth_suites", "sae");
					break;

				case 9:  /* FT/SAE */
				case 10: /* undefined */
					break;

				case 11: /* 802.1x Suite-B */
				case 12: /* 802.1x Suite-B-192 */
					blobmsg_add_u16(&s, "wpa_version", 4);
					blobmsg_add_string(&s, "auth_suites", "8021x");
					break;

				case 13: /* FT/802.1x SHA-384 */
				case 14: /* FILS SHA-256 */
				case 15: /* FILS SHA-384 */
				case 16: /* FT/FILS SHA-256 */
				case 17: /* FT/FILS SHA-384 */
					break;

				case 18: /* OWE */
					blobmsg_add_u16(&s, "wpa_version", 4);
					blobmsg_add_string(&s, "auth_suites", "owe");
					break;
			}
		}
	}
}

static void nl80211_get_scanlist_ie(struct nlattr **bss)
{
	int ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	unsigned char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	char ssid[ESSID_MAX_SIZE + 1] = { 0 };
	void *c;
	int len;

	while (ielen >= 2 && ielen >= ie[1]) {
		switch (ie[0]) {
		case 0: /* SSID */
		case 114: /* Mesh ID */
			if (ssid[0] == 0) {
				len = min(ie[1], ESSID_MAX_SIZE);
				memcpy(ssid, ie + 2, len);
				ssid[len] = 0;
				blobmsg_add_string(&s, "ssid", ssid);
			}
			break;
		case 11: /* BSS Load */
			c = blobmsg_open_table(&s, "bss_load");
			blobmsg_add_u16(&s, "station_count", (ie[3] << 8) | ie[2]);
			blobmsg_add_u8(&s, "channel_utilization", ie[4]);
			blobmsg_add_u16(&s, "admission_capacity", (ie[6] << 8) | ie[5]);
			blobmsg_close_table(&s,  c);
			break;
		case 48: /* RSN */
			iwinfo_parse_rsn(ie + 2, ie[1], "CCMP", "8021x");
			break;
		}

		ielen -= ie[1] + 2;
		ie += ie[1] + 2;
	}
}

static void mac_addr_n2a(char *mac_addr, const unsigned char *arg)
{
	int i, l;

	l = 0;
	for (i = 0; i < ETH_ALEN ; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

static int cb_nl80211_scan(struct nl_msg *msg, void *arg)
{
	int32_t rssi;
	uint16_t caps;
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_TSF]                  = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
		[NL80211_BSS_BSSID]                = { 0 },
		[NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { 0 },
		[NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8  },
		[NL80211_BSS_STATUS]               = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO]          = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES]           = { 0 },
	};
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	void *c;
	char tmp[64] = {};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS] ||
	    nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) ||
	    !bss[NL80211_BSS_BSSID])
	{
		return NL_SKIP;
	}

	c = blobmsg_open_table(&s, NULL);

	if (bss[NL80211_BSS_BSSID]) {
		mac_addr_n2a(tmp, nla_data(bss[NL80211_BSS_BSSID]));
		blobmsg_add_string(&s, "bssid", tmp);
	}

	if (bss[NL80211_BSS_CAPABILITY])
		caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
	else
		caps = 0;

	if (caps & (1<<1))
		blobmsg_add_string(&s, "mode", "adhoc");
	else if (caps & (1<<0))
		blobmsg_add_string(&s, "mode", "master");
	else
		blobmsg_add_string(&s, "mode", "mesh");

	if (caps & (1<<4))
		blobmsg_add_u16(&s, "crypto", 1);

	if (bss[NL80211_BSS_FREQUENCY])
		blobmsg_add_u32(&s, "channel",
			nl80211_freq2channel(nla_get_u32(
					bss[NL80211_BSS_FREQUENCY])));

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
		nl80211_get_scanlist_ie(bss);

	if (bss[NL80211_BSS_SIGNAL_MBM]) {
		int signal = ((int32_t)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]) / 100);

		sprintf(tmp, "%d", signal);
		blobmsg_add_string(&s, "mbm", tmp);

		rssi = signal - 0x100;
		if (rssi < -110)
			rssi = -110;
		else if (rssi > -40)
			rssi = -40;
		sprintf(tmp, "%d", rssi);
		blobmsg_add_string(&s, "rssi", tmp);

		blobmsg_add_u16(&s, "quality", rssi + 110);
		blobmsg_add_u16(&s, "quality_max", 70);
	}

	blobmsg_close_table(&s, c);

	return NL_SKIP;
}

static void nl80211_scan_tout(struct uloop_timeout *t)
{
	struct wifi_iface *wif;

	wif = find_wif("scan");
	if (wif) {
		if (!wif->scanning && !wif->cac)
			nl80211_trigger_scan(wif, 0);
	}
	uloop_timeout_set(&nl80211_scan_timer, config.scan_period * 1000);
}

int nl80211_init_scan(void)
{
	if (!nl_socket(&nl80211_scan, NETLINK_GENERIC, cb_nl80211_scan, &nl80211_scan_arg))
		return -1;

	if (config.scan_period) {
		int ret = nl80211_iface_add(config.scan_phy, "scan", NL80211_IFTYPE_AP);
		if (ret)
			return -1;
		iface_up("scan");
		nl80211_scan_timer.cb = nl80211_scan_tout;
		uloop_timeout_set(&nl80211_scan_timer, config.scan_period * 1000);
	}

	return 0;
}

void nl80211_deinit_scan(void)
{
	nl_socket_free(nl80211_scan.sock);
	nl80211_iface_del("scan");
}
