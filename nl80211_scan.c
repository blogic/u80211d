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

#define HT_CHANNELS_MAX 2
#define VHT_CHANNELS_MAX 8
#define HE_CHANNELS_MAX VHT_CHANNELS_MAX

#define CHANNEL_WIDTH_STR_MAX 6

#define HT_CHAN_WIDTH_MASK 0x04
#define HT_SECONDARY_CHAN_OFFS_MASK 0x03

#define VHT_OP_INFO_OCTET_OFFSET 2

#define HE_OP_PARAMS_6GHZ_OP_INFO_MASK 0x02
#define HE_OP_PARAMS_VHT_OP_INFO_MASK 0x04
#define HE_6GHZ_OP_INFO_OCTET_OFFSET 9
#define HE_VHT_OP_INFO_OCTET_OFFSET 9


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

struct bss_mode_channels {
	unsigned char ht[HT_CHANNELS_MAX];
	unsigned char vht[VHT_CHANNELS_MAX];
	unsigned char he[HE_CHANNELS_MAX];
};

struct bss_mode_widths {
	char ht[CHANNEL_WIDTH_STR_MAX];
	char vht[CHANNEL_WIDTH_STR_MAX];
	char he[CHANNEL_WIDTH_STR_MAX];
};

struct bss_modes {
	bool has_ht;
	bool has_vht;
	bool has_he;
};

struct bss_capabilities {
	struct bss_mode_channels channels;
	struct bss_mode_widths widths;
	struct bss_modes modes;
};

static void determine_6ghz_he_mode_and_channel(unsigned char *ie, struct bss_capabilities *capabilities) {
	if ((!ie) || (!capabilities))
		return;

	unsigned char primary_channel = ie[0];
	unsigned char chan_width = ie[1];
	unsigned char CCFS0 = ie[2];			/* Channel Center Frequency Segment 0 */
	unsigned char CCFS1 = ie[3];			/* Channel Center Frequency Segment 1 */
	unsigned char CCF_diff = abs(ie[3] - ie[2]);    /* CCFS1 - CCFS0 */

	switch(chan_width) {
	case 0:	/* 20 MHz */
		snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "20");
		capabilities->channels.he[0] = primary_channel;
		break;

	case 1:	/* 40 MHz */
		snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "40");
		capabilities->channels.he[0] = CCFS0 - 2;
		capabilities->channels.he[1] = CCFS0 + 2;
		break;

	case 2: /* 80 MHz */
		snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "80");
		for (int idx = 0, base = -6; idx < (HE_CHANNELS_MAX / 2); ++idx, base += 4)
			capabilities->channels.he[idx] = CCFS0 + base;

		break;

	case 3: /* 160 MHz or 80+80 MHz */
		if ((CCFS1 > 0) && (CCF_diff = 8)) {    /* 160 MHz */
			snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "160");
			for (int idx = 0, base = -14; idx < HE_CHANNELS_MAX; ++idx, base += 4)
				capabilities->channels.he[idx] = CCFS0 + base;
		} else if ((CCFS1 > 0) && (CCF_diff > 16)) {    /* 80+80 MHz */
			snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "80+80");
			for (int idx = 0, base = -6; idx < (HE_CHANNELS_MAX / 2); ++idx, base += 4) {
				capabilities->channels.he[idx] = CCFS0 + base;
				capabilities->channels.he[idx+4] = CCFS1 + base;
			}
		}

		break;

	default:	/* 4 to 255 is reserved */
		break;
	}
}

static void __determine_vht_mode_channels(unsigned char *ie, unsigned char *dest_chans,
		char *dest_width, struct bss_capabilities *capabilities)
{
	if ((!ie) || (!capabilities))
		return;

	unsigned char chan_width = ie[0];
	unsigned char CCFS0 = ie[1];
	unsigned char CCFS1 = ie[2];
	unsigned CCF_diff = abs(ie[2] - ie[1]);

	switch (chan_width) {
	case 0:	/* 20 MHz or 40 MHz */
		snprintf(dest_width, CHANNEL_WIDTH_STR_MAX, "%s",
				(capabilities->channels.ht[0] && capabilities->channels.ht[1]) ? "40" : "20");
		dest_chans[0] = capabilities->channels.ht[0];
		dest_chans[1] = capabilities->channels.ht[1];
		break;

	case 1:	/* 80 MHz, 160 MHz, or 80+80 MHz */
		/* The formula to determine VHT channel width found in the 802.11 spec:
		*  Table 9-253 — BSS bandwidth when the VHT Operation Information field Channel Width sub-field is 1.
		*/
		if (CCFS1 == 0) {
			snprintf(dest_width, CHANNEL_WIDTH_STR_MAX, "80");
			for (int idx = 0, base = -6; idx < (VHT_CHANNELS_MAX / 2); ++idx, base += 4)
				dest_chans[idx] = CCFS0 + base;
		} else if ((CCFS1 > 0) && (CCF_diff == 8)) {
			snprintf(dest_width, CHANNEL_WIDTH_STR_MAX, "160");
			for (int idx = 0, base = -14; idx < VHT_CHANNELS_MAX; ++idx, base += 4)
				dest_chans[idx] = CCFS0 + base;

		} else if ((CCFS1 > 0) && (CCF_diff > 16)) {
			snprintf(dest_width, CHANNEL_WIDTH_STR_MAX, "80+80");
			for (int idx = 0, base = -6; idx < (VHT_CHANNELS_MAX / 2); ++idx, base += 4) {
				dest_chans[idx] = CCFS0 + base;
				dest_chans[idx+4] = CCFS1 + base;
			}
		}
		break;

	case 2:	/* 160 MHz (deprecated) */
		snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "160");
		for (int idx = 0, base = -14; idx < VHT_CHANNELS_MAX; ++idx, base += 4)
			capabilities->channels.he[idx] = CCFS0 + base;
		break;

	case 3:	/* Non-contiguous 80+80 MHz (deprecated) */
		snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "80+80");
		for (int idx = 0, base = -6; idx < (VHT_CHANNELS_MAX / 2); ++idx, base += 4) {
			capabilities->channels.he[idx] = CCFS0 + base;
			capabilities->channels.he[idx+4] = CCFS1 + base;
		}
		break;

	default:	/* 4 to 255 is reserved */
		break;
	}

}

static void determine_vht_mode_and_channels(unsigned char *ie, struct bss_capabilities *capabilities)
{
	unsigned char *vht_base = (unsigned char *) (ie + VHT_OP_INFO_OCTET_OFFSET);
	char dest_width[CHANNEL_WIDTH_STR_MAX] = {0};

	__determine_vht_mode_channels(vht_base, capabilities->channels.vht, dest_width, capabilities);

	snprintf(capabilities->widths.vht, sizeof(capabilities->widths.vht), "%s", dest_width);
}

static void determine_he_mode_and_channels(unsigned char *ie, struct bss_capabilities *capabilities)
{
	unsigned char *he_base = (unsigned char *) (ie + HE_VHT_OP_INFO_OCTET_OFFSET);
	char dest_width[CHANNEL_WIDTH_STR_MAX] = {0};

	__determine_vht_mode_channels(he_base, capabilities->channels.he, dest_width, capabilities);

	snprintf(capabilities->widths.ht, sizeof(capabilities->widths.he), "%s", dest_width);
}


static void nl80211_get_scanlist_ie(struct nlattr **bss, struct bss_capabilities *capabilities)
{
	if ((!bss) || (!capabilities))
		return;

	int ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	unsigned char *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
	char ssid[ESSID_MAX_SIZE + 1] = { 0 };
	void *c;
	int len;

	/* 802.11 BSS IE (information element) IDs defined in 802.11 section 9.4.2 in Table 9-77 "Element IDs" */
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

		case 61: /* HT Operation */
			capabilities->modes.has_ht = true;
			capabilities->channels.ht[0] = ie[2];

			if (ie[3] & HT_CHAN_WIDTH_MASK) { /* is HT40 */
				switch (ie[3] & HT_SECONDARY_CHAN_OFFS_MASK) {
				case 0:		/* no secondary channel */
					snprintf(capabilities->widths.ht, sizeof(capabilities->widths.ht), "20");
					break;
				case 1:		/* secondary channel above */
					snprintf(capabilities->widths.ht, sizeof(capabilities->widths.ht), "40+");
					capabilities->channels.ht[1] = ie[2] + 4;
					break;
				case 3:		/* secondary channel below */
					snprintf(capabilities->widths.ht, sizeof(capabilities->widths.ht), "40-");
					capabilities->channels.ht[1] = ie[2] - 4;
					break;
				default:	/* 2 is reserved */
					break;
				}
			} else {
				snprintf(capabilities->widths.ht, sizeof(capabilities->widths.ht), "20");
			}

			break;

		case 192: /* VHT Operation */
			capabilities->modes.has_vht = true;
			determine_vht_mode_and_channels(ie, capabilities);
			break;

		case 255: /* Max Element ID */
			/* Check element ID Extension */
			if (ie[2] != 36) /* Is not "HE Operation" element */
				break;

			/* HE Operates at channel widths of 20/40/80/80+80/160 MHz */
			/* The channel width is determined by either the 6 GHz, VHT or HT width */
			/* Reference 802.11 Section 9.4.243 "HE Operation Element" */
			capabilities->modes.has_he = true;

			if (ie[5] & HE_OP_PARAMS_6GHZ_OP_INFO_MASK) {
				/* If this is a 6 GHz HE AP, the "6 GHz Operation Information" field shows channel width
				 *
				 * The "6 GHz Operation Information" field should start at octet 10 because
				 * the "VHT Operation Information Present" and "Co-Hosted BSS" bits should never be set as
				 * defined in 802.11 Section 26.17.2.1
				 * Reference Figure 9-772h for element format */
				determine_6ghz_he_mode_and_channel((unsigned char *) (ie + HE_6GHZ_OP_INFO_OCTET_OFFSET), capabilities);
			} else if (capabilities->modes.has_vht) {    /* If we have VHT information already, reuse it */
				snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "%s", capabilities->widths.vht);
				for (int idx=0; idx < HE_CHANNELS_MAX; ++idx)
					capabilities->channels.he[idx] = capabilities->channels.vht[idx];

			} else if (ie[4] & HE_OP_PARAMS_VHT_OP_INFO_MASK) {
				/* If this beacon did not include a VHT operation element, this beacon should have it embedded
				 * inside the HE operation element, unless this is 2.4 GHz HE AP */
				determine_he_mode_and_channels(ie, capabilities);
			} else if (capabilities->modes.has_ht) {	  /* If there is no VHT information, use HT information */
				snprintf(capabilities->widths.he, sizeof(capabilities->widths.he), "%s", capabilities->widths.ht);
				capabilities->channels.he[0] = capabilities->channels.ht[0];
				capabilities->channels.he[1] = capabilities->channels.ht[1];
			}

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

static void add_bss_capabilites_report(struct bss_capabilities *capabilities, int frequency)
{
	if (!capabilities)
		return;

	if (capabilities->modes.has_ht) {
		blobmsg_add_string(&s, "ht", capabilities->widths.ht);
		void *ht_cookie = blobmsg_open_array(&s, "ht_channels");

		if (ht_cookie) {
			blobmsg_add_u32(&s, "ht_channel", (unsigned int) capabilities->channels.ht[0]);

			if (capabilities->channels.ht[1])
				blobmsg_add_u32(&s, "ht_channel", (unsigned int) capabilities->channels.ht[1]);
		}

		blobmsg_close_array(&s, ht_cookie);
		ht_cookie = NULL;
	}

	if (capabilities->modes.has_vht) {
		blobmsg_add_string(&s, "vht", capabilities->widths.vht);
		void *vht_cookie = blobmsg_open_array(&s, "vht_channels");

		if (vht_cookie) {
			for (int idx = 0; ((idx < VHT_CHANNELS_MAX) && capabilities->channels.vht[idx]); ++idx) {
				blobmsg_add_u32(&s, "vht_channel", (unsigned int) capabilities->channels.vht[idx]);
			}
		}

		blobmsg_close_array(&s, vht_cookie);
		vht_cookie = NULL;
	}

	if (capabilities->modes.has_he) {
		blobmsg_add_string(&s, "he", capabilities->widths.he);
		void *he_cookie = blobmsg_open_array(&s, "he_channels");

		if (he_cookie) {
			for (int idx = 0; ((idx < HE_CHANNELS_MAX) && capabilities->channels.he[idx]); ++idx) {
				blobmsg_add_u32(&s, "he_channel", (unsigned int) capabilities->channels.he[idx]);
			}
		}

		blobmsg_close_array(&s, he_cookie);
		he_cookie = NULL;
	}

}

static void add_bss_supported_modes_report(struct bss_capabilities *capabilities, int frequency)
{
	if (!capabilities)
		return;

	char wifi_mode_str[24] = {0};

	if (frequency == 2) {
		int ret = snprintf(wifi_mode_str, sizeof(wifi_mode_str) - 1, "11b/g/%s%s", (capabilities->modes.has_ht) ? "n/" : "",
				(capabilities->modes.has_he) ? "ax/" : "");
		wifi_mode_str[ret-1] = '\0';	/* drop the trailing / from the string */
		blobmsg_add_string(&s, "wifi_modes", wifi_mode_str);
	} else if ((frequency == 5) || (frequency == 6)) {
		int ret = snprintf(wifi_mode_str, sizeof(wifi_mode_str) - 1, "11%s%s%s", (capabilities->modes.has_ht) ? "n/" : "a/",
				(capabilities->modes.has_vht) ? "ac/" : "", (capabilities->modes.has_he) ? "ax/" : "");
		wifi_mode_str[ret-1] = '\0';	/* drop the trailing / from the string */
		blobmsg_add_string(&s, "wifi_modes", wifi_mode_str);
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

	struct bss_capabilities capabilities = {0};

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


	if (bss[NL80211_BSS_FREQUENCY]) {
		blobmsg_add_u32(&s, "channel",
			nl80211_freq2channel(nla_get_u32(
					bss[NL80211_BSS_FREQUENCY])));
	}

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
		nl80211_get_scanlist_ie(bss, &capabilities);

	if (bss[NL80211_BSS_FREQUENCY] && bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		int frequency = nla_get_u32(bss[NL80211_BSS_FREQUENCY]) >> 10;
		add_bss_capabilites_report(&capabilities, frequency);
		add_bss_supported_modes_report(&capabilities, frequency);

		if (frequency >= 2) {
			char band_str[8] = {0};

			snprintf(band_str, sizeof(band_str), "%sGHz", (frequency == 2) ? "2.4" : ((frequency == 5) ? "5" : "6"));
			blobmsg_add_string(&s, "band", band_str);
		}
	}

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
	if (wif && !wif->scanning)
		nl80211_trigger_scan(wif, 0);
	uloop_timeout_set(&nl80211_scan_timer, config.scan_period * 1000);
}

int nl80211_init_scan(void)
{
	if (!nl_socket(&nl80211_scan, NETLINK_GENERIC, cb_nl80211_scan, &nl80211_scan_arg))
		return -1;

	if (config.scan_period) {
		int ret = nl80211_iface_add(config.scan_phy, "scan", NL80211_IFTYPE_STATION);
		if (ret)
			return -1;
		iface_up("scan");
		nl80211_scan_timer.cb = nl80211_scan_tout;
		uloop_timeout_set(&nl80211_scan_timer, (config.scan_delay ? config.scan_delay : config.scan_period) * 1000);
	}

	return 0;
}

void nl80211_deinit_scan(void)
{
	nl_socket_free(nl80211_scan.sock);
	nl80211_iface_del("scan");
}
