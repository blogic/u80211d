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

struct ubus_auto_conn conn;
static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj);

enum {
	SURVEY_IFNAME,
	__SURVEY_MAX,
};

static const struct blobmsg_policy survey_policy[__SURVEY_MAX] = {
	[SURVEY_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

static int survey_cb(struct ubus_context *ctx,
		     struct ubus_object *obj,
		     struct ubus_request_data *req,
		     const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__SURVEY_MAX];
	char *ifname;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(survey_policy, __SURVEY_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SURVEY_IFNAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ifname = blobmsg_get_string(tb[SURVEY_IFNAME]);
	if (!nl80211_get_survey(ifname))
		ubus_send_reply(ctx, req, s.head);

	return UBUS_STATUS_OK;
}

enum {
	IFACE_PHY,
	IFACE_IFTYPE_STA,
	IFACE_IFTYPE_AP,
	IFACE_IFTYPE_MON,
	IFACE_ADD,
	IFACE_DELETE,
	__IFACE_MAX,
};

static const struct blobmsg_policy iface_policy[__IFACE_MAX] = {
	[IFACE_PHY] = { .name = "phy", .type = BLOBMSG_TYPE_INT32 },
	[IFACE_ADD] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_DELETE] = { .name = "delete", .type = BLOBMSG_TYPE_STRING },
	[IFACE_IFTYPE_STA] = { .name = "sta", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_IFTYPE_AP] = { .name = "ap", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_IFTYPE_MON] = { .name = "mon", .type = BLOBMSG_TYPE_BOOL },
};

struct wifi_iface *find_wif(char *ifname)
{
	struct wifi_iface *wif;

	avl_for_each_element(&wif_tree, wif, avl)
		if (!strcmp(ifname, wif->ifname))
			return wif;
	return NULL;
}

static int wif_busy(struct ubus_context *ctx,
		    struct ubus_request_data *req,
		    struct wifi_iface *wif)
{
	if (!wif->scanning && !wif->cac)
		return 0;

	blob_buf_init(&b, 0);
	if (wif->scanning)
		blobmsg_add_u8(&b, "scanning", true);
	if (wif->cac)
		blobmsg_add_u8(&b, "cac", true);
	ubus_send_reply(ctx, req, b.head);

	return 1;
}

static int iface_cb(struct ubus_context *ctx,
		    struct ubus_object *obj,
		    struct ubus_request_data *req,
		    const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__IFACE_MAX];
	char *ifname;
	int phy = 0;
	int iftype;
	int add = 1;
	int ret;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!blob_len(msg)) {
		struct wifi_iface *wif;
		blob_buf_init(&b, 0);
		avl_for_each_element(&wif_tree, wif, avl)
			blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, wif->ifname, blobmsg_data(wif->info), blobmsg_data_len(wif->info));
		ubus_send_reply(ctx, req, b.head);

		return UBUS_STATUS_OK;
	}

	blobmsg_parse(iface_policy, __IFACE_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[IFACE_ADD])
		ifname = blobmsg_get_string(tb[IFACE_ADD]);
	else if (tb[IFACE_DELETE]) {
		ifname = blobmsg_get_string(tb[IFACE_DELETE]);
		add = 0;
	} else
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (add && !tb[IFACE_PHY])
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (add)
		phy = blobmsg_get_u32(tb[IFACE_PHY]);

	if (tb[IFACE_IFTYPE_AP])
		iftype = NL80211_IFTYPE_AP;
	else if (tb[IFACE_IFTYPE_STA])
		iftype = NL80211_IFTYPE_STATION;
	else if (tb[IFACE_IFTYPE_MON])
		iftype = NL80211_IFTYPE_MONITOR;
	else if (add)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (add)
		ret = nl80211_iface_add(phy, ifname, iftype);
	else
		ret = nl80211_iface_del(ifname);

	if (add && !ret)
		iface_up(ifname);

	return UBUS_STATUS_OK;
}

enum {
	SCAN_DUMP,
	SCAN_IFNAME,
	__SCAN_MAX,
};

static const struct blobmsg_policy scan_policy[__SCAN_MAX] = {
	[SCAN_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[SCAN_DUMP] = { .name = "dump", .type = BLOBMSG_TYPE_BOOL },
};

static int scan_cb(struct ubus_context *ctx,
		   struct ubus_object *obj,
		   struct ubus_request_data *req,
		   const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__SCAN_MAX];
	struct wifi_iface *wif;
	char *ifname;
	int dump = 0;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(scan_policy, __SCAN_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[SCAN_IFNAME])
		return UBUS_STATUS_INVALID_ARGUMENT;
	ifname = blobmsg_get_string(tb[SCAN_IFNAME]);
	wif = find_wif(ifname);
	if (!wif)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[SCAN_DUMP])
		dump = blobmsg_get_bool(tb[SCAN_DUMP]);
	if (dump) {
		blob_buf_init(&b, 0);
		if (wif->scan_result)
			blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, wif->ifname, blobmsg_data(wif->scan_result), blobmsg_data_len(wif->scan_result));
		ubus_send_reply(ctx, req, b.head);
	} else if (!wif_busy(ctx, req, wif))
		nl80211_trigger_scan(wif);

	return UBUS_STATUS_OK;
}

enum {
	CAC_IFNAME,
	CAC_CHANNEL,
	CAC_WIDTH,
	__CAC_MAX,
};

static const struct blobmsg_policy cac_policy[__CAC_MAX] = {
	[CAC_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[CAC_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
	[CAC_WIDTH] = { .name = "width", .type = BLOBMSG_TYPE_INT32 },
};

static int cac_cb(struct ubus_context *ctx,
		  struct ubus_object *obj,
		  struct ubus_request_data *req,
		  const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CAC_MAX];
	struct wifi_iface *wif;
	char *ifname;
	int width = 80;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(cac_policy, __CAC_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[CAC_IFNAME] || !tb[CAC_CHANNEL])
		return UBUS_STATUS_INVALID_ARGUMENT;
	ifname = blobmsg_get_string(tb[CAC_IFNAME]);
	wif = find_wif(ifname);
	if (!wif)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[CAC_WIDTH])
		width = blobmsg_get_u32(tb[CAC_WIDTH]);
	switch (width) {
	case 20:
		width = 0;
		break;
	case 40:
		width = 1;
		break;
	case 80:
		width = 2;
		break;
	default:
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!wif_busy(ctx, req, wif))
		if (nl80211_trigger_cac(wif, blobmsg_get_u32(tb[CAC_CHANNEL]), width))
			return UBUS_STATUS_INVALID_ARGUMENT;

	return UBUS_STATUS_OK;
}

enum {
	ASSOC_IFNAME,
	__ASSOC_MAX,
};

static const struct blobmsg_policy assoc_policy[__ASSOC_MAX] = {
	[ASSOC_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

static int assoclist_cb(struct ubus_context *ctx,
			struct ubus_object *obj,
			struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__ASSOC_MAX] = { 0 };
	char *ifname = NULL;
	struct wifi_station *sta;

	if (msg)
		blobmsg_parse(assoc_policy, __ASSOC_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[ASSOC_IFNAME])
		ifname = blobmsg_get_string(tb[ASSOC_IFNAME]);

	blob_buf_init(&b, 0);
	avl_for_each_element(&sta_tree, sta, avl) {
		if (ifname && strcmp(sta->ifname, ifname))
			continue;
		blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, ether_ntoa((struct ether_addr *)sta->addr), blobmsg_data(sta->info), blobmsg_data_len(sta->info));
	}
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

enum {
	REG_COUNTRY,
	__REG_MAX,
};

static const struct blobmsg_policy reg_policy[__REG_MAX] = {
	[REG_COUNTRY] = { .name = "country", .type = BLOBMSG_TYPE_STRING },
};

static int reg_cb(struct ubus_context *ctx,
		  struct ubus_object *obj,
		  struct ubus_request_data *req,
		  const char *method, struct blob_attr *msg)
{
	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (blob_len(msg)) {
		struct blob_attr *tb[__REG_MAX];

		blobmsg_parse(reg_policy, __REG_MAX, tb, blob_data(msg), blob_len(msg));
		if (!tb[REG_COUNTRY])
			return UBUS_STATUS_INVALID_ARGUMENT;
		nl80211_reg_set(blobmsg_get_string(tb[REG_COUNTRY]));
		return UBUS_STATUS_OK;
	}

	if (nl80211_reg_get())
		return UBUS_STATUS_INVALID_ARGUMENT;

	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static const struct ubus_method wifi_methods[] = {
        UBUS_METHOD("assoclist", assoclist_cb, assoc_policy),
        UBUS_METHOD("scan", scan_cb, scan_policy),
        UBUS_METHOD("cac", cac_cb, cac_policy),
        UBUS_METHOD("reg", reg_cb, reg_policy),
        UBUS_METHOD("iface", iface_cb, iface_policy),
        UBUS_METHOD("survey", survey_cb, survey_policy),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("wifi", wifi_methods);

struct ubus_object ubus_object = {
	.name = "wifi",
	.type = &ubus_object_type,
	.methods = wifi_methods,
	.n_methods = ARRAY_SIZE(wifi_methods),
	.subscribe_cb = ubus_state_handler,
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj)
{
	struct wifi_iface *wif;
	struct wifi_station *sta;

	if (!ubus_object.has_subscribers)
		return;

	avl_for_each_element(&wif_tree, wif, avl)
		ubus_notify(&conn.ctx, &ubus_object, "wifi.enum.iface", wif->info, -1);
	avl_for_each_element(&sta_tree, sta, avl)
		ubus_notify(&conn.ctx, &ubus_object, "wifi.enum.station", sta->info, -1);
}

void ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}

void ubus_uninit(void)
{
	ubus_auto_shutdown(&conn);
}
