/** @file
    Custom data tags for data struct.

    Copyright (C) 2021 Christian Zuckschwerdt

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "data_tag.h"
#include "mongoose.h"
#include "data.h"
#include "optparse.h"
#include "fileformat.h"
#include "fatal.h"

typedef struct gpsd_client {
    struct mg_connect_opts connect_opts;
    struct mg_connection *conn;
    int prev_status;
    char address[253 + 6 + 1]; // dns max + port
    int json_mode;
    char msg[1024]; // GPSd TPV should about 600 bytes
} gpsd_client_t;

char const watch_json[] = "?WATCH={\"enable\":true,\"json\":true}\n";
char const watch_nmea[] = "?WATCH={\"enable\":true,\"nmea\":true}\n";

static void gpsd_client_line(gpsd_client_t *ctx, char *line)
{
    // JSON mode
    if (strncmp(line, "{\"class\":\"TPV\",", 15) == 0) {
        strncpy(ctx->msg, line, sizeof(ctx->msg) - 1);
    }
    // NMEA mode
    if (strncmp(line, "$GPGGA,", 7) == 0) {
        strncpy(ctx->msg, line, sizeof(ctx->msg) - 1);
    }
}

static struct mg_connection *gpsd_client_connect(gpsd_client_t *ctx, struct mg_mgr *mgr);

static void gpsd_client_event(struct mg_connection *nc, int ev, void *ev_data)
{
    // note that while shutting down the ctx is NULL
    gpsd_client_t *ctx = (gpsd_client_t *)nc->user_data;

    //if (ev != MG_EV_POLL)
    //    fprintf(stderr, "GPSd user handler got event %d\n", ev);

    switch (ev) {
    case MG_EV_CONNECT: {
        int connect_status = *(int *)ev_data;
        if (connect_status == 0) {
            // Success
            fprintf(stderr, "GPSd Connected...\n");
            if (ctx->json_mode) {
                mg_send(nc, watch_json, sizeof(watch_json));
            } else {
                mg_send(nc, watch_nmea, sizeof(watch_nmea));
            }
        }
        else {
            // Error, print only once
            if (ctx && ctx->prev_status != connect_status)
                fprintf(stderr, "GPSd connect error: %s\n", strerror(connect_status));
        }
        if (ctx)
            ctx->prev_status = connect_status;
        break;
    }
    case MG_EV_RECV: {
        // Require a newline
        struct mbuf *io = &nc->recv_mbuf;
        // note: we could scan only the last *(int *)ev_data bytes...
        char *eol = memchr(io->buf, '\n', io->len);
        if (eol) {
            size_t len = eol - io->buf + 1;
            // strip [\r]\n
            io->buf[len - 1] = '\0';
            if (len >= 2 && io->buf[len - 2] == '\r') {
                io->buf[len - 2] = '\0';
            }
            gpsd_client_line(ctx, io->buf);
            mbuf_remove(io, len); // Discard line from recv buffer
        }
        break;
    }
    case MG_EV_CLOSE:
        if (!ctx)
            break; // shutting down
        if (ctx->prev_status == 0)
            fprintf(stderr, "GPSd Connection failed...\n");
        // reconnect
        gpsd_client_connect(ctx, nc->mgr);
        break;
    }
}

static struct mg_connection *gpsd_client_connect(gpsd_client_t *ctx, struct mg_mgr *mgr)
{
    char const *error_string       = NULL;
    ctx->connect_opts.error_string = &error_string;
    ctx->conn                      = mg_connect_opt(mgr, ctx->address, gpsd_client_event, ctx->connect_opts);
    ctx->connect_opts.error_string = NULL;
    if (!ctx->conn) {
        fprintf(stderr, "GPSd connect (%s) failed%s%s\n", ctx->address,
                error_string ? ": " : "", error_string ? error_string : "");
    }
    return ctx->conn;
}

static gpsd_client_t *gpsd_client_init(char const *host, char const *port, int json_mode, struct mg_mgr *mgr)
{
    gpsd_client_t *ctx;
    ctx = calloc(1, sizeof(gpsd_client_t));
    if (!ctx) {
        WARN_CALLOC("gpsd_client_init()");
        return NULL;
    }

    // if the host is an IPv6 address it needs quoting
    if (strchr(host, ':'))
        snprintf(ctx->address, sizeof(ctx->address), "[%s]:%s", host, port);
    else
        snprintf(ctx->address, sizeof(ctx->address), "%s:%s", host, port);

    ctx->json_mode = json_mode;
    ctx->connect_opts.user_data = ctx;

    if (!gpsd_client_connect(ctx, mgr)) {
        exit(1);
    }

    return ctx;
}

static void gpsd_client_free(gpsd_client_t *ctx)
{
    if (ctx && ctx->conn) {
        ctx->conn->user_data = NULL;
        ctx->conn->flags |= MG_F_CLOSE_IMMEDIATELY;
    }
    free(ctx);
}

data_tag_t *data_tag_create(char *param, struct mg_mgr *mgr)
{
    data_tag_t *tag;
    tag = calloc(1, sizeof(data_tag_t));
    if (!tag) {
        WARN_CALLOC("data_tag_create()");
        return NULL;
    }

    tag->val = param;
    tag->key = asepc(&tag->val, '=');
    if (!tag->val) {
        tag->val = tag->key;
        tag->key = NULL;
    }

    if (strncmp(tag->val, "gpsd", 4) == 0) {
        if (!tag->key)
            tag->key = "gps";

        param      = arg_param(tag->val); // strip scheme
        char *host = "localhost";
        char *port = "2947";
        char *opts = hostport_param(param, &host, &port);

        int json_mode = 1; // default to JSON
        // parse format options
        char *key, *val;
        while (getkwargs(&opts, &key, &val)) {
            key = remove_ws(key);
            val = trim_ws(val);
            if (!key || !*key)
                continue;
            else if (!strcasecmp(key, "nmea"))
                json_mode = 0;
            else {
                fprintf(stderr, "Invalid key \"%s\" option.\n", key);
                exit(1);
            }
        }

        fprintf(stderr, "Getting GPSd data (%s) from %s port %s\n", json_mode ? "JSON" : "NMEA", host, port);

        tag->gpsd_client = gpsd_client_init(host, port, json_mode, mgr);
    }
    else {
        if (!tag->key)
            tag->key = "tag";
        tag->prepend = 1; // always prepend simple tags
    }

    return tag; // NOTE: returns NULL on alloc failure.
}

void data_tag_free(data_tag_t *tag)
{
    gpsd_client_free(tag->gpsd_client);

    free(tag);
}

data_t *data_tag_apply(data_tag_t *tag, data_t *data, char const *filename)
{
    char const *val = tag->val;
    if (tag->gpsd_client) {
        // TODO: if tag->includes then filter keys, else
        val = tag->gpsd_client->msg;
    }
    else if (filename && !strcmp("PATH", tag->val)) {
        val = filename;
    }
    else if (filename && !strcmp("FILE", tag->val)) {
        val = file_basename(filename);
    }
    data = data_prepend(data,
            tag->key, "", DATA_STRING, val,
            NULL);

    return data;
}
