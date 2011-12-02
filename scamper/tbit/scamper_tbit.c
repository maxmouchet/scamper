/*
 * scamper_tbit.c
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 The University of Waikato
 * Authors: Ben Stasiewicz, Matthew Luckie
 *
 * $Id: scamper_tbit.c,v 1.12 2011/11/17 21:14:58 mjl Exp $
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the replye that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tbit.c,v 1.12 2011/11/17 21:14:58 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tbit.h"
#include "utils.h"

char *scamper_tbit_type2str(const scamper_tbit_t *tbit, char *buf, size_t len)
{
  static char *t[] = {
    NULL,
    "pmtud",
    "ecn",
    "null",
    "sack-rcvr",
  };

  if(tbit->type > sizeof(t) / sizeof(char *) || t[tbit->type] == NULL)
    {
      snprintf(buf, len, "%d", tbit->type);
      return buf;
    }

  return t[tbit->type];
}

char *scamper_tbit_res2str(const scamper_tbit_t *tbit, char *buf, size_t len)
{
  static char *t[] = {
    "none",                /* 0 */
    "tcp-noconn",
    "tcp-rst",
    "tcp-error",
    "sys-error",
    "aborted",
    "tcp-noconn-rst",
    "halted",
    "tcp-badopt",
    "tcp-fin",
    NULL,                  /* 10 */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "pmtud-noack",         /* 20 */
    "pmtud-nodata",
    "pmtud-toosmall",
    "pmtud-nodf",
    "pmtud-fail",
    "pmtud-success",
    "pmtud-cleardf",
    NULL,
    NULL,
    NULL,
    "ecn-success",         /* 30 */
    "ecn-incapable",
    "ecn-badsynack",
    "ecn-noece",
    "ecn-noack",
    "ecn-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    "null-success",        /* 40 */
    "null-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "sack-incapable",      /* 50 */
    "sack-rcvr-success",
    "sack-rcvr-shifted",
    "sack-rcvr-timeout",
    "sack-rcvr-nosack",
  };

  if(tbit->result > sizeof(t) / sizeof(char *) || t[tbit->result] == NULL)
    {
      snprintf(buf, len, "%d", tbit->result);
      return buf;
    }

  return t[tbit->result];
}

scamper_tbit_pkt_t *scamper_tbit_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv)
{
  scamper_tbit_pkt_t *pkt;

  if((pkt = malloc_zero(sizeof(scamper_tbit_pkt_t))) == NULL)
    goto err;

  pkt->dir = dir;
  if(len != 0 && data != NULL)
    {
      if((pkt->data = memdup(data, len)) == NULL)
	goto err;
      pkt->len = len;
    }
  if(tv != NULL) timeval_cpy(&pkt->tv, tv);
  return pkt;

 err:
  free(pkt);
  return NULL;
}

void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt)
{
  if(pkt == NULL)
    return;
  if(pkt->data != NULL) free(pkt->data);
  free(pkt);
  return;
}

int scamper_tbit_pkts_alloc(scamper_tbit_t *tbit, uint32_t count)
{
  size_t size = count * sizeof(scamper_tbit_pkt_t *);
  if((tbit->pkts = (scamper_tbit_pkt_t **)malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_tbit_record_pkt(scamper_tbit_t *tbit, scamper_tbit_pkt_t *pkt)
{
  size_t len = (tbit->pktc + 1) * sizeof(scamper_tbit_pkt_t *);

  /* Add a new element to the pkts array */
  if(realloc_wrap((void**)&tbit->pkts, len) != 0)
    return -1;

  tbit->pkts[tbit->pktc++] = pkt;
  return 0;
}

scamper_tbit_app_http_t *scamper_tbit_app_http_alloc(char *host, char *file)
{
  scamper_tbit_app_http_t *http;

  if((http = malloc_zero(sizeof(scamper_tbit_app_http_t))) == NULL ||
     (host != NULL && (http->host = strdup(host)) == NULL) ||
     (file != NULL && (http->file = strdup(file)) == NULL))
    {
      if(http == NULL) return NULL;
      if(http->host != NULL) free(http->host);
      if(http->file != NULL) free(http->file);
      return NULL;
    }

  return http;
}

void scamper_tbit_app_http_free(scamper_tbit_app_http_t *http)
{
  if(http == NULL)
    return;
  if(http->host != NULL) free(http->host);
  if(http->file != NULL) free(http->file);
  free(http);
  return;
}

scamper_tbit_pmtud_t *scamper_tbit_pmtud_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_pmtud_t));
}

void scamper_tbit_pmtud_free(scamper_tbit_pmtud_t *pmtud)
{
  if(pmtud == NULL)
    return;
  if(pmtud->ptbsrc != NULL)
    scamper_addr_free(pmtud->ptbsrc);
  free(pmtud);
  return;
}

scamper_tbit_null_t *scamper_tbit_null_alloc(void)
{
  return malloc_zero(sizeof(scamper_tbit_null_t));
}

void scamper_tbit_null_free(scamper_tbit_null_t *null)
{
  if(null == NULL)
    return;
  free(null);
  return;
}

/* Free the tbit object. */
void scamper_tbit_free(scamper_tbit_t *tbit)
{
  uint32_t i;

  if(tbit == NULL)
    return;

  if(tbit->src != NULL)   scamper_addr_free(tbit->src);
  if(tbit->dst != NULL)   scamper_addr_free(tbit->dst);
  if(tbit->list != NULL)  scamper_list_free(tbit->list);
  if(tbit->cycle != NULL) scamper_cycle_free(tbit->cycle);

  /* Free the recorded packets */
  if(tbit->pkts != NULL)
    {
      for(i=0; i<tbit->pktc; i++)
	scamper_tbit_pkt_free(tbit->pkts[i]);
      free(tbit->pkts);
    }

  /* Free protocol specific data */
  if(tbit->app_data != NULL)
    {
      if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
	scamper_tbit_app_http_free(tbit->app_data);
    }

  /* Free test-specific data */
  if(tbit->data != NULL)
    {
      if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
	scamper_tbit_pmtud_free(tbit->data);
      else if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
	scamper_tbit_null_free(tbit->data);
    }

  free(tbit);
  return;
}

scamper_tbit_t *scamper_tbit_alloc(void)
{
  return (scamper_tbit_t *)malloc_zero(sizeof(scamper_tbit_t));
}
