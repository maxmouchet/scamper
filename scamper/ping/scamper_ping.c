/*
 * scamper_ping.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping.c,v 1.25 2011/09/16 03:15:44 mjl Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
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
  "$Id: scamper_ping.c,v 1.25 2011/09/16 03:15:44 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_ping.h"

#include "utils.h"

int scamper_ping_stats(const scamper_ping_t *ping,
		       uint32_t *nreplies, uint32_t *ndups, uint16_t *nloss,
		       struct timeval *min_rtt, struct timeval *max_rtt,
		       struct timeval *avg_rtt, struct timeval *stddev_rtt)
{
  struct timeval min_rtt_, max_rtt_, avg_rtt_, stddev_rtt_;
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t us;
  uint32_t nreplies_ = 0;
  uint32_t ndups_ = 0;
  uint16_t nloss_ = 0;
  double d, sum = 0, diff = 0, rtt;
  int first = 1;
  uint32_t n;

  memset(&min_rtt_, 0, sizeof(min_rtt_));
  memset(&max_rtt_, 0, sizeof(max_rtt_));
  memset(&avg_rtt_, 0, sizeof(avg_rtt_));
  memset(&stddev_rtt_, 0, sizeof(stddev_rtt_));

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL)
	{
	  nloss_++;
	  continue;
	}

      nreplies_++;
      for(;;)
	{
	  if(first == 0)
	    {
	      if(timeval_cmp(&reply->rtt, &min_rtt_) < 0)
		memcpy(&min_rtt_, &reply->rtt, sizeof(min_rtt_));
	      if(timeval_cmp(&reply->rtt, &max_rtt_) > 0)
		memcpy(&max_rtt_, &reply->rtt, sizeof(max_rtt_));
	    }
	  else
	    {
	      memcpy(&min_rtt_, &reply->rtt, sizeof(min_rtt_));
	      memcpy(&max_rtt_, &reply->rtt, sizeof(max_rtt_));
	      first = 0;
	    }

	  sum += ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);

	  if(reply->next != NULL)
	    {
	      reply = reply->next;
	      ndups_++;
	    }
	  else break;
	}
    }

  n = nreplies_ + ndups_;

  if(n > 0)
    {
      /* compute the average */
      us = (sum / n);
      avg_rtt_.tv_sec  = us / 1000000;
      avg_rtt_.tv_usec = us % 1000000;

      /* compute the standard deviation */
      d = (sum / n);
      sum = 0;
      for(i=0; i<ping->ping_sent; i++)
	{
	  for(reply=ping->ping_replies[i]; reply != NULL; reply = reply->next)
	    {
	      rtt = ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);
	      diff = rtt - d;
	      sum += (diff * diff);
	    }
	}

      us = sqrt(sum/n);
      stddev_rtt_.tv_sec  = us / 1000000;
      stddev_rtt_.tv_usec = us % 1000000;
    }

  if(min_rtt != NULL) memcpy(min_rtt, &min_rtt_, sizeof(min_rtt_));
  if(max_rtt != NULL) memcpy(max_rtt, &max_rtt_, sizeof(max_rtt_));
  if(avg_rtt != NULL) memcpy(avg_rtt, &avg_rtt_, sizeof(avg_rtt_));
  if(stddev_rtt != NULL) memcpy(stddev_rtt, &stddev_rtt_, sizeof(stddev_rtt_));
  if(ndups != NULL) *ndups = ndups_;
  if(nreplies != NULL) *nreplies = nreplies_;
  if(nloss != NULL) *nloss = nloss_;

  return 0;
}

int scamper_ping_setdata(scamper_ping_t *ping, uint8_t *bytes, uint16_t len)
{
  uint8_t *dup;

  /* make a duplicate of the pattern bytes before freeing the old pattern */
  if(bytes != NULL && len > 0)
    {
      if((dup = memdup(bytes, len)) == NULL)
	{
	  return -1;
	}
    }
  else
    {
      dup = NULL;
      len = 0;
    }

  /* clear out anything there */
  if(ping->probe_data != NULL)
    {
      free(ping->probe_data);
    }

  /* copy in the new pattern */
  ping->probe_data    = dup;
  ping->probe_datalen = len;

  return 0;
}

scamper_addr_t *scamper_ping_addr(const void *va)
{
  return ((const scamper_ping_t *)va)->dst;
}

void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->ipc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc)
{
  scamper_ping_v4ts_t *ts = NULL;

  if(ipc == 0)
    goto err;

  if((ts = malloc_zero(sizeof(scamper_ping_reply_v4ts_t))) == NULL)
    goto err;
  ts->ipc = ipc;

  if((ts->ips = malloc_zero(sizeof(scamper_addr_t *) * ipc)) == NULL)
    goto err;

  return ts;

 err:
  scamper_ping_v4ts_free(ts);
  return NULL;
}

scamper_ping_t *scamper_ping_alloc()
{
  return (scamper_ping_t *)malloc_zero(sizeof(scamper_ping_t));
}

void scamper_ping_free(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply, *reply_next;
  uint16_t i;

  if(ping == NULL) return;

  if(ping->ping_replies != NULL)
    {
      for(i=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      reply_next = reply->next;
	      scamper_ping_reply_free(reply);
	      reply = reply_next;
	    }
	}
      free(ping->ping_replies);
    }

  if(ping->dst != NULL) scamper_addr_free(ping->dst);
  if(ping->src != NULL) scamper_addr_free(ping->src);

  if(ping->cycle != NULL) scamper_cycle_free(ping->cycle);
  if(ping->list != NULL) scamper_list_free(ping->list);

  if(ping->probe_tsps != NULL) scamper_ping_v4ts_free(ping->probe_tsps);

  free(ping);
  return;
}

uint32_t scamper_ping_reply_count(const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  uint16_t i;
  uint32_t count;

  for(i=0, count=0; i<ping->ping_sent; i++)
    {
      reply = ping->ping_replies[i];

      while(reply != NULL)
	{
	  count++;
	  reply = reply->next;
	}
    }

  return count;
}

int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply)
{
  scamper_ping_reply_t *replies;

  if(p == NULL || reply == NULL || reply->probe_id >= p->ping_sent)
    {
      return -1;
    }

  if((replies = p->ping_replies[reply->probe_id]) == NULL)
    {
      p->ping_replies[reply->probe_id] = reply;
    }
  else
    {
      while(replies->next != NULL)
	{
	  replies = replies->next;
	}

      replies->next = reply;
    }

  return 0;
}

int scamper_ping_replies_alloc(scamper_ping_t *ping, int count)
{
  size_t size;

  size = sizeof(scamper_ping_reply_t *) * count;
  if((ping->ping_replies = (scamper_ping_reply_t **)malloc_zero(size)) != NULL)
    {
      return 0;
    }

  return -1;
}

void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->tss != NULL)
    free(ts->tss);

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->tsc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip)
{
  scamper_ping_reply_v4ts_t *ts = NULL;

  if(tsc == 0)
    goto err;

  if((ts = malloc_zero(sizeof(scamper_ping_reply_v4ts_t))) == NULL)
    goto err;
  ts->tsc = tsc;

  if((ts->tss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
    goto err;

  if(ip != 0 && (ts->ips = malloc_zero(sizeof(scamper_addr_t *)*tsc)) == NULL)
    goto err;

  return ts;

 err:
  scamper_ping_reply_v4ts_free(ts);
  return NULL;
}

void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr)
{
  uint8_t i;

  if(rr == NULL)
    return;

  if(rr->rr != NULL)
    {
      for(i=0; i<rr->rrc; i++)
	if(rr->rr[i] != NULL)
	  scamper_addr_free(rr->rr[i]);
      free(rr->rr);
    }

  free(rr);
  return;
}

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t rrc)
{
  scamper_ping_reply_v4rr_t *rr = NULL;

  if(rrc == 0)
    goto err;

  if((rr = malloc_zero(sizeof(scamper_ping_reply_v4rr_t))) == NULL)
    goto err;
  rr->rrc = rrc;

  if((rr->rr = malloc_zero(sizeof(scamper_addr_t *) * rrc)) == NULL)
    goto err;

  return rr;

 err:
  scamper_ping_reply_v4rr_free(rr);
  return NULL;
}

scamper_ping_reply_t *scamper_ping_reply_alloc(void)
{
  return (scamper_ping_reply_t *)malloc_zero(sizeof(scamper_ping_reply_t));
}

void scamper_ping_reply_free(scamper_ping_reply_t *reply)
{
  if(reply == NULL) return;

  if(reply->addr != NULL)
    scamper_addr_free(reply->addr);

  if(reply->v4rr != NULL)
    scamper_ping_reply_v4rr_free(reply->v4rr);

  if(reply->v4ts != NULL)
    scamper_ping_reply_v4ts_free(reply->v4ts);

  free(reply);
  return;
}
