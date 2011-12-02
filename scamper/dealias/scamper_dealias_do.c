/*
 * scamper_do_dealias.c
 *
 * $Id: scamper_dealias_do.c,v 1.100 2011/10/25 01:41:33 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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
  "$Id: scamper_dealias_do.c,v 1.100 2011/10/25 01:41:33 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper_dealias_do.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_task_funcs_t funcs;

/* the default source port to use when tracerouting */
static uint16_t             default_sport;

/* packet buffer for generating the payload of each packet */
static uint8_t             *pktbuf     = NULL;
static size_t               pktbuf_len = 0;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define DEALIAS_OPT_DPORT        1
#define DEALIAS_OPT_FUDGE        2
#define DEALIAS_OPT_METHOD       3
#define DEALIAS_OPT_REPLYC       4
#define DEALIAS_OPT_OPTION       5
#define DEALIAS_OPT_PROBEDEF     6
#define DEALIAS_OPT_ATTEMPTS     7
#define DEALIAS_OPT_WAIT_ROUND   8
#define DEALIAS_OPT_SPORT        9
#define DEALIAS_OPT_TTL          10
#define DEALIAS_OPT_USERID       11
#define DEALIAS_OPT_WAIT_TIMEOUT 12
#define DEALIAS_OPT_WAIT_PROBE   13
#define DEALIAS_OPT_EXCLUDE      14

static const scamper_option_in_t opts[] = {
  {'d', NULL, DEALIAS_OPT_DPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, DEALIAS_OPT_FUDGE,        SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, DEALIAS_OPT_METHOD,       SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, DEALIAS_OPT_REPLYC,       SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, DEALIAS_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, DEALIAS_OPT_PROBEDEF,     SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, DEALIAS_OPT_ATTEMPTS,     SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, DEALIAS_OPT_WAIT_ROUND,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, DEALIAS_OPT_SPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_OPT_TTL,          SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, DEALIAS_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, DEALIAS_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, DEALIAS_OPT_WAIT_PROBE,   SCAMPER_OPTION_TYPE_NUM},
  {'x', NULL, DEALIAS_OPT_EXCLUDE,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

#define DEALIAS_PROBEDEF_OPT_CSUM  1
#define DEALIAS_PROBEDEF_OPT_DPORT 2
#define DEALIAS_PROBEDEF_OPT_IP    3
#define DEALIAS_PROBEDEF_OPT_PROTO 4
#define DEALIAS_PROBEDEF_OPT_SPORT 5
#define DEALIAS_PROBEDEF_OPT_TTL   6

static const scamper_option_in_t probedef_opts[] = {
  {'c', NULL, DEALIAS_PROBEDEF_OPT_CSUM,  SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, DEALIAS_PROBEDEF_OPT_DPORT, SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, DEALIAS_PROBEDEF_OPT_IP,    SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, DEALIAS_PROBEDEF_OPT_PROTO, SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, DEALIAS_PROBEDEF_OPT_SPORT, SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_PROBEDEF_OPT_TTL,   SCAMPER_OPTION_TYPE_NUM},
};
static const int probedef_opts_cnt = SCAMPER_OPTION_COUNT(probedef_opts);

const char *scamper_do_dealias_usage(void)
{
  return
    "dealias [-d dport] [-f fudge] [-m method] [-o replyc] [-O option]\n"
    "        [-p '[-c sum] [-d dp] [-i ip] [-P meth] [-s sp] [-t ttl]']\n"
    "        [-q attempts] [-r wait-round] [-s sport] [-t ttl]\n"
    "        [-U userid] [-w wait-timeout] [-W wait-probe] [-x exclude]\n";
}

typedef struct dealias_probe
{
  scamper_dealias_probe_t     *probe;
  struct dealias_probe        *next;
  uint16_t                     icmpseq;
} dealias_probe_t;

typedef struct dealias_prefixscan
{
  scamper_dealias_probedef_t  *probedefs;
  int                          probedefc;
  scamper_addr_t             **aaliases;
  int                          aaliasc;
  int                          attempt; 
  int                          seq;
  int                          round0;
  int                          round;
  int                          replyc;
} dealias_prefixscan_t;

typedef struct dealias_radargun
{
  uint32_t                    *order; /* probedef order */
  uint32_t                     i;     /* index into order */
} dealias_radargun_t;

typedef struct dealias_bump
{
  uint8_t                      step;
  uint8_t                      attempt;
  uint16_t                     bump;
} dealias_bump_t;

typedef struct dealias_options
{
  char                        *addr;
  uint8_t                      attempts;
  uint8_t                      replyc;
  uint8_t                      wait_timeout;
  uint16_t                     wait_probe;
  uint32_t                     wait_round;
  uint16_t                     sport;
  uint16_t                     dport;
  uint8_t                      ttl;
  uint16_t                     fudge;
  char                       **probedefs;
  uint32_t                     probedefc;
  char                       **xs;
  int                          xc;
  int                          nobs;
  int                          shuffle;
  int                          inseq;
} dealias_options_t;

typedef struct dealias_state
{
  uint8_t                      mode;
  uint8_t                      id;
  scamper_dealias_probedef_t  *probedefs;
  uint32_t                     probedefc;
  uint32_t                    *tcp_seqs;
  uint32_t                    *tcp_acks;
  uint32_t                     probe;
  uint32_t                     round;
  struct timeval               last_tx;
  struct timeval               next_tx;
  struct timeval               next_round;
  dealias_probe_t             *probes[256];
  void                        *methodstate;
} dealias_state_t;

static scamper_dealias_t *dealias_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static dealias_state_t *dealias_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void dealias_queue(scamper_task_t *task)
{
  dealias_state_t *state = dealias_getstate(task);
  struct timeval   tv;

  if(scamper_task_queue_isdone(task))
    return;

  gettimeofday_wrap(&tv);

  if(timeval_cmp(&state->next_tx, &tv) <= 0)
    {
      scamper_task_queue_probe(task);
      return;
    }

  scamper_task_queue_wait_tv(task, &state->next_tx);
  return;
}

static void dealias_handleerror(scamper_task_t *task, int error)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void dealias_result(scamper_task_t *task, uint8_t result)
{
  scamper_dealias_t *dealias = dealias_getdata(task);

  if(result == SCAMPER_DEALIAS_RESULT_NONE)
    scamper_debug(__func__, "none");
  else if(result == SCAMPER_DEALIAS_RESULT_ALIASES)
    scamper_debug(__func__, "aliases");
  else if(result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
    scamper_debug(__func__, "not aliases");
  else if(result == SCAMPER_DEALIAS_RESULT_HALTED)
    scamper_debug(__func__, "halted");
  else
    scamper_debug(__func__, "%d", result);

  dealias->result = result;
  scamper_task_queue_done(task, 0);
  return;
}

static int dealias_prefixscan_aalias_cmp(const void *va, const void *vb)
{
  const scamper_addr_t *a = *((const scamper_addr_t **)va);
  const scamper_addr_t *b = *((const scamper_addr_t **)vb);
  return scamper_addr_cmp(a, b);
}

static void dealias_prefixscan_array_free(scamper_addr_t **addrs, int addrc)
{
  int i;

  if(addrs == NULL)
    return;

  for(i=0; i<addrc; i++)
    if(addrs[i] != NULL)
      scamper_addr_free(addrs[i]);

  free(addrs);
  return;
}

static int dealias_prefixscan_array_add(scamper_dealias_t *dealias,
					scamper_addr_t ***out, int *outc,
					struct in_addr *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = *out;
  scamper_addr_t *sa;

  /* convert the in_addr into something that scamper deals with */
  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, addr);
  if(sa == NULL)
    {
      printerror(errno, strerror, __func__, "could not get addr");
      return -1;
    }

  /*
   * don't consider this address if it is the same as the address
   * we are trying to find an alias for, or it is in the exclude list.
   */
  if(scamper_addr_cmp(prefixscan->a, sa) == 0 ||
     scamper_dealias_prefixscan_xs_in(dealias, sa) != 0)
    {
      scamper_addr_free(sa);
      return 0;
    }

  /* add the scamper address to the array */
  if(array_insert((void ***)&array, outc, sa, NULL) != 0)
    {
      printerror(errno, strerror, __func__, "could not add addr");
      scamper_addr_free(sa);
      return -1;
    }

  *out = array;
  return 0;
}

/*
 * dealias_prefixscan_array:
 *
 * figure out what the next address to scan will be, based on what the
 * previously probed address was.  below are examples of the order in which
 * addresses should be probed given a starting address.  addresses in
 * prefixes less than /30 could be probed in random order.
 *
 * 00100111 39        00100010 34        00101001 41       00100000 32
 * 00100110 38 /31    00100001 33        00101010 42       00100001 33 /31
 * 00100101 37        00100000 32        00101000 40       00100010 34
 * 00100100 36 /30    00100011 35 /30    00101011 43 /30   00100011 35 /30
 * 00100011 35        00100100 36        00101100 44
 * 00100010 34        00100101 37        00101101 45
 * 00100001 33        00100110 38        00101110 46
 * 00100000 32 /29    00100111 39 /29    00101111 47 /29
 * 00101000 40        00101000 40        00100000 32
 * 00101001 41        00101001 41        00100001 33
 * 00101010 42        00101010 42
 * 00101011 43
 * 00101100 44
 * 00101101 45
 * 00101110 46
 * 00101111 47 /28
 *
 */
static int dealias_prefixscan_array(scamper_dealias_t *dealias,
				    scamper_addr_t ***out, int *outc)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = NULL;
  uint32_t hostid, netid, mask;
  uint32_t slash30[4][3] = {{1, 2, 3}, {2, 0, 3}, {1, 0, 3}, {2, 1, 0}};
  uint32_t cnt[] = {4, 8, 16, 32, 64, 128};
  uint32_t bit;
  struct in_addr a;
  int pre, i;

  memcpy(&a, prefixscan->b->addr, sizeof(a));
  *outc = 0;

  /* if we've been instructed only to try /31 pair */
  if(prefixscan->prefix == 31)
    {
      netid  = ntohl(a.s_addr) & ~0x1;
      hostid = ntohl(a.s_addr) &  0x1;

      if(hostid == 1)
	a.s_addr = htonl(netid | 0);
      else
	a.s_addr = htonl(netid | 1);

      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;

      *out = array;
      return 0;
    }

  /* when probing a /30 the first three probes have a particular order */
  mask   = 0x3;
  netid  = ntohl(a.s_addr) & ~mask;
  hostid = ntohl(a.s_addr) &  mask;
  for(i=0; i<3; i++)
    {
      a.s_addr = htonl(netid | slash30[hostid][i]);
      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;
    }

  for(pre = 29; pre >= prefixscan->prefix; pre--)
    {
      bit   = (0x1 << (31-pre));
      mask |= bit;

      memcpy(&a, prefixscan->b->addr, sizeof(a));
      netid = ntohl(a.s_addr) & ~mask;

      if((ntohl(a.s_addr) & bit) != 0)
	bit = 0;

      for(hostid=0; hostid<cnt[29-pre]; hostid++)
	{
	  a.s_addr = htonl(netid | bit | hostid);
	  if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	    goto err;
	}
    }

  *out = array;
  return 0;

 err:
  dealias_prefixscan_array_free(array, *outc);
  return -1;
}

static scamper_dealias_probe_t *
dealias_probe_udp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  for(dp = state->probes[ir->ir_inner_ip_id & 0xff]; dp != NULL; dp = dp->next)
    {
      def = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def) == 0 ||
	 def->un.udp.sport != ir->ir_inner_udp_sport ||
	 scamper_addr_cmp(def->dst, &addr) != 0)
	{
	  continue;
	}

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	{
	  if(def->un.udp.dport == ir->ir_inner_udp_dport)
	    return dp->probe;
	}
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	{
	  if(def->un.udp.dport + dp->probe->seq == ir->ir_inner_udp_dport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  for(dp = state->probes[ir->ir_inner_ip_id & 0xff]; dp != NULL; dp = dp->next)
    {
      def = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != ir->ir_inner_tcp_dport ||
	 scamper_addr_cmp(def->dst, &addr) != 0)
	{
	  continue;
	}

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == ir->ir_inner_tcp_sport)
	    return dp->probe;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  if(def->un.tcp.sport + dp->probe->seq == ir->ir_inner_tcp_sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_icmp_find(dealias_state_t *state, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  scamper_addr_t addr;

  if(scamper_icmp_resp_inner_dst(ir, &addr) != 0)
    return NULL;

  for(dp = state->probes[ir->ir_inner_ip_id & 0xff]; dp != NULL; dp = dp->next)
    {
      /*
       * check that the icmp probe matches what we would have sent.
       * don't check the checksum as it can be modified.
       */
      def = dp->probe->probedef;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def) &&
	 def->un.icmp.type == ir->ir_inner_icmp_type &&
	 def->un.icmp.code == ir->ir_inner_icmp_code &&
	 def->un.icmp.id   == ir->ir_inner_icmp_id   &&
	 dp->icmpseq       == ir->ir_inner_icmp_seq  &&
	 scamper_addr_cmp(def->dst, &addr) == 0)
	{
	  return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_echoreq_find(scamper_dealias_t *dealias, scamper_icmp_resp_t *ir)
{
  scamper_dealias_probedef_t *probedef;
  scamper_dealias_probe_t *probe;
  scamper_addr_t addr;
  uint32_t p, i;

  if(ir->ir_icmp_seq >= dealias->probec)
    return NULL;

  p = dealias->probec / 65536;

  if((dealias->probec % 65536) > ir->ir_icmp_seq)
    i = (p * 65536) + ir->ir_icmp_seq;
  else
    i = ((p-1) * 65536) + ir->ir_icmp_seq;

  if(scamper_icmp_resp_src(ir, &addr) != 0)
    return NULL;

  for(;;)
    {
      probe    = dealias->probes[i];
      probedef = probe->probedef;

      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(probedef) &&
	 probedef->un.icmp.type == ICMP_ECHO &&
	 probedef->un.icmp.code == 0 &&
	 probedef->un.icmp.id   == ir->ir_icmp_id &&
	 scamper_addr_cmp(&addr, probedef->dst) == 0)
	{
	  return probe;
	}

      if(i >= 65536)
	i -= 65536;
      else
	break;
    }

  return NULL;
}

static void dealias_mercator_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply)
{
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->probedef->dst, reply->src) != 0)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
    }
  else
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }
  return;
}

static void dealias_mercator_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  scamper_dealias_mercator_t *mercator = dealias->data;

  if(dealias->probec < mercator->attempts)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static int dealias_ally_allzero(scamper_dealias_t *dealias,
				scamper_dealias_ally_t *ally)
{
  uint32_t i;
  uint16_t j;

  for(i=0; i<dealias->probec; i++)
    {
      assert(dealias->probes[i] != NULL);
      for(j=0; j<dealias->probes[i]->replyc; j++)
	{
	  assert(dealias->probes[i]->replies[j] != NULL);
	  if(dealias->probes[i]->replies[j]->ipid != 0)
	    return 0;
	}
    }

  return 1;
}

static void dealias_ally_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  scamper_dealias_ally_t  *ally    = dealias->data;
  scamper_dealias_probe_t *probes[5];
  uint32_t k;
  int rc, probec = 0, useful = 0;

  if(probe->replyc != 1)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* check to see if the response could be useful for alias resolution */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply))
    useful = 1;
  else if(SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply) &&
	  probe->probedef->ttl != 255)
    useful = 1;

  if(useful == 0)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* can't make any decision unless at least two probes have been sent */
  if(dealias->probec < 2)
    return;

  /*
   * try and make a decision about whether or not probing should continue
   * based on the responses we have (even if not all probes have been sent)
   * note that we check the responses of up to 5 adjacent probes, rather
   * than the entire complement.
   */
  k = (probe->seq * 2) + probe->probedef->id;

  if(k >= 2)
    {
      if(dealias->probes[k-2]->replyc == 1)
	probes[probec++] = dealias->probes[k-2];

      if(dealias->probes[k-1]->replyc == 1)
	probes[probec++] = dealias->probes[k-1];
      else
	probec = 0;
    }
  else if(k >= 1)
    {
      if(dealias->probes[k-1]->replyc == 1)
	probes[probec++] = dealias->probes[k-1];
    }
  probes[probec++] = probe;
  if(k+2 < dealias->probec)
    {
      if(dealias->probes[k+1]->replyc == 1)
	probes[probec++] = dealias->probes[k+1];
      if(dealias->probes[k+2]->replyc == 1)
	probes[probec++] = dealias->probes[k+2];
    }
  else if(k+1 < dealias->probec)
    {
      if(dealias->probes[k+1]->replyc == 1)
	probes[probec++] = dealias->probes[k+1];
    }

  /* not enough adjacent responses to make a classification */
  if(probec < 2)
    return;

  if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias) == 0)
    rc = scamper_dealias_ipid_inseq(probes, probec, ally->fudge);
  else
    rc = scamper_dealias_ipid_inseqbs(probes, probec, ally->fudge);

  /* check if the replies are in sequence */
  if(rc == 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);

  return;
}

static void dealias_ally_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t      *dealias = dealias_getdata(task);
  scamper_dealias_ally_t *ally    = dealias->data;
  uint32_t k;
  int rc;

  /* do a final classification */
  if(dealias->probec == ally->attempts)
    {
      for(k=0; k<dealias->probec; k++)
	if(dealias->probes[k]->replyc != 1)
	  break;

      if(k != dealias->probec)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
	  return;
	}

      if(SCAMPER_DEALIAS_ALLY_IS_NOBS(dealias) == 0)
	rc = scamper_dealias_ally_inseq(dealias, ally->fudge);
      else
	rc = scamper_dealias_ally_inseqbs(dealias, ally->fudge);

      /* check if the replies are in sequence */
      if(rc == 1)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      else if(dealias_ally_allzero(dealias, ally) != 0)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      else
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
    }

  return;
}

static void dealias_radargun_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  dealias_state_t            *state    = dealias_getstate(task);
  scamper_dealias_radargun_t *radargun = dealias->data;

  /* check to see if we are now finished */
  if(state->round != radargun->attempts)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static int dealias_prefixscan_next(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def = &pfstate->probedefs[state->probedefc-1];
  uint32_t *defids = NULL, p;

  /*
   * if the address we'd otherwise probe has been observed as an alias of
   * prefixscan->a, then we don't need to bother probing it.
   */
  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc, def->dst,
		dealias_prefixscan_aalias_cmp) != NULL)
    {
      prefixscan->ab = scamper_addr_use(def->dst);
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      return 0;
    }

  /* remember the probedef used with each probe */
  if((defids = malloc(sizeof(uint32_t) * dealias->probec)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc defids");
      goto err;
    }
  for(p=0; p<dealias->probec; p++)
    defids[p] = dealias->probes[p]->probedef->id;

  /* add the probedef */
  if(scamper_dealias_prefixscan_probedef_add(dealias, def) != 0)
    {
      printerror(errno, strerror, __func__, "could not add probedef");
      goto err;
    }

  /* re-set the pointers to the probedefs */
  for(p=0; p<dealias->probec; p++)
    dealias->probes[p]->probedef = &prefixscan->probedefs[defids[p]];
  free(defids); defids = NULL;

  state->probedefs = prefixscan->probedefs;
  state->probedefc = prefixscan->probedefc;

  return 0;

 err:
  if(defids != NULL) free(defids);
  return -1;
}

static void dealias_prefixscan_handlereply(scamper_task_t *task,
					   scamper_dealias_probe_t *probe,
					   scamper_dealias_reply_t *reply)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_probe_t **probes = NULL;
  uint32_t defid;
  int p, s, seq;

  /* if the reply is not for the most recently sent probe */
  if(probe != dealias->probes[dealias->probec-1])
    return;

  /* if the reply is not the first reply for this probe */
  if(probe->replyc != 1)
    return;

  /*
   * if we are currently waiting for our turn to probe, then for now
   * ignore the late response.
   */
  if(scamper_task_queue_isprobe(task))
    return;

  /* check if we should count this reply as a valid response */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply))
    pfstate->replyc++;
  else
    return;

  /*
   * if we sent a UDP probe, and got a port unreachable message back from a
   * different interface, then we might be able to use that for alias
   * resolution.
   */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(probe->probedef) &&
     SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->probedef->dst, reply->src) != 0)
    {
      if(probe->probedef->id == 0)
	{
	  /*
	   * if the reply is for prefixscan->a, then keep a record of the
	   * address of the interface used in the response.
	   */
	  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, dealias_prefixscan_aalias_cmp) == NULL)
	    {
	      if(array_insert((void ***)&pfstate->aaliases, &pfstate->aaliasc,
			      reply->src, dealias_prefixscan_aalias_cmp) != 0)
		{
		  printerror(errno, strerror, __func__,
			     "could not add to aaliases");
		  goto err;
		}
	      scamper_addr_use(reply->src);
	    }
	}
      else
	{
	  /*
	   * if the address used to reply is probedef->a, or is one of the
	   * aliases previously observed for a, then we infer aliases.
	   */
	  if(scamper_addr_cmp(reply->src, prefixscan->a) == 0 ||
	     array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, dealias_prefixscan_aalias_cmp) != NULL)
	    {
	      prefixscan->ab = scamper_addr_use(probe->probedef->dst);
	      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	      return;
	    }
	}
    }

  /*
   * another probe received in sequence.
   * we will probably send another probe, so reset attempts
   */
  seq = ++pfstate->seq;
  pfstate->attempt = 0;

  assert(seq >= 1 && seq <= prefixscan->replyc);

  /*
   * if we don't have a reply from each IP address yet, then keep probing.
   * ideally, this could be optimised to use the previous observed IP-ID
   * for probedef zero if we have probed other probedefs in the interim and
   * have just obtained a reply.
   */
  if(seq < 2)
    {
      if(state->probe != 0)
	{
	  state->probe = 0;
	  return;
	}

      if(state->probedefc == 1)
	{
	  /* figure out what we're going to probe next */
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;
	}

      state->probe = state->probedefc-1;
      dealias_queue(task);
      return;
    }

  if((probes = malloc_zero(sizeof(scamper_dealias_probe_t *) * seq)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probes");
      goto err;
    }
  probes[seq-1] = probe;

  /* if the reply was not for the first probe, then skip over earlier probes */
  p = dealias->probec-2; defid = probes[seq-1]->probedef->id;
  while(p >= 0 && dealias->probes[p]->probedef->id == defid)
    p--;
  if(p<0)
    goto err;

  for(s=seq-1; s>0; s--)
    {
      if(probes[s]->probedef->id == 0)
	defid = state->probedefc - 1;
      else
	defid = 0;

      if(p < 0)
	goto err;

      while(p >= 0)
	{
	  assert(defid == dealias->probes[p]->probedef->id);

	  /* skip over any unresponded to probes */
	  if(dealias->probes[p]->replyc == 0)
	    {
	      p--;
	      continue;
	    }

	  /* record the probe for this defid */
	  probes[s-1] = dealias->probes[p];

	  /* skip over any probes that proceeded this one with same defid */
	  while(p >= 0 && dealias->probes[p]->probedef->id == defid)
	    p--;

	  break;
	}
    }

  /*
   * check to see if the sequence of replies indicates an alias.  free
   * the probes array before we check the result, as it is easiest here.
   */
  if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(dealias) == 0)
    p = scamper_dealias_ipid_inseq(probes, seq, prefixscan->fudge);
  else
    p = scamper_dealias_ipid_inseqbs(probes, seq, prefixscan->fudge);
  free(probes); probes = NULL;

  if(p != 0)
    {
      if(seq == prefixscan->replyc)
	{
	  p = state->probedefc-1;
	  prefixscan->ab = scamper_addr_use(prefixscan->probedefs[p].dst);
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      if(state->probe == 0)
	state->probe = state->probedefc - 1;
      else
	state->probe = 0;
	
      return;
    }

  /* if there are no other addresses to try, then finish */
  if(state->probedefc-1 == pfstate->probedefc)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(dealias_prefixscan_next(task) != 0)
    goto err;
  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
    return;

  pfstate->round   = 0;
  pfstate->attempt = 0;
  state->probe     = state->probedefc-1;

  if(dealias->probes[dealias->probec-1]->probedef->id == 0)
    pfstate->seq = 1;
  else
    pfstate->seq = 0;

  dealias_queue(task);
  return;

 err:
  if(probes != NULL) free(probes);
  dealias_handleerror(task, errno);
  return;
}

static void dealias_prefixscan_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *probe;

  prefixscan = dealias->data;
  probe = dealias->probes[dealias->probec-1];
  def = probe->probedef;

  if(pfstate->replyc == 0)
    {
      /* if we're allowed to send another attempt, then do so */
      if(pfstate->attempt < prefixscan->attempts)
	{
	  goto done;
	}

      /*
       * if the probed address is unresponsive, and it is not prefixscan->a,
       * and there are other addresses to try, then probe one now
       */
      if(def->id != 0 && state->probedefc-1 < (uint32_t)pfstate->probedefc)
	{
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;

	  pfstate->round   = 0;
	  pfstate->seq     = 0;
	  pfstate->attempt = 0;
	  state->probe     = state->probedefc-1;

	  goto done;
	}

      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* keep going! */
 done:
  if(state->probe == 0)
    state->round = pfstate->round0;
  else
    state->round = pfstate->round;

  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void dealias_bump_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  dealias_state_t         *state   = dealias_getstate(task);
  dealias_bump_t          *bs      = state->methodstate;
  scamper_dealias_bump_t  *bump    = dealias->data;
  scamper_dealias_probe_t *probes[3];
  uint32_t i, x, y;

  if(bs->step < 2)
    {
      bs->step++;
    }
  else if(bs->step == 2)
    {
      /* check if the last set of probes are in sequence */
      for(i=0; i<3; i++)
	if(dealias->probes[dealias->probec-3+i]->replyc == 1)
	  probes[i] = dealias->probes[dealias->probec-3+i];
	else
	  break;

      if(i != 3)
	goto none;

      if(scamper_dealias_ipid_inseq(probes, 3, 0) != 1)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
	  return;
	}

      if(bs->attempt > bump->attempts)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      x = probes[1]->replies[0]->ipid;
      y = probes[2]->replies[0]->ipid;
      if(x < y)
	i = y - x;
      else
	i = 0x10000 + y - x;

      if(i * 2 > 65535)
	goto none;

      bs->bump = i * 2;
      if(bs->bump == 2)
	bs->bump++;

      if(bs->bump > bump->bump_limit)
	goto none;

      bs->step++;
    }
  else if(bs->step == 3)
    {
      if(bs->bump != 0)
	{
	  bs->bump--;
	  return;
	}

      bs->attempt++;
      bs->step = 1;
    }

  if(state->probe == 1)
    state->probe = 0;
  else
    state->probe = 1;

  return;

 none:
  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
  return;
}

static void dealias_bump_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply)
{
  /* check to see if the response could be useful for alias resolution */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe,reply) == 0 || probe->replyc != 1)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  return;
}

static void do_dealias_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
  };
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias  = dealias_getdata(task);
  scamper_addr_t addr;
  uint32_t i;
  int type;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(SCAMPER_DL_IS_TCP(dl) == 0 || dl->dl_af != AF_INET)
    return;

  addr.type = SCAMPER_ADDR_TYPE_IPV4;
  addr.addr = dl->dl_ip_src;

  i = dealias->probec - 1;
  for(;;)
    {
      probe = dealias->probes[i];
      def   = probe->probedef;

      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) &&
	 def->un.tcp.dport == dl->dl_tcp_sport &&
	 scamper_addr_cmp(def->dst, &addr) == 0)
	{
	  if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	    {
	      if(def->un.tcp.sport == dl->dl_tcp_dport)
		break;
	    }
	  else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	    {
	      if(def->un.tcp.sport + probe->seq == dl->dl_tcp_dport)
		break;
	    }
	}

      if(i == 0)
	return;

      i--;
    }

  scamper_dl_rec_tcp_print(dl);

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  type = SCAMPER_ADDR_TYPE_IPV4;
  if((reply->src = scamper_addrcache_get(addrcache, type, addr.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &dl->dl_tv);
  reply->ttl       = dl->dl_ip_ttl;
  reply->ipid      = dl->dl_ip_id;
  reply->proto     = IPPROTO_TCP;
  reply->tcp_flags = dl->dl_tcp_flags;
  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_icmp(scamper_task_t *task,scamper_icmp_resp_t *ir)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
  };
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  void *addr;
  int type;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(ir->ir_af != AF_INET)
    return;

  /* if the ICMP type is not something that we care for, then drop it */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
     SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 ||
	 ir->ir_inner_ip_off != 0)
	{
	  return;
	}

      /* the IPID value used is expected to be of the form 0xabab */
      if((ir->ir_inner_ip_id & 0xff) != (ir->ir_inner_ip_id >> 8))
	return;

      if(ir->ir_inner_ip_proto == IPPROTO_UDP)
	probe = dealias_probe_udp_find(state, ir);
      else if(ir->ir_inner_ip_proto == IPPROTO_ICMP)
	probe = dealias_probe_icmp_find(state, ir);
      else if(ir->ir_inner_ip_proto == IPPROTO_TCP)
	probe = dealias_probe_tcp_find(state, ir);
      else return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) != 0)
    {
      probe = dealias_probe_echoreq_find(dealias, ir);
    }
  else
    {
      return;
    }

  if(probe == NULL)
    return;

  scamper_icmp_resp_print(ir);

  type = SCAMPER_ADDR_TYPE_IPV4;
  addr = &ir->ir_ip_src.v4;

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  if((reply->src = scamper_addrcache_get(addrcache, type, addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &ir->ir_rx);
  reply->ttl           = (uint8_t)ir->ir_ip_ttl;
  reply->ipid          = ir->ir_ip_id;
  reply->proto         = IPPROTO_ICMP;
  reply->icmp_type     = ir->ir_icmp_type;
  reply->icmp_code     = ir->ir_icmp_code;
  reply->icmp_q_ip_ttl = ir->ir_inner_ip_ttl;
  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_timeout(scamper_task_t *task)
{
  static void (*const func[])(scamper_task_t *) = {
    dealias_mercator_handletimeout,
    dealias_ally_handletimeout,
    dealias_radargun_handletimeout,
    dealias_prefixscan_handletimeout,
    dealias_bump_handletimeout,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  func[dealias->method-1](task);
  return;
}

/*
 * dealias_state_probe
 *
 * record the fact that a probe was sent with a particular IP-ID value.
 */
static int dealias_state_probe(dealias_state_t *state,
			       scamper_dealias_probe_t *probe, uint16_t seq)
{
  dealias_probe_t *dp = NULL;

  /* allocate a structure to record this probe's details */
  if((dp = malloc(sizeof(dealias_probe_t))) == NULL)
    {
      printerror(errno,strerror,__func__, "could not malloc dealias_probe_t");
      return -1;
    }
  dp->icmpseq = seq;
  dp->probe = probe;

  dp->next = state->probes[probe->ipid & 0xff];
  state->probes[probe->ipid & 0xff] = dp;

  return 0;
}

static void dealias_probe_free(void *item)
{
  dealias_probe_t *probe = item, *next;
  while(probe != NULL)
    {
      next = probe->next;
      free(probe);
      probe = next;
    }
  return;
}

static void dealias_prefixscan_free(void *data)
{
  dealias_prefixscan_t *pfstate = data;
  int j;

  if(pfstate->probedefs != NULL)
    {
      for(j=0; j<pfstate->probedefc; j++)
	{
	  if(pfstate->probedefs[j].src != NULL)
	    scamper_addr_free(pfstate->probedefs[j].src);
	  if(pfstate->probedefs[j].dst != NULL)
	    scamper_addr_free(pfstate->probedefs[j].dst);
	}
      free(pfstate->probedefs);
    }
  if(pfstate->aaliases != NULL)
    {
      for(j=0; j<pfstate->aaliasc; j++)
	if(pfstate->aaliases[j] != NULL)
	  scamper_addr_free(pfstate->aaliases[j]);
      free(pfstate->aaliases);
    }
  free(pfstate);

  return;
}

static int dealias_prefixscan_alloc(scamper_dealias_t *dealias,
				    dealias_state_t *state)
{
  scamper_dealias_prefixscan_t *pfxscan = dealias->data;
  scamper_dealias_probedef_t pd;
  dealias_prefixscan_t *pfstate = NULL;
  scamper_addr_t      **addrs = NULL;
  int                   i, addrc = 0;

  /* figure out the addresses that will be probed */
  if(dealias_prefixscan_array(dealias, &addrs, &addrc) != 0)
    goto err;

  if((pfstate = malloc_zero(sizeof(dealias_prefixscan_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc pfstate");
      goto err;
    }
  state->methodstate = pfstate;

  pfstate->probedefs = malloc_zero(addrc * sizeof(scamper_dealias_probedef_t));
  if(pfstate->probedefs == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc probedefs");
      goto err;
    }
  pfstate->probedefc = addrc;

  for(i=0; i<addrc; i++)
    {
      memcpy(&pd, &pfxscan->probedefs[0], sizeof(pd));
      pd.dst = scamper_addr_use(addrs[i]);
      pd.src = scamper_getsrc(pd.dst, 0);
      memcpy(&pfstate->probedefs[i], &pd, sizeof(pd));
    }

  dealias_prefixscan_array_free(addrs, addrc);
  return 0;

 err:
  if(addrs != NULL) dealias_prefixscan_array_free(addrs, addrc);
  return -1;
}

static void dealias_radargun_free(void *data)
{
  dealias_radargun_t *rgstate = data;
  if(rgstate->order != NULL)
    free(rgstate->order);
  free(rgstate);
  return;
}

static int dealias_radargun_alloc(scamper_dealias_radargun_t *rg,
				  dealias_state_t *state)
{
  dealias_radargun_t *rgstate = NULL;
  uint32_t i;

  /* if the probe order is to be shuffled, then shuffle it */
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) == 0)
    return 0;

  if((rgstate = malloc_zero(sizeof(dealias_radargun_t))) == NULL)
    {
      printerror(errno,strerror,__func__, "could not malloc rgstate");
      return -1;
    }
  state->methodstate = rgstate;

  if((rgstate->order = malloc(sizeof(uint32_t) * rg->probedefc)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc order");
      return -1;
    }
  for(i=0; i<rg->probedefc; i++)
    rgstate->order[i] = i;
  if(shuffle32(rgstate->order, rg->probedefc) != 0)
    return -1;

  return 0;
}

static int dealias_bump_alloc(dealias_state_t *state)
{
  dealias_bump_t *bstate = NULL;
  if((bstate = malloc_zero(sizeof(dealias_bump_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc bstate");
      return -1;
    }
  state->methodstate = bstate;
  return 0;
}

static void dealias_bump_free(void *data)
{
  free(data);
  return;
}

static void dealias_state_free(scamper_dealias_t *dealias,
			       dealias_state_t *state)
{
  int j;

  if(state == NULL)
    return;

  if(state->methodstate != NULL)
    {
      if(SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias))
	dealias_prefixscan_free(state->methodstate);
      else if(SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias))
	dealias_radargun_free(state->methodstate);
      else if(SCAMPER_DEALIAS_METHOD_IS_BUMP(dealias))
	dealias_bump_free(state->methodstate);
    }

  if(state->probes != NULL)
    {
      for(j=255; j>=0; j--)
	{
	  if(state->probes[j] == NULL)
	    break;
	  dealias_probe_free(state->probes[j]);
	}
    }

  if(state->tcp_seqs != NULL)
    free(state->tcp_seqs);
  if(state->tcp_acks != NULL)
    free(state->tcp_acks);

  free(state);
  return;
}

static void do_dealias_probe(scamper_task_t *task)
{
  scamper_dealias_t            *dealias    = dealias_getdata(task);
  dealias_state_t              *state      = dealias_getstate(task);
  scamper_dealias_mercator_t   *mercator   = dealias->data;
  scamper_dealias_radargun_t   *rg         = dealias->data;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_ally_t       *ally       = dealias->data;
  scamper_dealias_bump_t       *bump       = dealias->data;
  dealias_prefixscan_t         *pfstate    = state->methodstate;
  dealias_radargun_t           *rgstate    = state->methodstate;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *dp = NULL;
  scamper_probe_t probe;
  struct timeval tv;
  uint16_t u16;
  uint32_t u32;
  size_t size;

  if(dealias->probec == 0)
    {
      gettimeofday_wrap(&dealias->start);

      /* check if we need to keep tcp state */
      for(u32=0; u32<state->probedefc; u32++)
	{
	  def = &state->probedefs[u32];
	  if(def->method != SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	    continue;

	  if(state->tcp_acks == NULL)
	    {
	      size = sizeof(uint32_t) * state->probedefc;
	      if((state->tcp_acks = malloc_zero(size)) == NULL ||
		 (state->tcp_seqs = malloc_zero(size)) == NULL)
		{
		  printerror(errno, strerror, __func__,
			     "could not malloc tcp state");
		  goto err;
		}
	    }

	  if(random_u32(&state->tcp_seqs[u32]) != 0 ||
	     random_u32(&state->tcp_acks[u32]) != 0)
	    {
	      goto err;
	    }
	}
    }

  if(pktbuf_len < 2)
    {
      if(realloc_wrap((void **)&pktbuf, 2) != 0)
	{
	  printerror(errno, strerror, __func__, "could not realloc pktbuf");
	  goto err;
	}
      pktbuf_len = 2;
    }

  if(SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias) == 0 ||
     (rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) == 0)
    {
      def = &state->probedefs[state->probe];
    }
  else
    {
      def = &state->probedefs[rgstate->order[rgstate->i++]];
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src    = def->src;
  probe.pr_ip_dst    = def->dst;
  probe.pr_ip_ttl    = def->ttl;
  probe.pr_ip_tos    = def->tos;
  probe.pr_flags     = SCAMPER_PROBE_FLAG_IPID;
  probe.pr_ip_id     = state->id << 8 | state->id;
  probe.pr_ip_off    = IP_DF;
  probe.pr_data      = pktbuf;
  probe.pr_len       = 2;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = def->un.udp.sport;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	probe.pr_udp_dport = def->un.udp.dport;
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	probe.pr_udp_dport = def->un.udp.dport + state->round;
      else
	goto err;

      /* hack to get the udp csum to be a particular value, and be valid */
      u16 = htons(dealias->probec + 1);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_udp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      probe.pr_ip_proto  = IPPROTO_ICMP;
      probe.pr_icmp_type = ICMP_ECHO;
      probe.pr_icmp_code = 0;
      probe.pr_icmp_id   = def->un.icmp.id;
      probe.pr_icmp_seq  = dealias->probec & 0xffff;

      /* hack to get the icmp csum to be a particular value, and be valid */
      u16 = htons(def->un.icmp.csum);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_icmp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = def->un.tcp.dport;
      probe.pr_tcp_flags = def->un.tcp.flags;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  probe.pr_tcp_sport = def->un.tcp.sport;
	  probe.pr_tcp_seq   = state->tcp_seqs[def->id];
	  probe.pr_tcp_ack   = state->tcp_acks[def->id];
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  probe.pr_tcp_sport = def->un.tcp.sport + state->round;
	  if(random_u32(&probe.pr_tcp_seq) != 0 ||
	     random_u32(&probe.pr_tcp_ack) != 0)
	    goto err;
	}
      else goto err;
    }

  /*
   * allocate a probe record before we try and send the probe as there is no
   * point sending something into the wild that we can't record
   */
  if((dp = scamper_dealias_probe_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc probe");
      goto err;
    }
  dp->probedef = def;
  dp->ipid = probe.pr_ip_id;
  dp->seq = state->round;

  if(dealias_state_probe(state, dp, dealias->probec & 0xffff) != 0)
    {
      goto err;
    }

  /* send the probe */
  if(scamper_probe_task(&probe, task) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }
  timeval_cpy(&tv, &probe.pr_tx);
  timeval_cpy(&state->last_tx, &tv);

  /* record details of the probe in the scamper_dealias_t data structures */
  timeval_cpy(&dp->tx, &tv);
  if(scamper_dealias_probe_add(dealias, dp) != 0)
    {
      scamper_debug(__func__, "could not add probe to dealias data");
      goto err;
    }

  /* figure out how long to wait until sending the next probe */
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      /* we just wait the specified number of seconds with mercator probes */
      timeval_add_s(&state->next_tx, &tv, mercator->wait_timeout);
      state->round++;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      /*
       * we wait a fixed amount of time before we send the next probe with
       * ally.  except when the last probe has been sent, where we wait for
       * some other length of time for any final replies to come in
       */
      if(dealias->probec != ally->attempts)
	timeval_add_ms(&state->next_tx, &tv, ally->wait_probe);
      else
	timeval_add_s(&state->next_tx, &tv, ally->wait_timeout);

      if(++state->probe == 2)
	{
	  state->probe = 0;
	  state->round++;
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      if(state->probe == 0)
	timeval_add_ms(&state->next_round, &tv, rg->wait_round);

      state->probe++;

      if(state->probe < rg->probedefc)
	{
	  timeval_add_ms(&state->next_tx, &tv, rg->wait_probe);
	}
      else
	{
	  state->probe = 0;
	  state->round++;

	  if(state->round < rg->attempts)
	    {
	      if(timeval_cmp(&tv, &state->next_round) >= 0 ||
		 timeval_diff_ms(&state->next_round, &tv) < rg->wait_probe)
		{
		  timeval_add_ms(&state->next_tx, &tv, rg->wait_probe);
		}
	      else
		{
		  timeval_cpy(&state->next_tx, &state->next_round);
		}

	      if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) != 0)
		{
		  if(shuffle32(rgstate->order, rg->probedefc) != 0)
		    goto err;
		  rgstate->i = 0;
		}
	    }
	  else
	    {
	      /* we're all finished */
	      timeval_add_s(&state->next_tx, &tv, rg->wait_timeout);
	    }
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      if(def->id == 0)
	pfstate->round0++;
      else
	pfstate->round++;

      pfstate->attempt++;
      pfstate->replyc = 0;

      timeval_add_ms(&state->next_tx, &tv, prefixscan->wait_probe);
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    {
      timeval_add_ms(&state->next_tx, &tv, bump->wait_probe);
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", dealias->method);
      goto err;
    }

  assert(state->id != 0);
  if(--state->id == 0)
    state->id = 255;

  dealias_queue(task);
  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_dealias(sf, dealias_getdata(task));
  return;
}

static void do_dealias_halt(scamper_task_t *task)
{
  dealias_result(task, SCAMPER_DEALIAS_RESULT_HALTED);
  return;
}

static void do_dealias_free(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);

  if(state != NULL)
    dealias_state_free(dealias, state);

  if(dealias != NULL)
    scamper_dealias_free(dealias);

  return;
}

static int dealias_arg_param_validate(int optid, char *param, long *out)
{
  long tmp;

  switch(optid)
    {
    case DEALIAS_OPT_OPTION:
    case DEALIAS_OPT_PROBEDEF:
    case DEALIAS_OPT_EXCLUDE:
      tmp = 0;
      break;

    case DEALIAS_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_FUDGE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_METHOD:
      if(strcasecmp(param, "mercator") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MERCATOR;
      else if(strcasecmp(param, "ally") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_ALLY;
      else if(strcasecmp(param, "radargun") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_RADARGUN;
      else if(strcasecmp(param, "prefixscan") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_PREFIXSCAN;
      else if(strcasecmp(param, "bump") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_BUMP;
      else
	return -1;
      break;

    case DEALIAS_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 500)
	return -1;
      break;

    case DEALIAS_OPT_SPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_TTL:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_TIMEOUT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_PROBE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_ROUND:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 180000)
	return -1;
      break;

    case DEALIAS_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 3 || tmp > 255)
	return -1;
      break;

    default:
      scamper_debug(__func__, "unhandled optid %d", optid);
      return -1;
    }

  if(out != NULL)
    *out = tmp;
  return 0;
}

static int dealias_probedef_args(scamper_dealias_probedef_t *def, char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  uint16_t dport = 33435;
  uint16_t sport = default_sport;
  uint16_t csum  = 0;
  uint16_t opts  = 0;
  uint8_t  ttl   = 255;
  uint8_t  tos   = 0;
  char *end;
  long tmp;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, probedef_opts, probedef_opts_cnt,
			   &opts_out, &end) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      /* check for an option being used multiple times */
      if(opts & (1<<(opt->id-1)))
	{
	  scamper_debug(__func__,"option %d specified multiple times",opt->id);
	  goto err;
	}

      opts |= (1 << (opt->id-1));

      switch(opt->id)
	{
	case DEALIAS_PROBEDEF_OPT_CSUM:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 0 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid csum %s", opt->str);
	      goto err;
	    }
	  csum = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_DPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid dport %s", opt->str);
	      goto err;
	    }
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_IP:
	  def->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, opt->str);
	  if(def->dst == NULL)
	    {
	      scamper_debug(__func__, "invalid dst ip %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_PROTO:
	  if(strcasecmp(opt->str, "udp") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  else if(strcasecmp(opt->str, "tcp-ack") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK;
	  else if(strcasecmp(opt->str, "icmp-echo") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
	  else if(strcasecmp(opt->str, "tcp-ack-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT;
	  else if(strcasecmp(opt->str, "udp-dport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT;
	  else if(strcasecmp(opt->str, "tcp-syn-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT;
	  else
	    {
	      scamper_debug(__func__, "invalid probe type %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_SPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid sport %s", opt->str);
	      goto err;
	    }
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_TTL:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 255)
	    {
	      scamper_debug(__func__, "invalid ttl %s", opt->str);
	      goto err;
	    }
	  ttl = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled optid %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  /*
   * if there is something at the end of the option string, then this
   * probedef is not valid
   */
  if(end != NULL)
    {
      scamper_debug(__func__, "invalid option string");
      goto err;
    }

  /* record the ttl, tos */
  def->ttl = ttl;
  def->tos = tos;

  /* if no protocol type is defined, choose UDP */
  if((opts & (1<<(DEALIAS_PROBEDEF_OPT_PROTO-1))) == 0)
    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      /* don't provide the choice of the checksum value in a UDP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for udp");
	  goto err;
	}

      def->un.udp.dport = dport;
      def->un.udp.sport = sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      /* ICMP probes don't have source or destination ports */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_SPORT-1)))
	{
	  scamper_debug(__func__, "sport option not permitted for icmp");
	  goto err;
	}
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_DPORT-1)))
	{
	  scamper_debug(__func__, "dport option not permitted for icmp");
	  goto err;
	}

      def->un.icmp.type = ICMP_ECHO;
      def->un.icmp.code = 0;
      def->un.icmp.csum = csum;
      def->un.icmp.id   = default_sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      /* don't provide the choice of the checksum value in a TCP probe */
      if(opts & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  scamper_debug(__func__, "csum option not permitted for tcp");
	  goto err;
	}

      def->un.tcp.dport = dport;
      def->un.tcp.sport = sport;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_ACK(def))
	def->un.tcp.flags = TH_ACK;
      else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_SYN(def))
	def->un.tcp.flags = TH_SYN;
      else
	{
	  scamper_debug(__func__,"unhandled flags for method %d",def->method);
	  goto err;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", def->method);
      goto err;
    }

  return 0;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(def->dst != NULL) scamper_addr_free(def->dst);
  return -1;
}

static int dealias_alloc_mercator(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_mercator_t *mercator;
  scamper_addr_t *dst = NULL;

  /* if there is no IP address after the options string, then stop now */
  if(o->addr == NULL)
    {
      scamper_debug(__func__, "missing target address for mercator");
      goto err;
    }
  if((dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr)) == NULL)
    {
      scamper_debug(__func__, "unable to resolve address for mercator");
      goto err;
    }
  if(o->probedefc != 0 || o->xc != 0 || o->wait_probe != 0 || o->fudge != 0 ||
     o->attempts > 3 || o->nobs != 0 || o->replyc != 0 || o->shuffle != 0 ||
     o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for mercator");
      goto err;
    }
  if(o->attempts == 0) o->attempts = 3;
  if(o->dport == 0)    o->dport    = 33435;
  if(o->sport == 0)    o->sport    = default_sport;
  if(o->ttl == 0)      o->ttl      = 255;

  if(scamper_dealias_mercator_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc mercator structure");
      goto err;
    }
  mercator = d->data;
  mercator->attempts              = o->attempts;
  mercator->wait_timeout          = o->wait_timeout;
  mercator->probedef.id           = 0;
  mercator->probedef.dst          = dst; dst = NULL;
  mercator->probedef.ttl          = o->ttl;
  mercator->probedef.method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
  mercator->probedef.un.udp.sport = o->sport;
  mercator->probedef.un.udp.dport = o->dport;

  return 0;

 err:
  if(dst != NULL) scamper_addr_free(dst);
  return -1;
}

static int dealias_alloc_ally(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_ally_t *ally = NULL;
  scamper_dealias_probedef_t pd[2];
  uint8_t flags = 0;
  char *addr2;
  int i;

  memset(&pd, 0, sizeof(pd));

  if(o->probedefc > 2 || o->xc != 0 || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->replyc != 0 || o->shuffle != 0 ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for ally");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 150;
  if(o->attempts == 0)   o->attempts   = 5;

  if(o->nobs != 0)
    flags |= SCAMPER_DEALIAS_ALLY_FLAG_NOBS;

  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  for(i=0; i<o->probedefc; i++)
    {
      if(dealias_probedef_args(&pd[i], o->probedefs[i]) != 0)
	{
	  scamper_debug(__func__, "could not read ally probedef %d", i);
	  goto err;
	}
    }

  if(o->probedefc == 0)
    {
      for(i=0; i<2; i++)
	{
	  pd[i].ttl          = 255;
	  pd[i].method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  pd[i].un.udp.sport = default_sport;
	  pd[i].un.udp.dport = 33435;
	}
    }
  else if(o->probedefc == 1)
    {
      if(pd[0].dst != NULL || o->addr == NULL)
	{
	  scamper_debug(__func__, "dst IP specified incorrectly");
	  goto err;
	}
      memcpy(&pd[1], &pd[0], sizeof(scamper_dealias_probedef_t));
    }

  if(o->addr == NULL)
    {
      if(pd[0].dst == NULL || pd[1].dst == NULL)
	{
	  scamper_debug(__func__, "missing destination IP address");
	  goto err;
	}
    }
  else
    {
      if(pd[0].dst != NULL || pd[1].dst != NULL)
	{
	  scamper_debug(__func__, "dst IP specified inconsisently");
	  goto err;
	}

      /* make sure there are two addresses specified */
      if((addr2 = string_nextword(o->addr)) == NULL)
	{
	  scamper_debug(__func__, "missing second address");
	  goto err;
	}

      /* resolve each address */
      pd[0].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
      if(pd[0].dst == NULL)
	{
	  printerror(errno,strerror,__func__, "could not resolve %s", o->addr);
	  goto err;
	}
      pd[1].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr2);
      if(pd[1].dst == NULL)
	{
	  printerror(errno,strerror,__func__, "could not resolve %s", addr2);
	  goto err;
	}
    }

  if(pd[0].dst->type != SCAMPER_ADDR_TYPE_IPV4 ||
     pd[1].dst->type != SCAMPER_ADDR_TYPE_IPV4)
    {
      scamper_debug(__func__, "destination IP address not IPv4");
      goto err;
    }

  if(scamper_dealias_ally_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc ally structure");
      goto err;
    }
  ally = d->data;

  ally->attempts     = o->attempts;
  ally->wait_probe   = o->wait_probe;
  ally->wait_timeout = o->wait_timeout;
  ally->fudge        = o->fudge;
  ally->flags        = flags;

  for(i=0; i<2; i++)
    pd[i].id = i;

  memcpy(ally->probedefs, pd, sizeof(ally->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}

static int dealias_alloc_radargun(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_radargun_t *rg;
  scamper_dealias_probedef_t *pd = NULL;
  scamper_addr_t *dst = NULL;
  uint32_t i;
  uint8_t flags = 0;
  size_t len;

  if(o->probedefc == 0 || o->xc != 0 || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->nobs != 0 || o->replyc != 0 || o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for radargun");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe   = 150;
  if(o->attempts == 0)   o->attempts     = 30;
  if(o->wait_round == 0) o->wait_round   = o->probedefc * o->wait_probe;

  if(o->shuffle != 0)
    flags |= SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE;

  len = o->probedefc * sizeof(scamper_dealias_probedef_t);
  if((pd = malloc_zero(len)) == NULL)
    {
      scamper_debug(__func__, "could not malloc radargun pd");
      goto err;
    }

  for(i=0; i<o->probedefc; i++)
    {
      if(dealias_probedef_args(&pd[i], o->probedefs[i]) != 0)
	{
	  scamper_debug(__func__,"could not parse radargun probedef %d",i);
	  goto err;
	}

      if((pd[0].dst == NULL && pd[i].dst != NULL) ||
	 (pd[0].dst != NULL && pd[i].dst == NULL))
	{
	  scamper_debug(__func__, "inconsistent dst IP addresses");
	  goto err;
	}

      pd[i].id = i;
    }

  if(pd[0].dst == NULL)
    {
      if(o->addr == NULL)
	{
	  scamper_debug(__func__, "required dst IP address missing");
	  goto err;
	}

      if((dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,o->addr))==NULL)
	{
	  scamper_debug(__func__, "could not resolve %s", o->addr);
	  goto err;
	}

      for(i=0; i<o->probedefc; i++)
	pd[i].dst = scamper_addr_use(dst);

      scamper_addr_free(dst); dst = NULL;
    }
  else if(o->addr != NULL)
    {
      scamper_debug(__func__, "destination IP address specified twice");
      goto err;
    }

  if(scamper_dealias_radargun_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun structure");
      goto err;
    }
  rg = d->data;

  if(scamper_dealias_radargun_probedefs_alloc(rg, o->probedefc) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun probedefs");
      goto err;
    }

  rg->attempts     = o->attempts;
  rg->wait_probe   = o->wait_probe;
  rg->wait_timeout = o->wait_timeout;
  rg->wait_round   = o->wait_round;
  rg->probedefc    = o->probedefc;
  rg->flags        = flags;

  for(i=0; i<o->probedefc; i++)
    memcpy(&rg->probedefs[i], &pd[i], sizeof(scamper_dealias_probedef_t));

  return 0;

 err:
  if(pd != NULL)
    {
      for(i=0; i<o->probedefc; i++)
	if(pd[i].dst != NULL)
	  scamper_addr_free(pd[i].dst);
      free(pd);
    }
  return -1;
}

static int dealias_alloc_prefixscan(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t pd0;
  scamper_addr_t *dst = NULL;
  uint8_t flags = 0;
  uint8_t prefix;
  char *addr2 = NULL, *pfxstr;
  long tmp;
  int xi, af;

  /* check the sanity of various parameters */
  if(o->probedefc != 1 || o->addr == NULL || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->shuffle != 0 || (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for prefixscan");
      goto err;
    }

  if(o->ttl == 0)        o->ttl        = 255;
  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 2;
  if(o->replyc == 0)     o->replyc     = 5;

  if(o->nobs != 0)
    flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS;

  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  /*
   * we need `a' and `b' to traceroute.  parse the `addr' string.
   * start by getting the second address.
   *
   * skip over the first address until we get to whitespace.
   */
  if((addr2 = string_nextword(o->addr)) == NULL)
    {
      scamper_debug(__func__, "missing second address");
      goto err;
    }

  if(string_nullterm_char(addr2, '/', &pfxstr) == NULL)
    {
      scamper_debug(__func__, "missing prefix");
      goto err;
    }

  if(string_tolong(pfxstr, &tmp) != 0 || tmp < 24 || tmp >= 32)
    {
      scamper_debug(__func__, "invalid prefix %s", pfxstr);
      goto err;
    }
  prefix = (uint8_t)tmp;

  /* check the sanity of the probedef */
  memset(&pd0, 0, sizeof(pd0));
  if(dealias_probedef_args(&pd0, o->probedefs[0]) != 0)
    {
      scamper_debug(__func__, "could not parse prefixscan probedef");
      goto err;
    }
  if(pd0.dst != NULL)
    {
      scamper_debug(__func__, "prefixscan ip address spec. in probedef");
      scamper_addr_free(pd0.dst); pd0.dst = NULL;
      goto err;
    }

  if(scamper_dealias_prefixscan_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan structure");
      goto err;
    }
  prefixscan = d->data;

  prefixscan->attempts     = o->attempts;
  prefixscan->fudge        = o->fudge;
  prefixscan->wait_probe   = o->wait_probe;
  prefixscan->wait_timeout = o->wait_timeout;
  prefixscan->replyc       = o->replyc;
  prefixscan->prefix       = prefix;
  prefixscan->flags        = flags;

  /* resolve the two addresses now */
  prefixscan->a = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
  if(prefixscan->a == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", o->addr);
      goto err;
    }
  af = scamper_addr_af(prefixscan->a);
  prefixscan->b = scamper_addrcache_resolve(addrcache, af, addr2);
  if(prefixscan->b == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", addr2);
      goto err;
    }

  /* add the first probedef */
  if(scamper_dealias_prefixscan_probedefs_alloc(prefixscan, 1) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan probedefs");
      goto err;
    }
  memcpy(prefixscan->probedefs, &pd0, sizeof(pd0));
  prefixscan->probedefs[0].dst = scamper_addr_use(prefixscan->a);
  prefixscan->probedefs[0].id  = 0;
  prefixscan->probedefc        = 1;

  /* resolve any addresses to exclude in the scan */
  for(xi=0; xi<o->xc; xi++)
    {
      if((dst = scamper_addrcache_resolve(addrcache, af, o->xs[xi])) == NULL)
	{
	  scamper_debug(__func__, "could not resolve %s", o->xs[xi]);
	  goto err;
	}
      if(scamper_dealias_prefixscan_xs_add(d, dst) != 0)
	{
	  scamper_debug(__func__, "could not add %s to xs", o->xs[xi]);
	  goto err;
	}
      scamper_addr_free(dst); dst = NULL;
    }

  return 0;

 err:
  return -1;
}

static int dealias_alloc_bump(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_bump_t *bump = NULL;
  scamper_dealias_probedef_t pd[2];
  int i;

  memset(&pd, 0, sizeof(pd));

  if(o->probedefc != 2 || o->xc != 0 || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->replyc != 0 || o->shuffle != 0 || o->addr != NULL ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for bump");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 3;
  if(o->fudge == 0)      o->fudge      = 30; /* bump limit */

  for(i=0; i<2; i++)
    {
      if(dealias_probedef_args(&pd[i], o->probedefs[i]) != 0)
	{
	  scamper_debug(__func__, "could not read bump probedef %d", i);
	  goto err;
	}
      if(pd[i].dst == NULL)
	{
	  scamper_debug(__func__, "missing dst address in probedef %d", i);
	  goto err;
	}
      if(pd[i].dst->type != SCAMPER_ADDR_TYPE_IPV4)
	{
	  scamper_debug(__func__, "dst address not IPv4 in probedef %d", i);
	  goto err;
	}
      pd[i].id = i;
    }

  if(scamper_dealias_bump_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc bump structure");
      goto err;
    }
  bump = d->data;

  bump->attempts     = o->attempts;
  bump->wait_probe   = o->wait_probe;
  bump->bump_limit   = o->fudge;
  memcpy(bump->probedefs, pd, sizeof(bump->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}


/*
 * scamper_do_dealias_alloc
 *
 * given a string representing a dealias task, parse the parameters and
 * assemble a dealias.  return the dealias structure so that it is all ready
 * to go.
 */
void *scamper_do_dealias_alloc(char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_dealias_t *dealias = NULL;
  dealias_options_t o;
  uint8_t  method = SCAMPER_DEALIAS_METHOD_MERCATOR;
  uint32_t userid = 0;
  size_t len;
  long tmp = 0;
  int rc;

  memset(&o, 0, sizeof(o));

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &o.addr) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 dealias_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case DEALIAS_OPT_METHOD:
	  method = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_OPTION:
	  if(strcasecmp(opt->str, "nobs") == 0)
	    o.nobs = 1;
	  else if(strcasecmp(opt->str, "shuffle") == 0)
	    o.shuffle = 1;
	  else if(strcasecmp(opt->str, "inseq") == 0)
	    o.inseq = 1;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_DPORT:
	  o.dport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_SPORT:
	  o.sport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_FUDGE:
	  o.fudge = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_TTL:
	  o.ttl = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_PROBEDEF:
	  len = sizeof(char *) * (o.probedefc+1);
	  if(realloc_wrap((void **)&o.probedefs, len) != 0)
	    {
	      scamper_debug(__func__, "could not realloc probedefs");
	      goto err;
	    }
	  o.probedefs[o.probedefc++] = opt->str;
	  break;

	case DEALIAS_OPT_WAIT_TIMEOUT:
	  o.wait_timeout = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_PROBE:
	  o.wait_probe = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_ROUND:
	  o.wait_round = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_EXCLUDE:
	  len = sizeof(char *) * (o.xc+1);
	  if(realloc_wrap((void **)&o.xs, len) != 0)
	    {
	      scamper_debug(__func__, "could not realloc excludes");
	      goto err;
	    }
	  o.xs[o.xc++] = opt->str;
	  break;

	case DEALIAS_OPT_REPLYC:
	  o.replyc = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out);
  opts_out = NULL;

  if(o.wait_timeout == 0)
    o.wait_timeout = 5;

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc dealias structure");
      goto err;
    }
  dealias->method = method;
  dealias->userid = userid;

  if(method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    rc = dealias_alloc_mercator(dealias, &o);
  else if(method == SCAMPER_DEALIAS_METHOD_ALLY)
    rc = dealias_alloc_ally(dealias, &o);
  else if(method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    rc = dealias_alloc_radargun(dealias, &o);
  else if(method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    rc = dealias_alloc_prefixscan(dealias, &o);
  else if(method == SCAMPER_DEALIAS_METHOD_BUMP)
    rc = dealias_alloc_bump(dealias, &o);
  else
    goto err;

  if(rc != 0)
    goto err;

  if(o.probedefs != NULL)
    free(o.probedefs);

  return dealias;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(o.probedefs != NULL) free(o.probedefs);
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

/*
 * scamper_do_dealias_arg_validate
 *
 *
 */
int scamper_do_dealias_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  dealias_arg_param_validate);
}

void scamper_do_dealias_free(void *data)
{
  scamper_dealias_free((scamper_dealias_t *)data);
  return;
}

static int probedef2sig(scamper_task_t *task, scamper_dealias_probedef_t *def)
{
  scamper_task_sig_t *sig = NULL;
  char buf[32];

  if(def->src == NULL && (def->src = scamper_getsrc(def->dst, 0)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not get src address for %s",
		 scamper_addr_tostr(def->dst, buf, sizeof(buf)));
      goto err;
    }

  /* form a signature */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(def->dst);
  sig->sig_tx_ip_src = scamper_addr_use(def->src);

  /* add it to the task */
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;

  return 0;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  return -1;
}

scamper_task_t *scamper_do_dealias_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle)
{
  scamper_dealias_t             *dealias = (scamper_dealias_t *)data;
  dealias_state_t               *state = NULL;
  scamper_task_t                *task = NULL;
  scamper_dealias_prefixscan_t  *pfxscan;
  scamper_dealias_mercator_t    *mercator;
  scamper_dealias_radargun_t    *radargun;
  scamper_dealias_ally_t        *ally;
  scamper_dealias_bump_t        *bump;
  dealias_prefixscan_t          *pfstate;
  uint32_t p;
  int i;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(dealias, &funcs)) == NULL)
    goto err;

  if((state = malloc_zero(sizeof(dealias_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }
  state->id = 255;

  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      mercator = dealias->data;
      if(probedef2sig(task, &mercator->probedef) != 0)
	goto err;
      state->probedefs = &mercator->probedef;
      state->probedefc = 1;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      ally = dealias->data;
      for(i=0; i<2; i++)
	if(probedef2sig(task, &ally->probedefs[i]) != 0)
	  goto err;
      state->probedefs = ally->probedefs;
      state->probedefc = 2;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      radargun = dealias->data;
      for(p=0; p<radargun->probedefc; p++)
	if(probedef2sig(task, &radargun->probedefs[p]) != 0)
	  goto err;

      state->probedefs = radargun->probedefs;
      state->probedefc = radargun->probedefc;
      if(dealias_radargun_alloc(radargun, state) != 0)
	goto err;
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      if(dealias_prefixscan_alloc(dealias, state) != 0)
	goto err;
      pfxscan = dealias->data;
      if(probedef2sig(task, &pfxscan->probedefs[0]) != 0)
	goto err;
      state->probedefs = pfxscan->probedefs;
      state->probedefc = pfxscan->probedefc;

      pfstate = state->methodstate;
      for(i=0; i<pfstate->probedefc; i++)
	{
	  if(probedef2sig(task, &pfstate->probedefs[i]) != 0)
	    goto err;
	}
    }
  else if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    {
      bump = dealias->data;
      for(i=0; i<2; i++)
	if(probedef2sig(task, &bump->probedefs[i]) != 0)
	  goto err;

      state->probedefs = bump->probedefs;
      state->probedefc = 2;
      if(dealias_bump_alloc(state) != 0)
	goto err;
    }
  else goto err;

  /* associate the list and cycle with the trace */
  dealias->list  = scamper_list_use(list);
  dealias->cycle = scamper_cycle_use(cycle);

  scamper_task_setstate(task, state);
  state = NULL;

  return task;

 err:
  if(task != NULL) 
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  if(state != NULL) dealias_state_free(dealias, state);
  return NULL;
}

void scamper_do_dealias_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_dealias_init(void)
{
#ifndef _WIN32
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif

  default_sport = (pid & 0x7fff) + 0x8000;

  funcs.probe                  = do_dealias_probe;
  funcs.handle_icmp            = do_dealias_handle_icmp;
  funcs.handle_timeout         = do_dealias_handle_timeout;
  funcs.handle_dl              = do_dealias_handle_dl;
  funcs.write                  = do_dealias_write;
  funcs.task_free              = do_dealias_free;
  funcs.halt                   = do_dealias_halt;

  return 0;
}
