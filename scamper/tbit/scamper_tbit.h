/*
 * scamper_tbit.h
 *
 * $Id: scamper_tbit.h,v 1.17 2011/11/17 21:14:58 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 University of Waikato
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

#ifndef __SCAMPER_TBIT_H
#define __SCAMPER_TBIT_H

/* types of tbit tests */
#define SCAMPER_TBIT_TYPE_PMTUD              1
#define SCAMPER_TBIT_TYPE_ECN                2
#define SCAMPER_TBIT_TYPE_NULL               3
#define SCAMPER_TBIT_TYPE_SACK_RCVR          4

/* application layer protocols supported by the tbit test */
#define SCAMPER_TBIT_APP_HTTP                1
#define SCAMPER_TBIT_APP_SMTP                2
#define SCAMPER_TBIT_APP_DNS                 3
#define SCAMPER_TBIT_APP_FTP                 4

/* generic tbit results */
#define SCAMPER_TBIT_RESULT_NONE             0 /* no result */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN       1 /* no connection */
#define SCAMPER_TBIT_RESULT_TCP_RST          2 /* Early reset */
#define SCAMPER_TBIT_RESULT_TCP_ERROR        3 /* TCP Error */
#define SCAMPER_TBIT_RESULT_ERROR            4 /* System error */
#define SCAMPER_TBIT_RESULT_ABORTED          5 /* Test aborted */
#define SCAMPER_TBIT_RESULT_TCP_NOCONN_RST   6 /* no connection: rst rx */
#define SCAMPER_TBIT_RESULT_HALTED           7 /* halted */
#define SCAMPER_TBIT_RESULT_TCP_BADOPT       8 /* bad TCP option */
#define SCAMPER_TBIT_RESULT_TCP_FIN          9 /* early fin */

/* possible PMTUD test results */
#define SCAMPER_TBIT_RESULT_PMTUD_NOACK      20 /* no ACK of request */
#define SCAMPER_TBIT_RESULT_PMTUD_NODATA     21 /* no data received */
#define SCAMPER_TBIT_RESULT_PMTUD_TOOSMALL   22 /* packets too small */
#define SCAMPER_TBIT_RESULT_PMTUD_NODF       23 /* DF not set (IPv4 only) */
#define SCAMPER_TBIT_RESULT_PMTUD_FAIL       24 /* did not reduce pkt size */
#define SCAMPER_TBIT_RESULT_PMTUD_SUCCESS    25 /* responded correctly */
#define SCAMPER_TBIT_RESULT_PMTUD_CLEARDF    26 /* cleared DF in response */

/* possible ECN test results */
#define SCAMPER_TBIT_RESULT_ECN_SUCCESS      30 /* responded correctly */
#define SCAMPER_TBIT_RESULT_ECN_INCAPABLE    31 /* no ece on syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_BADSYNACK    32 /* bad syn/ack */
#define SCAMPER_TBIT_RESULT_ECN_NOECE        33 /* no ECN echo */
#define SCAMPER_TBIT_RESULT_ECN_NOACK        34 /* no ack of request */
#define SCAMPER_TBIT_RESULT_ECN_NODATA       35 /* no data received */

/* possible NULL test results */
#define SCAMPER_TBIT_RESULT_NULL_SUCCESS     40 /* responded correctly */
#define SCAMPER_TBIT_RESULT_NULL_NODATA      41 /* no data received */

/* possible SACK-RCVR test results */
#define SCAMPER_TBIT_RESULT_SACK_INCAPABLE      50 /* not capable of SACK */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SUCCESS   51 /* responded correctly */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_SHIFTED   52 /* shifted sack blocks */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_TIMEOUT   53 /* missing ack */
#define SCAMPER_TBIT_RESULT_SACK_RCVR_NOSACK    54 /* missing sack blocks */

/* direction of recorded packet */
#define SCAMPER_TBIT_PKT_DIR_TX              1
#define SCAMPER_TBIT_PKT_DIR_RX              2

/* pmtud options */
#define SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE  0x1 /* test blackhole behaviour */

/* null options */
#define SCAMPER_TBIT_NULL_OPTION_TCPTS       0x1 /* tcp timestamps */

typedef struct scamper_tbit_pkt
{
  struct timeval       tv;
  uint8_t              dir;
  uint16_t             len;
  uint8_t             *data;
} scamper_tbit_pkt_t;

typedef struct scamper_tbit_app_http
{
  char                *host;
  char                *file;
} scamper_tbit_app_http_t;

typedef struct scamper_tbit_pmtud
{
  uint16_t             mtu;
  uint8_t              ptb_retx;
  uint8_t              options;
  scamper_addr_t      *ptbsrc;
} scamper_tbit_pmtud_t;

typedef struct scamper_tbit_null
{
  uint16_t             options;
} scamper_tbit_null_t;

/*
 * scamper_tbit
 *
 * parameters and results of a measurement conducted with tbit.
 */
typedef struct scamper_tbit
{
  scamper_list_t      *list;
  scamper_cycle_t     *cycle;
  uint32_t             userid;

  scamper_addr_t      *src;
  scamper_addr_t      *dst;
  uint16_t             sport;
  uint16_t             dport;
  struct timeval       start;

  /* outcome of test */
  uint16_t             result;

  /* type of tbit test and data specific to that test */
  uint8_t              type;
  void                *data;

  /* details of application protocol used */
  uint8_t              app_proto;
  void                *app_data;

  /* client and server mss values advertised */
  uint16_t             client_mss;
  uint16_t             server_mss;

  /* various generic retransmit values */
  uint8_t              syn_retx;
  uint8_t              dat_retx;

  /* packets collected as part of this test */
  scamper_tbit_pkt_t **pkts;
  uint32_t             pktc;
} scamper_tbit_t;

scamper_tbit_t *scamper_tbit_alloc(void);
void scamper_tbit_free(scamper_tbit_t *tbit);

char *scamper_tbit_res2str(const scamper_tbit_t *tbit, char *buf, size_t len);
char *scamper_tbit_type2str(const scamper_tbit_t *tbit, char *buf, size_t len);

scamper_tbit_pkt_t *scamper_tbit_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv);
void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt);

scamper_tbit_pmtud_t *scamper_tbit_pmtud_alloc(void);
void scamper_tbit_pmtud_free(scamper_tbit_pmtud_t *pmtud);

scamper_tbit_null_t *scamper_tbit_null_alloc(void);
void scamper_tbit_null_free(scamper_tbit_null_t *null);

scamper_tbit_app_http_t *scamper_tbit_app_http_alloc(char *host, char *file);
int scamper_tbit_app_http_host(scamper_tbit_app_http_t *http, const char *h);
int scamper_tbit_app_http_file(scamper_tbit_app_http_t *http, const char *f);
void scamper_tbit_app_http_free(scamper_tbit_app_http_t *http);

int scamper_tbit_pkts_alloc(scamper_tbit_t *tbit, uint32_t count);
int scamper_tbit_record_pkt(scamper_tbit_t *tbit, scamper_tbit_pkt_t *pkt);

#endif /* __SCAMPER_TBIT_H */
