/*
 * Bounce Address Tag Validation
 * http://www.mipassoc.org/batv/
 * control files:
 *
 *   control/signenv     signing nonce
 *   control/nosign      accept unsigned bounces from these domains
 *   control/nosigndoms  local domains that accept unsigned bounces
 * Env vars:
 *   NOBATV - don't do BATV on this message, passed from tcpserver
 */

#include <unistd.h>
#include <ctype.h>
#include "mailfront.h"
#include "conf_qmail.c"
#include <iobuf/ibuf.h>
#include <dict/dict.h>
#include <dict/load.h>
#include <msg/msg.h>
#include <openssl/md5.h>
#include <sys/time.h>
#include <string.h>

#define BATVLEN 3		/* number of bytes */
#define BATVSTALE 7		/* accept for a week */
/* #define OLDBATV 1		/* also accept prvs=user=sig */

static int isbounce;
static dict nosign;

static dict nosigndoms;
static int nsdloaded;
static str signkey;

static RESPONSE(no_chdir,451,"4.3.0 Could not change to the qmail directory.");
static RESPONSE(batv,553, "Not our message (5.7.1)");

static const response* batv_sender(str* sender)
{
  const char *qh;
  str domstr;

  isbounce = 0;
  if(sender->len == 0) {		/* actual bounce */
    if(!getenv("NOBATV")) isbounce = 1;
    return 0;
  }

  if(!str_case_starts(sender, "mailer-daemon@")) return 0;

  /* for mailer daemon, have to check nosign */

  if ((qh = getenv("QMAILHOME")) == 0)
    qh = conf_qmail;
  if (chdir(qh) == -1) return &resp_no_chdir;
  if (!dict_load_list(&nosign, "control/nosign", 0, 0))
    return &resp_internal;
  str_init(&domstr);
  str_copyb(&domstr, sender->s+14, sender->len-14);
  if(!dict_get(&nosign, &domstr)) isbounce = 1; /* do batv */

  return 0;
}

/* unwrap an address, and check its BATV-ness */
static int bvunwrap(str* address)
{
  int i;
  int md5pos;
  char kdate[] = "0000";
  MD5_CTX md5;
  unsigned char md5digest[MD5_DIGEST_LENGTH];
  unsigned long signday;
  int daynumber;
  struct timespec ts;
#if OLDBATV
  int atpos, slpos;
  int oldfmt = 0;
#endif

  if(address->len >= (11+2*BATVLEN) && str_starts(address, "prvs=0")
			  && address->s[9+2*BATVLEN] == '=') {
    memcpy(kdate, address->s+5, 4);
    md5pos = 9;
  }
#if OLDBATV
  else if(address->len >= (11+2*BATVLEN) && str_starts(address, "prvs=")) {
    int reallen = address->len;

    atpos = str_findlast(address, '@');
    address->len = atpos;		/* just for a moment */
    slpos = str_findlast(address, '=');
    address->len = reallen;
    if((slpos+5+2*BATVLEN) != atpos) return 0; /* no = in the right place */
    memcpy(kdate, address->s+slpos+1, 4);
    md5pos = slpos+5;
    oldfmt = 1;
  } 
#endif /* OLDBATV */
  else return 0;		/* no BATV */

  clock_gettime(CLOCK_REALTIME, &ts);
  daynumber = (ts.tv_sec / 86400) % 1000;

  if(kdate[0] != '0') return 0;	/* not known format 0 */
  signday = atoi(kdate+1);
  if(((unsigned)(daynumber-signday))%1000 > BATVSTALE) return 0; /* stale bounce */

  /* get signkey */
  if(!signkey.s) {
    const char *qh;
    ibuf sebuf;

    if ((qh = getenv("QMAILHOME")) == 0)
      qh = conf_qmail;
    if (chdir(qh) == -1) return 0; /* no BATV today */
    if(!ibuf_open(&sebuf, "control/signenv", 0)) return 0;
    str_init(&signkey);
    ibuf_getstr_crlf(&sebuf, &signkey);
    ibuf_close(&sebuf);
    if(!signkey.len) return 0;	/* no key there */
  }

  MD5_Init(&md5);
  MD5_Update(&md5, kdate, 4);
#if OLDBATV
  if(oldfmt) {
    MD5_Update(&md5, address->s+5, slpos-5);
    MD5_Update(&md5, address->s+atpos, address->len-atpos);
  } else {
#endif /* OLDBATV */
    MD5_Update(&md5, address->s+10+2*BATVLEN, address->len-(10+2*BATVLEN));
#if OLDBATV
  }
#endif /* OLDBATV */
  MD5_Update(&md5, signkey.s, signkey.len);
  MD5_Final(md5digest, &md5);

  for(i = 0; i < BATVLEN; i++) {
    int c, x;

    c = address->s[md5pos+2*i];

    if(isdigit(c)) x = c-'0';
    else if(c >= 'a' && c <= 'f') x = 10+c-'a';
    else if(c >= 'A' && c <= 'F') x = 10+c-'A';
    else return 0;
  
    c = address->s[md5pos+1+2*i];
    x <<= 4;

    if(isdigit(c)) x += c-'0';
    else if(c >= 'a' && c <= 'f') x += 10+c-'a';
    else if(c >= 'A' && c <= 'F') x += 10+c-'A';
    else return 0;

    if(x != md5digest[i]) return 0;
  }

  /* peel off the signature */
#if OLDBATV
  if(oldfmt) {
    memcpy(address->s, address->s+5, slpos-5); /* mailbox */
    memcpy(address->s+slpos-5, address->s+atpos, 1+address->len-atpos);
  } else {
#endif /* OLDBATV */
    memcpy(address->s, address->s+10+2*BATVLEN, address->len-(10+2*BATVLEN));
#if OLDBATV
  }
#endif /* OLDBATV */
  str_rcut(address, 10+2*BATVLEN);
  msg2("recipient is ",address->s);
  return 1;  
}

static const response* batv_recipient(str* recipient)
{
  str domstr;
  int i;

  if(bvunwrap(recipient)) return 0; /* it was signed, we're done */
  if(!isbounce) return 0;	/* not a bounce, we're done */

  /* check if it's a domain that accepts unsigned bounces */
  if(!nsdloaded) {
    const char* qh;

    if ((qh = getenv("QMAILHOME")) == 0)
      qh = conf_qmail;
    if (chdir(qh) == -1) return &resp_no_chdir;
    if (!dict_load_list(&nosigndoms, "control/nosigndoms", 0, 0))
      return &resp_internal;
    nsdloaded = 1;
  }
  str_init(&domstr);
  i = str_findlast(recipient, '@');
  if(i < 0) return 0;		/* no domain, huh? */
  i++;
  str_copyb(&domstr, recipient->s+i, recipient->len-i);
  if(dict_get(&nosigndoms, &domstr)) return 0; /* unsigned OK */

  session_setnum("badbatv", 1);
  return &resp_batv;
}

struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = 0,
  .sender = batv_sender,
  .recipient = batv_recipient,
};
