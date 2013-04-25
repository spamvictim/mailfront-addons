/* 
 * Greylist via daemon
 * Daemon address in GREYIP
 *
 * Has to come after anything else that might reject a recipient
 * But before anything else that might accept one
 */

#include <stdlib.h>
#include <unistd.h>

#include "mailfront.h"
#include <net/socket.h>

static str greymsg;
static int hasgreyrcpt = 0;
static int greysocket;
static ipv4addr greyaddr;
static ipv4port greyport = 1999;

static RESPONSE(grey,451,"4.4.5 Try again later.");

/* collect envelope info for later query */

static const response* grey_sender(str* sender, str* param)
{
  hasgreyrcpt = 0; 

  if(!str_copy2s(&greymsg, "I", getprotoenv("REMOTEIP"))
     || !str_catc(&greymsg, 0)
     || !str_cat2s(&greymsg, "F", sender->s)
     || !str_catc(&greymsg, 0)) return &resp_oom;
  return 0;
  (void)param;
}

static const response* grey_recipient(str* recipient, str* param)
{
  if(session_getnum("sump", 0)) return 0; /* known spam, don't bother */
  hasgreyrcpt++;
  if(!str_cat2s(&greymsg, "T", recipient->s)
     || !str_catc(&greymsg, 0)) return &resp_oom;
  return 0;
  (void)param;
}

static const response* grey_data_start(int fd)
{
  fd_set fs;
  struct timeval fst;
  int r;
  char rbuf[2];
  ipv4addr raddr;
  ipv4port rport;

  if(!hasgreyrcpt) return 0;	/* nothing to delay */

  if(!greysocket) {
    char *greyip = getenv("GREYIP");

    if(!greyip) return 0;
    if(!ipv4_scan(greyip, &greyaddr)) return 0;

    if((greysocket = socket_udp4()) < 0) return 0;
  }

  if(!socket_send4(greysocket, greymsg.s, greymsg.len,
     &greyaddr, greyport)) return 0;
  
  /* don't wait very long */
  FD_ZERO(&fs);
  FD_SET(greysocket, &fs);
  fst.tv_sec = 3; fst.tv_usec = 0;
  r = select(greysocket+1, &fs, NULL, NULL, &fst);
  if(r <= 0) { close(greysocket); greysocket = 0; return 0; }

  r = socket_recv4(greysocket, rbuf, sizeof rbuf, &raddr, &rport);

  if(r > 0 && rbuf[0] == 0) {
    session_setnum("greylist", 1);
    return &resp_grey; /* greylist */
  }
  
  return 0;
  (void)fd;
}

struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = 0,
  .sender = grey_sender,
  .recipient = grey_recipient,
  .data_start = grey_data_start,
};
