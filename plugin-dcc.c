/*
 * Run the message through DCC via dccifd
 * Socket name in DCC_SOCKET
 */

#include <unistd.h>
#include <string.h>
#include "mailfront.h"
#include <net/socket.h>
#include <iobuf/ibuf.h>
#include <iobuf/obuf.h>
#include <msg/msg.h>

static str dccsender;
static str dccrecips;

/* remember the envelope */
static const response* dcc_sender(str* sender)
{
  if(!str_copy(&dccsender, sender))return &resp_oom;
  str_init(&dccrecips);

  return 0;
}

static const response* dcc_recipient(str* recipient)
{
  const char *s = 0;

  if(!dccrecips.len) {		/* first one */
    s = session_getstr("username");
  }
  if(!str_cats(&dccrecips, recipient->s)) return &resp_oom;
  if(s && !str_cat2s(&dccrecips, "\r", s)) return &resp_oom;
  if(!str_catc(&dccrecips, LF)) return &resp_oom;

  return 0;
}

/* now run it through DCC, and recopy to a new file */
static const response* dcc_message_end(int fd)
{
  char *sockname = getenv("DCC_SOCKET");
  unsigned bodystart = 0;		/* offset of message body */
  const char *s;
  int sockfd;
  int newfd;
  obuf dccob;
  ibuf dccib;
  ibuf msgib;
  obuf newob;
  str msgstr;
  str retstr;
  int sump = session_getnum("sump", 0);


  if(!sump && (newfd = scratchfile()) == -1) return &resp_internal;

  if(!sockname) return 0;

  if(!(sockfd = socket_unixstr())) return 0;
  if(!socket_connectu(sockfd, sockname)) return 0;
  obuf_init(&dccob, sockfd, 0, 0, 0);
  if(!sump) obuf_init(&newob, newfd, 0, 0, 0);

  /* now send the DCC header */
  /* control info */
  if(sump) obuf_puts(&dccob, "spam ");
  obuf_puts(&dccob, "header\n");

  /* client */
  obuf_put4s(&dccob, getprotoenv("REMOTEIP"), "\r", getprotoenv("REMOTEHOST"), "\n");

  /* HELO or null */
  s = session_getstr("helo_domain");
  if(s) obuf_puts(&dccob, s);
  obuf_putc(&dccob, LF);

  /* sender */
  obuf_putstr(&dccob, &dccsender);
  obuf_putc(&dccob, LF);

  /* recipients */
  obuf_putstr(&dccob, &dccrecips);
  obuf_putc(&dccob, LF);

  /* now blat out the whole message */

  /* can't use ibuf_rewind, it thinks it's already there */
  if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
  ibuf_init(&msgib, fd, 0, 0, 0);

  str_init(&msgstr);
  str_init(&retstr);

  /* copy header to dcc and new msg, discard existing X-DCC */
  /* copy body to dcc */
  while(ibuf_getstr(&msgib, &msgstr, LF)) {
    if(!bodystart) { /* in header */
      if(str_starts(&msgstr, "X-DCC-")) continue;
      if(msgstr.s[0] == LF) bodystart = ibuf_tell(&msgib);
      else if(!sump) obuf_putstr(&newob, &msgstr);
    }
    obuf_putstr(&dccob, &msgstr);
  }
  obuf_flush(&dccob);

  /* shutdown output and see what happened */
  socket_shutdown(sockfd, 0, 1);
  ibuf_init(&dccib, sockfd, 0, IOBUF_NEEDSCLOSE, 0);

  /* summary */
  if(!ibuf_getstr(&dccib, &retstr, LF)) return &resp_internal;
  str_rstrip(&retstr);
  msg2("dcc said ",retstr.s);

  /* per recipient */
  if(!ibuf_getstr(&dccib, &retstr, LF)) return &resp_internal;

  /* new X-DCC line */
  if(!ibuf_getstr(&dccib, &retstr, LF)) return &resp_internal;
  ibuf_close(&dccib);

  if(sump) return 0;	     /* no new info if we said spam, no rewrite */

  obuf_putstr(&newob, &retstr);
  obuf_putc(&newob, LF);	/* end of header */

  if(bodystart) {
    ibuf_seek(&msgib, bodystart);
    if(!iobuf_copyflush(&msgib, &newob)) return &resp_internal;
  }

  /* now replace the temp file */
  dup2(newfd, fd);
  close(newfd);

  return 0;
}


struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = FLAG_NEED_FILE,
  .sender = dcc_sender,
  .recipient = dcc_recipient,
  .message_end = dcc_message_end,
};
