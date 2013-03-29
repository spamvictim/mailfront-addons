/*
 * Run the message through spamassassin via spamd
 * Socket name in SA_SOCKET, max message size to filter in SA_MAXSIZE
 * don't do it if in sump mode
 * Take user name from session "username"
 * Optional list of nofilter users in control/nosafilter
 */

#include <unistd.h>
#include <string.h>
#include "mailfront.h"
#include <net/socket.h>
#include <iobuf/ibuf.h>
#include <iobuf/obuf.h>
#include <msg/msg.h>
#include "conf_qmail.c"
#include <dict/dict.h>
#include <dict/load.h>

static dict sanf;
static str sasender;

static RESPONSE(no_chdir,451,"4.3.0 Could not change to the qmail directory.");

/* remember the envelope */
static const response* sa_sender(str* sender)
{
  if(!str_copy(&sasender, sender))return &resp_oom;

  return 0;
}

/* now run it through spamd, and recopy to a new file */
static const response* sa_message_end(int fd)
{
  char *sockname = getenv("SA_SOCKET");
  char *sa_maxsize = getenv("SA_MAXSIZE");
  char *nosa = getenv("NOSPAMASSASSIN");
  int maxsize = 700000;
  const char *s;
  const char* qh;
  int sockfd;
  int newfd;
  obuf saob;
  ibuf saib;
  ibuf msgib;
  obuf newob;
  unsigned bodystart = 0;
  str msgstr;

  if(!sockname) return 0;

  str_init(&msgstr);

  /* see if this is worth doing */
  if(nosa) {
    msg1("Skip spamassassin");
    return 0;			/* we already know about this, don't bother */
  }
  if(session_getnum("sump", 0)) return 0; /* known spam, don't bother */

  if(sa_maxsize) maxsize = atoi(sa_maxsize);
  if(lseek(fd, 0, SEEK_CUR) > maxsize) return 0; /* too big */

  s = session_getstr("username");
  if(s) {
    if ((qh = getenv("QMAILHOME")) == 0)
      qh = conf_qmail;
    if (chdir(qh) == -1) return &resp_no_chdir;
    if (!dict_load_list(&sanf, "control/nosafilter", 0, 0))
      return &resp_internal;
    str_copys(&msgstr, s);
    if(dict_get(&sanf, &msgstr)) {
      msg2("no sa for ", s);
      return 0; /* don't do sa for this user */
    }
  }

  if((newfd = scratchfile()) == -1) return &resp_internal;
  obuf_init(&newob, newfd, 0, 0, 0);

  if(!(sockfd = socket_unixstr())) return 0;
  if(!socket_connectu(sockfd, sockname)) return 0;
  obuf_init(&saob, sockfd, 0, 0, 0);

  /* now send the control header */
  if(!obuf_puts(&saob, "HEADERS SPAMC/1.4\r\n")) return &resp_internal;
  if(s && !obuf_put3s(&saob, "User: ", s, "\r\n")) return &resp_internal;
  if(!obuf_puts(&saob, "\r\n")) return &resp_internal;

  /* send it a return path for a hint about the sender */
  if(!obuf_put3s(&saob, "Return-Path: <", sasender.s, ">\r\n")) return &resp_internal;

  /* can't use ibuf_rewind, it thinks it's already there */
  if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
  ibuf_init(&msgib, fd, 0, 0, 0);

  /* copy msg to sa, remember where the body started */
  while(ibuf_getstr(&msgib, &msgstr, LF)) {
    if(!bodystart) { /* in header */
      if(msgstr.s[0] == LF) bodystart = ibuf_tell(&msgib);
    }
    /* LF -> CRLF */
    if(!obuf_write(&saob, msgstr.s, msgstr.len-1)
       || !obuf_write(&saob, "\r\n", 2)) return &resp_internal;
  }
  obuf_flush(&saob);

  /* shutdown output and see what happened */
  socket_shutdown(sockfd, 0, 1);
  ibuf_init(&saib, sockfd, 0, 0, 0);

  /* summary */
  if(!ibuf_getstr_crlf(&saib, &msgstr)) return &resp_internal;
  if(!str_globs(&msgstr, "SPAMD*EX_OK")) return &resp_internal;

  /* loop over status lines */
  while(ibuf_getstr_crlf(&saib, &msgstr)) {
    if(!msgstr.len) break;
    if(str_starts(&msgstr, "Spam:")) {
      msg2("sa said ",msgstr.s);

      /* extract spamfulness stats some day */
    }
  }

  /* throw away our return-path, qmail will add its own */
  if(ibuf_getstr_crlf(&saib, &msgstr) &&
     !str_starts(&msgstr, "Return-Path:")) {
    if(!obuf_putstr(&newob, &msgstr)
       || !obuf_putc(&newob, LF)) return &resp_internal;
  }

  /* copy new header to new msg */
  while(ibuf_getstr_crlf(&saib, &msgstr)) {
    if(!obuf_putstr(&newob, &msgstr)
       || !obuf_putc(&newob, LF)) return &resp_internal;
  }

  if(bodystart) {
    ibuf_seek(&msgib, bodystart);
    if(!iobuf_copy(&msgib, &newob)) return &resp_internal;
  }
  obuf_flush(&newob);

  /* now replace the temp file */
  dup2(newfd, fd);
  close(newfd);

  return 0;
}

struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = FLAG_NEED_FILE,
  .sender = sa_sender,
  .message_end = sa_message_end,
};
