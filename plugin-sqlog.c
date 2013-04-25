/* 
 * Log statistics in a mysql database
 * also provides Received: line with id of mysql record
 *
 * mysql interface routines in separate module sqllib due to symbol
 * collisions
 * *******************************

CREATE TABLE mail (
  serial int(7) unsigned NOT NULL AUTO_INCREMENT,
  server int(10) unsigned DEFAULT NULL,
  server6 binary(16) DEFAULT NULL,
  mailtime timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  sourceip int(10) unsigned DEFAULT NULL,
  sourceip6 binary(16) DEFAULT NULL,
  spamserial int(7) unsigned DEFAULT NULL,
  flags set('greylist','sump','spam','virus','badabuse','badrcpt','badbatv','dnsbl','dblhelo','dblfrom') NOT NULL,
  mailfrom varchar(255) NOT NULL,
  envdomain varchar(255) DEFAULT NULL,
  PRIMARY KEY (serial),
  KEY mailtime (mailtime),
  KEY sourceip (sourceip),
  KEY sourceip6 (sourceip6),
  KEY envdomain (envdomain)
) ENGINE=MyISAM AUTO_INCREMENT=100 DEFAULT CHARSET=latin1;

CREATE TABLE mailrcpt (
  serial int(7) unsigned NOT NULL,
  rcptto varchar(255) NOT NULL,
  KEY serial (serial),
  KEY rcptto (rcptto)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

*****************/

#include <systime.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h> 
#include <msg/msg.h>
#include "mailfront.h"

static unsigned int sqlseq;
static str sqlseqstr;

static str received;

static const char* linkproto;
static const char* local_host;
static const char* local_ip;
static const char* local_port;
static const char* remote_host;
static const char* remote_ip;
static const char* remote_port;

static void dosqlog(void);

extern int opendb(void);
extern int newsqlmsg(void);
extern int sqlquote(str *in, str *out);
extern int sqlquery(str *query, unsigned int *seqno);

static str qsender;
static str qrecips;

static const response* get_seq(void);

/* open the connection */
static const response* sq_sender(str* sender, str* params)
{
  if(!opendb()) return &resp_internal;
  const response *r;
  
  if(sqlseq) {			/* dump the previous one */
    dosqlog();
    sqlseq = 0;
    session_delnum("sqlseq");
  }

  r = get_seq();
  if(r) return r;		/* seq error */

  str_copy(&qsender, sender);
  str_init(&qrecips);

  return 0;
  (void)params;
}

static const response* sq_recipient(str* recipient, str* params)
{
  str_cat(&qrecips, recipient);
  str_catc(&qrecips, 0);

  return 0;
  (void)params;
}

/* from plugin-add-received */
static const char* date_string(void)
{
  static char datebuf[64];
  struct timeval tv;
  struct tm* tm;

  gettimeofday(&tv, NULL);
  tm = gmtime(&tv.tv_sec);
  strftime(datebuf, sizeof datebuf - 1, "%d %b %Y %H:%M:%S -0000", tm);
  return datebuf;
}

static int str_catfromby(str* s, const char* helo_domain,
			 const char* host, const char* ip)
{
  int c;

  if (helo_domain == 0)
    helo_domain = (host != 0 && *host != 0) ? host : (ip != 0) ? ip : UNKNOWN;
  while((c = *helo_domain++) != 0) {
    if(!str_catc(s, (isalnum(c) || (c == '.') || (c == '-'))? c:'_')) return 0;
  }
  /* if (!str_cats(s, helo_domain)) return 0; */
  if (host != 0 || ip != 0) {
    if (!str_cats(s, " (")) return 0;
    if (host != 0) {
      if (!str_cats(s, host)) return 0;
      if (ip != 0)
	if (!str_catc(s, ' ')) return 0;
    }
    if (ip != 0) {
      if (!str_catc(s, '[')) return 0;
      if(strchr(ip, ':') && !str_cats(s, "IPV6:")) return 0;
      if( !str_cats(s, ip) ||
	  !str_catc(s, ']'))
	return 0;
    }
    if (!str_catc(s, ')')) return 0;
  }
  return 1;
}

static int build_received(str* s, str *seqno)
{
  if (!str_cats(s, "Received: from ")) return 0;
  if (!str_catfromby(s, session_getstr("helo_domain"),
		     remote_host, remote_ip))
    return 0;
  if (!str_cats(s, "\n  by ")) return 0;
  if (!str_catfromby(s, local_host, 0, local_ip)) return 0;
  if (!str_cat4s(s, "\n  with ", session_protocol(),
		 " via ", linkproto))
    return 0;
  if (!str_cat4s(s, " port ", remote_port, "/", local_port)) return 0;
  if (!str_cat2s(s, " id ", seqno->s)) return 0;
  if (!str_cat3s(s, "; ", date_string(), "\n")) return 0;
  return 1;
}

static const response* sq_init(void)
{
  linkproto = getprotoenv(0);
  local_ip = getprotoenv("LOCALIP");
  remote_ip = getprotoenv("REMOTEIP");
  local_host = getprotoenv("LOCALHOST");
  remote_host = getprotoenv("REMOTEHOST");
  remote_port = getprotoenv("REMOTEPORT");
  local_port = getprotoenv("LOCALPORT");

  if(!local_ip) local_ip = "0.0.0.0";
  if(!remote_port) remote_port = "??";

  atexit(dosqlog);

  return 0;
}

static const response* get_seq(void)
{
  str sql;

  str_init(&sql);
  /* do IPv6 differently */
  if(strchr(remote_ip, ':')) {
    if(!str_copy5s(&sql,
		   "INSERT INTO mail SET serial=NULL,mailtime=NULL,server6=INET_PTO6('",
		   local_ip,
		   "'),sourceip6=INET_PTO6('",
		   remote_ip,
		   "')")) return &resp_internal;
  } else {
    if(!str_copy5s(&sql,
		   "INSERT INTO mail SET serial=NULL,mailtime=NULL,server=INET_ATON('",
		   local_ip,
		   "'),sourceip=INET_ATON('",
		   remote_ip,
		   "')")) return &resp_internal;
  }
  
  if(!sqlquery(&sql, &sqlseq)
     || !str_init(&sqlseqstr)
     || !str_catu(&sqlseqstr, sqlseq)) return &resp_internal;
  
  msg2("assigned seq ",sqlseqstr.s);
  session_setnum("sqlseq", (unsigned long)sqlseq);

  return 0;
}

static const response* sq_data_start(int fd)
{
  received.len = 0;
  if (!build_received(&received, &sqlseqstr))
    return &resp_internal;
  return backend_data_block(received.s, received.len);
  (void)fd;
}

static const response* sq_message_end(int fd)
{
  return 0;
  (void)fd;
}

static str mflags;

static void addflag(const char *var, const char* flag, int reset)
{
  if(!session_getnum(var, 0)) return;

  if(reset) session_delnum(var);

  if(mflags.len) str_cats(&mflags, ",");
  str_cats(&mflags, flag);

}

/* actually do the log entry */
static void dosqlog(void)
{
  str sql;
  str mq, mr, md;
  unsigned int i, ni;

  if(!sqlseq) return;		/* nothing happened */

  str_init(&sql);
  str_init(&mq);
  str_init(&mr);
  str_init(&mflags);
  addflag("greylist", "greylist", 1);
  addflag("sump", "sump", 0);
  addflag("dblhelo", "dblhelo", 0);
  addflag("dblfrom", "dblfrom", 1);
  addflag("badrcpt", "badrcpt", 1);
  addflag("badbatv", "badbatv", 1);
  addflag("rcptrule", "badabuse", 1);

  str_copys(&sql, "update mail set flags='");
  str_cat(&sql, &mflags);
  sqlquote(&qsender, &mq);
  str_cats(&sql, "',mailfrom='");
  str_cat(&sql, &mq);
  /* envelope domain */
  i = str_findfirst(&qsender, '@');
  if(i < qsender.len) {
    str_init(&md);
    str_copyb(&md, qsender.s+i+1, qsender.len-i-1);
    sqlquote(&md, &mq);
    str_cats(&sql, "',envdomain='");
    str_cat(&sql, &mq);
  }
  str_cats(&sql, "' where serial=");
  str_cat(&sql, &sqlseqstr);
  sqlquery(&sql, 0);

  /* now add the recipients */
  for(i = 0; i < qrecips.len ; i = ni+1) {
    ni = str_findnext(&qrecips, 0, i);

    str_copyb(&mr, qrecips.s+i, ni-i);
    sqlquote(&mr, &mq);
    str_copys(&sql,"insert into mailrcpt(serial,rcptto) values(");
    str_cat(&sql, &sqlseqstr);
    str_cats(&sql, ",'");
    str_cat(&sql, &mq);
    str_cats(&sql, "')");
    sqlquery(&sql, 0);
  }
}

/* Plugins must export this structure.
 * Remove any of the entries that are not used (ie 0 or NULL).
 */
struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = 0,
  .init = sq_init,
  .sender = sq_sender,
  .recipient = sq_recipient,
  .data_start = sq_data_start,
  .message_end = sq_message_end,
};
