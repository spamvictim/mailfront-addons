/*
 * Create Authentication-Results: header
 * and log it
 * Check DKIM signatures if any
 * Check SPF, too
 *
 * Needs to run with sqlog to assign sqlseq
 *******************************
CREATE TABLE mailspf (
  serial int(7) unsigned NOT NULL,
  result enum('neutral','pass','fail','softfail','none','temperror','permerror')
      NOT NULL DEFAULT 'none', -- matches response_t result values
  helo varchar(255),
  sender varchar(255), -- from header
  PRIMARY KEY (serial)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE maildkim (
  serial int(7) unsigned NOT NULL,
  result enum('pass','failhdr','failbody') NOT NULL,
  domain varchar(255),
  sigstr varchar(255),	-- header.b value in A-R
  KEY (serial),
  KEY (domain)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

*/

#include <unistd.h>
#include <string.h>
#include "mailfront.h"
#include <iobuf/ibuf.h>
#include <iobuf/obuf.h>
#include <msg/msg.h>

#include <opendkim/dkim.h>

/* way too much junk for SPF */
# include <sys/socket.h>   /* inet_ functions / structs */
# include <netinet/in.h>   /* inet_ functions / structs */
# include <arpa/inet.h> /* in_addr struct */

#include <spf2/spf.h>

extern int opendb(void);
extern int newsqlmsg(void);
extern int sqlquote(str *in, str *out);
extern int sqlquery(str *query, unsigned int *seqno);

static str arstr = { 0, 0};		/* authentication results header */

static str spf_sresponse = {0, 0 };	/* save for sql later */

static const response* arlog_sender(str* sender)
{
	SPF_server_t *spf_server;
	SPF_request_t *spf_request;
	SPF_response_t *spf_response;
	const char *ip;
	const char *helo;
	
	spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	if(!spf_server) return 0;
	spf_request = SPF_request_new(spf_server);

	ip = getprotoenv("REMOTEIP");
	if(!ip) return 0;		/* can't tell IP, no SPF */

	if(strchr(ip, ':'))
	   SPF_request_set_ipv6_str( spf_request, ip);
	else
		SPF_request_set_ipv4_str( spf_request, ip );

	helo = session_getstr("helo_domain");
	SPF_request_set_helo_dom( spf_request, helo);
	SPF_request_set_env_from( spf_request, sender->s);

	SPF_request_query_mailfrom(spf_request, &spf_response);
	str_init(&spf_sresponse);
	str_copys(&spf_sresponse, SPF_strresult(SPF_response_result(spf_response)));

	if(!arstr.s) str_init(&arstr);
	str_cat2s(&arstr, "; spf=", spf_sresponse.s);
	str_cat4s(&arstr, " spf.mailfrom=", sender->s, " spf.helo=", helo);
	
	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	SPF_server_free(spf_server);

	return 0;
}

/* now run it through opendkim, and recopy with a-r header to a new file */
/* and add the sql records */
static const response* arlog_message_end(int fd)
{
	DKIM_LIB *dl;
	DKIM *dk;
	DKIM_STAT ds;

	int newfd;
	ibuf msgib;
	obuf newob;
	str msgstr, matchstr;
	str sqlstr;
	int sump = session_getnum("sump", 0);
	DKIM_SIGINFO **sigs;
	int nsigs;
	unsigned int opts = DKIM_LIBFLAGS_FIXCRLF;
	unsigned int sqlseq;
	const char *fromdom;
	const char *host = getprotoenv("LOCALHOST");

	if(!host) host = "localhost";

	dl = dkim_init(NULL, NULL);
	if(!dl) {
		msg1("dkim_init failed");
		return 0;
	}
	ds = dkim_options(dl, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS, &opts, sizeof(opts));
	if(ds != DKIM_STAT_OK) {
		msg2("dkim_options failed: ", dkim_getresultstr(ds));
		return 0;
	}

	dk = dkim_verify(dl, "msg", NULL, &ds);
	if(!dk) {
		msg2("dkim_verify failed: ", dkim_getresultstr(ds));
		return 0;
	}

	/* can't use ibuf_rewind, it thinks it's already there */
	if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
	ibuf_init(&msgib, fd, 0, 0, 0);

	/* send the message as chunks */
	str_init(&msgstr);
	str_init(&matchstr);
	str_copy3s(&matchstr, "Authentication-Results:*",host,"*"); /* close enough */
	while(ibuf_getstr(&msgib, &msgstr, LF)) {
		/* check for existing A-R header from us and delete it */
		if(str_case_match(&msgstr, &matchstr)) continue;

		ds = dkim_chunk(dk, msgstr.s, msgstr.len);
		if(ds != DKIM_STAT_OK) {
			if(ds != DKIM_STAT_NOSIG)
				msg2("dkim_chunk failed: ", dkim_getresultstr(ds));
			break;
		}
	}
	str_free(&msgstr);
	dkim_chunk(dk, NULL, 0);
	ds = dkim_eom(dk, NULL);

	fromdom = dkim_getdomain(dk);

	ds = dkim_getsiglist(dk, &sigs, &nsigs);
	if(ds != DKIM_STAT_OK) {
		msg2("dkim_getsiglist failed: ", dkim_getresultstr(ds));
		nsigs = 0;	/* continue to add A-R and sql logs */
	}

	/* do the spf */
	sqlseq = session_getnum("sqlseq", 0L); /* if set, mysql is
						open and serial	assigned */
	if(!str_init(&sqlstr)) return &resp_internal;
	if(sqlseq > 0) {
		const char *helo = session_getstr("helo_domain");

		if(!str_copys(&sqlstr, "INSERT INTO mailspf SET serial=")
		   || !str_catu(&sqlstr, sqlseq)) return &resp_internal;
		if(spf_sresponse.s)
			if(!str_cat3s(&sqlstr, ",result='",spf_sresponse.s,"'")) return &resp_internal;
		if(helo)
			if(!str_cat3s(&sqlstr, ",helo='",helo,"'")) return &resp_internal;
		if(fromdom)
			if(!str_cat3s(&sqlstr, ",sender='",fromdom,"'")) return &resp_internal;

		/* msg2("sql ", sqlstr.s); */
		sqlquery(&sqlstr, NULL);
	} else
		msg2("no sqlseq ", fromdom);

	if(nsigs > 0) {
		int i;

		if(!arstr.s) str_init(&arstr);

		const char *helo = session_getstr("helo_domain");

		for(i = 0; i < nsigs; i++) {
			DKIM_SIGINFO *sp = sigs[i];
			DKIM_STAT dss = dkim_sig_process(dk, sp);

			if(dss == DKIM_STAT_OK) {
				const char *d;
				unsigned int fl = dkim_sig_getflags(sp);
				char hashbuf[20];
				size_t hblen;

				if(!str_copys(&sqlstr, "INSERT INTO maildkim SET serial=")
				   || !str_catu(&sqlstr, sqlseq)) return &resp_internal;

				if(fl & DKIM_SIGFLAG_PASSED) {
					if(dkim_sig_getbh(sp) == DKIM_SIGBH_MATCH) {
						str_cats(&arstr, "; dkim=pass");
						str_cats(&sqlstr, ",result='pass'");
					} else {
						str_cats(&arstr, "; dkim=fail (bad body hash)");
						str_cats(&sqlstr, ",result='failbody'");
					}
				} else {
					str_cats(&arstr, "; dkim=fail (bad signature)");
					str_cats(&sqlstr, ",result='failhdr'");
				}
				d = dkim_sig_getdomain(sp);
				if(d) {
					str_cat2s(&arstr, " header.d=", d);
					str_cat3s(&sqlstr, ",domain='", d, "'");
				}

				hblen = sizeof(hashbuf)-1;
				hashbuf[hblen] = 0; /* ensure null term */
				ds = dkim_get_sigsubstring(dk, sp, hashbuf, &hblen);
				if(ds == DKIM_STAT_OK) {
					str_cat3s(&arstr, " header.b=\"", hashbuf, "\"");
					str_cat3s(&sqlstr, ",sigstr='", hashbuf, "'");
				}
				/* msg2("sql ", sqlstr.s); */
				sqlquery(&sqlstr, NULL);
			}
		}
	}

	str_free(&sqlstr);

	dkim_free(dk);
	dkim_close(dl);

	if(sump) return 0;	/* done, no a-r header, or it's a sump message */
	if(!arstr.len) {
		msg2("no ","arstr");
		return 0;
	}
	if((newfd = scratchfile()) == -1) return &resp_internal;
	obuf_init(&newob, newfd, 0, 0, 0);
	if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
	ibuf_init(&msgib, fd, 0, 0, 0);

	obuf_put3s(&newob, "Authentication-Results: ", host, " / 1");
	obuf_putstr(&newob, &arstr);
	obuf_putc(&newob, '\n');
	if(!iobuf_copyflush(&msgib, &newob)) return &resp_internal;

	/* now replace the temp file */
	dup2(newfd, fd);
	close(newfd);
	msg4("Authentication-Results: ", host, " / 1", arstr.s);

	return 0;
}

struct plugin plugin = {
	.version = PLUGIN_VERSION,
	.flags = FLAG_NEED_FILE,
	.sender = arlog_sender,
	.message_end = arlog_message_end,
};
