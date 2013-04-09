/*
 * Create Authentication-Results: header
 * authserv-id in A-R header is env AUTHSERVID,
 * defaulting to TCPLOCALHOST
 * and log it in a SQL database
 * Check DKIM signatures if any
 * Check SPF, too
 * env DMARCREJECT=y means actually do reject
 * env DMARCRUF means @virtdom for DMARC failure reports
 * file control/nodmarcpolicy lists domains not to reject
 * note that reject just sets a flag, needs code in backend-qmailsump
 * to do the rejection after maybe queueing for failure report
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

CREATE TABLE maildmarc (
  serial int(7) unsigned NOT NULL,
  result enum('absent','pass','fail.none','fail.reject','fail.quarantine') NOT NULL,
  domain varchar(255),
  PRIMARY KEY (serial),
  KEY (domain)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include "mailfront.h"
#include "conf_qmail.c"
#include <iobuf/ibuf.h>
#include <iobuf/obuf.h>
#include <msg/msg.h>
/* HACK HACK */
#undef CLOCK_REALTIME
#undef CLOCK_MONOTONIC
#include <dict/dict.h>
#include <dict/load.h>

#include <opendkim/dkim.h>

/* way too much junk for SPF */
# include <sys/socket.h>   /* inet_ functions / structs */
# include <netinet/in.h>   /* inet_ functions / structs */
# include <arpa/inet.h> /* in_addr struct */

#include <spf2/spf.h>
#include <opendmarc/dmarc.h>

extern int opendb(void);
extern int newsqlmsg(void);
extern int sqlquote(str *in, str *out);
extern int sqlquery(str *query, unsigned int *seqno);

static str arstr = { 0, 0};		/* authentication results header */

static str spf_sresponse = {0, 0 };	/* save for sql later */

static int spf_result;					/* for DMARC */
static str spf_domain = { 0, 0 };		/* for DMARC */

static RESPONSE(no_chdir,451,"4.3.0 Could not change to the qmail directory.");
static RESPONSE(nodmarc,550,"5.7.1 DMARC policy failure");

static dict dmnp;

static const response* arlog_sender(str* sender)
{
	SPF_server_t *spf_server;
	SPF_request_t *spf_request;
	SPF_response_t *spf_response;
	const char *ip;
	const char *helo;
	
	ip = getprotoenv("REMOTEIP");
	if(!ip) return 0;		/* can't tell IP, no SPF */

	spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	if(!spf_server) return 0;
	spf_request = SPF_request_new(spf_server);

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
	
	/* for DMARC later */
	if(!spf_domain.s) str_init(&spf_domain);
	str_copys(&spf_domain, sender->s);
	switch (SPF_response_result(spf_response)) {
		default: spf_result = DMARC_POLICY_SPF_OUTCOME_NONE; break;
		case SPF_RESULT_PASS: spf_result = DMARC_POLICY_SPF_OUTCOME_PASS; break;
		case SPF_RESULT_PERMERROR: 
		case SPF_RESULT_NEUTRAL: 
		case SPF_RESULT_SOFTFAIL: 
		case SPF_RESULT_FAIL: spf_result = DMARC_POLICY_SPF_OUTCOME_FAIL; break;
		case SPF_RESULT_TEMPERROR: spf_result = DMARC_POLICY_SPF_OUTCOME_TMPFAIL; break;
	}

	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	SPF_server_free(spf_server);

	return 0;
}

/* now run it through opendkim and opendmarc, and recopy with a-r header to a new file */
/* and add the sql records */
static const response* arlog_message_end(int fd)
{
	DKIM_LIB *dl;
	DKIM *dk;
	DKIM_STAT ds;
	DKIM_SIGINFO **sigs;
	unsigned int opts = DKIM_LIBFLAGS_FIXCRLF;
	OPENDMARC_LIB_T dmarclib = {
		.tld_type = OPENDMARC_TLD_TYPE_MOZILLA,
		.tld_source_file = "control/effective_tld_names.dat"
	};
	DMARC_POLICY_T *dmp;
	OPENDMARC_STATUS_T dms;

	int newfd;
	ibuf msgib;
	obuf newob;
	str msgstr, matchstr;
	str sqlstr;
	int sump = session_getnum("sump", 0);
	int nsigs;
	int doreject = 0;	/* DMARC results */
	int doquarantine = 0;
	int dofail = 0;
	unsigned int sqlseq;
	const char *authservid = getenv("AUTHSERVID");
	const char *ip = getprotoenv("REMOTEIP");
	const char *dmrm = getenv("DMARCREJECT");
	const char *helo;
	str fromdom = {0, 0};             /* from domain name */
	const char *qh;

	if(!authservid) authservid = getprotoenv("LOCALHOST");
	if(!authservid) authservid = "localhost";

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
	str_copy3s(&matchstr, "Authentication-Results:*",authservid,"*"); /* close enough */
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
	dkim_chunk(dk, NULL, 0);
	ds = dkim_eom(dk, NULL);

	str_init(&fromdom);
	qh = dkim_getdomain(dk);
	if(qh)str_copys(&fromdom, qh);

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
		if(fromdom.len)
			if(!str_cat3s(&sqlstr, ",sender='",fromdom.s,"'")) return &resp_internal;

		/* msg2("sql ", sqlstr.s); */
		sqlquery(&sqlstr, NULL);
	} else
		msg2("no sqlseq ", fromdom.s);

	/* check dmarc policy if there's anything to check */
	if(fromdom.len) {
		if ((qh = getenv("QMAILHOME")) == 0)	/* for reference to public suffix file in control/ */
			qh = conf_qmail;
		if (chdir(qh) == -1) return &resp_no_chdir;

		opendmarc_policy_library_init(&dmarclib);
		dmp = opendmarc_policy_connect_init((u_char *)ip, !!strchr(ip, ':'));
		if(!dmp) return &resp_internal;
		if(opendmarc_policy_store_from_domain(dmp, (u_char *)fromdom.s) != DMARC_PARSE_OKAY) {
			/* bogus from, should recover, but probably no great loss */
			return &resp_internal;
		}
	
		/* install SPF results here */
		opendmarc_policy_store_spf(dmp, (u_char *)(spf_domain.len? spf_domain.s: helo), spf_result,
							   spf_domain.len?DMARC_POLICY_SPF_ORIGIN_MAILFROM: DMARC_POLICY_SPF_ORIGIN_HELO,
							   NULL);
	}

	if(nsigs > 0) {
		int i;

		if(!arstr.s) str_init(&arstr);

		const char *helo = session_getstr("helo_domain");

		for(i = 0; i < nsigs; i++) {
			DKIM_SIGINFO *sp = sigs[i];
			DKIM_STAT dss = dkim_sig_process(dk, sp);

			if(dss == DKIM_STAT_OK) {
				unsigned int fl = dkim_sig_getflags(sp);
				char hashbuf[20];
				int dmx = DMARC_POLICY_DKIM_OUTCOME_NONE;
				size_t hblen;
				char *d;

				if(!str_copys(&sqlstr, "INSERT INTO maildkim SET serial=")
				   || !str_catu(&sqlstr, sqlseq)) return &resp_internal;

				if(fl & DKIM_SIGFLAG_PASSED) {
					if(dkim_sig_getbh(sp) == DKIM_SIGBH_MATCH) {
						str_cats(&arstr, "; dkim=pass");
						str_cats(&sqlstr, ",result='pass'");
						dmx = DMARC_POLICY_DKIM_OUTCOME_PASS;
					} else {
						str_cats(&arstr, "; dkim=fail (bad body hash)");
						str_cats(&sqlstr, ",result='failbody'");
						dmx = DMARC_POLICY_DKIM_OUTCOME_FAIL;
					}
				} else {
					str_cats(&arstr, "; dkim=fail (bad signature)");
					str_cats(&sqlstr, ",result='failhdr'");
					dmx = DMARC_POLICY_DKIM_OUTCOME_FAIL;
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
					if(fromdom.len)opendmarc_policy_store_dkim(dmp, d, dmx, NULL);
					
				}
				/* msg2("sql ", sqlstr.s); */
				sqlquery(&sqlstr, NULL);
			}
		}
	}

	dkim_free(dk);
	dkim_close(dl);

	/* do DMARC stuff, log and do a-r */
	if(fromdom.len) {
		dms = opendmarc_policy_query_dmarc(dmp, NULL);
		if(dms == DMARC_PARSE_OKAY) {
			char *dmres = "temperror";

			if(!arstr.s) str_init(&arstr);
			dms = opendmarc_get_policy_to_enforce(dmp);
			/* dms has the dmarc policy */
			if(dms == DMARC_POLICY_PASS) {
				dmres = "pass";
			} else if(dms == DMARC_POLICY_NONE) {
				dmres = "fail.none";
				dofail = 1;
			} else if(dms == DMARC_POLICY_REJECT) {
				dmres = "fail.reject";
				dofail = doreject = 1;
			} else if(dms == DMARC_POLICY_QUARANTINE) {
				dmres = "fail.quarantine";
				dofail = doquarantine = 1;
			}
			str_cat4s(&arstr, "; dmarc=", dmres, " header.from=", fromdom.s);

			msg4("dmarc: ",dmres," for ", fromdom.s);
			if(!str_copys(&sqlstr, "INSERT INTO maildmarc SET serial=")
			   || !str_catu(&sqlstr, sqlseq)
			   || !str_cat5s(&sqlstr, ",result='",dmres,"',domain='",fromdom.s,"'")
			  ) return &resp_internal;
			sqlquery(&sqlstr, NULL);
		}
	}
	str_free(&sqlstr);

	/* do this only so many percent */
	if(doreject || doquarantine) {
		int pct;

		if(opendmarc_policy_fetch_pct(dmp, &pct) == DMARC_PARSE_OKAY && pct < 100) {
			struct timeval tv;

			gettimeofday(&tv, NULL);
			if((tv.tv_sec%100) >= pct) {
				doreject = doquarantine = 0;
				msg1("dmarc: no policy due to pct");
			}
		}
	}

	/* set note for back end to send a failure report */
	if(dofail) {
		char ruf[500];

		if(opendmarc_policy_fetch_ruf(dmp, ruf, sizeof(ruf), 1))
			session_setstr("dmarcruf", ruf);
	}

	if(fromdom.len) {
		opendmarc_policy_connect_shutdown(dmp);
		opendmarc_policy_library_shutdown(&dmarclib);
	}

	if(sump) return 0;	/* done, no a-r header, or it's a sump message */

	if(doreject && dmrm && dmrm[0] == 'y') {
		char * qh;

		if (!dict_load_list(&dmnp, "control/nodmarcpolicy", 0, 0)) /* already in qmail dir */
			return &resp_internal;
		if(dict_get(&dmnp, &fromdom)) {
			msg2("no dmarc policy for ", fromdom.s);
		} else
			session_setnum("dmarcreject", 1);
	}
	/* XXX nothing about doquarantine */
	str_free(&fromdom);

	if(!arstr.len) {
		msg2("no ","arstr");
		return 0;
	}
	if((newfd = scratchfile()) == -1) return &resp_internal;
	obuf_init(&newob, newfd, 0, 0, 0);
	if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
	ibuf_init(&msgib, fd, 0, 0, 0);

	obuf_put3s(&newob, "Authentication-Results: ", authservid, " / 1");
	obuf_putstr(&newob, &arstr);
	obuf_putc(&newob, '\n');

	str_init(&msgstr);
	while(ibuf_getstr(&msgib, &msgstr, LF)) {
		/* check for existing A-R header from us and delete it */
		if(str_case_match(&msgstr, &matchstr)) continue;
		if(!obuf_putstr(&newob, &msgstr)) return &resp_internal;
	}
	obuf_flush(&newob);
	str_free(&msgstr);
	str_free(&matchstr);

	/* now replace the temp file */
	dup2(newfd, fd);
	close(newfd);
	msg4("Authentication-Results: ", authservid, " / 1", arstr.s);

	return 0;
}

struct plugin plugin = {
	.version = PLUGIN_VERSION,
	.flags = FLAG_NEED_FILE,
	.sender = arlog_sender,
	.message_end = arlog_message_end,
};
