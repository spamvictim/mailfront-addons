/*
 * Create Authentication-Results: header
 * authserv-id in A-R header is env AUTHSERVID,
 * defaulting to TCPLOCALHOST
 * Check DKIM signatures if any
 * Check SPF, too
 * env DMARCREJECT=y means actually do reject
 * file control/nodmarcpolicy lists domains not to reject
 *
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
#include <str/str.h>
#include <dict/dict.h>
#include <dict/load.h>

#include <opendkim/dkim.h>

/* way too much junk for SPF */
# include <sys/socket.h>   /* inet_ functions / structs */
# include <netinet/in.h>   /* inet_ functions / structs */
# include <arpa/inet.h> /* in_addr struct */

#include <spf2/spf.h>
#include <opendmarc/dmarc.h>

static str arstr = {0,0,0};		/* authentication results header */

static int spf_result;					/* for DMARC */
static str spf_domain = {0,0,0};		/* for DMARC */

static RESPONSE(no_chdir,451,"4.3.0 Could not change to the qmail directory.");
static RESPONSE(nodmarc,550,"5.7.1 DMARC policy failure");

static dict dmnp;

static const response* authres_sender(str* sender, str* params)
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

	if(!arstr.s) str_init(&arstr);
	str_cat2s(&arstr, "; spf=", SPF_strresult(SPF_response_result(spf_response)));

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
	(void)params;
}

/* now run it through opendkim and opendmarc, and recopy with a-r header to a new file */
static const response* authres_message_end(int fd)
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
	DMARC_POLICY_T *dmp = 0;
	OPENDMARC_STATUS_T dms;

	int newfd;
	ibuf msgib;
	obuf newob;
	str msgstr, matchstr;
	int sump = session_getnum("sump", 0);
	int nsigs;
	int doreject = 0;	/* DMARC results */
	int doquarantine = 0;
	const char *authservid = getenv("AUTHSERVID");
	const char *ip = getprotoenv("REMOTEIP");
	const char *dmrm = getenv("DMARCREJECT");
	const char *helo = session_getstr("helo_domain");
	str fromdom;             /* from domain name */
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

	dk = dkim_verify(dl, (unsigned char *)"msg", NULL, &ds);
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

		ds = dkim_chunk(dk, (unsigned char *)msgstr.s, msgstr.len);
		if(ds != DKIM_STAT_OK) {
			if(ds != DKIM_STAT_NOSIG)
				msg2("dkim_chunk failed: ", dkim_getresultstr(ds));
			break;
		}
	}
	dkim_chunk(dk, NULL, 0);
	ds = dkim_eom(dk, NULL);

	str_init(&fromdom);
	qh = (char *)dkim_getdomain(dk);
	if(qh)str_copys(&fromdom, qh);

	ds = dkim_getsiglist(dk, &sigs, &nsigs);
	if(ds != DKIM_STAT_OK) {
		msg2("dkim_getsiglist failed: ", dkim_getresultstr(ds));
		nsigs = 0;	/* continue to add A-R */
	}

	/* check dmarc policy */
	if ((qh = getenv("QMAILHOME")) == 0)	/* for reference to public suffix file in control/ */
		qh = conf_qmail;
	if (chdir(qh) == -1) return &resp_no_chdir;

	if(fromdom.len) {
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

		for(i = 0; i < nsigs; i++) {
			DKIM_SIGINFO *sp = sigs[i];
			DKIM_STAT dss = dkim_sig_process(dk, sp);

			if(dss == DKIM_STAT_OK) {
				unsigned int fl = dkim_sig_getflags(sp);
				char hashbuf[20];
				int dmx = DMARC_POLICY_DKIM_OUTCOME_NONE;
				size_t hblen;
				char *d;

				if(fl & DKIM_SIGFLAG_PASSED) {
					if(dkim_sig_getbh(sp) == DKIM_SIGBH_MATCH) {
						str_cats(&arstr, "; dkim=pass");
						dmx = DMARC_POLICY_DKIM_OUTCOME_PASS;
					} else {
						str_cats(&arstr, "; dkim=fail (bad body hash)");
						dmx = DMARC_POLICY_DKIM_OUTCOME_FAIL;
					}
				} else {
					str_cats(&arstr, "; dkim=fail (bad signature)");
					dmx = DMARC_POLICY_DKIM_OUTCOME_FAIL;
				}
				d = (char *)dkim_sig_getdomain(sp);
				if(d) {
					str_cat2s(&arstr, " header.d=", d);
				}

				hblen = sizeof(hashbuf)-1;
				hashbuf[hblen] = 0; /* ensure null term */
				ds = dkim_get_sigsubstring(dk, sp, hashbuf, &hblen);
				if(ds == DKIM_STAT_OK) {
					str_cat3s(&arstr, " header.b=\"", hashbuf, "\"");
					if(fromdom.len)opendmarc_policy_store_dkim(dmp, (unsigned char*)d, dmx, NULL);
					
				}
			}
		}
	}

	dkim_free(dk);
	dkim_close(dl);

	if(fromdom.len) {
		/* do DMARC stuff, log and do a-r */
		dms = opendmarc_policy_query_dmarc(dmp, NULL);
		if(dms == DMARC_PARSE_OKAY) {
			char *dmres = "temperror";
			int policy;
			char *dmpol = "unspecified";

			if(!arstr.s) str_init(&arstr);
			dms = opendmarc_get_policy_to_enforce(dmp);
			/* dms has the dmarc policy */
			if(dms == DMARC_POLICY_PASS) {
				dmres = "pass";
			} if(dms == DMARC_POLICY_NONE) {
				dmres = "fail.none";
			} else if(dms == DMARC_POLICY_REJECT) {
				dmres = "fail.reject";
				doreject = 1;
			} else if(dms == DMARC_POLICY_QUARANTINE) {
				dmres = "fail.quarantine";
				doquarantine = 1;
			}
			dms = opendmarc_policy_fetch_p(dmp, &policy);
			if(dms == DMARC_PARSE_OKAY)
				switch(policy) {
					case DMARC_RECORD_P_NONE: dmpol = "none" ;
					case DMARC_RECORD_P_QUARANTINE: dmpol = "quarantine";
					case DMARC_RECORD_P_REJECT: dmpol = "reject";
				}
			str_cat6s(&arstr, "; dmarc=", dmres, " header.from=", fromdom.s,
				  " policy=",dmpol);

			msg6("dmarc: ",dmres," for ", fromdom.s, " policy=",dmpol);
		}

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

		opendmarc_policy_connect_shutdown(dmp);
		opendmarc_policy_library_shutdown(&dmarclib);
	}

	if(sump) return 0;	/* done, no a-r header, or it's a sump message */

	if(doreject && dmrm && dmrm[0] == 'y') {
		if (!dict_load_list(&dmnp, "control/nodmarcpolicy", 0, 0)) /* already in qmail dir */
			return &resp_internal;
		if(dict_get(&dmnp, &fromdom)) {
			msg2("no dmarc policy for ", fromdom.s);
		} else
			return &resp_nodmarc;
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

	obuf_put2s(&newob, "Authentication-Results: ", authservid);
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
	msg3("Authentication-Results: ", authservid, arstr.s);

	return 0;
}

struct plugin plugin = {
	.version = PLUGIN_VERSION,
	.flags = FLAG_NEED_FILE,
	.sender = authres_sender,
	.message_end = authres_message_end,
};
