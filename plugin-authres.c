/*
 * Create Authentication-Results: header
 * Check DKIM signatures if any
 * Check SPF, too
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

str arstr = { 0, 0};		/* authentication results header */

static const response* authres_sender(str* sender)
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

	if(!arstr.s) str_init(&arstr);
	str_cat2s(&arstr, "; spf=", SPF_strresult(SPF_response_result(spf_response)));
	str_cat4s(&arstr, " spf.mailfrom=", sender->s, " spf.helo=", helo);
	
	SPF_response_free(spf_response);
	SPF_request_free(spf_request);
	SPF_server_free(spf_server);

	return 0;
}

/* now run it through opendkim, and recopy with a-r header to a new file */
static const response* authres_message_end(int fd)
{
	DKIM_LIB *dl;
	DKIM *dk;
	DKIM_STAT ds;

	int newfd;
	ibuf msgib;
	obuf newob;
	str msgstr;
	int sump = session_getnum("sump", 0);
	DKIM_SIGINFO **sigs;
	int nsigs;
	unsigned int opts = DKIM_LIBFLAGS_FIXCRLF;
	const char *host;

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
	while(ibuf_getstr(&msgib, &msgstr, LF)) {
		ds = dkim_chunk(dk, msgstr.s, msgstr.len);
		if(ds != DKIM_STAT_OK) {
			if(ds != DKIM_STAT_NOSIG)
				msg2("dkim_chunk failed: ", dkim_getresultstr(ds));
			break;
		}
	}
	dkim_chunk(dk, NULL, 0);
	ds = dkim_eom(dk, NULL);

	ds = dkim_getsiglist(dk, &sigs, &nsigs);
	if(ds != DKIM_STAT_OK) {
		msg2("dkim_getsiglist failed: ", dkim_getresultstr(ds));
		nsigs = 0;	/* continue to add A-R header */
	}

	if(nsigs > 0) {
		int i;

		if(!arstr.s) str_init(&arstr);

		for(i = 0; i < nsigs; i++) {
			DKIM_SIGINFO *sp = sigs[i];
			DKIM_STAT dss = dkim_sig_process(dk, sp);

			if(dss == DKIM_STAT_OK) {
				const char *d;
				unsigned int fl = dkim_sig_getflags(sp);
				char hashbuf[20];
				size_t hblen;

				if(fl & DKIM_SIGFLAG_PASSED) {
					if(dkim_sig_getbh(sp) == DKIM_SIGBH_MATCH)
						str_cats(&arstr, "; dkim=pass");
					else
						str_cats(&arstr, "; dkim=fail (bad body hash)");
				} else {
					str_cats(&arstr, "; dkim=fail (bad signature)");
				}
				d = dkim_sig_getdomain(sp);
				if(d)
					str_cat2s(&arstr, " header.d=", d);

				hblen = sizeof(hashbuf)-1;
				hashbuf[hblen] = 0; /* ensure null term */
				ds = dkim_get_sigsubstring(dk, sp, hashbuf, &hblen);
				if(ds == DKIM_STAT_OK)
					str_cat3s(&arstr, " header.b=\"", hashbuf, "\"");
			}
		}
	}

	dkim_free(dk);
	dkim_close(dl);

	if(sump || !arstr.len) return 0;	/* done, no a-r header, or it's a sump message */

	if((newfd = scratchfile()) == -1) return &resp_internal;
	obuf_init(&newob, newfd, 0, 0, 0);
	if (lseek(fd, 0, SEEK_SET) != 0) return &resp_internal;
	ibuf_init(&msgib, fd, 0, 0, 0);

	host = getprotoenv("LOCALHOST");
	if(!host) host = "localhost";
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
	.sender = authres_sender,
	.message_end = authres_message_end,
};
