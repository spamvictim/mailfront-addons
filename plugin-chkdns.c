/* 
 * Make DNS checks on envelope data
 * Check that domain in MAIL FROM has MX, A, or AAAA record
 * Check HELO, MAIL FROM against DBLLOOKUP domain 
 *
 * Has to come before anything that might accept a sender
 * everything except non-existent MAIL FROM sends mail to sump
 * or rejects if DBLREJECT is set
 * 
 */

#include <stdlib.h>
#include <unistd.h>

#include "mailfront.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <msg/msg.h>

static RESPONSE(badfrom,553,"5.1.8 Invalid sender domain.");
static response resp_baddbl = { 553, "???" };

static int dblchk(str *domain, str *dbltxt)
{
	str dblstr;
	char *dbl = getenv("DBLLOOKUP");
	int l, i;
	unsigned char ansbuf[512];
	
	if(!dbl || domain->len == 0) return 0;
	if(session_getnum("sump",0)) return 0; /* no point */


	str_init(&dblstr);
	str_copy(&dblstr, domain);
	str_catc(&dblstr, '.');
	str_cats(&dblstr, dbl);
			
	l = res_query(dblstr.s, C_IN, T_TXT, ansbuf, sizeof(ansbuf));
	if(l > 0 && ((HEADER *)ansbuf)->ancount != 0) {  /* something in the answer */
		unsigned char *recbuf = ansbuf+NS_HFIXEDSZ;
		
		/* skip over questions, why am I still writing stuff
		 * like this? */
		for(i = ns_get16(ansbuf+4); i != 0; --i)
			recbuf += dn_skipname(recbuf, ansbuf+l)+4;

		for(i = ns_get16(ansbuf+6); i != 0; --i) {
			recbuf += dn_skipname(recbuf, ansbuf+l);

			if(ns_get16(recbuf) != T_TXT) { /* CNAME or something */
				recbuf += 10 + ns_get16(recbuf+8);
				continue;
			}
			/* it's a TXT record, wow */
			str_init(dbltxt);
			str_copyb(dbltxt, recbuf+11, recbuf[10]);
			str_free(&dblstr);
			return 1;
		}
	} /* didn't find anything */
	str_free(&dblstr);
	return 0;
	}

static const response* chkdns_helo(str* hostname)
{
	str dbltxt;

	/* hack, don't check numeric, guess from first character */
	if(hostname->s[0] >= '0' && hostname->s[0] <= '9') return 0;

	if(dblchk(hostname, &dbltxt)) {
		session_setenv("RBLSMTPD", dbltxt.s, 0);
		session_setnum("dblhelo", 1);
		session_setnum("sump", 1);
		msg4("HELO ", hostname->s, " in DBL ",dbltxt.s);
		if(getenv("DBLREJECT")) {
			resp_baddbl.message = dbltxt.s;
			return &resp_baddbl;
		}
	}
	return 0;
}

/* check sender domain */

static const response* chkdns_sender(str* sender)
{
	str domstr, dbltxt;
	int i;
	char ansbuf[512];
	
	if(sender->len == 0) return 0;	/* bounce */
	i = str_findlast(sender, '@');
	if(i < 0) {
		return &resp_badfrom;	/* no domain */
	}
	str_init(&domstr);
	str_copyb(&domstr, sender->s+i+1, sender->len-i-1);
	if(domstr.len == 0) { /* null domain */
		str_free(&domstr);
		return &resp_badfrom;
	}

	/* first check dbl */
	if(dblchk(&domstr, &dbltxt)) {
		session_setenv("RBLSMTPD", dbltxt.s, 0);
		session_setnum("dblfrom", 1);
		session_setnum("sump", 1);
		msg2("MAIL FROM in DBL ",dbltxt.s);
		str_free(&domstr);
		if(getenv("DBLREJECT")) {
			resp_baddbl.message = dbltxt.s;
			return &resp_baddbl;
		}
		return 0;
	}

	i = res_query(domstr.s, C_IN, T_MX, ansbuf, sizeof(ansbuf));
	if(i > 0 && ((HEADER *)ansbuf)->ancount != 0) {  /* has an MX */
		str_free(&domstr);
		return 0;
	}

	i = res_query(domstr.s, C_IN, T_A, ansbuf, sizeof(ansbuf));
	if(i > 0 && ((HEADER *)ansbuf)->ancount != 0) { /* has an A */
		str_free(&domstr);
		return 0;
		}

	i = res_query(domstr.s, C_IN, T_AAAA, ansbuf, sizeof(ansbuf));
	str_free(&domstr);
	if(i > 0 && ((HEADER *)ansbuf)->ancount != 0) return 0; /* has an AAAA */

	return &resp_badfrom;
}

struct plugin plugin = {
  .version = PLUGIN_VERSION,
  .flags = 0,
  .helo = chkdns_helo,
  .sender = chkdns_sender,
};
