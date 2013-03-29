/*
 * Small library to do mysql calls
 * Separate from the rest of the plugin due to symbol collisions
 *
 * opendb() -> 1 for OK, 0 for fail
 * sqlquote(str *in, str *out) -> 1 for OK, 0 for fail
 * non-select query:
 * sqlquery(str *query, int unsigned *seqno) -> 1 for OK, 0 for fail
 *
 * select query, single record:
 * sqlvalquery(str *query, int nresult, str *result)
 *  -> 1 for OK, 0 for fail, -1 for OK but no data
 * stores up to nresult str's
 */

#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include <msg/msg.h>
#include <str/str.h>

MYSQL mysql;

/* open the connection */

int opendb()
{
  static int isopen;
  char *host = getenv("MYSQL_HOST");
  char *user = getenv("MYSQL_USER");
  char *pass = getenv("MYSQL_PASS");
  char *dbname = getenv("MYSQL_DBNAME");
 
  if(!host) host = "localhost";
  if(!user || !pass || !dbname) {
    msg1("Missing mysql login parameter");
    return 0;
  }

  if(isopen) return 1;

  mysql_init(&mysql);
  if (!mysql_real_connect(&mysql,host, user, pass, dbname, 0,NULL,0)) {
      msg2("mysql connect failed: ", mysql_error(&mysql));
      return 0;
  }
  isopen = 1;
  /* msg2("opened mysql database ", dbname); */
  return 1;
}

/* quote a string */
int
sqlquote(str *in, str *out)
{
  if(!str_ready(out, 1+2*in->len)) return 0;

  mysql_real_escape_string(&mysql, out->s, in->s, in->len);
  out->len = strlen(out->s);
  return 1;
}

/* static MYSQL_RES *result; */

/* do a non-value query, optionally return sequence no */
int
sqlquery(str *query, int unsigned *seqno)
{
  int i;

  i = mysql_real_query(&mysql, query->s, query->len);
  if(i) {
    msg2("mysql error: ", mysql_error(&mysql));
    return 0;
  }
  
  /* assume no result, store optional ID */
  if(seqno) *seqno = mysql_insert_id(&mysql);

  return 1;
}

/*
 * Do a query, return the first result as an array of str's
 * value 1 if there's a result, 0 on error, -1 on no result
 * return values in str's, add a nul so they can be used as C strings
 */
int
sqlvalquery(str *query, int nresult, str *result)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned int nfields;
  unsigned long *lengths;
  int i;

  i = mysql_real_query(&mysql, query->s, query->len);
  if(i) {
    msg2("mysql error: ", mysql_error(&mysql));
    return 0;
  }
  res = mysql_store_result(&mysql);
  if(!res) return 0;
  if(mysql_num_rows(res) == 0) { /* no result */
    mysql_free_result(res);
    return -1;
  }
  row = mysql_fetch_row(res);
  if(!row) {			/* error, where's my row? */
    mysql_free_result(res);
    return 0;
  }
  nfields = mysql_num_fields(res);
  lengths = mysql_fetch_lengths(res);

  for(i = 0; i < nfields; i++) {
    if(i >= nresult)
      break;	/* too many, ignore */
    str_init(&result[i]);
    if(row[i])
      str_copyb(&result[i], row[i], lengths[i]);
    str_catc(&result[i], 0);	/* NUL terminate */
    result[i].len--;
    /* NULL is a null string, close enough */
  }
  mysql_free_result(res);  
  return 1;
}
