/*****************************************************
 SixXSd - Common Functions
******************************************************
 $Author: jeroen $
 $Id: common.h,v 1.1 2004-08-30 19:33:45 jeroen Exp $
 $Date: 2004-08-30 19:33:45 $
*****************************************************/

void dologA(int level, char *fmt, va_list ap);
void dolog(int level, char *fmt, ...);
void sock_printf(int sock, char *fmt, ...);
int sock_getline(int sockfd, char *rbuf, int rbuflen, int *filled, char *ubuf, int ubuflen);
int huprunning();
void savepid();
void cleanpid(int i);
int listen_server(const char *description, const char *hostname, const char *service, int family, int socktype);
unsigned int countfields(char *s);
bool copyfield(char *s, unsigned int n, char *buf, unsigned int buflen);
