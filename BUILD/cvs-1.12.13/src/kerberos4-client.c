/* CVS Kerberos4 client stuff.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.  */

#include <config.h>

#include "cvs.h"

#include "buffer.h"
#include "socket-client.h"

#   include <krb.h>

extern char *krb_realmofhost ();
#   ifndef HAVE_KRB_GET_ERR_TEXT
#     define krb_get_err_text(status) krb_err_txt[status]
#   endif /* HAVE_KRB_GET_ERR_TEXT */

/* Information we need if we are going to use Kerberos encryption.  */
static C_Block kblock;
static Key_schedule sched;


/* This function has not been changed to deal with NO_SOCKET_TO_FD
   (i.e., systems on which sockets cannot be converted to file
   descriptors).  The first person to try building a kerberos client
   on such a system (OS/2, Windows 95, and maybe others) will have to
   take care of this.  */
void
start_kerberos4_server (cvsroot_t *root, struct buffer **to_server_p,
                        struct buffer **from_server_p)
{
    int s;
    int port;
    int gerr;
    struct addrinfo hints, *res, *res0;
    char *hname;
    char pbuf[32], hbuf[1025];

    port = get_cvs_port_number (root);

    sprintf (pbuf, "%u", port);
    pbuf[sizeof(pbuf)-1] = '\0';
    memset (&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    gerr = getaddrinfo (root->hostname, pbuf, &hints, &res0);
    if (gerr) {
	fprintf (stderr, "Unknown host %s.\n", root->hostname);
	exit (EXIT_FAILURE);
    }

    /* Try connect to current_parsed_root->hostname using all available families */
    gerr = -1;
    for (res = res0; res != NULL; res = res->ai_next)
    {
	s = socket (res->ai_family, res->ai_socktype, 0);
	if (s < 0)
	{
	    if (res->ai_next)
		continue;
	    else
	    {
		char *sock_error = SOCK_STRERROR (SOCK_ERRNO);
		freeaddrinfo(res0);
		error (1, 0, "cannot create socket: %s", sock_error);
	    }
	}
	if (trace)
	{
	    char hbuf[1025];
	    getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
		    NULL, 0, NI_NUMERICHOST);
	    fprintf (stderr, " -> Connecting to %s(%s):%d\n",
		    root->hostname, hbuf, port);
	}
	
	if (connect (s, res->ai_addr, res->ai_addrlen) < 0)
	{
	    if (res->ai_next)
	    {
		close(s);
		continue;
	    }
	    else
	    {
		char *sock_error = SOCK_STRERROR (SOCK_ERRNO);
		freeaddrinfo(res0);
		error (1, 0, "connect to [%s]:%s failed: %s",
			root->hostname, pbuf, sock_error);
	    }
	}
	getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf), NULL, 0, 0);
	hname = xmalloc (strlen (hbuf) + 1);
	strcpy (hname, hbuf);
	/* success */
	break;
    }

    {
	const char *realm;
	struct sockaddr_storage laddr;
	int laddrlen;
	KTEXT_ST ticket;
	MSG_DAT msg_data;
	CREDENTIALS cred;
	int status;

	realm = krb_realmofhost (hname);

	laddrlen = sizeof (laddr);
	if (getsockname (s, (struct sockaddr *) &laddr, &laddrlen) < 0)
	    error (1, 0, "getsockname failed: %s", SOCK_STRERROR (SOCK_ERRNO));

	/* We don't care about the checksum, and pass it as zero.  */
	status = krb_sendauth (KOPT_DO_MUTUAL, s, &ticket, "rcmd",
			       hname, realm, (unsigned long) 0, &msg_data,
			       &cred, sched, &laddr, res->ai_addr, "KCVSV1.0");
	if (status != KSUCCESS)
	    error (1, 0, "kerberos authentication failed: %s",
		   krb_get_err_text (status));
	memcpy (kblock, cred.session, sizeof (C_Block));
    }

    freeaddrinfo(res0);

    close_on_exec (s);

    free (hname);

    /* Give caller the values it wants. */
    make_bufs_from_fds (s, s, 0, root, to_server_p, from_server_p, 1);
}

void
initialize_kerberos4_encryption_buffers( struct buffer **to_server_p,
                                         struct buffer **from_server_p )
{
  *to_server_p = krb_encrypt_buffer_initialize (*to_server_p, 0, sched,
						kblock, NULL);
  *from_server_p = krb_encrypt_buffer_initialize (*from_server_p, 1,
						  sched, kblock, NULL);
}

