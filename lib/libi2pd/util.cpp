/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstdlib>
#include <string>

#include "util.h"
#include "Log.h"

#if not defined (__FreeBSD__)
#include <pthread.h>
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#include <pthread_np.h>
#endif


#ifdef _WIN32
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysinfoapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

// inet_pton exists Windows since Vista, but XP doesn't have that function!
// This function was written by Petar Korponai?. See http://stackoverflow.com/questions/15660203/inet-pton-identifier-not-found
int inet_pton_xp (int af, const char *src, void *dst)
{
	struct sockaddr_storage ss;
	int size = sizeof (ss);
	char src_copy[INET6_ADDRSTRLEN + 1];

	ZeroMemory (&ss, sizeof (ss));
	strncpy (src_copy, src, INET6_ADDRSTRLEN + 1);
	src_copy[INET6_ADDRSTRLEN] = 0;

	if (WSAStringToAddress (src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0)
	{
		switch (af)
		{
		case AF_INET:
			*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
			return 1;
		case AF_INET6:
			*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
			return 1;
		}
	}
	return 0;
}
#else /* !_WIN32 => UNIX */
#include <sys/types.h>
#ifdef ANDROID
#include "ifaddrs.h"
#else
#include <ifaddrs.h>
#endif
#endif

namespace i2p
{
namespace util
{

	void SetThreadName (const char *name) {
#if defined(__APPLE__) && !defined(__powerpc__)
		pthread_setname_np((char*)name);
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
		pthread_set_name_np(pthread_self(), name);
#elif defined(__NetBSD__)
		pthread_setname_np(pthread_self(), "%s", (void *)name);
#elif !defined(__gnu_hurd__)
		pthread_setname_np(pthread_self(), name);
#endif
	}

} // util
} // i2p
