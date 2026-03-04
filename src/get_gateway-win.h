/*
 * ZMap Windows gateway/interface discovery
 *
 * Uses Windows IP Helper API to replicate Linux Netlink functionality.
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifndef ZMAP_GET_GATEWAY_WIN_H
#define ZMAP_GET_GATEWAY_WIN_H

#ifdef ZMAP_GET_GATEWAY_BSD_H
#error "Don't include both get_gateway-bsd.h and get_gateway-win.h"
#endif
#ifdef ZMAP_GET_GATEWAY_LINUX_H
#error "Don't include both get_gateway-linux.h and get_gateway-win.h"
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <pcap/pcap.h>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#endif

#define GW_BUFFER_SIZE 16384

/*
 * Get the hardware (MAC) address of a remote IP via ARP.
 */
int get_hw_addr(struct in_addr *gw_ip, char *iface, unsigned char *hw_mac)
{
	(void)iface;
	if (!gw_ip || !hw_mac) {
		return -1;
	}

	ULONG mac_addr[2];
	ULONG mac_addr_len = 6;
	DWORD ret = SendARP(gw_ip->s_addr, 0, mac_addr, &mac_addr_len);
	if (ret != NO_ERROR) {
		log_error("get-gw", "SendARP failed for %s: error %lu",
			  inet_ntoa(*gw_ip), (unsigned long)ret);
		return -1;
	}
	memcpy(hw_mac, mac_addr, 6);
	return 0;
}

/*
 * Get the default gateway IP and associated interface name.
 */
static int _get_default_gw(struct in_addr *gw, char *iface)
{
	if (!gw || !iface) {
		return -1;
	}

	/* Use GetBestRoute to find route to 0.0.0.0 (default route) */
	MIB_IPFORWARDROW best_route;
	memset(&best_route, 0, sizeof(best_route));
	DWORD ret = GetBestRoute(0, 0, &best_route);
	if (ret != NO_ERROR) {
		log_error("get-gw", "GetBestRoute failed: %lu",
			  (unsigned long)ret);
		return -1;
	}

	gw->s_addr = (ULONG)best_route.dwForwardNextHop;

	/* Convert interface index to name using GetAdaptersAddresses */
	DWORD if_index = best_route.dwForwardIfIndex;
	ULONG buf_len = GW_BUFFER_SIZE;
	PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
	ret = GetAdaptersAddresses(AF_INET,
				   GAA_FLAG_SKIP_ANYCAST |
				       GAA_FLAG_SKIP_MULTICAST |
				       GAA_FLAG_SKIP_DNS_SERVER,
				   NULL, addrs, &buf_len);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		free(addrs);
		addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
		ret = GetAdaptersAddresses(AF_INET,
					   GAA_FLAG_SKIP_ANYCAST |
					       GAA_FLAG_SKIP_MULTICAST |
					       GAA_FLAG_SKIP_DNS_SERVER,
					   NULL, addrs, &buf_len);
	}
	if (ret != NO_ERROR) {
		log_error("get-gw", "GetAdaptersAddresses failed: %lu",
			  (unsigned long)ret);
		free(addrs);
		return -1;
	}

	PIP_ADAPTER_ADDRESSES curr = addrs;
	int found = 0;
	while (curr) {
		if (curr->IfIndex == if_index) {
			/* Use the adapter FriendlyName or AdapterName.
			 * For pcap, we need to use the AdapterName
			 * (which is a GUID like {GUID}) prefixed with
			 * \\Device\\NPF_
			 */
			snprintf(iface, IF_NAMESIZE, "\\Device\\NPF_%s",
				 curr->AdapterName);
			found = 1;
			break;
		}
		curr = curr->Next;
	}
	free(addrs);

	if (!found) {
		log_error("get-gw",
			  "Could not find adapter for interface index %lu",
			  (unsigned long)if_index);
		return -1;
	}
	return 0;
}

/*
 * Get the default network interface name (for pcap).
 */
char *get_default_iface(void)
{
	struct in_addr gw;
	char *iface;

	iface = (char *)malloc(IF_NAMESIZE);
	memset(iface, 0, IF_NAMESIZE);

	if (_get_default_gw(&gw, iface)) {
		log_fatal(
		    "send",
		    "ZMap could not detect your default network interface. "
		    "You likely do not have sufficient privileges. "
		    "Try running as Administrator. "
		    "You may also need to manually set interface using the \"-i\" flag "
		    "with the Npcap device name (e.g. \\Device\\NPF_{GUID}).");
	} else {
		return iface;
	}
}

/*
 * Get default gateway for a specific interface.
 */
int get_default_gw(struct in_addr *gw, char *iface)
{
	(void)iface;
	struct in_addr _gw;
	char _iface[IF_NAMESIZE];
	memset(_iface, 0, IF_NAMESIZE);

	_get_default_gw(&_gw, _iface);

	/* On Windows, we don't strictly enforce interface matching
	 * because interface names are GUIDs and may differ in format.
	 * Just use the detected gateway. */
	gw->s_addr = _gw.s_addr;
	return EXIT_SUCCESS;
}

/*
 * Get the IP address of a network interface.
 */
int get_iface_ip(char *iface, struct in_addr *ip)
{
	ULONG buf_len = GW_BUFFER_SIZE;
	PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
	DWORD ret = GetAdaptersAddresses(
	    AF_INET,
	    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER,
	    NULL, addrs, &buf_len);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		free(addrs);
		addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
		ret = GetAdaptersAddresses(
		    AF_INET,
		    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_DNS_SERVER,
		    NULL, addrs, &buf_len);
	}
	if (ret != NO_ERROR) {
		log_fatal("get-iface-ip", "GetAdaptersAddresses failed: %lu",
			  (unsigned long)ret);
	}

	PIP_ADAPTER_ADDRESSES curr = addrs;
	while (curr) {
		/* Match by adapter name (the GUID part) */
		if (strstr(iface, curr->AdapterName) != NULL) {
			/* Get the first unicast IPv4 address */
			PIP_ADAPTER_UNICAST_ADDRESS unicast =
			    curr->FirstUnicastAddress;
			while (unicast) {
				struct sockaddr_in *sa =
				    (struct sockaddr_in *)
					unicast->Address.lpSockaddr;
				if (sa->sin_family == AF_INET) {
					ip->s_addr = sa->sin_addr.s_addr;
					free(addrs);
					return EXIT_SUCCESS;
				}
				unicast = unicast->Next;
			}
		}
		curr = curr->Next;
	}
	free(addrs);
	log_fatal("get-iface-ip",
		  "Unable to find IP address for interface %s. "
		  "Try specifying the source IP with -S.",
		  iface);
	return EXIT_FAILURE;
}

/*
 * Get the hardware (MAC) address of a local interface.
 */
int get_iface_hw_addr(char *iface, unsigned char *hw_mac)
{
	ULONG buf_len = GW_BUFFER_SIZE;
	PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
	DWORD ret = GetAdaptersAddresses(
	    AF_INET,
	    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER,
	    NULL, addrs, &buf_len);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		free(addrs);
		addrs = (PIP_ADAPTER_ADDRESSES)xmalloc(buf_len);
		ret = GetAdaptersAddresses(
		    AF_INET,
		    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_DNS_SERVER,
		    NULL, addrs, &buf_len);
	}
	if (ret != NO_ERROR) {
		log_error("get_iface_hw_addr",
			  "GetAdaptersAddresses failed: %lu",
			  (unsigned long)ret);
		free(addrs);
		return EXIT_FAILURE;
	}

	PIP_ADAPTER_ADDRESSES curr = addrs;
	while (curr) {
		if (strstr(iface, curr->AdapterName) != NULL) {
			if (curr->PhysicalAddressLength == 6) {
				memcpy(hw_mac, curr->PhysicalAddress, 6);
				free(addrs);
				return EXIT_SUCCESS;
			}
		}
		curr = curr->Next;
	}
	free(addrs);
	log_error("get_iface_hw_addr",
		  "Unable to find hardware address for %s", iface);
	return EXIT_FAILURE;
}

#endif /* ZMAP_GET_GATEWAY_WIN_H */
