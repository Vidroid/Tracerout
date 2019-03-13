#pragma pack(4)

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
//============================================================================================================
									// Defines for ICMP message types
#define ICMP_ECHOREP		0		//
#define ICMP_DESTUNREACH    3		//
#define ICMP_SRCQUENCH      4		//
#define ICMP_REDIRECT       5		//
#define ICMP_ECHO           8		//
#define ICMP_TIMEOUT       11		//
#define ICMP_PARMERR       12		//
//============================================================================================================
#define MAX_HOPS           30		// Maximal hops count
#define ICMP_MIN			8		// Minimum 8 byte icmp packet (just header)
//============================================================================================================

typedef struct iphdr				// IP Header
{
	unsigned int   h_len : 4;       // Length of the header
	unsigned int   version : 4;     // Version of IP
	unsigned char  tos;             // Type of service
	unsigned short total_len;       // Total length of the packet
	unsigned short ident;           // Unique identifier
	unsigned short frag_and_flags;  // Flags
	unsigned char  ttl;             // Time to live
	unsigned char  proto;           // Protocol (TCP, UDP etc)
	unsigned short checksum;        // IP checksum
	unsigned int   sourceIP;        // Source IP
	unsigned int   destIP;          // Destination IP
} IpHeader;

//=============================================================================================================
typedef struct _ihdr				// ICMP header
{
	BYTE   i_type;					// ICMP message type
	BYTE   i_code;					// Sub code
	WORD   i_cksum;					// Checksumm
	WORD   i_id;					// Unique id
	WORD   i_seq;					// Sequence number
	
	ULONG	SendTimeStamp;				// This is not the std header, but we reserve space for time
	ULONG   RecvTimeStamp;
	ULONG	TmitTimeStamp;
} IcmpHeader;
//=============================================================================================================
#define DEF_PACKET_SIZE         32
#define MAX_PACKET            1024
//=============================================================================================================

// Function: set_ttl
// Description:
//    Set the time to live parameter on the socket. This controls
//    how far the packet will be forwared before a "timeout"
//    response will be sent back to us. This way we can see all
//    the hops along the way to the destination.
//=============================================================================================================
int SetTimetoLive(SOCKET s, int nTimeToLive)
{
	int     nRet;

	nRet = setsockopt(s, IPPROTO_IP, IP_TTL, (LPSTR)&nTimeToLive, sizeof(int));
	if (nRet == SOCKET_ERROR)
	{
		printf("setsockopt(IP_TTL) failed: %d\n",
			WSAGetLastError());
		return 0;
	}
	return 1;
}
//===========================================================================================================
// Function: decode_resp
// Description:
//    The response is an IP packet. We must decode the IP header
//    to locate the ICMP data.
int DecodeResponse(char *buf, int bytes, SOCKADDR_IN *from, int ttl, ULONG *SendTime)
{
	IpHeader       *iphdr = NULL;
	IcmpHeader     *icmphdr = NULL;
	unsigned short  iphdrlen;

	struct hostent *lpHostent = NULL;
	struct in_addr  inaddr = from->sin_addr;

	ULONG			AnswTime;
//----------------------------------------------------------------------------------------------------------
	iphdr = (IpHeader *)buf;  // Number of 32-bit words * 4 = bytes
	iphdrlen = iphdr->h_len * 4;

	if (bytes < iphdrlen + ICMP_MIN)
	{
		printf("Too few bytes from %s\n", inet_ntoa(from->sin_addr));
	}
	icmphdr = (IcmpHeader*)(buf + iphdrlen);

	AnswTime = GetTickCount()-(*SendTime);
	

	switch (icmphdr->i_type)
	{

	case ICMP_ECHOREP:     // Response from destination

		lpHostent = gethostbyaddr((const char *)&from->sin_addr, AF_INET, sizeof(struct in_addr));

		if (lpHostent != NULL)
		{
			if (AnswTime > 1000)
			{
				printf(" %c %s (%s)\n", '*', lpHostent->h_name, inet_ntoa(inaddr));
			}
			else
			{
				printf(" %d %s (%s)\n", AnswTime, lpHostent->h_name, inet_ntoa(inaddr));
			}
		}
		return 1;
		break;
	
	case ICMP_TIMEOUT:      // Response from router along the way
		if (AnswTime > 1000)
		{
			printf(" %c  %s\n", '*', inet_ntoa(inaddr));
		}
		else
		{
			printf(" %d  %s\n", AnswTime, inet_ntoa(inaddr));
		}
		return 0;
		break;
	
	case ICMP_DESTUNREACH:  // Can't reach the destination at all
		
		printf(" %d  %s  reports: Host is unreachable\n", AnswTime, inet_ntoa(inaddr));
		return 1;
		break;
	
	default:
		
		printf("non-echo type %d recvd\n", icmphdr->i_type);
		return 1;
		break;
	
	}
	return 0;
}


//	  Function: checksum
//	  Description:
//    This function calculates the checksum for the ICMP header
//    which is a necessary field since we are building packets by
//    hand. Normally, the TCP layer handles all this when you do
//    sockets, but ICMP is at a somewhat lower level.
//=============================================================================================================
WORD CheckSumm(WORD *buffer, int size)
{
	unsigned long cksum = 0;
	
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(WORD);
	}
	if (size)
		cksum += *(BYTE*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (WORD)(~cksum);
}
//============================================================================================================
//    Function: fill_icmp_data
//	  Description:
//    Helper function to fill in various stuff in our ICMP request.
//
void FillicmpData(char * icmp_data, int datasize)
{
	IcmpHeader *icmp_hdr;
	char       *datapart;

	icmp_hdr = (IcmpHeader*)icmp_data;

	icmp_hdr->i_type = ICMP_ECHO;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = (WORD)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;

	datapart = icmp_data + sizeof(IcmpHeader);
	//
	// Place some junk in the buffer. Don't care about the data...
	//
	memset(datapart, 'E', datasize - sizeof(IcmpHeader));
}

// Function: main
int main(void)
{
	WSADATA      Wsd;
	SOCKET       SockRaw;
	HOSTENT     *Hp = NULL;
	SOCKADDR_IN  Dest, From;
	int          Ret, DataSize;
	int   		 FromLen = sizeof(From), TimeOut;
	int			 Done = 0, MaxHops, TTL = 1;
	char        *IcmpData, *RecvBuf;
	BOOL         BOpt;
	WORD		 SeqNo = 0;
	char		 DestAdr[80];
	ULONG	 *OldTime, CurTime;
	OldTime = (ULONG*)malloc(sizeof(ULONG));
	*OldTime = 0;
	printf("Please enter IP-addres or internet name\n");
	scanf("%s", &DestAdr);


	// Initialize the Winsock2 DLL

	if (WSAStartup(MAKEWORD(2, 2), &Wsd) != 0)
	{
		printf("WSAStartup() failed: %d\n", GetLastError());
		return -1;
	}

		MaxHops = MAX_HOPS;

	// Create a raw socket that will be used to send the ICMP
	// packets to the remote host you want to ping

	SockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);

	if (SockRaw == INVALID_SOCKET)
	{
		printf("WSASocket() failed: %d\n", WSAGetLastError());
		ExitProcess(-1);
	}
	
	// Set the receive and send timeout values to a second
	
	TimeOut = 1000;

	Ret = setsockopt(SockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut));
	if (Ret == SOCKET_ERROR)
	{
		printf("setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
		return -1;
	}

	TimeOut = 1000;

	Ret = setsockopt(SockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *)&TimeOut, sizeof(TimeOut));
	if (Ret == SOCKET_ERROR)
	{
		printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
		return -1;
	}

	ZeroMemory(&Dest, sizeof(Dest));
	
	// We need to resolve the host's ip address.  We check to see
	// if it is an actual Internet name versus an dotted decimal
	// IP address string.
	
	Dest.sin_family = AF_INET;
	if ((Dest.sin_addr.s_addr = inet_addr(DestAdr)) == INADDR_NONE)
	{
		Hp = gethostbyname(DestAdr);
		if (Hp)
			memcpy(&(Dest.sin_addr), Hp->h_addr, Hp->h_length);
		else
		{
			printf("Unable to resolve %s\n", DestAdr);
			ExitProcess(-1);
		}
	}
	
	// Set the data size to the default packet size.
	// We don't care about the data since this is just traceroute/ping
	
	DataSize = DEF_PACKET_SIZE;

	DataSize += sizeof(IcmpHeader);
	
	// Allocate the sending and receiving buffers for ICMP packets
	
	IcmpData = (char*)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET));
	RecvBuf = (char*)(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET));

	if ( (!IcmpData)||(!RecvBuf) )
	{
		printf("HeapAlloc() failed %d\n", GetLastError());
		return -1;
	}
	// Set the socket to bypass the standard routing mechanisms
	//  i.e. use the local protocol stack to the appropriate network
	//       interface
	
	BOpt = TRUE;
	if (setsockopt(SockRaw, SOL_SOCKET, SO_DONTROUTE, (char *)&BOpt, sizeof(BOOL)) == SOCKET_ERROR)
		printf("setsockopt(SO_DONTROUTE) failed: %d\n",WSAGetLastError());

	 
	// Here we are creating and filling in an ICMP header that is the
	// core of trace route.
	
	memset(IcmpData, 0, MAX_PACKET);
	FillicmpData(IcmpData, DataSize);

	printf("\nTracing route to %s over a maximum of %d hops:\n\n", DestAdr, MaxHops);

	for (TTL = 1; ((TTL < MaxHops) && (!Done)); TTL++)
	{
		int bwrote;

		
		//sending icmp packet
		//for greater accuracy send three times

		for (int i = 1; i < 4; i++)
		{
			// Set the time to live option on the socket
			SetTimetoLive(SockRaw, TTL);

			
			// Fill in some more data in the ICMP header
			
			((IcmpHeader*)IcmpData)->i_cksum = 0;
			((IcmpHeader*)IcmpData)->SendTimeStamp = GetTickCount();

			((IcmpHeader*)IcmpData)->i_seq = SeqNo++;
			((IcmpHeader*)IcmpData)->i_cksum = CheckSumm((WORD*)IcmpData, DataSize);
			*OldTime = ((IcmpHeader*)IcmpData)->SendTimeStamp;//current time on this machine for 
															  //checking send-receive-transmit time
															  
															  // Send the ICMP packet to the destination
			
			bwrote = sendto(SockRaw, IcmpData, DataSize, 0,(SOCKADDR *)&Dest, sizeof(Dest));

			if (bwrote == SOCKET_ERROR)
			{
				if (i < 2)
				{
					printf("%2d\n\n", TTL);
				}
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					printf("%2d  Send request timed out.\n", (GetTickCount()-(*OldTime)));
					continue;
				}
				printf("sendto() failed: %d\n", WSAGetLastError());
				return -1;
			}

			// Read a packet back from the destination or a router along
			// the way.
			
			Ret = recvfrom(SockRaw, RecvBuf, MAX_PACKET, 0, (struct sockaddr*)&From, &FromLen);

			if (Ret == SOCKET_ERROR)
			{
				if (i < 2)
				{
					printf("%2d\n\n", TTL);
				}
				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					printf("%2d  Receive Request timed out.\n", (GetTickCount() - (*OldTime)));
					continue;
				}
				printf("recvfrom() failed: %d\n", WSAGetLastError());
				return -1;
			}
			
			// Decode the response to see if the ICMP response is from a
			// router along the way or whether it has reached the destination.
			
			
			((IcmpHeader*)RecvBuf)->RecvTimeStamp;

			if (i < 2)
			{
				printf("%2d\n\n", TTL);
			}

			Done = DecodeResponse(RecvBuf, Ret, &From, TTL, OldTime);
			
			//CurTime= ((IcmpHeader*)IcmpData)->SendTimeStamp;
		}
		printf("\n");
	}
	HeapFree(GetProcessHeap(), 0, RecvBuf);
	HeapFree(GetProcessHeap(), 0, IcmpData);
	system("pause");

	return 0;
}