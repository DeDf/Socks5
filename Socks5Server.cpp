/*
    SOCKS v4 && v5 && Http Proxy Server
    usage:
        双击 - 直接启动，默认端口10086
        Socks5 [port] [UserName] [PassWord]
*/
#include <winsock2.h>
#include <stdio.h>
#include <errno.h>

#pragma comment(lib,"ws2_32.lib")

#define MAX_HOSTNAME 256
#define MAXBUFSIZE   20480
#define TIMEOUT      10000
#define HEADLEN      7

#define _OUT_

char HTTP_200_OK[]="HTTP/1.0 200 OK\r\n\r\n";

char g_Username[256];
char g_Password[256];

struct Socks4Req
{
    BYTE Ver;
    BYTE REP;
    WORD wPort;
    DWORD dwIP;
    BYTE other[1];
};

struct Socks5Req
{
    BYTE Ver;
    BYTE nMethods;
    BYTE Methods[255];
};

struct AuthReq
{
    BYTE Ver;
    BYTE Ulen;
    BYTE UserPass[1024];
};

typedef struct
{
	BYTE Ver;      // Version Number
	BYTE CMD;      // 0x01==TCP CONNECT,0x02==TCP BIND,0x03==UDP ASSOCIATE
	BYTE RSV;
	BYTE ATYP;
	BYTE IP_LEN;
	BYTE szIP;
}Socks5Info;

typedef struct
{
	DWORD IP;
	WORD Port;
}IP_PORT;

typedef struct
{
	BYTE Ver;
	BYTE REP;
	BYTE RSV;
	BYTE ATYP;
	IP_PORT IP_PORT;
}Socks5AnsConn;

typedef struct
{
	BYTE RSV[2];
	BYTE FRAG;
	BYTE ATYP;
	IP_PORT IP_PORT;
	// BYTE DATA;
}Socks5UDPHead;

struct SocketInfo
{
	SOCKET socks;
	IP_PORT IP_Port;
};

typedef struct
{
	SocketInfo Local;
	SocketInfo Client;
	SocketInfo Server;
}Socks5Para;
// End Of Structure

void TCPTransfer(SOCKET* CSsocket);
void UDPTransfer(Socks5Para *sPara);
BOOL ConnectToRemoteHost(SOCKET *ServerSocket,char *HostName,const WORD RemotePort);

//functions

void GetHostNameAndPort(char *ReceiveBuf,int datalen,char *HostName,UINT *RemotePort)
{
    if (datalen > MAX_HOSTNAME)
        datalen = MAX_HOSTNAME;

	char *p = ReceiveBuf;
	for(int i = 0;
        i < datalen && *p != ':' && *p != '\0' && *p != '\r' && *p != '/';
        i++)
	{
		HostName[i]=*p++;

		if(*p == ':')
			*RemotePort=atoi(p+1);
	}
}
//---------------------------------------------------------------------------
char * GetURLRootPoint(char * ReceiveBuf,int DataLen,int *HostNaneLen)
{
	for(int i = 0;i < DataLen; i++)
	{
		if(ReceiveBuf[i] == '/')
		{
			*HostNaneLen = i;
			return &ReceiveBuf[i];
		}
	}
	return NULL;
}
//---------------------------------------------------------------------------
// 检查从client收到的请求buf，看是否为http请求
int CheckHttpRequest(const char *ReceiveBuf, int *MethodLength)  // done!
{
	if(!_strnicmp(ReceiveBuf,"GET ",4))
	{
		*MethodLength = 4;
		return 1;
	}
	
    if(!_strnicmp(ReceiveBuf,"HEAD ",5)) //Looks like the same with GET
	{
		*MethodLength = 5;
		return 2;
	}
	
    if(!_strnicmp(ReceiveBuf,"POST ",5))
	{
		*MethodLength = 5;
		return 3;
	}
	
    if(!_strnicmp(ReceiveBuf,"CONNECT ",8))
	{
		*MethodLength = 8;
		return 4;
	}

	return 0;
}

int ModifyRequest(char *SenderBuf,char *ReceiveBuf,int DataLen,int MethodLength)
{
	strncpy_s(SenderBuf,MAXBUFSIZE,ReceiveBuf,MethodLength);
	
	if(strncmp(ReceiveBuf+MethodLength, "http://", HEADLEN))
		return 0;
	
    int HedLen = 0;
	char * Getrootfp = GetURLRootPoint(ReceiveBuf+MethodLength+HEADLEN,DataLen-MethodLength-HEADLEN,&HedLen);
	if(Getrootfp == NULL)
		return 0;
	
	memcpy(SenderBuf+MethodLength, Getrootfp, DataLen-MethodLength-HEADLEN-HedLen);
	
	return DataLen-HEADLEN-HedLen;
}

BOOL HttpProxy(SOCKET* CSsocket, char *ReceiveBuf, int DataLen)
{
    int MethodLength;
    int Flag = CheckHttpRequest(ReceiveBuf, &MethodLength);
    if (!Flag)
        goto exit;

    char *SenderBuf = (char*)malloc(MAXBUFSIZE);
    if (SenderBuf)
    {
        memset(SenderBuf,0,MAXBUFSIZE);

        char HostName[MAX_HOSTNAME] = {0};
        UINT RemotePort = 80;

        if(Flag==1 || Flag==2 || Flag==3)
        {
            int SendLength=ModifyRequest(SenderBuf,ReceiveBuf,DataLen,MethodLength);
            if(!SendLength)
                return 0;

            GetHostNameAndPort(ReceiveBuf+MethodLength+HEADLEN,
                DataLen-MethodLength-HEADLEN,
                HostName,
                &RemotePort);

            if(!ConnectToRemoteHost(&CSsocket[1],HostName,RemotePort))
                return 0;

            if(send(CSsocket[1],SenderBuf,SendLength,0) == SOCKET_ERROR)
                return 0;
        }
        else if(Flag==4)
        {
            GetHostNameAndPort(ReceiveBuf+MethodLength,
                DataLen-MethodLength,
                HostName,
                &RemotePort);

            if(!ConnectToRemoteHost(&CSsocket[1],HostName,RemotePort))
                return 0;

            send(CSsocket[0], HTTP_200_OK, (int)strlen(HTTP_200_OK)+1, 0);
        }

        free(SenderBuf);
        return 1;
    }

exit:
    return 0;
}

BOOL SendRequest(SOCKET* CSsocket, char *SenderBuf, char *ReceiveBuf, int DataLen)
{
	int MethodLength=0;
	int Flag = CheckHttpRequest(ReceiveBuf,&MethodLength);
	if(Flag==0)
        return 0;
	
    char HostName[MAX_HOSTNAME] = {0};
    UINT RemotePort = 80;

	if(Flag==1 || Flag==2 || Flag==3)
	{
		int SendLength=ModifyRequest(SenderBuf,ReceiveBuf,DataLen,MethodLength);
		if(!SendLength)
			return 0;

		GetHostNameAndPort(ReceiveBuf+MethodLength+HEADLEN,DataLen-MethodLength-HEADLEN,HostName,&RemotePort);
		if(!ConnectToRemoteHost(&CSsocket[1],HostName,RemotePort))
			return 0;

		if(send(CSsocket[1],SenderBuf,SendLength,0) == SOCKET_ERROR)
			return 0;
	}
    else if(Flag==4)
	{
		GetHostNameAndPort(ReceiveBuf+MethodLength,
                           DataLen-MethodLength,
                           HostName,
                           &RemotePort);
		if(!ConnectToRemoteHost(&CSsocket[1],HostName,RemotePort))
			return 0;

		send(CSsocket[0], HTTP_200_OK, (int)strlen(HTTP_200_OK)+1,0);
	}

	if(CSsocket[0] && CSsocket[1])
	{
		//printf("HTTP Proxy request OK.\n");
		HANDLE ThreadHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)TCPTransfer,(LPVOID)CSsocket,0,0);
		if (ThreadHandle)
			WaitForSingleObject(ThreadHandle, INFINITE);
	}else
		return 0;

	return 1;
}

int Authentication(SOCKET s, char *ReceiveBuf)
{
	Socks5Req *sq = (Socks5Req *)ReceiveBuf;

    char Method[2]={0x05,0};

	if((sq->Methods[0]==0)||(sq->Methods[0]==2))//00，无需认证；01，GSSAPI；02，需要用户名和PASSWORD
	{
		if(strlen(g_Username)==0)
			Method[1]=0x00;
		else
			Method[1]=0x02;

		if(send(s,Method,2,0) == SOCKET_ERROR)
			return 0;
	}else
		return 0;

	if(Method[1]==0x02)
	{
		char USER[256];
		char PASS[256];
		memset(USER,0,sizeof(USER));
		memset(PASS,0,sizeof(PASS));

		int DataLen = recv(s,ReceiveBuf,MAXBUFSIZE,0);
		if(DataLen == SOCKET_ERROR || DataLen == 0)
			return 0;

		AuthReq *aq=(AuthReq *)ReceiveBuf;
		if(aq->Ver!=1)
			return 0;

		if((aq->Ulen!=0)&&(aq->Ulen<=256))
			memcpy(USER,ReceiveBuf+2,aq->Ulen);

		int PLen=ReceiveBuf[2+aq->Ulen];
		if((PLen!=0)&&(PLen<=256))
			memcpy(PASS,ReceiveBuf+3+aq->Ulen,PLen);

		if(!strcmp(g_Username,USER) && !strcmp(g_Password,PASS))
		{
			ReceiveBuf[1]=0x00;
			//printf("Socks5 Authentication Passed~\n");
		}
		else
		{
			ReceiveBuf[1]=0xFF;
			printf("Invalid Password\n");
		}

		if(send(s,ReceiveBuf,2,0) == SOCKET_ERROR)
			return 0;
	}
	
	return 1;
}

ULONG DNS(char *HostName)
{
	HOSTENT *hostent = gethostbyname(HostName);
	if (hostent == NULL)
		return 0;

	return **(PULONG*)hostent->h_addr_list;
}

int GetAddressAndPort(char *ReceiveBuf, int DataLen, char *HostName, ULONG *pIp, WORD *RemotePort)  // done!
{
	Socks5Info *Socks5Request=(Socks5Info *)ReceiveBuf;
	
	if( (Socks5Request->Ver==0)&&(Socks5Request->CMD==0) )
    {
        if (Socks5Request->ATYP==1)       // IPv4
        {
            IP_PORT *IPP=(IP_PORT *)&Socks5Request->IP_LEN;
            *pIp = IPP->IP;
            *RemotePort = IPP->Port;
            return 10;                       //return Data Enter point
        }
        else if (Socks5Request->ATYP==3)  // 域名
        {
            memcpy(HostName, &Socks5Request->szIP, Socks5Request->IP_LEN);
            memcpy(RemotePort, &Socks5Request->szIP+Socks5Request->IP_LEN, 2);
            return 7 + Socks5Request->IP_LEN;  //return Data Enter point
        }

        return 1;
    }

	return 0;
}

SOCKET ConnectToRemoteIP(IP_PORT *pIPP)
{
	// Create Socket
    SOCKET ServerSocket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if (ServerSocket == INVALID_SOCKET)
		return NULL;

    struct sockaddr_in Server;
    memset(&Server, 0, sizeof(Server));

    Server.sin_family = AF_INET;
    Server.sin_addr.s_addr = pIPP->IP;
    Server.sin_port = pIPP->Port;

	UINT TimeOut = TIMEOUT;
	setsockopt(ServerSocket,SOL_SOCKET,SO_RCVTIMEO,(char *)&TimeOut,sizeof(TimeOut));
	if (connect(ServerSocket, (const SOCKADDR *)&Server,sizeof(Server)) == SOCKET_ERROR)
	{
		printf("Fail To Connect To Remote Host\n");
		closesocket(ServerSocket);
        return NULL;
	}
	
	return ServerSocket;
}

BOOL ConnectToRemoteHost(SOCKET *ServerSocket,char *HostName,const WORD RemotePort)
{
    struct sockaddr_in Server;
    memset(&Server, 0, sizeof(Server));

    Server.sin_family = AF_INET;
    Server.sin_port = htons(RemotePort);

    if (inet_addr(HostName) != INADDR_NONE)
        Server.sin_addr.s_addr = inet_addr(HostName);
    else
        Server.sin_addr.s_addr = DNS(HostName);

    // Create Socket
    *ServerSocket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (*ServerSocket == INVALID_SOCKET)
        return FALSE;

    UINT TimeOut = TIMEOUT;
    setsockopt(*ServerSocket,SOL_SOCKET,SO_RCVTIMEO,(char *)&TimeOut,sizeof(TimeOut));
    if (connect(*ServerSocket, (const SOCKADDR *)&Server,sizeof(Server)) == SOCKET_ERROR)
    {
        printf("Fail To Connect To Remote Host\n");
        closesocket(*ServerSocket);
        return FALSE;
    }

    return TRUE;
}

int Get_IP_Port(SOCKET s, char *ReceiveBuf, IP_PORT *IPP)
{
    int DataLen = recv(s,ReceiveBuf,MAXBUFSIZE,0);
    if(DataLen == SOCKET_ERROR || DataLen == 0)
        return 0;

    Socks5Info *Socks5Request=(Socks5Info *)ReceiveBuf;

    //Get IP Type //0x01==IP V4地址 0x03代表域名;0x04代表IP V6地址;not Support
    if(Socks5Request->ATYP==1)
    {
        *IPP = *(IP_PORT *)&Socks5Request->IP_LEN;
    }
    else if (Socks5Request->ATYP==3)
    {
        IPP->Port = *(WORD*)((char*)&Socks5Request->szIP + Socks5Request->IP_LEN);

        if (Socks5Request->IP_LEN >= MAX_HOSTNAME)
            return 0;

        char HostName[MAX_HOSTNAME];
        memcpy(HostName, (char*)&Socks5Request->szIP, Socks5Request->IP_LEN);
        HostName[Socks5Request->IP_LEN] = 0;
        HOSTENT *hostent = gethostbyname(HostName);
        if (hostent == NULL)
            return 0;

        IPP->IP = **(PULONG*)hostent->h_addr_list;
    }
    else
        return 0;

    //Get and return the work mode. 1:TCP CONNECT   3:UDP ASSOCIATE
    if((Socks5Request->CMD == 1)||(Socks5Request->CMD == 3))
        return Socks5Request->CMD;

    return 0;
}

BOOL CreateUDPSocket(_OUT_ Socks5AnsConn *SAC, _OUT_ SOCKET *p_sock)  // done!
{
    *p_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(*p_sock == SOCKET_ERROR)
        return 0;

    struct sockaddr_in UDPServer;
    UDPServer.sin_family=AF_INET;
    UDPServer.sin_addr.s_addr=INADDR_ANY;
    UDPServer.sin_port=INADDR_ANY;

    if(bind(*p_sock, (SOCKADDR*)&UDPServer, sizeof(UDPServer)) == SOCKET_ERROR)
    {
        printf("UDP socket bind failed.\n");
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(sockaddr_in));
    int AddrLen=sizeof(sockaddr_in);
    getsockname(*p_sock, (struct sockaddr *)&addr, &AddrLen);
    SAC->IP_PORT.IP   = addr.sin_addr.s_addr;
    SAC->IP_PORT.Port = addr.sin_port;

    return 1;
}

BOOL DoSocks5(SOCKET *CSsocket, char *ReceiveBuf)
{
    if ( !Authentication(CSsocket[0], ReceiveBuf) )
        goto exit;

    Socks5AnsConn SAC;
	memset(&SAC,0,sizeof(SAC));
    SAC.Ver =0x05;
    SAC.ATYP=0x01;
    SAC.REP =0x01;  // 拒绝

    IP_PORT IP_Port;
	int CMD = Get_IP_Port(CSsocket[0], ReceiveBuf, &IP_Port);
	if(!CMD)
	{
	/*
    SAC.Ver=0x05;
	SAC.REP=0x01;
	SAC.ATYP=0x01;
	send(CSsocket[0], (char *)&SAC, 10, 0);
    */
		goto exit;
	}
	else if(CMD==1) //TCP CONNECT
	{
        CSsocket[1] = ConnectToRemoteIP(&IP_Port);
        if (CSsocket[1])
            SAC.REP=0x00;

        if(send(CSsocket[0], (char *)&SAC, 10, 0) == SOCKET_ERROR)
			goto exit;

		if(SAC.REP==0x01)
			goto exit;

        return 1;
	}
	else if(CMD==3) //UDP ASSOCIATE
	{
        Socks5Para sPara;
        memset(&sPara,0,sizeof(Socks5Para));

        struct sockaddr_in in;
        memset(&in,0,sizeof(sockaddr_in));
        int structsize=sizeof(sockaddr_in);
		getpeername(CSsocket[0], (struct sockaddr *)&in, &structsize);  //Save the client connection information(client IP and source port)
        sPara.Client.socks=CSsocket[0];
		sPara.Client.IP_Port.IP  = in.sin_addr.s_addr;
		sPara.Client.IP_Port.Port= in.sin_port;
		
		if( CreateUDPSocket(&SAC, &sPara.Local.socks) )
			SAC.REP=0x00;

        if(SAC.REP==0x01)
            goto exit;

		if(send(CSsocket[0], (char *)&SAC, 10, 0) == SOCKET_ERROR)
			goto exit;
		
		sPara.Local.IP_Port = SAC.IP_PORT;
		UDPTransfer(&sPara);
	}

exit:
    return 0;
}

int UDPSend(SOCKET s, char *buf, int nBufSize, struct sockaddr_in *to, int tolen)  // done!
{
	int nBytesLeft = nBufSize;
	int nBytes = 0;

	while(nBytesLeft > 0)
	{
		nBytes = sendto(s, &buf[nBufSize - nBytesLeft], nBytesLeft, 0, (SOCKADDR *)to, tolen);
		if(nBytes == SOCKET_ERROR)
		{
			//printf("Failed to send buffer to socket %d.\r\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
		nBytesLeft -= nBytes;
	}

	return nBufSize - nBytesLeft;
}

void UDPTransfer(Socks5Para *sPara)
{
    int    result;
	struct sockaddr_in SenderAddr;
	int    SenderAddrSize = sizeof(SenderAddr);
	char   RecvBuf[MAXBUFSIZE];
	
	struct sockaddr_in UDPClient, UDPServer;
	memset(&UDPClient,0,sizeof(sockaddr_in));
	memset(&UDPServer,0,sizeof(sockaddr_in));
	
	UDPClient.sin_family = AF_INET;
	UDPClient.sin_addr.s_addr = sPara->Client.IP_Port.IP;
	UDPClient.sin_port = sPara->Client.IP_Port.Port;
	
	fd_set readfd;
    int DataLength=0;
	while(1)
	{
		FD_ZERO(&readfd);
		FD_SET((UINT)sPara->Local.socks,  &readfd);
		FD_SET((UINT)sPara->Client.socks, &readfd);
		result=select((int)sPara->Local.socks+1,&readfd,NULL,NULL,NULL);
		if((result<0) && (errno!=EINTR))
		{
			//printf("Select error.\r\n");
			break;
		}
		if(FD_ISSET(sPara->Client.socks, &readfd))
			break;
		if(FD_ISSET(sPara->Local.socks,  &readfd))
		{
			memset(RecvBuf,0,MAXBUFSIZE);
			DataLength=recvfrom(sPara->Local.socks,
				RecvBuf+10, MAXBUFSIZE-10, 0, (struct sockaddr FAR *)&SenderAddr, &SenderAddrSize);
			if(DataLength==SOCKET_ERROR)
			{
				//printf("UDPTransfer recvfrom error.\n");
				break;
			}
			if(SenderAddr.sin_addr.s_addr==sPara->Client.IP_Port.IP &&
               SenderAddr.sin_port       ==sPara->Client.IP_Port.Port) //Data come from client
			{
				//////这里要先修改udp数据报头
				WORD RemotePort = 0;
                char HostName[MAX_HOSTNAME] = {0};
                ULONG ip = 0;

				int DataOffset=GetAddressAndPort(RecvBuf+10, DataLength, HostName, &ip, &RemotePort);
				if(DataOffset)
				{
					// printf("Data come from client IP: %s:%d | %d Bytes.\n",
					// inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),DataLength);
					//send data to server
					// printf("IP: %s:%d || DataPoint: %d\n",HostName,RemotePort,DataPoint);
					
					UDPServer.sin_family=AF_INET;
                    if (ip)
                        UDPServer.sin_addr.s_addr= ip;
                    else
					    UDPServer.sin_addr.s_addr= DNS(HostName);
					UDPServer.sin_port=RemotePort;
					
					result=UDPSend(sPara->Local.socks,RecvBuf+10+DataOffset,DataLength-DataOffset,&UDPServer,sizeof(UDPServer));
					if(result == SOCKET_ERROR)
					{
						//printf("sendto server error\n");
						break;
					}
					//printf("Data(%d) sent to server succeed.|| Bytes: %d\n",DataLength-DataOffset,result);
				} else break;
			}
            else if(SenderAddr.sin_addr.s_addr==UDPServer.sin_addr.s_addr &&
                    SenderAddr.sin_port       ==UDPServer.sin_port)  //Data come from server
			{
				//send data to client
				// printf("Data come from server IP: %s:%d | %d Bytes.\n",
				// inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),DataLength);
				Socks5UDPHead *UDPHead = (Socks5UDPHead*)RecvBuf;
				memset(UDPHead,0,10);
				UDPHead->ATYP=0x01;
				UDPHead->IP_PORT=sPara->Client.IP_Port;
				
				result=UDPSend(sPara->Local.socks,RecvBuf,DataLength+10,&UDPClient,sizeof(UDPClient));
				if(result == SOCKET_ERROR)
				{
					//printf("sendto client error\n");
					break;
				}
				//printf("Data(%d) sent to client succeed.|| Bytes: %d\n",DataLength+10,result);
			}
		}
		Sleep(5);
	}

	closesocket(sPara->Local.socks);
	closesocket(sPara->Client.socks);
}

void TCPTransfer(SOCKET* CSsocket)
{
    int result;
	SOCKET ClientSocket = CSsocket[0];
	SOCKET ServerSocket = CSsocket[1];
	struct timeval timeset;
	fd_set readfd,writefd;
	
    char SenderBuf[MAXBUFSIZE];
	char read_in1[MAXBUFSIZE],send_out1[MAXBUFSIZE];
	char read_in2[MAXBUFSIZE],send_out2[MAXBUFSIZE];

	int read1=0,totalread1=0,send1=0;
	int read2=0,totalread2=0,send2=0;
	int sendcount1,sendcount2;

	int maxfd = max(ClientSocket,ServerSocket)+1;
    int i=0;

	memset(read_in1, 0,MAXBUFSIZE);
	memset(read_in2, 0,MAXBUFSIZE);
	memset(send_out1,0,MAXBUFSIZE);
	memset(send_out2,0,MAXBUFSIZE);
	
	timeset.tv_sec=TIMEOUT;
	timeset.tv_usec=0;
    while(1)
    {
        FD_ZERO(&readfd);
        FD_ZERO(&writefd);

        FD_SET((UINT)ClientSocket, &readfd);
        FD_SET((UINT)ClientSocket, &writefd);
        FD_SET((UINT)ServerSocket, &writefd);
        FD_SET((UINT)ServerSocket, &readfd);

        result=select(maxfd,&readfd,&writefd,NULL,&timeset);
        if((result<0) && (errno!=EINTR))
        {
            printf("Select error.\r\n");
            break;
        }
        else if(result==0)
        {
            printf("Socket time out.\r\n");
            break;
        }
        if(FD_ISSET(ServerSocket, &readfd))
        {
            if(totalread2<MAXBUFSIZE)
            {
                read2=recv(ServerSocket,read_in2,MAXBUFSIZE-totalread2, 0);
                if(read2==0)break;
                if((read2<0) && (errno!=EINTR))
                {
                    printf("Read ServerSocket data error,maybe close?\r\n\r\n");
                    break;
                }

                memcpy(send_out2+totalread2,read_in2,read2);

                totalread2+=read2;
                memset(read_in2,0,MAXBUFSIZE);
            }
        }

        if(FD_ISSET(ClientSocket, &writefd))
        {
            int err2=0;
            sendcount2=0;
            while(totalread2>0)
            {
                send2=send(ClientSocket, send_out2+sendcount2, totalread2, 0);
                if(send2==0)break;
                if((send2<0) && (errno!=EINTR))
                {
                    printf("Send to ClientSocket unknow error.\r\n");
                    err2=1;
                    break;
                }
                if((send2<0) && (errno==ENOSPC)) break;
                sendcount2+=send2;
                totalread2-=send2;

            }
            if(err2==1) break;
            if((totalread2>0) && (sendcount2 > 0))
            {
                /* move not sended data to start addr */
                memcpy(send_out2, send_out2+sendcount2, totalread2);
                memset(send_out2+totalread2, 0, MAXBUFSIZE-totalread2);
            }
            else
                memset(send_out2,0,MAXBUFSIZE);
        }


        if(FD_ISSET(ClientSocket, &readfd))
        {
            if(totalread1<MAXBUFSIZE)
            {
                read1=recv(ClientSocket, read_in1, MAXBUFSIZE-totalread1, 0);
                if((read1==SOCKET_ERROR) || (read1==0))
                {
                    break;
                }

                memcpy(send_out1+totalread1,read_in1,read1);

                totalread1+=read1;
                memset(read_in1,0,MAXBUFSIZE);
            }
            if(SendRequest(CSsocket,SenderBuf,send_out1,totalread1))
                totalread1=0;
        }

        if(FD_ISSET(ServerSocket, &writefd))
        {
            int err=0;
            sendcount1=0;
            while(totalread1>0)
            {
                send1=send(ServerSocket, send_out1+sendcount1, totalread1, 0);
                if(send1==0)break;
                if((send1<0) && (errno!=EINTR))
                {
                    err=1;
                    break;
                }

                if((send1<0) && (errno==ENOSPC)) break;
                sendcount1+=send1;
                totalread1-=send1;

            }

            if(err==1) break;
            if((totalread1>0) && (sendcount1>0))
            {
                memcpy(send_out1,send_out1+sendcount1,totalread1);
                memset(send_out1+totalread1,0,MAXBUFSIZE-totalread1);
            }
            else
                memset(send_out1,0,MAXBUFSIZE);
        }
        Sleep(5);
    }

    closesocket(ClientSocket);
    closesocket(ServerSocket);
}

DWORD WINAPI ProxyThread(PVOID sClient)
{
    SOCKET CSsocket[2];
    CSsocket[0] = (SOCKET)sClient;
    CSsocket[1] = NULL;

    char buf[1024];
    memset(buf, 0, sizeof(buf));

    int DataLen = recv(CSsocket[0],buf,sizeof(buf),0);
    if( DataLen == SOCKET_ERROR || DataLen == 0 )
        goto exit;

    // 判断代理类型，1代表是http代理，4是Socks4，5是Socks5，其他不支持直接return。
    char ProxyType = buf[0];
    if (ProxyType == 5)
    {
        if ( !DoSocks5(CSsocket, buf) )
            goto exit;
    }
    else if (ProxyType == 4)
    {
        Socks4Req *Socks4Request = (Socks4Req *)buf;
        IP_PORT IPP;
        IPP.Port = Socks4Request->wPort;

        if(buf[4]!=0x00) //USERID !!
            IPP.IP = Socks4Request->dwIP;
        else
        {
            HOSTENT *hostent = gethostbyname( (char*)&Socks4Request->other+1 );
            if (hostent == NULL)
                goto exit;

            IPP.IP = **(PULONG*)hostent->h_addr_list;
        }

        memset(Socks4Request, 0, 9);
        CSsocket[1] = ConnectToRemoteIP(&IPP);
        if( CSsocket[1] )
            Socks4Request->REP = 0x5A; //GRANT  准许
        else
            Socks4Request->REP = 0x5B; //REJECT 拒绝

        if(send(CSsocket[0], (char *)Socks4Request, 8, 0) == SOCKET_ERROR)
            goto exit;

        if(Socks4Request->REP==0x5B)
            goto exit;
    }
    else
    {
        if ( !HttpProxy(CSsocket, buf, DataLen) )
            goto exit;
    }

    if(CSsocket[0] && CSsocket[1])
        TCPTransfer(CSsocket);

exit:
    if (CSsocket[1])
        closesocket(CSsocket[1]);
    if (CSsocket[0])
        closesocket(CSsocket[0]);

    return 0;
}

void StartProxy(u_short LisPort)  // done!
{
    WSADATA WSAData;
    if(WSAStartup(MAKEWORD(2,2), &WSAData))
        return;

    SOCKET sProxy = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sProxy == SOCKET_ERROR)
        return;

    struct sockaddr_in Server={0};

    Server.sin_family = AF_INET;
    Server.sin_addr.S_un.S_addr = INADDR_ANY;
    Server.sin_port = htons(LisPort);

    if(bind(sProxy, (LPSOCKADDR)&Server, sizeof(Server)) == SOCKET_ERROR)
        return;

    if(listen(sProxy, SOMAXCONN) == SOCKET_ERROR)
        return;

    while(1)
    { 
        SOCKET sClient = accept(sProxy, NULL, NULL);
        HANDLE hThread = CreateThread (NULL,0,(LPTHREAD_START_ROUTINE)ProxyThread,(PVOID)sClient,0,NULL);
        if (hThread)
            CloseHandle(hThread);
    }

    closesocket(sProxy);
    WSACleanup();
}

int main(int argc, char* argv[])  // done!
{
    u_short LisPort = 10086;

    printf("SOCKS4 & SOCKS5 & Http Proxy V1.0\n"
           "  usage:\n"
           "    双击 - 直接启动，默认端口10086\n"
           "    Socks5 [port] [UserName] [PassWord]\n\n"
        );

    if(argc>=2)
    {
        LisPort=atoi(argv[1]);

        if(argc==4)
        {
            strcpy_s(g_Username, sizeof(g_Username), argv[2]);
            strcpy_s(g_Password, sizeof(g_Password), argv[3]);

            printf(" ~ Username : %s, Password : %s\n", g_Username, g_Password);
        }
    }

    printf(" ~ ProxyPort = %d\n", LisPort);
    StartProxy(LisPort);
	return 0;
}