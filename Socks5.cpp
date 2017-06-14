/*
    SOCKS v4 && v5 && Http Proxy
    usage:
        双击 - 直接启动，默认端口10086
        Socks5 -i 安装为服务
        Socks5 -u 删除服务
        Socks5 -p PORT USER PASS
*/
#include <winsock2.h>
#include <Windows.h>
#include <Winsvc.h>
#include <stdio.h>
#include <errno.h>

#pragma comment(lib,"ws2_32.lib")

#define MAX_HOSTNAME 256
#define DEFLISNUM    50
#define MAXBUFSIZE   20480
#define TIMEOUT      10000
#define HEADLEN      7

SERVICE_STATUS g_ServiceStatus;
SERVICE_STATUS_HANDLE g_ServiceStatusHandle;

char HTTP_200_OK[]="HTTP/1.0 200 OK\r\n\r\n";

u_short LisPort = 10086;
char Username[256]="\0";
char Password[256]="\0";

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
	IPandPort IPandPort;
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
		if(strlen(Username)==0)
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

		if(!strcmp(Username,USER) && !strcmp(Password,PASS))
		{
			ReceiveBuf[1]=0x00;
			printf("Socks5 Authentication Passed~\n");
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

int GetAddressAndPort(char *ReceiveBuf, int DataLen, int ATYP, char *HostName, WORD *RemotePort)
{
	Socks5Info *Socks5Request=(Socks5Info *)ReceiveBuf;
	struct sockaddr_in in;
	
	if( (Socks5Request->Ver==0)&&(Socks5Request->CMD==0) )
    {
        if (ATYP==1)
        {
            IP_PORT *IPP=(IP_PORT *)&Socks5Request->IP_LEN;
            in.sin_addr.S_un.S_addr = IPP->IP;
            memcpy(HostName, inet_ntoa(in.sin_addr),strlen(inet_ntoa(in.sin_addr)));
            *RemotePort = ntohs(IPP->Port);
            return 10;                       //return Data Enter point
        }
        else if (ATYP==3)
        {
            memcpy(HostName, &Socks5Request->szIP, Socks5Request->IP_LEN);
            memcpy(RemotePort, &Socks5Request->szIP+Socks5Request->IP_LEN, 2);
            *RemotePort=ntohs(*RemotePort);
            return 7+Socks5Request->IP_LEN;  //return Data Enter point
        }
    }
    else
		return 0;
	
	return 1;
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

BOOL CreateUDPSocket(Socks5AnsConn *SAC, SOCKET *socks)
{
    SOCKET Locals = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(Locals == SOCKET_ERROR)
        return 0;

    struct sockaddr_in UDPServer;
    UDPServer.sin_family=AF_INET;
    UDPServer.sin_addr.s_addr=INADDR_ANY;
    UDPServer.sin_port=INADDR_ANY;

    if(bind(Locals,(SOCKADDR*)&UDPServer, sizeof(UDPServer)) == SOCKET_ERROR)
    {
        printf("UDP socket bind failed.\n");
        return 0;
    }

    //UINT TimeOut = TIMEOUT;
    //setsockopt(Locals,SOL_SOCKET,SO_RCVTIMEO,(char *)&TimeOut,sizeof(TimeOut));
    *socks = Locals;

    struct sockaddr_in in;
    memset(&in,0,sizeof(sockaddr_in));
    int structsize=sizeof(sockaddr_in);
    getsockname(Locals, (struct sockaddr *)&in, &structsize);
    SAC->IP_PORT.IP  = in.sin_addr.s_addr;
    SAC->IP_PORT.Port = in.sin_port;

    return 1;
}

BOOL DoSocks5(SOCKET *CSsocket, char *ReceiveBuf)
{
    if ( !Authentication(CSsocket[0], ReceiveBuf) )
        goto exit;

    Socks5AnsConn SAC;
	memset(&SAC,0,sizeof(SAC));
    SAC.Ver=0x05;
    SAC.ATYP=0x01;
    SAC.REP=0x01;  // 拒绝

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
		sPara.Client.IPandPort.dwIP = in.sin_addr.s_addr;
		sPara.Client.IPandPort.wPort= in.sin_port;
		
		if( CreateUDPSocket(&SAC, &sPara.Local.socks) )
			SAC.REP=0x00;

		if(send(CSsocket[0], (char *)&SAC, 10, 0) == SOCKET_ERROR)
			goto exit;

		if(SAC.REP==0x01)
			goto exit;
		
		sPara.Local.IPandPort = SAC.IP_PORT;
		UDPTransfer(&sPara);
	}

exit:
    return 0;
}

DWORD WINAPI ProxyThread(SOCKET* CSsocket)
{
    // 申请ReceiveBuf，接收client发来的第一条消息
    int DataLen;
	char *ReceiveBuf = (char*)malloc(MAXBUFSIZE);
    if ( !ReceiveBuf)
        goto exit;

    memset(ReceiveBuf,0,MAXBUFSIZE);
    DataLen = recv(CSsocket[0],ReceiveBuf,MAXBUFSIZE,0);
    if( DataLen == SOCKET_ERROR || DataLen == 0 )
        goto exit;


    // 判断代理类型，1代表是http代理，4是Socks4，5是Socks5，其他不支持直接return。
    char ProxyType = ReceiveBuf[0];
    if (ProxyType == 5)
    {
        if ( !DoSocks5(CSsocket, ReceiveBuf) )
            goto exit;
    }
    else if (ProxyType == 4)
    {
        Socks4Req *Socks4Request = (Socks4Req *)ReceiveBuf;
        IP_PORT IPP;
        IPP.Port = Socks4Request->wPort;

        if(ReceiveBuf[4]!=0x00) //USERID !!
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
        if ( !HttpProxy(CSsocket, ReceiveBuf, DataLen) )
            goto exit;
    }
	
	if(CSsocket[0] && CSsocket[1])
		TCPTransfer(CSsocket);

exit:
    if (CSsocket[1])
        closesocket(CSsocket[1]);
	closesocket(CSsocket[0]);
	free(CSsocket);
    if (ReceiveBuf)
	    free(ReceiveBuf);
	return 0;
}

BOOL StartProxy()  // done!
{
	WSADATA WSAData;
	if(WSAStartup(MAKEWORD(2,2), &WSAData))
		return false;
	
	SOCKET ProxyServer= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(ProxyServer == SOCKET_ERROR)
		return false;
	
	struct sockaddr_in Server={0};
	
	Server.sin_family = AF_INET;
    Server.sin_addr.S_un.S_addr = INADDR_ANY;
	Server.sin_port = htons(LisPort);
	
	if(bind(ProxyServer, (LPSOCKADDR)&Server, sizeof(Server)) == SOCKET_ERROR)
		return false;
	
	if(listen(ProxyServer, DEFLISNUM) == SOCKET_ERROR)
		return false;
	
	SOCKET AcceptSocket = INVALID_SOCKET;
	SOCKET *CSsocket;
	DWORD dwThreadID;

	while(1)
	{
		AcceptSocket = accept(ProxyServer, NULL, NULL);

		CSsocket = (SOCKET*)malloc(sizeof(SOCKET)*2);
		if (CSsocket)
		{
            CSsocket[0] = AcceptSocket;
            CSsocket[1] = NULL;
            HANDLE hThread = CreateThread (NULL,0,(LPTHREAD_START_ROUTINE)ProxyThread,CSsocket,0,&dwThreadID);
            if (hThread)
                CloseHandle(hThread);
        }
	}
}

int UDPSend(SOCKET s, char *buff, int nBufSize, struct sockaddr_in *to,int tolen)
{
	int nBytesLeft = nBufSize;
	int idx = 0, nBytes = 0;
	while(nBytesLeft > 0)
	{
		nBytes = sendto(s, &buff[idx], nBytesLeft, 0, (SOCKADDR *)to, tolen);
		if(nBytes == SOCKET_ERROR)
		{
			//printf("Failed to send buffer to socket %d.\r\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
		nBytesLeft -= nBytes;
		idx += nBytes;
	}
	return idx;
}

void UDPTransfer(Socks5Para *sPara)
{
    int result;
	struct sockaddr_in SenderAddr;
	int   SenderAddrSize=sizeof(SenderAddr),DataLength=0;
	char RecvBuf[MAXBUFSIZE];
	
	struct sockaddr_in UDPClient,UDPServer;
	memset(&UDPClient,0,sizeof(sockaddr_in));
	memset(&UDPServer,0,sizeof(sockaddr_in));
	
	UDPClient.sin_family = AF_INET;
	UDPClient.sin_addr.s_addr = sPara->Client.IPandPort.dwIP;
	UDPClient.sin_port = sPara->Client.IPandPort.wPort;

	/*/test
	Socks5UDPHead test;
	memset(&test,0,sizeof(Socks5UDPHead));
	test.RSV[0]=0x05;
	test.ATYP=0x01;
	test.IPandPort=sPara->Local.IPandPort;
	if(sendto(sPara->Local.socks,(char*)&test, 10,0,(struct sockaddr FAR *)&UDPClient,sizeof(UDPClient)) == SOCKET_ERROR)
	{
	//printf("test sendto server error.\n");
	return;
}*/
	
	fd_set readfd;
	while(1)
	{
		FD_ZERO(&readfd);
		FD_SET((UINT)sPara->Local.socks, &readfd);
		FD_SET((UINT)sPara->Client.socks, &readfd);
		result=select(sPara->Local.socks+1,&readfd,NULL,NULL,NULL);
		if((result<0) && (errno!=EINTR))
		{
			//printf("Select error.\r\n");
			break;
		}
		if(FD_ISSET(sPara->Client.socks, &readfd))
			break;
		if(FD_ISSET(sPara->Local.socks, &readfd))
		{
			memset(RecvBuf,0,MAXBUFSIZE);
			DataLength=recvfrom(sPara->Local.socks,
				RecvBuf+10, MAXBUFSIZE-10, 0, (struct sockaddr FAR *)&SenderAddr, &SenderAddrSize);
			if(DataLength==SOCKET_ERROR)
			{
				//printf("UDPTransfer recvfrom error.\n");
				break;
			}//SenderAddr.sin_addr.s_addr==sPara->Client.IPandPort.dwIP&&
			if(SenderAddr.sin_port==sPara->Client.IPandPort.wPort)//Data come from client
			{
				//////这里要先修改udp数据报头
				WORD RemotePort = 0;
				char HostName[MAX_HOSTNAME];
				memset(HostName,0,MAX_HOSTNAME);
				int DataPoint=GetAddressAndPort(RecvBuf+10, DataLength, RecvBuf[13], HostName, &RemotePort);
				if(DataPoint)
				{
					////printf("Data come from client IP: %s:%d | %d Bytes.\n",
					// inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),DataLength);
					//send data to server
					////printf("IP: %s:%d || DataPoint: %d\n",HostName,RemotePort,DataPoint);
					
					UDPServer.sin_family=AF_INET;
					UDPServer.sin_addr.s_addr= DNS(HostName);
					UDPServer.sin_port=htons(RemotePort);
					
					result=UDPSend(sPara->Local.socks,RecvBuf+10+DataPoint, DataLength-DataPoint,&UDPServer,sizeof(UDPServer));
					if(result == SOCKET_ERROR)
					{
						//printf("sendto server error\n");
						break;
					}
					printf("Data(%d) sent to server succeed.|| Bytes: %d\n",DataLength-DataPoint,result);
				}else break;
			}else if(SenderAddr.sin_port==UDPServer.sin_port)//Data come from server
			{//SenderAddr.sin_addr.s_addr==UDPServer.sin_addr.s_addr&&
				//send data to client
				////printf("Data come from server IP: %s:%d | %d Bytes.\n",
				// inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port),DataLength);
				Socks5UDPHead *UDPHead = (Socks5UDPHead*)RecvBuf;
				memset(UDPHead,0,10);
				UDPHead->ATYP=0x01;
				UDPHead->IP_PORT=sPara->Client.IPandPort;
				//UDPHead->IPandPort.dwIP =SenderAddr.sin_addr.s_addr;
				//UDPHead->IPandPort.wPort=SenderAddr.sin_port;
				//memcpy(&UDPHead->DATA-2,RecvBuf,DataLength);//UDPHead->DATA-2!!!!!!!!!!!!
				
				result=UDPSend(sPara->Local.socks,RecvBuf,DataLength+10,&UDPClient,sizeof(UDPClient));
				if(result == SOCKET_ERROR)
				{
					////printf("sendto client error\n");
					break;
				}
				//printf("Data(%d) sent to client succeed.|| Bytes: %d\n",DataLength+10,result);
			}else
			{
				//printf("!!!!!The data are not from client or server.drop it.%s\n",inet_ntoa(SenderAddr.sin_addr));
			}
		}
		Sleep(5);
	}
	closesocket(sPara->Local.socks);
	closesocket(sPara->Client.socks);
}

void TCPTransfer(SOCKET* CSsocket)
{
	SOCKET ClientSocket = CSsocket[0];
	SOCKET ServerSocket = CSsocket[1];
	struct timeval timeset;
	fd_set readfd,writefd;
	int result,i=0;
	char read_in1[MAXBUFSIZE],send_out1[MAXBUFSIZE],SenderBuf[MAXBUFSIZE];
	char read_in2[MAXBUFSIZE],send_out2[MAXBUFSIZE];
	int read1=0,totalread1=0,send1=0;
	int read2=0,totalread2=0,send2=0;
	int sendcount1,sendcount2;
	int maxfd = max(ClientSocket,ServerSocket)+1;
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


void WINAPI ServiceCtrlHandler(DWORD Opcode)
{
    switch(Opcode)
    {
    case SERVICE_CONTROL_PAUSE: 
        g_ServiceStatus.dwCurrentState  = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        g_ServiceStatus.dwCurrentState  = SERVICE_RUNNING;
        break;
    case SERVICE_CONTROL_STOP:
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        g_ServiceStatus.dwCheckPoint    = 0;
        g_ServiceStatus.dwWaitHint      = 0;
        break;
    }

    SetServiceStatus (g_ServiceStatusHandle,&g_ServiceStatus);
}

void WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    g_ServiceStatus.dwServiceType      = SERVICE_WIN32;
    g_ServiceStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwWin32ExitCode    = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint       = 0;
    g_ServiceStatus.dwWaitHint         = 0;

    g_ServiceStatusHandle = 
        RegisterServiceCtrlHandlerA("socks5", ServiceCtrlHandler); 
    if (g_ServiceStatusHandle)
    {
        g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint   = 0;
        SetServiceStatus (g_ServiceStatusHandle, &g_ServiceStatus);

        StartProxy();
        WSACleanup();
    }
}

BOOL InstallService()  // done!
{
    BOOL ret = false;

    WCHAR str[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH,str);
    wcscat_s(str,L"\\Socks5.exe");

    SC_HANDLE schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (schSCManager) 
    {
        SC_HANDLE hService = CreateServiceW(schSCManager,
            L"socks5",            // service name
            L"socks5",            // display name 
            SERVICE_ALL_ACCESS,        // desired access 
            SERVICE_WIN32_OWN_PROCESS, // service type 
            SERVICE_AUTO_START,        // start type 
            SERVICE_ERROR_NORMAL,      // error control type 
            str,  // service's binary 
            NULL, // no load ordering group 
            NULL, // no tag identifier 
            NULL, // no dependencies
            NULL, // LocalSystem account
            NULL); // no password

        if (hService)
        {
            ret = true;
            SERVICE_DESCRIPTIONW SD; 
            SD.lpDescription = L"Socks5代理服务器软件"; 
            ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &SD);
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(schSCManager);
    }

    return ret;
}

BOOL DeleteService()  // done!
{
    BOOL ret = false;

    SC_HANDLE hSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (hSCManager)
    {
        SC_HANDLE hService = OpenServiceA(hSCManager,"socks5",SERVICE_ALL_ACCESS);
        if (hService)
        {
            if(DeleteService(hService))
                ret = true;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }

    return ret;
}

int main(int argc, char* argv[])
{
	if(argc>1)
	{
		if(strcmp(argv[1],"-i")==0)
		{
			if(InstallService())
				printf("\nSocks5 Service Install Sucessfully~\n");
			else
				printf("\nSocks5 Service Install Error!\n");
            goto L_Exit;
		}
        
        if(strcmp(argv[1],"-u")==0)
		{
			if(DeleteService())
				printf("\nSocks5 Service UnInstall Sucessfully~\n");
			else
				printf("\nSocks5 Service UnInstall Error!\n");
            goto L_Exit;
		}
	}

//     SERVICE_TABLE_ENTRYA DispatchTable[]=
//     {
//         {"socks5",ServiceMain},
//         {NULL,NULL}
//     };
//     StartServiceCtrlDispatcherA(DispatchTable);

    if (!g_ServiceStatusHandle)
    {
        printf("SOCKS4 & SOCKS5 & Http Proxy V1.0\n");

        if(argc>2)
        {
            if(strcmp(argv[1],"-p")==0)
            {
                LisPort=atoi(argv[2]);
                printf(" ProxyPort %d\n", LisPort);

                if(argc==5)
                {
                    strcpy_s(Username,argv[3]);
                    strcpy_s(Password,argv[4]);

                    printf("Username %s Password %s\n", Username, Password);
                }
            }
        }
        else
        {
            printf(" ~ ProxyPort = %d\n", LisPort);
        }

        StartProxy();
        WSACleanup();
    }

L_Exit:
	return 0;
}