#ifndef  ARPING_H
#define  ARPING_H

#pragma pack(1) //���ֽڶ��룬��������ʽ�޷�����
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP������Ӧ����˵�����ֶε�ֵΪx0806  
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ  
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ����Э����ַ����ֵΪx0800��ʾIP��ַ  
#define ARP_REQUEST     1   //ARP����  
#define ARP_REPLY       2      //ARPӦ��  
#define HOSTNUM         255   //�������� 
#define ECHO            8     //����
struct ethernet_head            //��̫������֡ͷ
{
	unsigned char dest_mac[6];
	unsigned char source_mac[6];
	unsigned short eh_type; //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};
struct arp_head                 //ARP���ݰ����ݲ��ֽṹ
{
	unsigned short hardware_type;  // Ӳ�����ͣ�Ethernet���ӿ�����Ϊ1
	unsigned short protocol_type;  // Э�����ͣ�IPЭ������Ϊ0x0800
	unsigned char add_len;         // Ӳ����ַ���ȣ�MAC��ַ����Ϊ6�ֽ�
	unsigned char pro_len;         // Э����ַ���ȣ�IP��ַ����Ϊ4�ֽ�
	unsigned short option;         // ARP�������ͣ�1��ʾ������2��ʾӦ��
	unsigned char sour_addr[6];    // ԴMAC��ַ�����ͷ���MAC��ַ
	unsigned long sour_ip;         // ԴIP��ַ�����ͷ���IP��ַ
	unsigned char dest_addr[6];    // Ŀ��MAC��ַ����ARP������û�����壬��ARP��Ӧ��Ϊ���շ���MAC��ַ
	unsigned long dest_ip;         // Ŀ��IP��ַ����ARP������Ϊ��������IP��ַ����ARP��Ӧ��Ϊ���շ���IP��ַ
	//unsigned char padding[18];     // �����ֽڣ�����������С����
};
struct arp_package              //ARP���ݰ��ṹ
{
	ethernet_head eth;
	arp_head arp;
};
/*
struct icmp_head{
	unsigned char i_type; //8λ����, ��ʵ���� 8: ECHO 0:ECHO REPLY
	unsigned char i_code; //8λ����, ��ʵ������
	byte checkSum[2];//�޷��ַ�byte
};
struct ip_head{
	unsigned char h_lenver; //4 λIP�汾��+4λ�ײ�����
	unsigned char tos; //8λ��������TOS
	unsigned short total_len; //16λIP���ܳ��ȣ��ֽڣ�
	unsigned short ident; //16λ��ʶ, ���ڸ���IP���Ĳ�װ,����
	unsigned short frag_and_flags; //3λ��־λ+13λƫ��λ, Ҳ������IP���Ĳ�װ,����
	unsigned char ttl; //8λIP������ʱ�� TTL
	unsigned char proto; //8λЭ�� (TCP, UDP ������),��Ϊ1
	unsigned short checksum; //16λIP�ײ�У����,��������,�����а�ͷ����д��ȷ��,���㲢�滻.
	unsigned int sourceIP; //32λԴIP��ַ
	unsigned int destIP; //32λĿ��IP��ַ
};
struct icmp_package
{
	ethernet_head eth;
	ip_head iph;
	icmp_head icmp;
};*/
#endif
