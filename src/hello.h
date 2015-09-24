#ifndef HELLO_H
#define HELLO_H

#include <stdlib.h>
#include <sys/time.h>

/*define the print debug level, sorted by the load to the AP */
#define LOG_DEBUG -1
#define LOG_SLIENT 0
#define LOG_INF 1
#define LOG_TRACE 2
#define LOG_DUMP 3

#define TCP_ACK 1
#define TCP_NON_ACK 2
#define C2AP_ACK 1
#define AP2C_ACK 2

#define MAC_LEN			6
#define HOLD_TIME       1000
#define CS_NUMBER       200
#define HT_NUMBER       100
#define PRINT_INTERVAL  20 /*20 seconds*/

#define TCP_HEADER      16

#define MAX_NODES		255
#define MAX_ESSIDS		255
#define MAX_BSSIDS		255
#define MAX_HISTORY		255
#define MAX_CHANNELS		64
#define MAX_ESSID_LEN		32
#define MAX_RATES		44	
#define MAX_FSTYPE		0xff
#define MAX_FILTERMAC		9

/* packet types we actually care about, e.g filter */
#define PKT_TYPE_CTRL		0x000001
#define PKT_TYPE_MGMT		0x000002
#define PKT_TYPE_DATA		0x000004

#define PKT_TYPE_BADFCS		0x000008

#define PKT_TYPE_BEACON		0x000010
#define PKT_TYPE_PROBE		0x000020
#define PKT_TYPE_ASSOC		0x000040
#define PKT_TYPE_AUTH		0x000080
#define PKT_TYPE_RTS		0x000100
#define PKT_TYPE_CTS		0x000200
#define PKT_TYPE_ACK		0x000400
#define PKT_TYPE_NULL		0x000800

#define PKT_TYPE_ARP		0x001000
#define PKT_TYPE_IP		0x002000
#define PKT_TYPE_ICMP		0x004000
#define PKT_TYPE_UDP		0x008000
#define PKT_TYPE_TCP		0x010000
#define PKT_TYPE_OLSR		0x020000
#define PKT_TYPE_OLSR_LQ	0x040000
#define PKT_TYPE_OLSR_GW	0x080000
#define PKT_TYPE_BATMAN		0x100000
#define PKT_TYPE_MESHZ		0x200000
#define PKT_TYPE_QDATA		0x400000

#define PKT_TYPE_ALL_MGMT	(PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL	(PKT_TYPE_RTS | PKT_TYPE_CTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA	(PKT_TYPE_NULL | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
				 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_OLSR_LQ | \
				 PKT_TYPE_OLSR_GW | PKT_TYPE_BATMAN | PKT_TYPE_MESHZ | PKT_TYPE_QDATA)

#define WLAN_MODE_AP		0x01
#define WLAN_MODE_IBSS		0x02
#define WLAN_MODE_STA		0x04
#define WLAN_MODE_PROBE		0x08

#define PHY_FLAG_SHORTPRE	0x0001
#define PHY_FLAG_BADFCS		0x0002
#define PHY_FLAG_A		0x0010
#define PHY_FLAG_B		0x0020
#define PHY_FLAG_G		0x0040
#define PHY_FLAG_MODE_MASK	0x00f0

/* default config values */
#define INTERFACE_NAME		"wlan0"
#define NODE_TIMEOUT		60	/* seconds */
#define CHANNEL_TIME		250000	/* 250 msec */
/* update display every 100ms - "10 frames per sec should be enough for everyone" ;) */
#define DISPLAY_UPDATE_INTERVAL 100000	/* usec */
#define RECV_BUFFER_SIZE	0	/* not used by default */
#define DEFAULT_PORT		"4444"	/* string because of getaddrinfo() */
#define DEFAULT_CONTROL_PIPE	"/tmp/horst"

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803    /* IEEE 802.11 + radiotap header */
#endif

#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header  */
#endif

struct inf_info {
	unsigned char wlan_src[MAC_LEN];
	unsigned char wlan_dst[MAC_LEN];
	float  value;
};
/***************
 store the delay break down info
****************/
struct delay_info {
	float udelay;
	float ddelay;
	float rtt;
};
struct packet_info {
	/* general */
	struct timeval tv;
	int len;
	/*wlan phy*/
	int phy_signal;
	int phy_noise;
	unsigned int phy_snr;
	unsigned int phy_rate;
	unsigned int phy_rate_idx;
	unsigned int phy_rate_flags;
	unsigned int phy_flags;

	/* wlan mac */
	u16		wlan_type;	/* frame control field */
	unsigned char		wlan_src[MAC_LEN];
	unsigned char		wlan_dst[MAC_LEN];
	int        ip_totlen;
	unsigned short int ip_id;
	unsigned short int ip_off;
	int tcp_type;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned int tcp_next_seq;
	unsigned int		wlan_nav;	/* frame NAV duration */
	unsigned int		wlan_retry;
	/*digest*/
	unsigned char		tcp_header[TCP_HEADER];
	u_int64_t		timestamp;	/* timestamp from mactime */
};
struct client{
	unsigned char mac[MAC_LEN];
	unsigned int pkt_all_data;
};
struct neighbor{
	struct timeval start_timeval;
	unsigned char mac[MAC_LEN];
	unsigned char clients[MAC_LEN];
	
	unsigned int pkt_all_data[HOLD_TIME];
	u16 type[HOLD_TIME];
	unsigned int index[HOLD_TIME];
	float time[HOLD_TIME];
	unsigned int retry[HOLD_TIME];
	
	unsigned int pkt_all; //including beacons
	unsigned int pkt_all_retry;
	struct client *cli;
	struct neighbor *next;
};
/* rate in 100kbps */
int
rate_to_index(int rate)
{
	switch (rate) {
		case 540: return 12;
		case 480: return 11;
		case 360: return 10;
		case 240: return 9;
		case 180: return 8;
		case 120: return 7;
		case 110: return 6;
		case 90: return 5;
		case 60: return 4;
		case 55: return 3;
		case 20: return 2;
		case 10: return 1;
		default: return 0;
	}
}


/* return rate in 100kbps */
int
rate_index_to_rate(unsigned int idx)
{
	switch (idx) {
		case 12: return 540;
		case 11: return 480;
		case 10: return 360;
		case 9: return 240;
		case 8: return 180;
		case 7: return 120;
		case 6: return 110;
		case 5: return 90;
		case 4: return 60;
		case 3: return 55;
		case 2: return 20;
		case 1: return 10;
		default: return 0;
	}
}

/* return rate in 100kbps */
int
mcs_index_to_rate(int mcs, int ht20, int lgi)
{
	/* MCS Index, http://en.wikipedia.org/wiki/IEEE_802.11n-2009#Data_rates */
	switch (mcs) {
		case 0:  return ht20 ? (lgi ? 65 : 72) : (lgi ? 135 : 150);
		case 1:  return ht20 ? (lgi ? 130 : 144) : (lgi ? 270 : 300);
		case 2:  return ht20 ? (lgi ? 195 : 217) : (lgi ? 405 : 450);
		case 3:  return ht20 ? (lgi ? 260 : 289) : (lgi ? 540 : 600);
		case 4:  return ht20 ? (lgi ? 390 : 433) : (lgi ? 810 : 900);
		case 5:  return ht20 ? (lgi ? 520 : 578) : (lgi ? 1080 : 1200);
		case 6:  return ht20 ? (lgi ? 585 : 650) : (lgi ? 1215 : 1350);
		case 7:  return ht20 ? (lgi ? 650 : 722) : (lgi ? 1350 : 1500);
		case 8:  return ht20 ? (lgi ? 130 : 144) : (lgi ? 270 : 300);
		case 9:  return ht20 ? (lgi ? 260 : 289) : (lgi ? 540 : 600);
		case 10: return ht20 ? (lgi ? 390 : 433) : (lgi ? 810 : 900);
		case 11: return ht20 ? (lgi ? 520 : 578) : (lgi ? 1080 : 1200);
		case 12: return ht20 ? (lgi ? 780 : 867) : (lgi ? 1620 : 1800);
		case 13: return ht20 ? (lgi ? 1040 : 1156) : (lgi ? 2160 : 2400);
		case 14: return ht20 ? (lgi ? 1170 : 1300) : (lgi ? 2430 : 2700);
		case 15: return ht20 ? (lgi ? 1300 : 1444) : (lgi ? 2700 : 3000);
		case 16: return ht20 ? (lgi ? 195 : 217) : (lgi ? 405 : 450);
		case 17: return ht20 ? (lgi ? 39 : 433) : (lgi ? 810 : 900);
		case 18: return ht20 ? (lgi ? 585 : 650) : (lgi ? 1215 : 1350);
		case 19: return ht20 ? (lgi ? 78 : 867) : (lgi ? 1620 : 1800);
		case 20: return ht20 ? (lgi ? 1170 : 1300) : (lgi ? 2430 : 2700);
		case 21: return ht20 ? (lgi ? 1560 : 1733) : (lgi ? 3240 : 3600);
		case 22: return ht20 ? (lgi ? 1755 : 1950) : (lgi ? 3645 : 4050);
		case 23: return ht20 ? (lgi ? 1950 : 2167) : (lgi ? 4050 : 4500);
		case 24: return ht20 ? (lgi ? 260 : 288) : (lgi ? 540 : 600);
		case 25: return ht20 ? (lgi ? 520 : 576) : (lgi ? 1080 : 1200);
		case 26: return ht20 ? (lgi ? 780 : 868) : (lgi ? 1620 : 1800);
		case 27: return ht20 ? (lgi ? 1040 : 1156) : (lgi ? 2160 : 2400);
		case 28: return ht20 ? (lgi ? 1560 : 1732) : (lgi ? 3240 : 3600);
		case 29: return ht20 ? (lgi ? 2080 : 2312) : (lgi ? 4320 : 4800);
		case 30: return ht20 ? (lgi ? 2340 : 2600) : (lgi ? 4860 : 5400);
		case 31: return ht20 ? (lgi ? 2600 : 2888) : (lgi ? 5400 : 6000);
	}
	return 0;
}


const char*
ether_sprintf(const unsigned char *mac)
{
	static char etherbuf[13];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf;
}

const char*
ether_sprintf2(const unsigned char *mac)
{
	static char etherbuf2[13];
	snprintf(etherbuf2, sizeof(etherbuf2), "%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf2;
}

int ieee80211_get_hdrlen(u16 fc)
{
	int hdrlen = 24;

	switch (fc & IEEE80211_FCTL_FTYPE) {
	case IEEE80211_FTYPE_DATA:
		if ((fc & IEEE80211_FCTL_FROMDS) && (fc & IEEE80211_FCTL_TODS))
			hdrlen = 30; /* Addr4 */
		/*
		 * The QoS Control field is two bytes and its presence is
		 * indicated by the IEEE80211_STYPE_QOS_DATA bit. Add 2 to
		 * hdrlen if that bit is set.
		 * This works by masking out the bit and shifting it to
		 * bit position 1 so the result has the value 0 or 2.
		 */
		hdrlen += (fc & IEEE80211_STYPE_QOS_DATA) >> 6;
		break;
	case IEEE80211_FTYPE_CTL:
		/*
		 * ACK and CTS are 10 bytes, all others 16. To see how
		 * to get this condition consider
		 *   subtype mask:   0b0000000011110000 (0x00F0)
		 *   ACK subtype:    0b0000000011010000 (0x00D0)
		 *   CTS subtype:    0b0000000011000000 (0x00C0)
		 *   bits that matter:         ^^^      (0x00E0)
		 *   value of those: 0b0000000011000000 (0x00C0)
		 */
		if ((fc & 0xE0) == 0xC0)
			hdrlen = 10;
		else
			hdrlen = 16;
		break;
	}

	return hdrlen;
}





static int
parse_radiotap_header(unsigned char * buf,  struct packet_info* p)
{
	struct ieee80211_radiotap_header* rh;
	__le32 present; /* the present bitmap */
	unsigned char* b; /* current byte */
	int i;
	u16 rt_len, x;
	unsigned char known, flags, ht20, lgi;

		


	rh = (struct ieee80211_radiotap_header*)buf;
	b = buf + sizeof(struct ieee80211_radiotap_header);
	present = le32toh(rh->it_present);
	rt_len = le16toh(rh->it_len);

	/* check for header extension - ignore for now, just advance current position */
	while (present & 0x80000000  && b - buf < rt_len) {
		present = le32toh(*(__le32*)b);
		b = b + 4;
	}
	present = le32toh(rh->it_present); // in case it moved
	/* radiotap bitmap has 32 bit, but we are only interrested until
	 * bit 19 (IEEE80211_RADIOTAP_MCS) => i<20 */
	for (i = 0; i < 20 && b - buf < rt_len; i++) {
		if ((present >> i) & 1) {
			
			switch (i) {
				/* just ignore the following (advance position only) */
				case IEEE80211_RADIOTAP_TSFT:
					
					p->timestamp = le64toh(*(u_int64_t*)b);//changhua
					b = b + 8;	
					break;
				case IEEE80211_RADIOTAP_DBM_TX_POWER:
				case IEEE80211_RADIOTAP_ANTENNA:
			
				case IEEE80211_RADIOTAP_RTS_RETRIES:
				case IEEE80211_RADIOTAP_DATA_RETRIES:
					
					b++;
					break;
				case IEEE80211_RADIOTAP_EXT:
					
					b = b + 4;
					break;
				case IEEE80211_RADIOTAP_FHSS:
				case IEEE80211_RADIOTAP_LOCK_QUALITY:
				case IEEE80211_RADIOTAP_TX_ATTENUATION:
					p->ip_totlen = le16toh(*(u_int16_t*)b);
				case IEEE80211_RADIOTAP_RX_FLAGS:
				case IEEE80211_RADIOTAP_TX_FLAGS:
				case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
					
					b = b + 2;
					break;
				/* we are only interrested in these: */
				case IEEE80211_RADIOTAP_RATE:
					p->phy_rate = (*b)*5; /* rate is in 500kbps */
					//p->phy_rate_idx = rate_to_index(p->phy_rate);
					b++;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
					p->tcp_ack = le32toh(*(u_int32_t*)b);
					p->phy_signal = *(char*)b;
					b++;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTNOISE:
					
					p->phy_noise = *(char*)b;
					b++;
					break;
				case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
					
					p->phy_snr = *b;
					b++;
					break;
				case IEEE80211_RADIOTAP_FLAGS:
					/* short preamble */
					
					if (*b & IEEE80211_RADIOTAP_F_SHORTPRE) {
						p->phy_flags |= PHY_FLAG_SHORTPRE;
						
					}
					if (*b & IEEE80211_RADIOTAP_F_BADFCS) {
						p->phy_flags |= PHY_FLAG_BADFCS;
						
					}
					
					/*here to get the potential tcp seq, only the outgoing tcp packet is valibale*/
					p->tcp_seq = le32toh(*(u_int32_t*)b);
					b++;
					break;
				case IEEE80211_RADIOTAP_CHANNEL:
					/* channel & channel type */
					if (((long)b)%2) b++; // align to 16 bit boundary
					
					b = b + 2;
					b = b + 2;
					break;
				case IEEE80211_RADIOTAP_MCS:
					/* Ref http://www.radiotap.org/defined-fields/MCS */
					known = *b++;
					flags = *b++;
					

					if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW)
						ht20 = (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20;
					else
						ht20 = 1; /* assume HT20 if not present */

					if (known & IEEE80211_RADIOTAP_MCS_HAVE_GI)
						lgi = !(flags & IEEE80211_RADIOTAP_MCS_SGI);
					else
						lgi = 1; /* assume long GI if not present */

					

					//p->phy_rate_idx = 12 + *b;
					p->phy_rate_flags = flags;
					/*to fix the debug of openwrt*/
					if (*(b-1) == 0x27)
						b++;
					p->phy_rate = mcs_index_to_rate(*b, ht20, lgi);
					
					
					b++;
					break;
			}
		}
		else {
			
		}
	}
	

	if (!(present & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL))) {
		/* no SNR in radiotap, try to calculate */
		if (present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) &&
		    present & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) &&
		    p->phy_noise < 0)
			p->phy_snr = p->phy_signal - p->phy_noise;
		/* HACK: here we just assume noise to be -95dBm */
		else {
			p->phy_snr = p->phy_signal + 95;
			//simulate noise: p->phy_noise = -90;
		}
	}

	/* sanitize */
	if (p->phy_snr > 99)
		p->phy_snr = 99;
	if (p->phy_rate == 0 || p->phy_rate > 6000) {
		/* assume min rate for mode */
		if (p->phy_flags & PHY_FLAG_A)
			p->phy_rate = 120; /* 6 * 2 */
		else if (p->phy_flags & PHY_FLAG_B)
			p->phy_rate = 20; /* 1 * 2 */
		else if (p->phy_flags & PHY_FLAG_G)
			p->phy_rate = 120; /* 6 * 2 */
		else
			p->phy_rate = 20;
	}



	
	
	return rt_len;
}


int parse_80211_header(const unsigned char * buf,  struct packet_info* p)
{
	
	struct ieee80211_hdr* wh;
	struct ieee80211_mgmt* whm;
	int hdrlen = 0;
	u8* sa = NULL;
	u8* da = NULL;
	u16 fc;
	//u16 type;



	wh = (struct ieee80211_hdr*)buf;
	fc = le16toh(wh->frame_control);
	//hdrlen = ieee80211_get_hdrlen(fc); //no need

	p->wlan_type = (fc & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE));
	//type = (fc & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE));
	
	switch (p->wlan_type & IEEE80211_FCTL_FTYPE) {
	case IEEE80211_FTYPE_DATA:
		hdrlen = 24;
		switch (p->wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_NULLFUNC:
			break;
		case IEEE80211_STYPE_QOS_DATA:
			hdrlen = 26;
			break;
		}

		p->wlan_nav = le16toh(wh->duration_id);

		sa = ieee80211_get_SA(wh);
		da = ieee80211_get_DA(wh);

		if (fc & IEEE80211_FCTL_PROTECTED)
			hdrlen = 34;
		if (fc & IEEE80211_FCTL_RETRY)
			p->wlan_retry = 1;

		break;

	case IEEE80211_FTYPE_CTL:
		switch (p->wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_RTS:
			p->wlan_nav = le16toh(wh->duration_id);
			sa = wh->addr2;
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_CTS:
			p->wlan_nav = le16toh(wh->duration_id);
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_ACK:
			p->wlan_nav = le16toh(wh->duration_id);
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_PSPOLL:
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_CFEND:
		case IEEE80211_STYPE_CFENDACK:
			da = wh->addr1;
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_BACK_REQ:
		case IEEE80211_STYPE_BACK:
			p->wlan_nav = le16toh(wh->duration_id);
			da = wh->addr1;
			sa = wh->addr2;
		}
		break;

	case IEEE80211_FTYPE_MGMT:
		//hdrlen = 24;
		whm = (struct ieee80211_mgmt*)buf;
		sa = whm->sa;
		da = whm->da;
		if (fc & IEEE80211_FCTL_RETRY)
			p->wlan_retry = 1;
		switch ( p->wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_BEACON:
		case IEEE80211_STYPE_PROBE_RESP:
/*		{
			if(debug == 1)
				printf("begin getting timestamp!\n");
			struct wlan_frame_beacon* bc = (struct wlan_frame_beacon*)((buf + 24));
			p->wlan_tsf = le64toh(bc->tsf);
			if(debug == 1)
				printf("find a beacon!!\n");
			break;
		}*/
		case IEEE80211_STYPE_PROBE_REQ:
		case IEEE80211_STYPE_ASSOC_REQ:
		case IEEE80211_STYPE_ASSOC_RESP:
		case IEEE80211_STYPE_REASSOC_REQ:
		case IEEE80211_STYPE_REASSOC_RESP:
		case IEEE80211_STYPE_DISASSOC:
		case IEEE80211_STYPE_AUTH:
		case IEEE80211_STYPE_DEAUTH:
			break;
		}
		break;
	
	}

	if (sa != NULL) {
		memcpy(p->wlan_src, sa, MAC_LEN);
	}
	if (da != NULL) {
		memcpy(p->wlan_dst, da, MAC_LEN);
	}
	
	return hdrlen;

}

/* return 1 if we parsed enough = min ieee header */
int parse_packet(const unsigned char *buf,  struct packet_info* p)
{
	
	int radio = parse_radiotap_header(buf,p);

	p->len = p->len - radio;
	
	int hdr = parse_80211_header(buf+radio,p);
	
	int llc = 8; /**/
	parse_ip_packet(buf+radio+hdr+llc,p);
	p->ip_totlen = radio+hdr+llc;
	p->tcp_type = hdr;
	return 0;
}

int parse_ip_packet(const unsigned char *buf,  struct packet_info* p)
{
	u8 *raw = (u8 *)(buf);
	if(((*raw) & 0x60) == 0x40){
		struct ip* ih;
		ih = (struct ip*)(buf);
		int ipl = ih->ip_hl*4;
		p->ip_totlen = ntohs(ih->ip_len);
		p->ip_id = ntohs(ih->ip_id);
		p->ip_off = ntohs(ih->ip_off);
		
	}else{
		
		/*ipv6, do nothing, need to be continue...*/
	}
	return 0;
}
			  

const char*
digest_sprintf16(const unsigned char *mac)   
{
	static char etherbuf[33];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],mac[6]
		,mac[7], mac[8], mac[9], mac[10], mac[11], mac[12],mac[13]
		,mac[14], mac[15]);
	return etherbuf;
}
const char*
digest_sprintf30(const unsigned char *mac)   
{
	static char etherbuf[61];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],mac[6]
		,mac[7], mac[8], mac[9], mac[10], mac[11], mac[12],mac[13]
		,mac[14], mac[15], mac[16], mac[17], mac[18], mac[19]
		,mac[20], mac[21], mac[22], mac[23], mac[24], mac[25]
		,mac[26], mac[27], mac[28], mac[29]);
	return etherbuf;
}

int str_equal(const unsigned char *s1,const unsigned char *s2,int len){
	int i ;
	for (i = 0; i < len ; i++)
	{
		if(( s1[i] != s2[i] )&&(tolower(s1[i]) != s2[i]))
			return 0;
	}
	return 1;
}

#endif
