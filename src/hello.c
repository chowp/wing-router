#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <ctype.h>
#include "ieee80211_radiotap.h"
#include "ieee80211.h"
#include "hello.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>
//#include <time.h>
#include <string.h>


#define __STDC_FORMAT_MACROS
#include <inttypes.h>
//#include "util.h"
/* Set of signals that get blocked while processing a packet. */
sigset_t block_set;

#define PCAP_TIMEOUT_MILLISECONDS 1000
#define PCAP_PROMISCUOUS 0
#define QUEUE_SIZE 0
#define IPV6 40
#define false 0
#define true 1

#define DUMP_DIR "/tmp/wifiunion-passive/m111.cap"
#define PENDING_UPDATE_FILENAME "/tmp/wifiunion-passive/current-update.gz"
#define PENDING_FREQUENT_UPDATE_FILENAME "/tmp/wifiunion-passive/current-frequent-update"
#define PENDING_FREQUENT_UPDATE_FILENAME_DELAY "/tmp/wifiunion-passive/current-frequent-update-delay"
#define UPDATE_FILENAME "/tmp/wifiunion-uploads/%s/passive/%s-%" PRIu64 "-%d.gz"
#define FREQUENT_UPDATE_FILENAME "/tmp/wifiunion-uploads/%s/inf_data/%s-%d-%d"
#define FREQUENT_UPDATE_FILENAME_DELAY "/tmp/wifiunion-uploads/%s/delay_data/%s-%d-%d"
#define UPLOAD_FAILURES_FILENAME "/tmp/wifiunion-data-transmit-failures.log"
//#define FREQUENT_UPDATE_PERIOD_SECONDS 30
#define NUM_MICROS_PER_SECOND 1e6
#define NUM_NANO_PER_SECOND   1e9
static int hold[HOLD_TIME];
static int FREQUENT_UPDATE_PERIOD_SECONDS;
static int FREQUENT_UPDATE_DELAY_SECONDS;

static unsigned char bismark_id[MAC_LEN];
static char mac[12];
static char mac_zero[12] = "000000000000";
static char mac_ffff[12] = "FFFFFFFFFFFF";
static int frequent_sequence_number = 0;
static int64_t start_timestamp_microseconds;
static int begin_time = 0;
static int now_time = 0;
static int last_time = 0;
static int debug;
static int rp = 0;
static int rpp = 0;
static int every = 0;
static int pch_count_debug = 0;
static double time_pch;
static int last_drop = 0;

struct packet_info store[HOLD_TIME]; /* used to store neighbor's info */
struct inf_info cs[CS_NUMBER]; /* used to store cs info in time gamma */
struct inf_info ht[HT_NUMBER]; /* used to store ht info in time gamma */
struct inf_info ht_tmp[HT_NUMBER];
static double inf_start_timestamp;
static double delay_start_timestamp;
static double inf_end_timestamp;    /* we record time to ouput the result */
static int pi = 0; /*use as the start point of neighbor packet_info */
static int pj = 0;

static int start_pointer = 0;
static int end_pointer = 0;

static pcap_t* pcap_handle = NULL;
pcap_dumper_t *pkt;
FILE *fin2;
static unsigned int rear = 0 ;
static unsigned int front = 0;
/*GLOBAL VALUE*/
struct packet_info p;
struct neighbor * nb;
static int nb_num = 1;

void init_neighbor(struct neighbor* n)
{
	int i =0;
	for(i = 0 ; i < HOLD_TIME ; i++)
		n->pkt_all_data[i] = 0;
	n->pkt_all = 0;
	n->pkt_all_retry = 0;
	n->cli = NULL;
	n->next = NULL;
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


int tcp_offset_mon(const unsigned char *buf){
	struct ieee80211_radiotap_header* rh;
	rh = (struct ieee80211_radiotap_header*)buf;
	int radio = le16toh(rh->it_len);
	//printf("radiotap' len is %d\n",radio);
	
	struct ieee80211_hdr* wh;
	u16 fc;
	wh = (struct ieee80211_hdr*)(buf+radio);
	fc = le16toh(wh->frame_control);
	int hdr = ieee80211_get_hdrlen(fc);
	//printf("ieee frame control is %x\n",fc);
	
	int llc = 8;
	

	
	int type = (int) fc;
	if(hdr == 26) //Qos Data
	{
		struct ip* ih;
		ih = (struct ip*)(buf+radio+hdr+8);
		int ipl = ih->ip_hl*4;
		//printf("IP header len is %d\n",ipl);
		
		return radio + hdr + llc + ipl;
	}
	else
		return type;
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
	
	int llc = 8;
	
	p->tcp_type = hdr;
	
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

void reset_one_line(int j)
{

	int no = 0;
	struct neighbor *tmp = nb;
	while (no < nb_num)
	{
		tmp->pkt_all_data[j] = 0;
		tmp = tmp->next;
		no = no + 1;
	}
	hold[j] = 0;

}


void update_list(struct inf_info *inf,int NUMBER, unsigned char mac1[], unsigned char mac2[], float value)
{	
	if (debug == 1)
		printf("debug parameter %s+%s:%f\n",ether_sprintf(mac1),ether_sprintf2(mac2),value);

	//printf("\n*******************************\n");
	int i;
	for(i=0;i<NUMBER;i++)
	{
		//printf("*  %s+%s:%f\n",ether_sprintf(inf[i].wlan_src),ether_sprintf2(inf[i].wlan_dst),inf[i].value);
		if (inf[i].value == 0)
		{
			//printf("*******************************\n\n");
			break;
			
		}
		if( 
			(
				(str_equal(mac_zero,ether_sprintf(mac1),2*MAC_LEN) != 1) &&
				(str_equal(mac_ffff,ether_sprintf(mac1),2*MAC_LEN) != 1)
			)
			&&
			( 
				(str_equal(ether_sprintf(mac1),ether_sprintf2(inf[i].wlan_src),2*MAC_LEN) == 1) ||
			    (str_equal(ether_sprintf(mac1),ether_sprintf2(inf[i].wlan_dst),2*MAC_LEN) == 1) 
			)
		  )

		{
			inf[i].value = inf[i].value + value; 
			//printf("US %s+%s:%f\n",ether_sprintf(inf[i].wlan_src),ether_sprintf2(inf[i].wlan_dst),inf[i].value);
			//printf("*******************************\n\n");
	
			return;
		}
		else if( 
			(	
				(str_equal(mac_zero,ether_sprintf(mac2),2*MAC_LEN) != 1)&&
				(str_equal(mac_ffff,ether_sprintf(mac2),2*MAC_LEN) != 1)
			)
			&&
			( 
				(str_equal(ether_sprintf(mac2),ether_sprintf2(inf[i].wlan_src),2*MAC_LEN) == 1) ||
			    (str_equal(ether_sprintf(mac2),ether_sprintf2(inf[i].wlan_dst),2*MAC_LEN) == 1) 
			)
		  )
		{
			inf[i].value = inf[i].value + value; 
			//printf("UD %s+%s:%f\n",ether_sprintf(inf[i].wlan_src),ether_sprintf2(inf[i].wlan_dst),inf[i].value);
			//printf("*******************************\n\n");
	
			return;
		}
	
	}

	/* i don't want oneof the "00000000000" to be the index of inf*/
	if (
		(str_equal(mac_zero,ether_sprintf(mac1),2*MAC_LEN) == 1)
	||  (str_equal(mac_zero,ether_sprintf2(mac2),2*MAC_LEN) == 1)
	||  (str_equal(mac_ffff,ether_sprintf(mac1),2*MAC_LEN) == 1)
	||	(str_equal(mac_ffff,ether_sprintf(mac2),2*MAC_LEN) == 1)
				 
		)
	{
		//printf("either 00000 or FFFFF !! return\n");
		//printf("*******************************\n\n");
	
		return;
	}
	/* there is no match!!*/
	for(i=0;i<NUMBER;i++)
	{
		if (inf[i].value ==0 )
		{
			memcpy(inf[i].wlan_src,mac1,MAC_LEN);
			memcpy(inf[i].wlan_dst,mac2,MAC_LEN);
			
			inf[i].value = value;
			//printf("C  %s+%s:%f\n",ether_sprintf(mac1),ether_sprintf2(mac2),inf[i].value);
			//printf("*******************************\n\n");
			return; /*pay attention whether it will jump out!*/
		}
	}
}

/**************************************/
static int write_frequent_update_delay() {
  //printf("Writing frequent log to %s\n", PENDING_FREQUENT_UPDATE_FILENAME);
  FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME_DELAY, "w");
  if (!handle) {
    perror("Could not open update file for writing\n");
    exit(1);
  }
  	end_pointer = rpp%HOLD_TIME;
 	int rounds =(end_pointer - start_pointer + HOLD_TIME )%HOLD_TIME;
 	int i = 0;
 	int ii = start_pointer;
 	printf("from %d to %d, rounds is %d\n",start_pointer,rpp,rounds);
 	while(i < rounds )
 	{
 		printf("ii is %d\n",ii);
 		if((store[ii].wlan_type == (u16)136) && 
 		  (str_equal(mac,ether_sprintf(store[ii].wlan_src),2*MAC_LEN) == 1) )
 		{
 			double time_pch1 = (double)((double)store[ii].tv.tv_sec + (double)((double)store[ii].tv.tv_usec/1000000.0));
			double time_pch2 = (double)store[ii].timestamp/(double)NUM_NANO_PER_SECOND;	
			
			fprintf(handle,"%lf,",time_pch1);
			fprintf(handle,"%lf,",time_pch2);
			fprintf(handle,"%u\n",store[ii].tcp_seq);
		}
		i = (i+1);
 		ii = (ii+1)%HOLD_TIME;
 	}
 /***************************/
	if(debug == 1)
	{
	printf("unlock and fileclose is good!\n");
	}
/*****************************/
  char update_filename[FILENAME_MAX];
  snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME_DELAY,
           mac,
           mac,
           1,
           frequent_sequence_number);
  if (rename(PENDING_FREQUENT_UPDATE_FILENAME_DELAY, update_filename)) {
    perror("Could not stage update");
    exit(1);
  }
  
 /************************/
	if(debug == 1)
	{
	printf("rename is good!\n");
	}
/*************************/

  start_timestamp_microseconds
      = nb->start_timeval.tv_sec + nb->start_timeval.tv_usec/NUM_MICROS_PER_SECOND;
  ++frequent_sequence_number;

    struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);

	if (debug == 11)
	{
		printf("received is: %d,dropped is: %d, total packets are :%d\n",statistics.ps_recv,statistics.ps_drop,rpp);
	}
	start_pointer = rpp%HOLD_TIME;
}


/**************************************/

static void write_frequent_update() {
  //printf("Writing frequent log to %s\n", PENDING_FREQUENT_UPDATE_FILENAME);
  FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME, "w");
 
  if (!handle) {
    perror("Could not open update file for writing\n");
    exit(1);
  }
 
  /*print out*/
  	
	int j = 0;
	for (j = 0 ; j < CS_NUMBER ;j ++)
	{
		if (cs[j].value == 0)
			break;
		fprintf(handle,"cs,%lf,%lf,%s,%s,%f\n",
			inf_start_timestamp,inf_end_timestamp,
			ether_sprintf(cs[j].wlan_src),ether_sprintf2(cs[j].wlan_dst),cs[j].value);
	}
		
	for (j = 0 ; j < HT_NUMBER ;j ++)
	{
		if (ht[j].value == 0)
			break;
		fprintf(handle,"ht,%lf,%lf,%s,%s,%f\n",
			inf_start_timestamp,inf_end_timestamp,
			ether_sprintf(ht[j].wlan_src),ether_sprintf2(ht[j].wlan_dst),ht[j].value);
	}

  fclose(handle);
 /***************************/
	if(debug == 1)
	{
	printf("unlock and fileclose is good!\n");
	}
/*****************************/
  char update_filename[FILENAME_MAX];
  snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME,
           mac,
           mac,
           nb->start_timeval.tv_sec,
           frequent_sequence_number);
  if (rename(PENDING_FREQUENT_UPDATE_FILENAME, update_filename)) {
    perror("Could not stage update");
    exit(1);
  }
  
 /************************/
	if(debug == 1)
	{
	printf("rename is good!\n");
	}
/*************************/

  start_timestamp_microseconds
      = nb->start_timeval.tv_sec + nb->start_timeval.tv_usec/NUM_MICROS_PER_SECOND;
  ++frequent_sequence_number;

    struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);

	if (debug == 11)
	{
		printf("received is: %d,dropped is: %d, total packets are :%d\n",statistics.ps_recv,statistics.ps_drop,rpp);
	}

}


/* libpcap calls this function for every packet it receives. */
static void process_packet(
        u_char* const user,
        const struct pcap_pkthdr* const header,
        const u_char* const bytes) {
 // if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
  //  perror("sigprocmask");
 //   exit(1);
 // }

//	int i = 0;
	float busywait = 0;
  ++rp;
	//if(debug == 1)
	//	printf("receive %d packets\n",rp);

	memset(&p, 0, sizeof(p));
	p.len = header->len;
	parse_packet(bytes,&p);
	
	//fiter
	//if((str_equal(mac,ether_sprintf(p.wlan_src),2*MAC_LEN) != 1))
	//{
	//	return;
	//}


	p.tv.tv_sec = header->ts.tv_sec;
	p.tv.tv_usec = header->ts.tv_usec;
	rpp++;

	/*begin store packet*/
	memcpy(store[rpp%HOLD_TIME].tcp_header,bytes+p.tcp_offset,16);
	memcpy(store[rpp%HOLD_TIME].wlan_src,p.wlan_src,MAC_LEN);
	memcpy(store[rpp%HOLD_TIME].wlan_dst,p.wlan_dst,MAC_LEN);
	store[rpp%HOLD_TIME].tv.tv_sec = p.tv.tv_sec;
	store[rpp%HOLD_TIME].tv.tv_usec = p.tv.tv_usec;
	store[rpp%HOLD_TIME].len = p.len;
	store[rpp%HOLD_TIME].wlan_type = p.wlan_type;
	store[rpp%HOLD_TIME].wlan_retry = p.wlan_retry;
	store[rpp%HOLD_TIME].phy_signal = p.phy_signal;
	store[rpp%HOLD_TIME].phy_rate = p.phy_rate;
	store[rpp%HOLD_TIME].timestamp = p.timestamp;
	store[rpp%HOLD_TIME].tcp_seq = p.tcp_seq;
	pj = rpp%HOLD_TIME;
	end_pointer = rpp%HOLD_TIME;
	if(debug == 1)
	{
		double neighbor_timestamp = (double)p.timestamp/(double)NUM_NANO_PER_SECOND;	
		double libpcap_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
	
		printf("+++++packet %d:%f<---->%f\n",rpp,neighbor_timestamp,libpcap_timestamp);	
	}
	/*end store packet*/
	
	if((str_equal(mac,ether_sprintf(p.wlan_src),2*MAC_LEN) == 1))
	{
		double tw = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		double te = (double)p.timestamp/(double)NUM_NANO_PER_SECOND;
		

		if(debug == 1)
			printf("\n-----[tw,te]:[%f,%f]\n",tw,te);
		double neighbor_timestamp = (double)store[pi].timestamp/(double)NUM_NANO_PER_SECOND;	
		double libpcap_timestamp = store[pi].tv.tv_sec + (double)store[pi].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		
		int pii = pi; /* looking from the very start point */
		while( (neighbor_timestamp < te) && (pii != pj) )
		{
			double neighbor_timestamp = (double)store[pii].timestamp/(double)NUM_NANO_PER_SECOND;
			double libpcap_timestamp = store[pii].tv.tv_sec + (double)store[pii].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		

			if(debug == 1)
			{
				printf("-----[%d/%d]:[%s+%s]:%f<---->%f\n",pii,pj,ether_sprintf(store[pii].wlan_src),ether_sprintf2(store[pii].wlan_dst),neighbor_timestamp,libpcap_timestamp);
			
			}
			
			if((str_equal(mac,ether_sprintf(store[pii].wlan_dst),2*MAC_LEN) == 1))
			{
				pii  =  (pii + 1)%HOLD_TIME;
				continue;
			}

			if ( ( neighbor_timestamp > tw ) && ( neighbor_timestamp < te) ) 
			{
				busywait = (float)store[pii].len * 8 * 10 / (float)store[pii].phy_rate;
				busywait = busywait/(float)NUM_MICROS_PER_SECOND;
				//printf("-----%s busywait %f\n",ether_sprintf(store[pi].wlan_src),busywait);
				if ( p.wlan_retry == 0)
				{
					update_list(cs,CS_NUMBER,store[pii].wlan_src,store[pii].wlan_dst,busywait);
				}
				else
				{
					update_list(ht_tmp,HT_NUMBER,store[pii].wlan_src,store[pii].wlan_dst,busywait); /* need to further update the hidden terminal*/
				}					

			}

			pii  =  (pii + 1)%HOLD_TIME;

			/* point i (pi) step forward, because the neighbor packet lose behind */
			if (neighbor_timestamp < tw)
				pi = pii;

		}

		int j = 0;
		float sum = 0.0;
		for(j =0 ; j < HT_NUMBER ; j ++)
		{
			sum = sum + ht_tmp[j].value;
		}
		for(j =0 ; j < HT_NUMBER ; j ++)
		{
			if (ht_tmp[j].value != 0 )
				update_list(ht,HT_NUMBER,ht_tmp[j].wlan_src,store[pi].wlan_dst,(float)(te-tw)*(ht_tmp[j].value/(float)sum) );
		}
		memset(ht_tmp,0,sizeof(ht_tmp));
		
			
	}

	inf_end_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
	//printf("start time is %f, end time is %f\n",inf_start_timestamp,inf_end_timestamp);
	if ((inf_end_timestamp - inf_start_timestamp) > FREQUENT_UPDATE_PERIOD_SECONDS)
	{
		/*print out*/
		write_frequent_update(); /*write the inf into the file*/
		
		memset(cs,0,sizeof(cs));
		memset(ht,0,sizeof(ht));
		memset(ht_tmp,0,sizeof(ht_tmp));
		inf_start_timestamp = inf_end_timestamp;
	}

	if ((inf_end_timestamp - delay_start_timestamp) > FREQUENT_UPDATE_DELAY_SECONDS)
	{
		/*print out*/
		write_frequent_update_delay(); /*write the delay into the file*/
		delay_start_timestamp = inf_end_timestamp;
	}

	if(debug == 10) //just for debug count
	{
		if((pch_count_debug % every) == 0)
		{
			printf("wireless data packet and loss is:[%d] and [%d]\n",rpp,pch_count_debug);	
		}
	}
	if(debug == 3)
		pcap_dump(user,header,bytes);
	//}//for 136
  
 

  //if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
   // perror("sigprocmask");
   // exit(1);
  //}
 
}




 static pcap_t* initialize_pcap(const char* const interface) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* const handle = pcap_open_live(
      interface, BUFSIZ, PCAP_PROMISCUOUS, PCAP_TIMEOUT_MILLISECONDS, errbuf);
  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    return NULL;
  }

    fprintf(stderr, "type is %d\n",pcap_datalink(handle));

  return handle;
}

static void clear_station(struct neighbor* p,int j)
{
	p->pkt_all_data[j] = 0;
}



static void set_next_alarm() {
  alarm(FREQUENT_UPDATE_PERIOD_SECONDS);
}

/* Unix only provides a single ALRM signal, so we use the same handler for
 * frequent updates (every 5 seconds) and differential updates (every 30
 * seconds). We trigger an ALRM every 5 seconds and only write differential
 * updates every 6th ALRM. */
static void handle_signals(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    exit(0);
  } else if (sig == SIGALRM) {
    write_frequent_update();
    set_next_alarm();
  }
}

static void initialize_signal_handler(){
	struct sigaction action;
	action.sa_handler = handle_signals;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;
	if (sigaction(SIGINT, &action, NULL) < 0
		|| sigaction(SIGTERM, &action, NULL) < 0
		|| sigaction(SIGALRM, &action, NULL)) {
		perror("sigaction");
		exit(1);
	}
	sigemptyset(&block_set);
	sigaddset(&block_set, SIGINT);
	sigaddset(&block_set, SIGTERM);
	sigaddset(&block_set, SIGALRM);
}
int main(int argc,char *argv[]){

	
    if (argc < 5) {
    fprintf(stderr, "Usage: %s <interface> <debug> <write-interval> <mac> <every>\n", argv[0]);
    }
	
	printf("hello world\n");
	printf("%s\n",argv[1]);
	debug = atoi(argv[2]);
	FREQUENT_UPDATE_PERIOD_SECONDS = atoi(argv[3]);
	memcpy(mac,argv[4],12);
	printf("%s\n",mac);
	every = atoi(argv[5]);
	FREQUENT_UPDATE_DELAY_SECONDS = every;
 //fin2=fopen(argv[2],"a+");

	//if(fin2==NULL)
	//{
	//	printf("File Open Error!\n");	
	//	exit(1);
	//}
	
	
	

	
	//initialize_signal_handler();
	//set_next_alarm();
	
	
	
	pcap_handle = initialize_pcap(argv[1]);
	
	if(!pcap_handle){
		return 1;
	}
	
	pkt = pcap_dump_open(pcap_handle,DUMP_DIR);
	
	nb = (struct neighbor *)malloc(sizeof(struct neighbor));
	init_neighbor(nb);
	pcap_loop(pcap_handle,QUEUE_SIZE,process_packet,(u_char *)pkt);
	
	
	printf("end capturing......\n");
	
	//fclose(fin2);
	
	return 0;
}
