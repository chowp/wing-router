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

#define bool int
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
static int debug;
static int rp = 0;
static int rpp = 0;
static int every = 0;

struct packet_info store[HOLD_TIME]; /* used to store packets info, including neighbors and mine */
struct inf_info cs[CS_NUMBER]; /* used to store cs info in time gamma */
struct inf_info ht[HT_NUMBER]; /* used to store ht info in time gamma */
struct inf_info ht_tmp[HT_NUMBER];
struct summary_info summary;
static double inf_start_timestamp;
static double delay_start_timestamp;
static double inf_end_timestamp;    /* we record time to ouput the result */
static double last_te; /*used to infer th*/
static int pi = 0; /*use as the start point of neighbor packet_info */
static int pj = 0;
static double ht_sum = 0;
static double cs_sum = 0;

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



/*
To check whether the current packet is in the cs list(\gamma) 
*/
bool matched(struct inf_info *inf,int i, unsigned char mac1[], unsigned char mac2[]){
	if ( (str_equal(ether_sprintf(mac1),ether_sprintf2(inf[i].wlan_src),2*MAC_LEN) != 1) &&
	   (str_equal(ether_sprintf(mac1),ether_sprintf2(inf[i].wlan_dst),2*MAC_LEN) != 1) ) 
		return false;
	if ( (str_equal(ether_sprintf(mac2),ether_sprintf2(inf[i].wlan_src),2*MAC_LEN) != 1) &&
	   (str_equal(ether_sprintf(mac2),ether_sprintf2(inf[i].wlan_dst),2*MAC_LEN) != 1) ) 
		return false;
	return true;
}
/*
To judge whether the current packet are broadcast, cts, ack or control packet(\gamma) 
*/
bool non_control_packet(struct inf_info *inf,unsigned char mac1[], unsigned char mac2[]){
	if (str_equal(mac_zero,ether_sprintf(mac1),2*MAC_LEN) == 1)
		return false;
	if (str_equal(mac_zero,ether_sprintf(mac2),2*MAC_LEN) == 1)
		return false;
	return true;
}
/*
Insert a packet to the carrier sense or hidden teriminal list
*/
bool update_list(struct inf_info *inf,int NUMBER, unsigned char mac1[], unsigned char mac2[], float value){	
	if (debug == LOG_DEBUG)
		printf("neighbor packets width %s+%s:%f\n",ether_sprintf(mac1),ether_sprintf2(mac2),value);
	//printf("\n*******************************\n");

	int i;
	for(i=0;i<NUMBER;i++){
		//printf("*  %s+%s:%f\n",ether_sprintf(inf[i].wlan_src),ether_sprintf2(inf[i].wlan_dst),inf[i].value);
		if (inf[i].value == 0)
			break;
		if (!non_control_packet(inf,mac1,mac2)){
			continue;
		} 
		if (matched(inf,i,mac1,mac2)){
			inf[i].value = inf[i].value + value;
		}
	}
	/* there is no match!!*/
	for(i=0;i<NUMBER;i++)
	{
		if (inf[i].value ==0 )
		{
			memcpy(inf[i].wlan_src,mac1,MAC_LEN);
			memcpy(inf[i].wlan_dst,mac2,MAC_LEN);
			
			inf[i].value = value;
			summary.inf_num = summary.inf_num + 1;
			//printf("C  %s+%s:%f\n",ether_sprintf(mac1),ether_sprintf2(mac2),inf[i].value);
			//printf("*******************************\n\n");
			return; /*pay attention whether it will jump out!*/
		}
	}
}

/*
 print out the packet trace
*/
static int write_frequent_packet_trace() {
  FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME_DELAY, "w");
  if (!handle) {
    perror("Could not open update file for writing\n");
    exit(1);
  }
  	end_pointer = rpp%HOLD_TIME;
 	int rounds =(end_pointer - start_pointer + HOLD_TIME )%HOLD_TIME;
 	int i = 0;
 	int ii = (start_pointer+1)%HOLD_TIME;
 	while(i < rounds )
 	{
 		// uncomment to print only mine's qos packet
 		// if((store[ii].wlan_type == (u16)136) && 
 		//   (str_equal(mac,ether_sprintf(store[ii].wlan_src),2*MAC_LEN) == 1) )
 		// {
 			double time_pch1 = (double)((double)store[ii].tv.tv_sec + (double)((double)store[ii].tv.tv_usec/1000000.0));
			double time_pch2 = (double)store[ii].timestamp/(double)NUM_NANO_PER_SECOND;	
			
			fprintf(handle,"%lf,",time_pch1);
			fprintf(handle,"%lf,",time_pch2);
			fprintf(handle,"%u,%d,%u,%u,%d,",store[ii].phy_rate,store[ii].len,store[ii].ip_id,store[ii].ip_off,store[ii].wlan_type);
			fprintf(handle,"%s,%s\n",ether_sprintf(store[ii].wlan_src),ether_sprintf2(store[ii].wlan_dst));
		//}
		i = (i+1);
 		ii = (ii+1)%HOLD_TIME;
 	}
 	if(debug == -1)
 		printf("from %d to %d, rounds is %d,last is %d\n",start_pointer,end_pointer,rounds,ii-1);
 
 	// print loss rate
  	struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);
	fprintf(handle,"received is: %d,dropped is: %d, total packets are :%d\n",statistics.ps_recv,statistics.ps_drop,rpp);

	fclose(handle);

	  int file_time = (int)inf_end_timestamp;
	  char update_filename[FILENAME_MAX];
	  snprintf(update_filename,
	           FILENAME_MAX,
	           FREQUENT_UPDATE_FILENAME_DELAY,
	           mac,
	           mac,
	           file_time,
	           frequent_sequence_number);
	  if (rename(PENDING_FREQUENT_UPDATE_FILENAME_DELAY, update_filename)) {
	    perror("Could not stage update");
	    exit(1);
	  }
  

	 ++frequent_sequence_number;

    
	start_pointer = rpp%HOLD_TIME;
}

/*
print out the overall interference every gamma interval
*/
static void write_frequent_print_overall_interference() {
  //printf("Writing frequent log to %s\n", PENDING_FREQUENT_UPDATE_FILENAME);
	 FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME, "w");
	 
	  if (!handle) {
	    perror("Could not open update file for writing\n");
	    exit(1);
	 }
  	
		
	fprintf(handle,"cs,%lf,%lf,cs,cs,%f\n",
			inf_start_timestamp,inf_end_timestamp,
			cs_sum);
	fprintf(handle,"ht,%lf,%lf,ht,ht,%f\n",
			inf_start_timestamp,inf_end_timestamp,
			ht_sum);
  	fclose(handle);

  	int file_time = (int)inf_end_timestamp;
  	char update_filename[FILENAME_MAX];
  	snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME,
           mac,
           mac,
           file_time,
           frequent_sequence_number);
  	if (rename(PENDING_FREQUENT_UPDATE_FILENAME, update_filename)) {
    perror("Could not stage update");
    exit(1);
  	}
  

  	++frequent_sequence_number;

    struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);
	if (debug == 11)
	{
		printf("received is: %d,dropped is: %d, total packets are :%d\n",statistics.ps_recv,statistics.ps_drop,rpp);
	}

}

/*
print out the carrier sense's interference seperately
*/
static void write_frequent_print_interference() {
 	FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME, "w");
 
  	if (!handle) {
    	perror("Could not open update file for writing\n");
    	exit(1);
  	}
 
  	/*print out*/ 	
	int j = 0;
	float overall_busywait = 0;
	for (j = 0 ; j < CS_NUMBER ;j ++)
	{
		if (cs[j].value == 0)
			break;
		// fprintf(handle,"cs,%lf,%lf,%s,%s,%f\n",
		// 	inf_start_timestamp,inf_end_timestamp,
		// 	ether_sprintf(cs[j].wlan_src),ether_sprintf2(cs[j].wlan_dst),cs[j].value);
		overall_busywait = overall_busywait + cs[j].value;
		printf("%f,%f\n",overall_busywait,cs[j].value)
	}
	
	printf("\nCS:");	
	for(j = 0 ; j < CS_NUMBER ; j ++){
		if (cs[j].value == 0)
			break;
		cs[j].percentage = 100.0*(cs[j].value/overall_busywait);
		printf("%d%%,",cs[j].percentage); 
	}

	// fprintf(handle,"ht,%lf,%lf,ht,ht,%f\n",
	// 		inf_start_timestamp,inf_end_timestamp,
	// 		ht_sum);
	printf("\nHT,%lf,%lf,%f\n",
			inf_start_timestamp,inf_end_timestamp,
			ht_sum);
  	fclose(handle);

	// print summary info
	printf("\ninf_num=%d,extra=%f,busywait=%f",summary.inf_num,summary.overall_extra_time,overall_busywait);
	memset(&summary, 0, sizeof(summary));
	
  	int file_time = (int)inf_end_timestamp;
  	char update_filename[FILENAME_MAX];
  	snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME,
           mac,
           mac,
           file_time,
           frequent_sequence_number);
  	if (rename(PENDING_FREQUENT_UPDATE_FILENAME, update_filename)) {
    	perror("Could not stage update");
    	exit(1);
  	}
  

  	++frequent_sequence_number;

    struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);

	if (debug == LOG_DEBUG)
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
//     perror("sigprocmask");
//     exit(1);
//  }


	float busywait = 0;
    ++rp;


	memset(&p, 0, sizeof(p));
	p.len = header->len;
	parse_packet(bytes,&p);
	


	p.tv.tv_sec = header->ts.tv_sec;
	p.tv.tv_usec = header->ts.tv_usec;
	rpp++;

	/*begin store packet*/
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
	store[rpp%HOLD_TIME].ip_totlen = p.ip_totlen;
	store[rpp%HOLD_TIME].tcp_ack = p.tcp_ack;
	store[rpp%HOLD_TIME].ip_id = p.ip_id;
	pj = rpp%HOLD_TIME;
	end_pointer = rpp%HOLD_TIME; //end store packet
	if(debug == LOG_DEBUG)
	{
		double neighbor_timestamp = (double)p.timestamp/(double)NUM_NANO_PER_SECOND;	
		double libpcap_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
	
		printf("+++++packet %d:%f<---->%f\n",rpp,neighbor_timestamp,libpcap_timestamp);	
	}
	
	
	if( ( (p.wlan_type == (u16)136) || (p.wlan_type == (u16)8) )
	   && (str_equal(mac,ether_sprintf(p.wlan_src),2*MAC_LEN) == 1)){ /*trigger calculation*/
		double tw = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		double te = (double)p.timestamp/(double)NUM_NANO_PER_SECOND;
		double th = last_te;
		if (tw > last_te){
			th = tw;
		}
		summary.overall_extra_time = summary.overall_extra_time + te - th;
		double neighbor_timestamp = store[pi].tv.tv_sec + (double)store[pi].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		
		int pii = pi; /* looking from the very start point */
		while( (neighbor_timestamp < te) && (pii != pj) )
		{
			double neighbor_timestamp = (double)store[pii].timestamp/(double)NUM_NANO_PER_SECOND;
			double libpcap_timestamp = store[pii].tv.tv_sec + (double)store[pii].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
		

			//printf("-----[%d/%d]:[%s+%s]:%f<---->%f\n",pii,pj,ether_sprintf(store[pii].wlan_src),ether_sprintf2(store[pii].wlan_dst),neighbor_timestamp,libpcap_timestamp);						
			


			if ( ( neighbor_timestamp > th ) && ( neighbor_timestamp < te) ) 
			{

				if((str_equal(mac,ether_sprintf(store[pii].wlan_dst),2*MAC_LEN) == 1) ||
			  	   (str_equal(mac,ether_sprintf2(store[pii].wlan_src),2*MAC_LEN) == 1)) {
					//printf("\n[%f,%f] packet type is %d",tw,te,store[pii].wlan_type);
					pii = (pii+1)%HOLD_TIME;
					continue;
				}
				busywait = (float)store[pii].len * 8 * 10 / (float)store[pii].phy_rate;
				busywait = busywait/(float)NUM_MICROS_PER_SECOND;
				//printf("-----%s busywait %f\n",ether_sprintf(store[pi].wlan_src),busywait);
				if ( p.wlan_retry == 0) /*actually, ip_totlen indicates the retry counts*/
				{
					if (debug == LOG_INF)
						update_list(cs,CS_NUMBER,store[pii].wlan_src,store[pii].wlan_dst,busywait);
					else
						cs_sum = cs_sum + te - tw;
				}
				else
				{
					ht_sum = ht_sum + te - tw;//update_list(ht_tmp,HT_NUMBER,store[pii].wlan_src,store[pii].wlan_dst,busywait); /* need to further update the hidden terminal*/
				}					

			}

			pii  =  (pii + 1)%HOLD_TIME;

			/* point i (pi) step forward, because the neighbor packet lose behind */
			if (neighbor_timestamp < te)
				pi = pii;

		}

		last_te = te;
		memset(ht_tmp,0,sizeof(ht_tmp));
		
			
	}

	inf_end_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
	//printf("start time is %f, end time is %f\n",inf_start_timestamp,inf_end_timestamp);
	if ((inf_end_timestamp - inf_start_timestamp) > FREQUENT_UPDATE_PERIOD_SECONDS)
	{
		/*print out*/
		if (debug == LOG_INF)
			write_frequent_print_interference(); 
		//write_frequent_print_overall_interference();
		memset(cs,0,sizeof(cs));
		ht_sum = 0;
		cs_sum = 0;
		inf_start_timestamp = inf_end_timestamp;
	}

	if ((inf_end_timestamp - delay_start_timestamp) > FREQUENT_UPDATE_DELAY_SECONDS)
	{
		/*print out*/
		if (debug == LOG_TRACE)
			write_frequent_packet_trace(); /*write the delay into the file*/
		delay_start_timestamp = inf_end_timestamp;
	}

	if(debug == LOG_DUMP)
		pcap_dump(user,header,bytes);
	//}//for 136
  
 

  // if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
  // perror("sigprocmask");
  // exit(1);
  // }
 
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
    	write_frequent_print_interference();
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
 	
	
	pcap_handle = initialize_pcap(argv[1]);
	
	if(!pcap_handle){
		return 1;
	}
	
	pkt = pcap_dump_open(pcap_handle,DUMP_DIR);
	
	pcap_loop(pcap_handle,QUEUE_SIZE,process_packet,(u_char *)pkt);
	
	
	printf("end capturing......\n");
	
	//fclose(fin2);
	
	return 0;
}
