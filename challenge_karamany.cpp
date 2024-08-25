#include<iostream>
#include<pcap/pcap.h>
#include <map>
#include <vector>
#include <string> 
#include <algorithm>


using namespace std;

/*

u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h) --->used to fetch packet one at a time(will mainly used this method to analyse the packet-storm)
*/

const int ethernet_header_size = 14;  //used wireshark and saw that it uses ethernet(ethernet header is 14 bytes)



struct IP_header {
	u_int8_t  version_headerLength;	//version
	u_int8_t TOS;		//type of service
	u_int16_t	total_packet_length;			// total length 
	u_int16_t ID;		// id
	u_int16_t ip_off;		// fragment offset field 
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char TTL;		// time to live - how many hops, when it reaches 0 the router will discard this packey
	u_char protocol;		// the higher level protocol used in the transport layer, such as TCP or UDP
	u_short checksum;		// IP is "Best effort services", but still uses the IP checksum to detect if errors occur.


	//then we have the source and destination IP addresses
	u_char src_octet1;	
	u_char src_octet2;
	u_char src_octet3;
	u_char src_octet4;
	
	u_char dest_octet1;
	u_char dest_octet2;
	u_char dest_octet3;
	u_char dest_octet4;
	
	
	
};





int main()
{
	
	map<string , int> source_ip_nums;	//count ip addresses used
	map<string , int> dest_ip_nums;	//count ip addresses used
	map<string , int> protocol_nums;	//count which protocol used(tcp,udp..etc)

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* packets = pcap_open_offline("packet-storm.pcap" , errbuf);
	


	if(packets == NULL)
	{
	cout << "cannot open the packet capture"<<endl;
	printf("errortype: %s \n", errbuf);
	return 1; 
	}
	
	
	struct pcap_pkthdr pkt_header;
	const u_char *packet;	//the current packet from pcap_next(..)
	
	unsigned long long totalSize = 0  ; 
	unsigned long long numPackets =  0  ; 
	
	unsigned long long packetSize = 0 ; 
	unsigned long long totalSize_with_header = 0 ; 
	string mostFreqDest = "";	//most frequenct destination ip
	unsigned long long num_most_freq =  0;	//how many times most frequent occured


	while(packet = pcap_next(packets, &pkt_header))	//as long as we can read packets
	{
		
		
		numPackets++;
		
		//move to start of packet  by adding 14 bytes which is the ethernet header  size
		struct IP_header* current_IP_header = (struct IP_header*)(packet + ethernet_header_size);

		totalSize += pkt_header.len;
		packetSize += ntohs(current_IP_header->total_packet_length);
		
		
		
		
		//the source ip address
 		int src1 = current_IP_header->src_octet1;
 		int src2 = current_IP_header->src_octet2;
 		int src3 = current_IP_header->src_octet3;
 		int src4= current_IP_header->src_octet4;
 		
 		string src_IP = to_string(src1) +"."+ to_string(src2) +"."+ to_string(src3)+"." + to_string(src4);
 		
 		source_ip_nums[src_IP]++;
 		
 		
 		//the destination ip address(in dotted notation)
 		int dst1 = current_IP_header->dest_octet1;
 		int dst2 = current_IP_header->dest_octet2;
 		int dst3 = current_IP_header->dest_octet3;
 		int dst4= current_IP_header->dest_octet4;
 		
 		string dst_IP = to_string(dst1) + "."+ to_string(dst2) +"."+ to_string(dst3)+"." + to_string(dst4);
 		
		dest_ip_nums[dst_IP]++;
 		if(dest_ip_nums[dst_IP] > num_most_freq)
 		{
 			mostFreqDest = dst_IP;
 			num_most_freq  = dest_ip_nums[dst_IP] ;
 		}
 		
 	
		int protocolNum = current_IP_header->protocol;
		
		//determine the protocol based on    the protocol number field and increment usage by 1
		switch(protocolNum)
		{
		case 1 :protocol_nums["ICMP"]++; break;
		
		case 2: protocol_nums["IGMP"]++; break;
		
		case 6: protocol_nums["TCP"]++; break;
		
		case 17: protocol_nums["UDP"]++; break;
		default:     protocol_nums["not-important"]++;
		}
		
	}
	
		
	if(numPackets>0)
	{
		cout<<"total size is "<<totalSize<< " bytes"<< endl;
		cout<<"total size of packets "<<packetSize<< " bytes" << endl;
		
		cout << "average frame size is "<<(double)totalSize / numPackets<<endl;
		cout<<"Excluding ethernet frame header->saverage packet size is "<<(double)packetSize / numPackets << endl;
		
	}
	
	
	cout<<"----------------------------------------------------------------"<<endl;
	
	
	
	cout<<"protocols used "<<endl;
	for(auto prot : protocol_nums)
	{
		cout<<prot.first<<" "<<prot.second<<endl;
	}
	
	
	cout<<"----------------------------------------"<<endl;
	cout<<"most frequenct destination:: " << mostFreqDest<< " "<<num_most_freq<<endl;
	
	//to identify the most frequent destinations, we could copy the map in a vector of pairs then sort
	//based on number of occurences of the ip_dest
	
	vector<pair<int,string>> ip_dest_vec;
	for(auto dst : dest_ip_nums)
	{
	
		ip_dest_vec.push_back({dst.second , dst.first});
	}
	//sort in descending order
	sort(ip_dest_vec.rbegin() , ip_dest_vec.rend());
	
	//here you can output the most frequent destinations
	
	cout<<"the 10 most frequenct destinations are "<<endl;
	for(int i = 0  ; i<ip_dest_vec.size() && i<10 ; i++)
	{
		
		cout<<ip_dest_vec[i].second<<" got visited "<<ip_dest_vec[i].first<<" times"<<endl;
	
	}
	
	
    


return 0 ;
}
