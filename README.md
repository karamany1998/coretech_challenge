# coretech_packet_storm_gradaute_challenge



To build: type "g++ challenge_karamany.cpp -o challenge_karamany -lpcap" in the terminal, make sure that packet-storm.pcap is in the same directory as the .cpp file.
Then just type "./challenge_karamany" in ther terminal 
----------------------------------------------------------------------------------------------------------------------------------------------------------------
Some comments:
1- an ethernet frame has a maximum size of 1518 bytes and I used unsigned long long for the total size of the packets
==>1000,000 * 1518 <= (sizeof)unsigned long long

2- I made a mistake when computing the average packet length, then when i used the struct pcap_pkthdr to obtain the length, it gave me the correct result and I verfied it using wireshark.




----------------------------------------------------------------------------------------------------------------------------------------------------------------


Explanation of my submission for the "Operation Packet Storm" challenge.

First of all, because the pcap file is already saved, we will need to use this function "pcap_open_offline("packet-storm.pcap" , errbuf)" which returns a pcap_t*. If reading the pcap file is not successful, just compare the return value with NULL.

To answer the questions for the challenge, we will need to loop over each packet and extract certain information such as packet length, destination ip address.etc
To do that we can just do a while loop such as this "while(packet = pcap_next(packets, &pkt_header))", which would obtain the next available packet until we are done.


For each packet we obtain, we can jump 14 bytes which is the ethernet frame header size to obtain the frame payload which is the IP Packet.
Each IP Packet has an IP header and Payload. From the IP header, we can find the total length and destination IP address.

I did this by defining a struct called IP_header. This struct contains all the header fields such as version, time to live, source and destination(divided into 4 octets each).

Now in each iteration through the while loop, we can easily cast the packet to (IP_header*) and then obtain all the information we need.
to obtain the total length, I initialised a variable called totalSize and just added totalSize += current_IP_header->total_packet_length;

To obtain the destination, I obtained the four destination octets and added them in dotted notation, then I had a map called map<string , int> dest_ip_nums which maps all the destination ip address to how many times they occurred in the packets.


To obtain the 10 most frequent destinations, I just put all the <key, value> pairs in the dest_ip_nums in a vector of pairs and sorted it in descending order based on the number of occurences. 
Then just looped over the first 10 and printed them to the console.
