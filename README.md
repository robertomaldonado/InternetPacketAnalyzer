INTERNET PACKET ANALYZER 
========================
PURPOSE
-------
Software implemented to experience with packet analyzing and the different Internet packet formats as ethernet frames (as especified in the RFCs - Request For Comments - for each protocol):
* ARP Packets
* IP Packets (UDP, TCP, ICMP, other)  
* Packets that belong to other protocols

DESCRIPTION
-------
Internet packet analyzer can process dump files produced by a packet sniffer. 
The analyzer reads packets from a dump file, parses packet headers, accumulates packet statistics, and outputs the statistics and packet information. The dump file is a binary file with the following format:
    frame_size Ethernet_frame .... frame_size Ethernet_frame   
* The frame size is a 4-byte integer in the network order format. 
* Each Ethernet frame contains Ethernet header and Ethernet payload. 
* Dump file is a binary file that does not have any delimiter between data items.
Depending on the command line options, different levels of statistics and the packet information will be printed.

### The following program works as following:

  #### To Compile:
    make all (Using the provided Makefile)
    
  #### To Execute:
    ./packetInspector filename <control_flag> <count_flag> <number_count_limit>

  #### Adding options to the command execution:

   ##### FLAG     =>     OUTPUT BEHAVIOUR
    -V      =>     Option calls the extended verbose mode. Prints packet headers in detail.
    -v      =>     Option calls the basic verbose mode, print single line for each packet.
    <noFlag>    =>     Option prints a summary of the packet.
    -c <Number of packets>  =>   Option specifies the number of frames to be processed.
    
### Sample Dump files:
May be found in  the "Dumfiles" directory

A sample execution looks like this:
    ./packetInspector Dumpfiles/dumpfile.3
    
with the following output:

    Ethernet broadcast:     0
      ARP packets:          0
    IP packets:           2
    UDP packets:        0
    TCP packets:        2
    ICMP packets:       0
    other IP packets:   0
  other packets:        1