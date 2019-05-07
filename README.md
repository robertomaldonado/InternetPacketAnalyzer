INTERNET PACKET ANALYZER 
========================
PURPOSE
-------
Software implemented to experience with packet analyzing and the different Internet packet formats as ethernet frames:

*ARP Packets
*IP Packets (UDP, TCP, ICMP, other)  
*Packets that belong to other protocols

### The following program works as following:

  #### To Compile:
    make all (Using the provided Makefile)
    
  #### To Execute:
    ./parser3 filename <control_flag> <count_flag> <number_count_limit>

  The options are as specified in the project description:

   ##### FLAG     =>     OUTPUT BEHAVIOUR
    -V      =>     High verbosity
    -v      =>     Low verbosity
    <noFlag>    =>     Summary of the analysis
    <- c (Number of packets)>  =>   Presents output with limited packet count.
