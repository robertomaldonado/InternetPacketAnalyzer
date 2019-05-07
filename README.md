INTERNET PACKET ANALYZER 
========================
PURPOSE
-------
Software implemented to experience with packet analyzing and the different Internet packet formats (ARP, ).

The following program works as following:

  To Compile: 
    make all (Using the provided Makefile)
  To Execute:
    ./parser3 filename <control_flag> <count_flag> <number_count_limit>

  The options are as specified in the project description:

    FLAG         OUTPUT BEHAVIOUR
    -V      =>  High verbosity
    -v      =>  Low verbosity
    <noFlag>    =>  Summary

Additional flag: <- c (Number of packets)> presents the output with a limited count of packets
