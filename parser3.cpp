#include <iostream>
#include <fstream>
#include <cstdio>
#include <bitset>

using namespace std;

void partialScan(string file_name, int marker);
void highVerbosityInspection(char* streamedData);
void summaryInspection(char* streamedData);
void lowVerbosityInspection(char* streamedData);
void partialPrint(int eth, int broadcasts, int arp_ct,
                int ip_ct, int udp_ct, int tcp_ct,int icmp_ct, 
                int other_ip_ct, int other_ct);
                
int stream_size = 0;
const int dec_ICMP=1;
const int dec_UDP=17;
const int dec_TCP=6;
int current_pkt_size = 0;
int global_ip_length = 0;
bool is_broadcast = 0;

int main(int argc, char *argv[])
{
    if (argc == 1){
        cerr << "No input file" << endl;
        exit(1);
    }else if (argc == 2){

        partialScan(argv[1], 1);

    }else if(argc == 3){
        if( std::string(argv[2]) == "-c" ){
            printf("Arguments missing\n");

        }else if( std::string(argv[2]) == "-v" ){

            partialScan(argv[1], 3);            

        }else if(std::string(argv[2]) == "-V"){

            partialScan(argv[1], 2);

        }else{
            printf("%s It is not an option... \n",argv[2] );
        }
    }else if(argc == 4){
        if( std::string(argv[2]) == "-c" ){
            //TO-DO:
            printf("%s\n",argv[2]);
            int limit = atoi(argv[3]);
            printf("%d\n", limit);

        }else{
            printf("%s It is not an option... ",argv[2] );
        }
    }else
        return 0;
}

void partialScan(string file_name, int marker)
{
    ifstream input_file(file_name, ios::in | ios::binary);
    int ether_counter=0;
    int arp_counter=0;
    int ip_counter=0;
    int other_ether_counter =0;    
    int udp_counter=0;
    int tcp_counter=0;
    int icmp_counter=0;

    int inspectedBytes=0;

    if (input_file.is_open()){
 // Get the file size to allocate memory
        input_file.seekg(0,ios::end);        
        stream_size = (long) input_file.tellg();
        input_file.seekg(0, ios::beg);

 // Allocate memory:
        char*  streamedData = new char[stream_size];

 // Read data as a block:
        input_file.read( streamedData,stream_size);
        input_file.close();
        if(marker == 1){//Summary
            summaryInspection(  streamedData );
        }else if(marker == 2){//Detailed
            highVerbosityInspection(  streamedData );
        }else if(marker == 3){
            lowVerbosityInspection( streamedData );
        }
    
    }else
    cerr << "Check file name. Does it exist under the name: " << file_name << " ?"<<endl;
}
    
void highVerbosityInspection(char*  streamedData){
    // cout <<" Size of stream " << stream_size <<endl;
    int ether_counter=0;
    int arp_counter=0;
    int ip_counter=0;
    int other_ip_counter=0;
    int other_ether_counter =0;    
    int udp_counter=0;
    int tcp_counter=0;
    int icmp_counter=0;
    int ether_broadcast_counter = 0;

    int inspectedBytes = 0;

    unsigned long pkt_size = 0;
    int ether_id = 0; 
    int main_counter = 0;

    while( inspectedBytes < stream_size ){ 

        printf("\nETHER:  ----- Ether Header -----\n");
        printf("ETHER:\n");
        printf("ETHER:  Packet %d\n", ether_id);            
        int main_counter = 0;        
        pkt_size = 0;
        unsigned char temp = 0;
        temp = streamedData[inspectedBytes];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;
        temp = streamedData[inspectedBytes+1];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+2];
        pkt_size = pkt_size | temp;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+3];
        pkt_size = pkt_size | temp ;
        printf("ETHER:  Packet size = %lu bytes\n", pkt_size); 

        inspectedBytes += 4;
        current_pkt_size = pkt_size;

        printf("ETHER:  Destination = ");
        unsigned long long ether_destination = 0;
        unsigned char tmp = 0; 
        int indicator = 0;
        for(int i=inspectedBytes; i < inspectedBytes + 6 ; i++){
            printf( "%x", (unsigned)(unsigned char) streamedData[i]); 
            tmp = streamedData[i];
            if((int)tmp == 255){
                indicator++;
            }
            ether_destination = ether_destination | tmp;
            ether_destination = ether_destination << 8;
            if(i != inspectedBytes + 6 -1){
                printf(":");
                tmp = streamedData[i];
                ether_destination = ether_destination | tmp;
                if((int)tmp == 255){
                    indicator++;
                }
                if(indicator == 6)
                    ether_broadcast_counter++;
            }
        }
        printf("\n");                
        inspectedBytes += 6;

        printf("ETHER:  Source      = ");

        for(int i=inspectedBytes; i <inspectedBytes + 6; i++){
            printf( "%x", (unsigned)(unsigned char) streamedData[i] ); 
            if(i != inspectedBytes + 6 - 1)
                printf(":");
        }
        printf("\n");        
        inspectedBytes += 6;
        
        int ether_type = 0;   
        tmp = 0;
        tmp = streamedData[inspectedBytes];            
        ether_type =  ether_type | tmp;            
        ether_type = ether_type << 8;
        tmp = streamedData[inspectedBytes+1];            
        ether_type =  ether_type | tmp; 

        printf("ETHER:  Ethertype   = %04x ", ether_type);
        inspectedBytes +=2;        

        if(ether_type == 2048)
            printf("(IP)\n");  
        else if(ether_type == 2054)
            printf("(ARP)\n");
        else
            printf("(unknown)\n");  
        
        
        printf("ETHER:\n");
        main_counter += 18; 

        if(ether_type == 2048){ //Decimal for 0x0800 (IP)
            ip_counter++;
            ether_counter++;
            printf("IP:  ----- IP Header -----\n");
            printf("IP:\n");
            unsigned char version = 0;
            version =  version | streamedData[inspectedBytes]; 
            version = version >> 4;
            printf("IP:  Version = %d\n", version);

            unsigned char ip_length = 0;
            ip_length =  ip_length | streamedData[inspectedBytes]; 
            ip_length = ip_length << 4;            
            ip_length = ip_length >> 4;
            printf("IP:  Header length = %d bytes\n", ip_length*4);
            inspectedBytes+=1;
            global_ip_length = ip_length;

            unsigned char ip_service = 0;
            ip_service =  ip_service | streamedData[inspectedBytes];            
            printf("IP:  Type of service = %x\n", ip_service);

            inspectedBytes+=1;         

            unsigned char tmp = 0;
            unsigned short ip_total_length = 0;
            tmp = streamedData[inspectedBytes];            
            ip_total_length =  ip_total_length | tmp;            
            ip_total_length = ip_total_length << 8;
            tmp = streamedData[inspectedBytes+1];            
            ip_total_length =  ip_total_length | tmp;            

            printf("IP:  Total length = %d bytes\n", ip_total_length);
            inspectedBytes+=2;           

            unsigned short ip_identification = 0;
            unsigned char ip_temp = 0;
            ip_temp = streamedData[inspectedBytes];
            ip_identification =  ip_identification | ip_temp;            
            ip_identification = ip_identification << 8;
            ip_temp = streamedData[inspectedBytes+1];
            ip_identification =  ip_identification | ip_temp; 
            printf("IP:  Identification = %d\n", ip_identification);
            inspectedBytes+=2;
            
            printf("IP:  Flags\n");
            unsigned char ip_flag_df = 0;
            ip_flag_df =  ip_flag_df | streamedData[inspectedBytes]; 
            ip_flag_df = ip_flag_df << 1;                       
            ip_flag_df = ip_flag_df >> 7;
            if(ip_flag_df == 0)
                printf("IP:    .%d.. .... = allow fragment\n", ip_flag_df);
            else
                printf("IP:    .%d.. .... = do not fragment\n", ip_flag_df);

            unsigned char ip_flag_mf = 0;
            ip_flag_mf =  ip_flag_mf | streamedData[inspectedBytes];            
            ip_flag_mf = ip_flag_mf << 2;                       
            ip_flag_mf = ip_flag_mf >> 7;
            if(ip_flag_mf == 0)
                printf("IP:    ..%d. .... = last fragment\n", ip_flag_mf);
            else
                printf("IP:    ..%d. .... = last fragment\n", ip_flag_mf);
            
            unsigned short ip_frag_offset = 0;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes];            
            ip_frag_offset = ip_frag_offset << 8;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes+1];            
            ip_frag_offset = ip_frag_offset << 3;
            ip_frag_offset = ip_frag_offset >> 3;
            printf("IP:  Fragment offset = %d bytes\n",ip_frag_offset);           
            inspectedBytes+=2;                       
            //Skip TTl
            inspectedBytes+=1;          

            //Protocol
            unsigned char ip_protocol = 0; 
            ip_protocol =  ip_protocol | streamedData[inspectedBytes]; 
            printf("IP:  Protocol = %d", ip_protocol);

            // printf(");
            if(ip_protocol == dec_TCP)
                printf(" (TCP)\n");
            else if(ip_protocol == dec_UDP)
                printf(" (UDP)\n");
            else if(ip_protocol == dec_ICMP)
                printf(" (ICMP)\n");
            else 
                printf(" (unknown)\n");                

            inspectedBytes+=1;         

            unsigned char ip_header_checksum_one = 0;
            unsigned char ip_header_checksum_two = 0;            
            ip_header_checksum_one =  ip_header_checksum_one | streamedData[inspectedBytes];  
            ip_header_checksum_two =  ip_header_checksum_two | streamedData[inspectedBytes+1]; 
            unsigned short ip_header_checksum = ip_header_checksum_one;
            ip_header_checksum = ip_header_checksum_one << 8;
            ip_header_checksum = ip_header_checksum | ip_header_checksum_two;            
            printf("IP:  Header checksum = %x\n" , ip_header_checksum);    
            inspectedBytes+=2;        

            printf("IP:  Source address = ");
            unsigned char ip_src_1 = 0;
            unsigned char ip_src_2 = 0; 
            unsigned char ip_src_3 = 0;            
            unsigned char ip_src_4 = 0;                                   
            ip_src_1 =  ip_src_1 | streamedData[inspectedBytes];  
            ip_src_2 =  ip_src_2 | streamedData[inspectedBytes+1]; 
            ip_src_3 =  ip_src_3 | streamedData[inspectedBytes+2];  
            ip_src_4 =  ip_src_4 | streamedData[inspectedBytes+3]; 
            printf("%d.%d.%d.%d\n", ip_src_1, ip_src_2,ip_src_3,ip_src_4);  //18e0          
            inspectedBytes+=4;          
            
            printf("IP:  Destination address = ");            
            unsigned char ip_dest_1 = 0;
            unsigned char ip_dest_2 = 0; 
            unsigned char ip_dest_3 = 0;            
            unsigned char ip_dest_4 = 0;                                   
            ip_dest_1 =  ip_dest_1 | streamedData[inspectedBytes];  
            ip_dest_2 =  ip_dest_2 | streamedData[inspectedBytes+1]; 
            ip_dest_3 =  ip_dest_3 | streamedData[inspectedBytes+2];  
            ip_dest_4 =  ip_dest_4 | streamedData[inspectedBytes+3]; 
            printf("%d.%d.%d.%d\n", ip_dest_1, ip_dest_2,ip_dest_3,ip_dest_4);  //18e0          
            inspectedBytes+=4;         
            
            if( 5 == ip_length )
                printf("IP:  No options\n");
            printf("IP:\n"); 
            main_counter+=8;            

            if(ip_protocol == dec_ICMP){
                icmp_counter++;
                printf("ICMP:  ----- ICMP Header -----\n");
                printf("ICMP: \n");

                unsigned char icmp_type = 0;
                icmp_type = icmp_type | streamedData[inspectedBytes]; 

                printf("ICMP: Type = ");
                if(icmp_type == 8)
                    printf("%d (Echo Request)\n", icmp_type); 
                else
                    printf("%d (Echo Reply)\n", icmp_type); 
                
                inspectedBytes += 1;  

                unsigned char icmp_code = 0;
                icmp_code = icmp_code | streamedData[inspectedBytes];  
                printf("ICMP: Code = %d\n", icmp_code); 
                inspectedBytes += 1;               
            
                unsigned char icmp_checksum_one = 0;
                unsigned char icmp_checksum_two = 0;            
                icmp_checksum_one =  icmp_checksum_one | streamedData[inspectedBytes];  
                icmp_checksum_two =  icmp_checksum_two | streamedData[inspectedBytes+1]; 
                printf("ICMP: Checksum = %2x%02x\n",icmp_checksum_one, icmp_checksum_two);
                inspectedBytes += 2;    

                unsigned char tmp = 0;
                unsigned short icmp_id = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_id =  icmp_id | tmp;  
                icmp_id = icmp_id << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_id =  icmp_id | tmp;  
                printf("ICMP: Identifier = %d\n", icmp_id);
                inspectedBytes += 2;  

                tmp = 0;
                unsigned short icmp_seq = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_seq =  icmp_seq | tmp;  
                icmp_seq = icmp_seq << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_seq =  icmp_seq | tmp;  
                printf("ICMP: Sequence number = %d\n", icmp_seq);
                inspectedBytes += 2;            

                printf("ICMP:\n");
                main_counter +=8;               
                inspectedBytes+= (current_pkt_size-main_counter)-8;

            }else if(ip_protocol == dec_TCP){
                tcp_counter++;
                printf("TCP:  ----- TCP Header -----\n");
                printf("TCP: \n");

                unsigned short tcp_src = 0;
                unsigned char tmp = 0;
                tmp = streamedData[inspectedBytes];
                tcp_src =  tcp_src | tmp;            
                tcp_src = tcp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_src =  tcp_src | tmp;   
                printf("TCP:  Source port = %d\n", tcp_src);    
                // printf("Source Port = %d\n", tcp_src);                
                inspectedBytes +=2;

                unsigned short tcp_dest = 0;
                tmp = streamedData[inspectedBytes];
                tcp_dest =  tcp_dest | tmp;            
                tcp_dest = tcp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_dest =  tcp_dest | tmp;  
                printf("TCP:  Destination port = %d\n", tcp_dest);               
                inspectedBytes +=2;
                unsigned long tcp_sequence_num =0;      
                unsigned char temp = 0; 

                temp = 0 | streamedData[inspectedBytes];  
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_sequence_num = tcp_sequence_num | temp;

                printf("TCP:  Sequence number = %lu\n", tcp_sequence_num);
                inspectedBytes +=4;

                unsigned long tcp_ack_num = 0; 
                temp = 0; 
                
                temp = 0 | streamedData[inspectedBytes];  
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_ack_num = tcp_ack_num | temp;
                printf("TCP:  Acknowledgement number = %lu\n", tcp_ack_num);               
                inspectedBytes +=4;          
                                
                unsigned char tcp_offset = 0;
                tcp_offset =  tcp_offset | streamedData[inspectedBytes];            
                tcp_offset = tcp_offset >> 4;
                printf("TCP:  Data offset = %d bytes\n", tcp_offset*4);              
                inspectedBytes +=1;

                printf("TCP:  Flags\n");
                unsigned char flags = 0;
                flags = flags | streamedData[inspectedBytes];
                unsigned char flag1 = flags;
                flag1 = flag1 << 2;
                flag1 = flag1 >> 7;                
                unsigned char flag2 = flags;
                flag2 = flag2 << 3;
                flag2 = flag2 >> 7; 
                unsigned char flag3 = flags;
                flag3 = flag3 << 4;
                flag3 = flag3 >> 7;
                unsigned char flag4 = flags;
                flag4 = flag4 << 5;
                flag4 = flag4 >> 7;
                unsigned char flag5 = flags;
                flag5 = flag5 << 6;
                flag5 = flag5 >> 7;
                unsigned char flag6 = flags;
                flag6 = flag6 << 7;
                flag6 = flag6 >> 7;

                if(flag1==0)
                    printf("TCP:      ..%d. .... = No urgent pointer\n", flag1);
                else
                    printf("TCP:      ..%d. .... = Urgent pointer\n", flag1);
                    
                if(flag2==0)
                    printf("TCP:      ...%d .... = No acknowledgement\n", flag2);
                else
                    printf("TCP:      ...%d .... = Acknowledgement\n", flag2);

                if(flag3==0)
                    printf("TCP:      .... %d... = No push\n", flag3);
                else
                    printf("TCP:      .... %d... = Push\n", flag3);

                if(flag4==0)
                    printf("TCP:      .... .%d.. = No reset\n", flag4);
                else
                    printf("TCP:      .... .%d.. = Reset\n", flag4);

                if(flag5==0)
                    printf("TCP:      .... ..%d. = No Syn\n", flag5);
                else
                    printf("TCP:      .... ..%d. = Syn\n", flag5);
                
                if(flag6==0)
                    printf("TCP:      .... ...%d = No Fin\n", flag6);
                else
                    printf("TCP:      .... ...%d = Fin\n", flag6);

                inspectedBytes+=1;

                unsigned int tcp_window=0;
                temp = 0;
                temp = streamedData[inspectedBytes];
                tcp_window = tcp_window | temp;
                tcp_window = tcp_window << 8;              
                temp = streamedData[inspectedBytes+1];
                tcp_window = tcp_window | temp;
                printf("TCP:  Window = %d\n", tcp_window);

                inspectedBytes+=2;

                unsigned char tcp_header_checksum_one = 0;
                unsigned char tcp_header_checksum_two = 0;  
                unsigned short tcp_header_checksum = 0;                                      
                tcp_header_checksum_one =  tcp_header_checksum_one | streamedData[inspectedBytes];  
                tcp_header_checksum_two =  tcp_header_checksum_two | streamedData[inspectedBytes+1]; 
                tcp_header_checksum = tcp_header_checksum_one;
                tcp_header_checksum = tcp_header_checksum << 8;
                tcp_header_checksum = tcp_header_checksum | tcp_header_checksum_two;                
                printf("TCP:  Checksum = %x\n",tcp_header_checksum);  
                inspectedBytes+=2;

                unsigned short urgent_pointer;
                temp = 0;
                temp = streamedData[inspectedBytes];
                urgent_pointer = urgent_pointer | temp;
                urgent_pointer = urgent_pointer << 8;
                temp = streamedData[inspectedBytes+1];
                urgent_pointer = urgent_pointer | temp;
                if(!(flag1==0))
                    printf("TCP:  Urgent pointer = %d\n" ,urgent_pointer); 
                else
                    printf("TCP:  Urgent pointer = 0\n");                
                                               
                inspectedBytes+=2;

                if( tcp_offset*4 == 20 )
                    printf("TCP:  No options\n");                
                else
                    printf("TCP:  Options ignored\n");

                printf("TCP:\n");

                main_counter +=28;               
                inspectedBytes+= current_pkt_size-main_counter;                
                
            }else if(ip_protocol == dec_UDP){
                udp_counter++;

                printf("UDP:  ----- UDP Header -----\n");
                printf("UDP: \n");

                unsigned char tmp = 0;
                unsigned short udp_src = 0;
                tmp = streamedData[inspectedBytes];
                udp_src =  udp_src | tmp;            
                udp_src = udp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_src =  udp_src | tmp;    
                tmp = 0;
                printf("UDP:  Source port = %d\n", udp_src);                
                inspectedBytes +=2;

                unsigned short udp_dest = 0;
                tmp = streamedData[inspectedBytes];
                udp_dest =  udp_dest | tmp;            
                udp_dest = udp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_dest =  udp_dest | tmp;
                tmp = 0; 
                printf("UDP:  Destination port = %d\n", udp_dest);                
                inspectedBytes +=2;

                unsigned short udp_length = 0;
                tmp = streamedData[inspectedBytes];
                udp_length =  udp_length | tmp;            
                udp_length = udp_length << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_length =  udp_length | tmp;
                tmp = 0;  
                printf("UDP:  Message length = %d\n", udp_length);                
                inspectedBytes +=2;

                unsigned char udp_checksum_1 = 0;
                unsigned char udp_checksum_2 = 0;    
                unsigned short udp_checksum = 0;                
                            
                udp_checksum_1 =  udp_checksum_1 | streamedData[inspectedBytes];            
                udp_checksum_2 =  udp_checksum_2 | streamedData[inspectedBytes+1]; 
                udp_checksum = udp_checksum_1;
                udp_checksum = udp_checksum << 8;
                udp_checksum = udp_checksum | udp_checksum_2;
                printf("UDP:  Checksum = %x\n", udp_checksum);                
                inspectedBytes +=2;
                printf("UDP:\n");
                inspectedBytes += udp_length-8;
                
            }else{
                other_ip_counter++;
            }

        }else if(ether_type == 2054){ //Decimal for 0x0806 (ARP)
            arp_counter++;
            ether_counter++;
            printf("ARP:  ----- ARP Frame -----\n");
            printf("ARP:  \n");

            unsigned short arp_hw_type=0;
            unsigned char arp_tmp = 0;
            arp_tmp = streamedData[inspectedBytes];
            arp_hw_type =  arp_hw_type | arp_tmp;            
            arp_hw_type = arp_hw_type << 8;
            arp_tmp = streamedData[inspectedBytes+1];            
            arp_hw_type =  arp_hw_type | arp_tmp; 
            printf("ARP:  Hardware type = 1 (Ethernet)\n");   
            inspectedBytes += 2;

            unsigned short arp_protocol_type=0;
            arp_tmp = streamedData[inspectedBytes];
            arp_protocol_type =  arp_protocol_type | arp_tmp;            
            arp_protocol_type = arp_protocol_type << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            arp_protocol_type =  arp_protocol_type | arp_tmp;
            printf("ARP:  Protocol type = %04x (IP)\n" ,arp_protocol_type);
            inspectedBytes += 2;

            unsigned char arp_hw_add_length= 0;
            arp_hw_add_length =  arp_hw_add_length | streamedData[inspectedBytes];            
            printf("ARP:  Length of hardware address = %d bytes\n" ,arp_hw_add_length);
            inspectedBytes += 1;

            unsigned char arp_add_length=0;
            arp_add_length =  arp_add_length | streamedData[inspectedBytes];            
            printf("ARP:  Length of protocol address = %d bytes\n" ,arp_add_length);
            inspectedBytes += 1;

            unsigned short arp_opcode=0;
            arp_tmp = streamedData[inspectedBytes+1];
            arp_opcode =  arp_opcode | arp_tmp; 

            printf("ARP:  Opcode %d" ,arp_opcode);
            if(arp_opcode == 1)
                printf(" (ARP Request)\n");
            else if(arp_opcode == 2)
                printf(" (ARP Reply)\n");
            else if(arp_opcode == 3)
                printf(" (RARP Request)\n");
            else if(arp_opcode == 4)
                printf(" (RARP Reply)\n");
            else if(arp_opcode == 5)
                printf(" (DRARP Request)\n");
            else if(arp_opcode == 6)
                printf(" (DRARP Reply)\n");
            else if(arp_opcode == 7)
                printf(" (DRARP Error)\n");
            else if(arp_opcode == 8)
                printf(" (InARP Request)\n");
            else if(arp_opcode == 9)
                printf(" (InARP Reply)\n");
            else 
                printf("(...)\n");
            
            inspectedBytes += 2;

            unsigned char current_byte=0;
            unsigned char add_section=0;            
            printf("ARP:  Sender's hardware address = ");

            unsigned long long arp_sender_hardware=0;
            arp_tmp = streamedData[inspectedBytes];
            printf("%x:",arp_tmp);
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+4];
            printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+5];
            printf("%x\n",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;

            inspectedBytes += 6;

            printf("ARP:  Sender's protocol address = ");
            unsigned long long arp_sender_protocol=0;
            arp_tmp = streamedData[inspectedBytes];
            printf("%d.",arp_tmp);
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            printf("%d.",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            printf("%d.",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            printf("%d\n",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;  

            inspectedBytes += 4;

            printf("ARP:  Target hardware address = ");
            unsigned long long target_hw_add = 0;
            unsigned char target_hw_add_1 = streamedData[inspectedBytes];
            unsigned char target_hw_add_2 = streamedData[inspectedBytes+1];
            unsigned char target_hw_add_3 = streamedData[inspectedBytes+2]; 
            unsigned char target_hw_add_4 = streamedData[inspectedBytes+3]; 
            unsigned char target_hw_add_5 = streamedData[inspectedBytes+4]; 
            unsigned char target_hw_add_6 = streamedData[inspectedBytes+5];
            
            if( arp_opcode%2 != 0)
                printf("?\n"); 
            else
                printf("%x:%x:%x:%x:%x:%x\n", target_hw_add_1, target_hw_add_2, target_hw_add_3, target_hw_add_4, target_hw_add_5, target_hw_add_6 );

            inspectedBytes+=6;

            printf("ARP:  Target protocol address = "); 
            //TO-DOs
            // printf("xxx.xxx.xxx.xxx\n");
            unsigned long long arp_target_protocol=0;
            arp_tmp = streamedData[inspectedBytes];
            printf("%d.",arp_tmp);
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            printf("%d.",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            printf("%d.",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            printf("%d\n",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            

            // printf("ARP:  Protocol type = %04x (IP)\n" ,arp_protocol_type);
            // inspectedBytes += 2;


            inspectedBytes+=4;  
            printf("ARP:\n");  
            main_counter+=28;
            inspectedBytes+=(current_pkt_size - main_counter)+4;   
            
        }else{
            other_ether_counter++;
            ether_counter++; 
            inspectedBytes += pkt_size-14;//14 Already counted in header + 12 +  

            pkt_size = 0;                   
        }
        ether_id++;
    }

    // printf("Other counter is: %d", other_ether_counter);
    // partialPrint(ether_counter,ether_broadcast_counter, arp_counter, ip_counter, udp_counter, tcp_counter,icmp_counter,other_ip_counter,other_ether_counter);
}

void summaryInspection(char*  streamedData){
    // cout <<" Size of stream " << stream_size <<endl;
    int ether_counter=0;
    int arp_counter=0;
    int ip_counter=0;
    int other_ip_counter=0;
    int other_ether_counter =0;    
    int udp_counter=0;
    int tcp_counter=0;
    int icmp_counter=0;
    int ether_broadcast_counter = 0;

    int inspectedBytes = 0;

    unsigned long pkt_size = 0;
    int ether_id = 0; 
    int main_counter = 0;
    int frame_limit = 0;

    while( inspectedBytes < stream_size ){ 

        //printf("\nETHER:  ----- Ether Header -----\n");
        //printf("ETHER:\n");
        //printf("ETHER:  Packet %d\n", ether_id);            
        int main_counter = 0;        
        pkt_size = 0;
        unsigned char temp = 0;
        temp = streamedData[inspectedBytes];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;
        temp = streamedData[inspectedBytes+1];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+2];
        pkt_size = pkt_size | temp;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+3];
        pkt_size = pkt_size | temp ;
        //printf("ETHER:  Packet size = %lu bytes\n", pkt_size); 

        inspectedBytes += 4;
        current_pkt_size = pkt_size;

        //printf("ETHER:  Destination = ");
        unsigned long long ether_destination = 0;
        unsigned char tmp = 0; 
        int indicator = 0;
        for(int i=inspectedBytes; i < inspectedBytes + 6 ; i++){
            //printf( "%x", (unsigned)(unsigned char) streamedData[i]); 
            tmp = streamedData[i];
            if((int)tmp == 255){
                indicator++;
            }
            ether_destination = ether_destination | tmp;
            ether_destination = ether_destination << 8;
            if(i != inspectedBytes + 6 -1){
                //printf(":");
                tmp = streamedData[i];
                ether_destination = ether_destination | tmp;
                if((int)tmp == 255){
                    indicator++;
                }
                if(indicator == 6)
                    ether_broadcast_counter++;
            }
        }
        //printf("\n");                
        inspectedBytes += 6;

        //printf("ETHER:  Source      = ");

        // for(int i=inspectedBytes; i <inspectedBytes + src_length; i++){
        //     //printf( "%x", (unsigned)(unsigned char) streamedData[i] ); 
        //     if(i != inspectedBytes + src_length - 1)
        //         //printf(":");
        // }
        //printf("\n");        
        inspectedBytes += 6;
        
         
        int ether_type = 0;   
        tmp = 0;
        tmp = streamedData[inspectedBytes];            
        ether_type =  ether_type | tmp;            
        ether_type = ether_type << 8;
        tmp = streamedData[inspectedBytes+1];            
        ether_type =  ether_type | tmp; 

        //printf("ETHER:  Ethertype   = %04x ", ether_type);
        inspectedBytes +=2;        

        // if(ether_type == 2048)
        //     //printf("(IP)\n");  
        // else if(ether_type == 2054)
        //     //printf("(ARP)\n");
        // else
        //     //printf("(unknown)\n");  
        
        
        //printf("ETHER:\n");
        main_counter += 18; 

        if(ether_type == 2048){ //Decimal for 0x0800 (IP)
            ip_counter++;
            ether_counter++;
            //printf("IP:  ----- IP Header -----\n");
            //printf("IP:\n");
            unsigned char version = 0;
            version =  version | streamedData[inspectedBytes]; 
            version = version >> 4;
            //printf("IP:  Version = %d\n", version);

            unsigned char ip_length = 0;
            ip_length =  ip_length | streamedData[inspectedBytes]; 
            ip_length = ip_length << 4;            
            ip_length = ip_length >> 4;
            //printf("IP:  Header length = %d bytes\n", ip_length*4);
            inspectedBytes+=1;
            global_ip_length = ip_length;

            unsigned char ip_service = 0;
            ip_service =  ip_service | streamedData[inspectedBytes];            
            //printf("IP:  Type of service = %x\n", ip_service);

            inspectedBytes+=1;         

            unsigned char tmp = 0;
            unsigned short ip_total_length = 0;
            tmp = streamedData[inspectedBytes];            
            ip_total_length =  ip_total_length | tmp;            
            ip_total_length = ip_total_length << 8;
            tmp = streamedData[inspectedBytes+1];            
            ip_total_length =  ip_total_length | tmp;            

            //printf("IP:  Total length = %d bytes\n", ip_total_length);
            inspectedBytes+=2;           

            unsigned short ip_identification = 0;
            unsigned char ip_temp = 0;
            ip_temp = streamedData[inspectedBytes];
            ip_identification =  ip_identification | ip_temp;            
            ip_identification = ip_identification << 8;
            ip_temp = streamedData[inspectedBytes+1];
            ip_identification =  ip_identification | ip_temp; 
            //printf("IP:  Identification = %d\n", ip_identification);
            inspectedBytes+=2;
            
            //printf("IP:  Flags\n");
            unsigned char ip_flag_df = 0;
            ip_flag_df =  ip_flag_df | streamedData[inspectedBytes]; 
            ip_flag_df = ip_flag_df << 1;                       
            ip_flag_df = ip_flag_df >> 7;
            // if(ip_flag_df == 0)
            //     //printf("IP:    .%d.. .... = allow fragment\n", ip_flag_df);
            // else
                //printf("IP:    .%d.. .... = do not fragment\n", ip_flag_df);

            unsigned char ip_flag_mf = 0;
            ip_flag_mf =  ip_flag_mf | streamedData[inspectedBytes];            
            ip_flag_mf = ip_flag_mf << 2;                       
            ip_flag_mf = ip_flag_mf >> 7;
            // if(ip_flag_mf == 0)
            //     //printf("IP:    ..%d. .... = last fragment\n", ip_flag_mf);
            // else
                //printf("IP:    ..%d. .... = last fragment\n", ip_flag_mf);
            
            unsigned short ip_frag_offset = 0;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes];            
            ip_frag_offset = ip_frag_offset << 8;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes+1];            
            ip_frag_offset = ip_frag_offset << 3;
            ip_frag_offset = ip_frag_offset >> 3;
            //printf("IP:  Fragment offset = %d bytes\n",ip_frag_offset);           
            inspectedBytes+=2;                       
            //Skip TTl
            inspectedBytes+=1;          

            //Protocol
            unsigned char ip_protocol = 0; 
            ip_protocol =  ip_protocol | streamedData[inspectedBytes]; 
            //printf("IP:  Protocol = %d", ip_protocol);

            // //printf(");
            // if(ip_protocol == dec_TCP)
            //     //printf(" (TCP)\n");
            // else if(ip_protocol == dec_UDP)
            //     //printf(" (UDP)\n");
            // else if(ip_protocol == dec_ICMP)
            //     //printf(" (ICMP)\n");
            // else 
            //     //printf(" (unknown)\n");                

            inspectedBytes+=1;         

            unsigned char ip_header_checksum_one = 0;
            unsigned char ip_header_checksum_two = 0;            
            ip_header_checksum_one =  ip_header_checksum_one | streamedData[inspectedBytes];  
            ip_header_checksum_two =  ip_header_checksum_two | streamedData[inspectedBytes+1]; 
            unsigned short ip_header_checksum = ip_header_checksum_one;
            ip_header_checksum = ip_header_checksum_one << 8;
            ip_header_checksum = ip_header_checksum | ip_header_checksum_two;            
            //printf("IP:  Header checksum = %x\n" , ip_header_checksum);    
            inspectedBytes+=2;        

            //printf("IP:  Source address = ");
            unsigned char ip_src_1 = 0;
            unsigned char ip_src_2 = 0; 
            unsigned char ip_src_3 = 0;            
            unsigned char ip_src_4 = 0;                                   
            ip_src_1 =  ip_src_1 | streamedData[inspectedBytes];  
            ip_src_2 =  ip_src_2 | streamedData[inspectedBytes+1]; 
            ip_src_3 =  ip_src_3 | streamedData[inspectedBytes+2];  
            ip_src_4 =  ip_src_4 | streamedData[inspectedBytes+3]; 
            //printf("%d.%d.%d.%d\n", ip_src_1, ip_src_2,ip_src_3,ip_src_4);  //18e0          
            inspectedBytes+=4;          
            
            //printf("IP:  Destination address = ");            
            unsigned char ip_dest_1 = 0;
            unsigned char ip_dest_2 = 0; 
            unsigned char ip_dest_3 = 0;            
            unsigned char ip_dest_4 = 0;                                   
            ip_dest_1 =  ip_dest_1 | streamedData[inspectedBytes];  
            ip_dest_2 =  ip_dest_2 | streamedData[inspectedBytes+1]; 
            ip_dest_3 =  ip_dest_3 | streamedData[inspectedBytes+2];  
            ip_dest_4 =  ip_dest_4 | streamedData[inspectedBytes+3]; 
            //printf("%d.%d.%d.%d\n", ip_dest_1, ip_dest_2,ip_dest_3,ip_dest_4);  //18e0          
            inspectedBytes+=4;         
            
            if( 5 == ip_length )
                //printf("IP:  No options\n");
            //printf("IP:\n"); 
            main_counter+=8;            

            if(ip_protocol == dec_ICMP){
                icmp_counter++;
                //printf("ICMP:  ----- ICMP Header -----\n");
                //printf("ICMP: \n");

                unsigned char icmp_type = 0;
                icmp_type = icmp_type | streamedData[inspectedBytes]; 

                //printf("ICMP: Type = ");
                // if(icmp_type == 8)
                //     //printf("%d (Echo Request)\n", icmp_type); 
                // else
                    //printf("%d (Echo Reply)\n", icmp_type); 
                
                inspectedBytes += 1;  

                unsigned char icmp_code = 0;
                icmp_code = icmp_code | streamedData[inspectedBytes];  
                //printf("ICMP: Code = %d\n", icmp_code); 
                inspectedBytes += 1;               
            
                unsigned char icmp_checksum_one = 0;
                unsigned char icmp_checksum_two = 0;            
                icmp_checksum_one =  icmp_checksum_one | streamedData[inspectedBytes];  
                icmp_checksum_two =  icmp_checksum_two | streamedData[inspectedBytes+1]; 
                //printf("ICMP: Checksum = %2x%02x\n",icmp_checksum_one, icmp_checksum_two);
                inspectedBytes += 2;    

                unsigned char tmp = 0;
                unsigned short icmp_id = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_id =  icmp_id | tmp;  
                icmp_id = icmp_id << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_id =  icmp_id | tmp;  
                //printf("ICMP: Identifier = %d\n", icmp_id);
                inspectedBytes += 2;  

                tmp = 0;
                unsigned short icmp_seq = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_seq =  icmp_seq | tmp;  
                icmp_seq = icmp_seq << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_seq =  icmp_seq | tmp;  
                //printf("ICMP: Sequence number = %d\n", icmp_seq);
                inspectedBytes += 2;            

                //printf("ICMP:\n");
                main_counter +=8;               
                inspectedBytes+= (current_pkt_size-main_counter)-8;

            }else if(ip_protocol == dec_TCP){
                tcp_counter++;
                //printf("TCP:  ----- TCP Header -----\n");
                //printf("TCP: \n");

                unsigned short tcp_src = 0;
                unsigned char tmp = 0;
                tmp = streamedData[inspectedBytes];
                tcp_src =  tcp_src | tmp;            
                tcp_src = tcp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_src =  tcp_src | tmp;   
                //printf("TCP:  Source port = %d\n", tcp_src);    
                // //printf("Source Port = %d\n", tcp_src);                
                inspectedBytes +=2;

                unsigned short tcp_dest = 0;
                tmp = streamedData[inspectedBytes];
                tcp_dest =  tcp_dest | tmp;            
                tcp_dest = tcp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_dest =  tcp_dest | tmp;  
                //printf("TCP:  Destination port = %d\n", tcp_dest);               
                inspectedBytes +=2;
                unsigned long tcp_sequence_num =0;      
                unsigned char temp = 0; 

                temp = 0 | streamedData[inspectedBytes];  
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_sequence_num = tcp_sequence_num | temp;

                //printf("TCP:  Sequence number = %lu\n", tcp_sequence_num);
                inspectedBytes +=4;

                unsigned long tcp_ack_num = 0; 
                temp = 0; 
                
                temp = 0 | streamedData[inspectedBytes];  
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_ack_num = tcp_ack_num | temp;
                //printf("TCP:  Acknowledgement number = %lu\n", tcp_ack_num);               
                inspectedBytes +=4;          
                                
                unsigned char tcp_offset = 0;
                tcp_offset =  tcp_offset | streamedData[inspectedBytes];            
                tcp_offset = tcp_offset >> 4;
                //printf("TCP:  Data offset = %d bytes\n", tcp_offset*4);              
                inspectedBytes +=1;

                //printf("TCP:  Flags\n");
                unsigned char flags = 0;
                flags = flags | streamedData[inspectedBytes];
                unsigned char flag1 = flags;
                flag1 = flag1 << 2;
                flag1 = flag1 >> 7;                
                unsigned char flag2 = flags;
                flag2 = flag2 << 3;
                flag2 = flag2 >> 7; 
                unsigned char flag3 = flags;
                flag3 = flag3 << 4;
                flag3 = flag3 >> 7;
                unsigned char flag4 = flags;
                flag4 = flag4 << 5;
                flag4 = flag4 >> 7;
                unsigned char flag5 = flags;
                flag5 = flag5 << 6;
                flag5 = flag5 >> 7;
                unsigned char flag6 = flags;
                flag6 = flag6 << 7;
                flag6 = flag6 >> 7;

                inspectedBytes+=1;

                unsigned int tcp_window=0;
                temp = 0;
                temp = streamedData[inspectedBytes];
                tcp_window = tcp_window | temp;
                tcp_window = tcp_window << 8;              
                temp = streamedData[inspectedBytes+1];
                tcp_window = tcp_window | temp;
                //printf("TCP:  Window = %d\n", tcp_window);

                inspectedBytes+=2;

                unsigned char tcp_header_checksum_one = 0;
                unsigned char tcp_header_checksum_two = 0;  
                unsigned short tcp_header_checksum = 0;                                      
                tcp_header_checksum_one =  tcp_header_checksum_one | streamedData[inspectedBytes];  
                tcp_header_checksum_two =  tcp_header_checksum_two | streamedData[inspectedBytes+1]; 
                tcp_header_checksum = tcp_header_checksum_one;
                tcp_header_checksum = tcp_header_checksum << 8;
                tcp_header_checksum = tcp_header_checksum | tcp_header_checksum_two;                
                //printf("TCP:  Checksum = %x\n",tcp_header_checksum);  
                inspectedBytes+=2;

                unsigned short urgent_pointer;
                temp = 0;
                temp = streamedData[inspectedBytes];
                urgent_pointer = urgent_pointer | temp;
                urgent_pointer = urgent_pointer << 8;
                temp = streamedData[inspectedBytes+1];
                urgent_pointer = urgent_pointer | temp;
                // if(!(flag1==0))
                //     //printf("TCP:  Urgent pointer = %d\n" ,urgent_pointer); 
                // else
                //     //printf("TCP:  Urgent pointer = 0\n");                
                                               
                inspectedBytes+=2;

                // if( tcp_offset*4 == 20 )
                //     //printf("TCP:  No options\n");                
                // else
                    //printf("TCP:  Options ignored\n");

                //printf("TCP:\n");

                main_counter +=28;               
                inspectedBytes+= current_pkt_size-main_counter;                
                
            }else if(ip_protocol == dec_UDP){
                udp_counter++;

                //printf("UDP:  ----- UDP Header -----\n");
                //printf("UDP: \n");

                unsigned char tmp = 0;
                unsigned short udp_src = 0;
                tmp = streamedData[inspectedBytes];
                udp_src =  udp_src | tmp;            
                udp_src = udp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_src =  udp_src | tmp;    
                tmp = 0;
                //printf("UDP:  Source port = %d\n", udp_src);                
                inspectedBytes +=2;

                unsigned short udp_dest = 0;
                tmp = streamedData[inspectedBytes];
                udp_dest =  udp_dest | tmp;            
                udp_dest = udp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_dest =  udp_dest | tmp;
                tmp = 0; 
                //printf("UDP:  Destination port = %d\n", udp_dest);                
                inspectedBytes +=2;

                unsigned short udp_length = 0;
                tmp = streamedData[inspectedBytes];
                udp_length =  udp_length | tmp;            
                udp_length = udp_length << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_length =  udp_length | tmp;
                tmp = 0;  
                //printf("UDP:  Message length = %d\n", udp_length);                
                inspectedBytes +=2;

                unsigned char udp_checksum_1 = 0;
                unsigned char udp_checksum_2 = 0;    
                unsigned short udp_checksum = 0;                
                            
                udp_checksum_1 =  udp_checksum_1 | streamedData[inspectedBytes];            
                udp_checksum_2 =  udp_checksum_2 | streamedData[inspectedBytes+1]; 
                udp_checksum = udp_checksum_1;
                udp_checksum = udp_checksum << 8;
                udp_checksum = udp_checksum | udp_checksum_2;
                //printf("UDP:  Checksum = %x\n", udp_checksum);                
                inspectedBytes +=2;
                //printf("UDP:\n");
                inspectedBytes += udp_length-8;
                
            }else{
                other_ip_counter++;
            }

        }else if(ether_type == 2054){ //Decimal for 0x0806 (ARP)
            arp_counter++;
            ether_counter++;
            //printf("ARP:  ----- ARP Frame -----\n");
            //printf("ARP:  \n");

            unsigned short arp_hw_type=0;
            unsigned char arp_tmp = 0;
            arp_tmp = streamedData[inspectedBytes];
            arp_hw_type =  arp_hw_type | arp_tmp;            
            arp_hw_type = arp_hw_type << 8;
            arp_tmp = streamedData[inspectedBytes+1];            
            arp_hw_type =  arp_hw_type | arp_tmp; 
            //printf("ARP:  Hardware type = 1 (Ethernet)\n");   
            inspectedBytes += 2;

            unsigned short arp_protocol_type=0;
            arp_tmp = streamedData[inspectedBytes];
            arp_protocol_type =  arp_protocol_type | arp_tmp;            
            arp_protocol_type = arp_protocol_type << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            arp_protocol_type =  arp_protocol_type | arp_tmp;
            //printf("ARP:  Protocol type = %04x (IP)\n" ,arp_protocol_type);
            inspectedBytes += 2;

            unsigned char arp_hw_add_length= 0;
            arp_hw_add_length =  arp_hw_add_length | streamedData[inspectedBytes];            
            //printf("ARP:  Length of hardware address = %d bytes\n" ,arp_hw_add_length);
            inspectedBytes += 1;

            unsigned char arp_add_length=0;
            arp_add_length =  arp_add_length | streamedData[inspectedBytes];            
            //printf("ARP:  Length of protocol address = %d bytes\n" ,arp_add_length);
            inspectedBytes += 1;

            unsigned short arp_opcode=0;
            arp_tmp = streamedData[inspectedBytes+1];
            arp_opcode =  arp_opcode | arp_tmp; 
            
            inspectedBytes += 2;

            unsigned char current_byte=0;
            unsigned char add_section=0;            
            //printf("ARP:  Sender's hardware address = ");

            unsigned long long arp_sender_hardware=0;
            arp_tmp = streamedData[inspectedBytes];
            //printf("%x:",arp_tmp);
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            //printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            //printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            //printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+4];
            //printf("%x:",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_tmp = streamedData[inspectedBytes+5];
            //printf("%x\n",arp_tmp);            
            arp_sender_hardware =  arp_sender_hardware | arp_tmp;

            inspectedBytes += 6;

            //printf("ARP:  Sender's protocol address = ");
            unsigned long long arp_sender_protocol=0;
            arp_tmp = streamedData[inspectedBytes];
            //printf("%d.",arp_tmp);
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            //printf("%d.",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            //printf("%d.",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            //printf("%d\n",arp_tmp);            
            arp_sender_protocol =  arp_sender_protocol | arp_tmp;  

            inspectedBytes += 4;

            //printf("ARP:  Target hardware address = ");
            unsigned long long target_hw_add = 0;
            unsigned char target_hw_add_1 = streamedData[inspectedBytes];
            unsigned char target_hw_add_2 = streamedData[inspectedBytes+1];
            unsigned char target_hw_add_3 = streamedData[inspectedBytes+2]; 
            unsigned char target_hw_add_4 = streamedData[inspectedBytes+3]; 
            unsigned char target_hw_add_5 = streamedData[inspectedBytes+4]; 
            unsigned char target_hw_add_6 = streamedData[inspectedBytes+5];
            
            inspectedBytes+=6;

            unsigned long long arp_target_protocol=0;
            arp_tmp = streamedData[inspectedBytes];
            //printf("%d.",arp_tmp);
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+1];
            //printf("%d.",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+2];
            //printf("%d.",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            
            arp_target_protocol = arp_target_protocol << 8;
            arp_tmp = streamedData[inspectedBytes+3];
            //printf("%d\n",arp_tmp);            
            arp_target_protocol =  arp_target_protocol | arp_tmp;            

            inspectedBytes+=4;  
            //printf("ARP:\n");  
            main_counter+=28;
            inspectedBytes+=(current_pkt_size - main_counter)+4;   
            
        }else{
            other_ether_counter++;
            ether_counter++; 
            inspectedBytes += pkt_size-14;//14 Already counted in header + 12 +  

            pkt_size = 0;                   
        }
        ether_id++;
    }

    partialPrint(ether_counter,ether_broadcast_counter, arp_counter, ip_counter, udp_counter, tcp_counter,icmp_counter,other_ip_counter,other_ether_counter);
}

void lowVerbosityInspection(char*  streamedData){

    int ether_counter=0;
    int arp_counter=0;
    int ip_counter=0;
    int other_ip_counter=0;
    int other_ether_counter =0;    
    int udp_counter=0;
    int tcp_counter=0;
    int icmp_counter=0;
    int ether_broadcast_counter = 0;

    int inspectedBytes = 0;

    unsigned long pkt_size = 0;
    int ether_id = 0; 
    int main_counter = 0;
    int frame_limit = 0;

    while( inspectedBytes < stream_size ){ 
          
        int main_counter = 0;        
        pkt_size = 0;
        unsigned char temp = 0;
        temp = streamedData[inspectedBytes];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;
        temp = streamedData[inspectedBytes+1];
        pkt_size = pkt_size | temp ;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+2];
        pkt_size = pkt_size | temp;
        pkt_size = pkt_size << 8;
        temp = 0;        
        temp = streamedData[inspectedBytes+3];
        pkt_size = pkt_size | temp ;

        inspectedBytes += 4;
        current_pkt_size = pkt_size;

        unsigned long long ether_destination = 0;
        unsigned char tmp = 0; 
        int indicator = 0;
        is_broadcast = 0;
        for(int i=inspectedBytes; i < inspectedBytes + 6 ; i++){
 
            tmp = streamedData[i];
            if((int)tmp == 255){
                indicator++;
            }
            ether_destination = ether_destination | tmp;
            ether_destination = ether_destination << 8;
            if(i != inspectedBytes + 6 -1){
                //printf(":");
                tmp = streamedData[i];
                ether_destination = ether_destination | tmp;
                if((int)tmp == 255){
                    indicator++;
                }
                if(indicator == 6){
                    ether_broadcast_counter++;
                    is_broadcast = 1;
                }
            }
        }
        unsigned char ether_src_add_1 = streamedData[inspectedBytes];
        unsigned char ether_src_add_2 = streamedData[inspectedBytes+1];
        unsigned char ether_src_add_3 = streamedData[inspectedBytes+2];
        unsigned char ether_src_add_4 = streamedData[inspectedBytes+3];
        unsigned char ether_src_add_5 = streamedData[inspectedBytes+4];
        unsigned char ether_src_add_6 = streamedData[inspectedBytes+5];
                       
        inspectedBytes += 6;

        unsigned char ether_dest_add_1 = streamedData[inspectedBytes];
        unsigned char ether_dest_add_2 = streamedData[inspectedBytes+1];
        unsigned char ether_dest_add_3 = streamedData[inspectedBytes+2];
        unsigned char ether_dest_add_4 = streamedData[inspectedBytes+3];
        unsigned char ether_dest_add_5 = streamedData[inspectedBytes+4];
        unsigned char ether_dest_add_6 = streamedData[inspectedBytes+5];       
        inspectedBytes += 6;
                  
        int ether_type = 0;   
        tmp = 0;
        tmp = streamedData[inspectedBytes];            
        ether_type =  ether_type | tmp;            
        ether_type = ether_type << 8;
        tmp = streamedData[inspectedBytes+1];            
        ether_type =  ether_type | tmp; 

        inspectedBytes +=2;        
        main_counter += 18; 

        if(ether_type == 2048){ //Decimal for 0x0800 (IP)
            ip_counter++;
            ether_counter++;
            unsigned char version = 0;
            version =  version | streamedData[inspectedBytes]; 
            version = version >> 4;

            unsigned char ip_length = 0;
            ip_length =  ip_length | streamedData[inspectedBytes]; 
            ip_length = ip_length << 4;            
            ip_length = ip_length >> 4;
            inspectedBytes+=1;

            global_ip_length = ip_length;

            unsigned char ip_service = 0;
            ip_service =  ip_service | streamedData[inspectedBytes];            

            inspectedBytes+=1;         

            unsigned char tmp = 0;
            unsigned short ip_total_length = 0;
            tmp = streamedData[inspectedBytes];            
            ip_total_length =  ip_total_length | tmp;            
            ip_total_length = ip_total_length << 8;
            tmp = streamedData[inspectedBytes+1];            
            ip_total_length =  ip_total_length | tmp;            

            inspectedBytes+=2;           

            unsigned short ip_identification = 0;
            unsigned char ip_temp = 0;
            ip_temp = streamedData[inspectedBytes];
            ip_identification =  ip_identification | ip_temp;            
            ip_identification = ip_identification << 8;
            ip_temp = streamedData[inspectedBytes+1];
            ip_identification =  ip_identification | ip_temp; 
            inspectedBytes+=2;
            
            unsigned char ip_flag_df = 0;
            ip_flag_df =  ip_flag_df | streamedData[inspectedBytes]; 
            ip_flag_df = ip_flag_df << 1;                       
            ip_flag_df = ip_flag_df >> 7;

            unsigned char ip_flag_mf = 0;
            ip_flag_mf =  ip_flag_mf | streamedData[inspectedBytes];            
            ip_flag_mf = ip_flag_mf << 2;                       
            ip_flag_mf = ip_flag_mf >> 7;
            
            unsigned short ip_frag_offset = 0;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes];            
            ip_frag_offset = ip_frag_offset << 8;
            ip_frag_offset =  ip_frag_offset | streamedData[inspectedBytes+1];            
            ip_frag_offset = ip_frag_offset << 3;
            ip_frag_offset = ip_frag_offset >> 3;
         
            inspectedBytes+=2;                       
            //Skip TTl
            inspectedBytes+=1;          

            //Protocol
            unsigned char ip_protocol = 0; 
            ip_protocol =  ip_protocol | streamedData[inspectedBytes]; 

            inspectedBytes+=1;         

            unsigned char ip_header_checksum_one = 0;
            unsigned char ip_header_checksum_two = 0;            
            ip_header_checksum_one =  ip_header_checksum_one | streamedData[inspectedBytes];  
            ip_header_checksum_two =  ip_header_checksum_two | streamedData[inspectedBytes+1]; 
            unsigned short ip_header_checksum = ip_header_checksum_one;
            ip_header_checksum = ip_header_checksum_one << 8;
            ip_header_checksum = ip_header_checksum | ip_header_checksum_two;            
    
            inspectedBytes+=2;        

            unsigned char ip_src_1 = 0;
            unsigned char ip_src_2 = 0; 
            unsigned char ip_src_3 = 0;            
            unsigned char ip_src_4 = 0;                                   
            ip_src_1 =  ip_src_1 | streamedData[inspectedBytes];  
            ip_src_2 =  ip_src_2 | streamedData[inspectedBytes+1]; 
            ip_src_3 =  ip_src_3 | streamedData[inspectedBytes+2];  
            ip_src_4 =  ip_src_4 | streamedData[inspectedBytes+3]; 
         
            inspectedBytes+=4;          
            
           
            unsigned char ip_dest_1 = 0;
            unsigned char ip_dest_2 = 0; 
            unsigned char ip_dest_3 = 0;            
            unsigned char ip_dest_4 = 0;                                   
            ip_dest_1 =  ip_dest_1 | streamedData[inspectedBytes];  
            ip_dest_2 =  ip_dest_2 | streamedData[inspectedBytes+1]; 
            ip_dest_3 =  ip_dest_3 | streamedData[inspectedBytes+2];  
            ip_dest_4 =  ip_dest_4 | streamedData[inspectedBytes+3]; 
       
            inspectedBytes+=4;         
            
            if( 5 == ip_length )
            main_counter+=8;            

            if(ip_protocol == dec_ICMP){
                icmp_counter++;

                unsigned char icmp_type = 0;
                icmp_type = icmp_type | streamedData[inspectedBytes]; 
                
                inspectedBytes += 1;  

                unsigned char icmp_code = 0;
                icmp_code = icmp_code | streamedData[inspectedBytes];  

                inspectedBytes += 1;               
            
                unsigned char icmp_checksum_one = 0;
                unsigned char icmp_checksum_two = 0;            
                icmp_checksum_one =  icmp_checksum_one | streamedData[inspectedBytes];  
                icmp_checksum_two =  icmp_checksum_two | streamedData[inspectedBytes+1]; 
                inspectedBytes += 2;    

                unsigned char tmp = 0;
                unsigned short icmp_id = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_id =  icmp_id | tmp;  
                icmp_id = icmp_id << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_id =  icmp_id | tmp;  

                inspectedBytes += 2;  

                tmp = 0;
                unsigned short icmp_seq = 0;  
                tmp = streamedData[inspectedBytes];    
                icmp_seq =  icmp_seq | tmp;  
                icmp_seq = icmp_seq << 8;
                tmp = streamedData[inspectedBytes+1];    
                icmp_seq =  icmp_seq | tmp;  

                inspectedBytes += 2;            

                main_counter +=8;               
                inspectedBytes+= (current_pkt_size-main_counter)-8;


                printf("%d.%d.%d.%d -> %d.%d.%d.%d (ICMP),",
                ip_src_1,ip_src_2,ip_src_3,ip_src_4,
                ip_dest_1,ip_dest_2,ip_dest_3,ip_dest_4);

                if(icmp_type == 8)
                    printf(" Echo Request (type=%d)\n", icmp_type); 
                else
                    printf(" Echo Reply (type=%d)\n", icmp_type); 
                

            }else if(ip_protocol == dec_TCP){
                tcp_counter++;

                unsigned short tcp_src = 0;
                unsigned char tmp = 0;
                tmp = streamedData[inspectedBytes];
                tcp_src =  tcp_src | tmp;            
                tcp_src = tcp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_src =  tcp_src | tmp;   
               
                inspectedBytes +=2;

                unsigned short tcp_dest = 0;
                tmp = streamedData[inspectedBytes];
                tcp_dest =  tcp_dest | tmp;            
                tcp_dest = tcp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                tcp_dest =  tcp_dest | tmp;  
          
                inspectedBytes +=2;
                unsigned long tcp_sequence_num =0;      
                unsigned char temp = 0; 

                temp = 0 | streamedData[inspectedBytes];  
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_sequence_num = tcp_sequence_num | temp;
                tcp_sequence_num = tcp_sequence_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_sequence_num = tcp_sequence_num | temp;

                inspectedBytes +=4;

                unsigned long tcp_ack_num = 0; 
                temp = 0; 
                
                temp = 0 | streamedData[inspectedBytes];  
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;  

                temp = 0 | streamedData[inspectedBytes+1];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+2];
                tcp_ack_num = tcp_ack_num | temp;
                tcp_ack_num = tcp_ack_num << 8;

                temp = 0 | streamedData[inspectedBytes+3];
                tcp_ack_num = tcp_ack_num | temp;            
                inspectedBytes +=4;          
                                
                unsigned char tcp_offset = 0;
                tcp_offset =  tcp_offset | streamedData[inspectedBytes];            
                tcp_offset = tcp_offset >> 4;             
                inspectedBytes +=1;

                unsigned char flags = 0;
                flags = flags | streamedData[inspectedBytes];
                unsigned char flag1 = flags;
                flag1 = flag1 << 2;
                flag1 = flag1 >> 7;                
                unsigned char flag2 = flags;
                flag2 = flag2 << 3;
                flag2 = flag2 >> 7; 
                unsigned char flag3 = flags;
                flag3 = flag3 << 4;
                flag3 = flag3 >> 7;
                unsigned char flag4 = flags;
                flag4 = flag4 << 5;
                flag4 = flag4 >> 7;
                unsigned char flag5 = flags;
                flag5 = flag5 << 6;
                flag5 = flag5 >> 7;
                unsigned char flag6 = flags;
                flag6 = flag6 << 7;
                flag6 = flag6 >> 7;

                inspectedBytes+=1;

                unsigned int tcp_window=0;
                temp = 0;
                temp = streamedData[inspectedBytes];
                tcp_window = tcp_window | temp;
                tcp_window = tcp_window << 8;              
                temp = streamedData[inspectedBytes+1];
                tcp_window = tcp_window | temp;

                inspectedBytes+=2;

                unsigned char tcp_header_checksum_one = 0;
                unsigned char tcp_header_checksum_two = 0;  
                unsigned short tcp_header_checksum = 0;                                      
                tcp_header_checksum_one =  tcp_header_checksum_one | streamedData[inspectedBytes];  
                tcp_header_checksum_two =  tcp_header_checksum_two | streamedData[inspectedBytes+1]; 
                tcp_header_checksum = tcp_header_checksum_one;
                tcp_header_checksum = tcp_header_checksum << 8;
                tcp_header_checksum = tcp_header_checksum | tcp_header_checksum_two;                

                inspectedBytes+=2;

                unsigned short urgent_pointer;
                temp = 0;
                temp = streamedData[inspectedBytes];
                urgent_pointer = urgent_pointer | temp;
                urgent_pointer = urgent_pointer << 8;
                temp = streamedData[inspectedBytes+1];
                urgent_pointer = urgent_pointer | temp;            
                                               
                inspectedBytes+=2;

                printf("%d.%d.%d.%d -> %d.%d.%d.%d (TCP) sourceport = %d destport = %d\n",
                ip_src_1,ip_src_2,ip_src_3,ip_src_4,
                ip_dest_1,ip_dest_2,ip_dest_3,ip_dest_4,
                 tcp_src, tcp_dest );

                main_counter +=28;               
                inspectedBytes+= current_pkt_size-main_counter;                
                
            }else if(ip_protocol == dec_UDP){
                udp_counter++;

                unsigned char tmp = 0;
                unsigned short udp_src = 0;
                tmp = streamedData[inspectedBytes];
                udp_src =  udp_src | tmp;            
                udp_src = udp_src << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_src =  udp_src | tmp;    
                tmp = 0;
               
                inspectedBytes +=2;

                unsigned short udp_dest = 0;
                tmp = streamedData[inspectedBytes];
                udp_dest =  udp_dest | tmp;            
                udp_dest = udp_dest << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_dest =  udp_dest | tmp;
                tmp = 0; 
           
                inspectedBytes +=2;

                unsigned short udp_length = 0;
                tmp = streamedData[inspectedBytes];
                udp_length =  udp_length | tmp;            
                udp_length = udp_length << 8;
                tmp = streamedData[inspectedBytes+1];
                udp_length =  udp_length | tmp;
                tmp = 0;                 
                inspectedBytes +=2;

                unsigned char udp_checksum_1 = 0;
                unsigned char udp_checksum_2 = 0;    
                unsigned short udp_checksum = 0;                
                            
                udp_checksum_1 =  udp_checksum_1 | streamedData[inspectedBytes];            
                udp_checksum_2 =  udp_checksum_2 | streamedData[inspectedBytes+1]; 
                udp_checksum = udp_checksum_1;
                udp_checksum = udp_checksum << 8;
                udp_checksum = udp_checksum | udp_checksum_2;
                
                inspectedBytes +=2;

                inspectedBytes += udp_length-8;
               
                printf("%d.%d.%d.%d -> %d.%d.%d.%d (UDP) sourceport = %d destport = %d\n",
                ip_src_1,ip_src_2,ip_src_3,ip_src_4,
                ip_dest_1,ip_dest_2,ip_dest_3,ip_dest_4,
                 udp_src, udp_dest );

            }else{
                other_ip_counter++;
            }

        }else if(ether_type == 2054){ //Decimal for 0x0806 (ARP)
            arp_counter++;
            ether_counter++;

            unsigned short arp_hw_type = 0;
            unsigned char arp_tmp = 0;
            arp_tmp = streamedData[inspectedBytes];
            arp_hw_type =  arp_hw_type | arp_tmp;            
            arp_hw_type = arp_hw_type << 8;
            arp_tmp = streamedData[inspectedBytes+1];            
            arp_hw_type =  arp_hw_type | arp_tmp; 
            inspectedBytes += 2;

            unsigned short arp_protocol_type=0;
            arp_tmp = streamedData[inspectedBytes];
            arp_protocol_type =  arp_protocol_type | arp_tmp;            
            arp_protocol_type = arp_protocol_type << 8;

            arp_tmp = streamedData[inspectedBytes+1];
            arp_protocol_type =  arp_protocol_type | arp_tmp;
            inspectedBytes += 2;

            unsigned char arp_hw_add_length= 0;
            arp_hw_add_length =  arp_hw_add_length | streamedData[inspectedBytes];            
            inspectedBytes += 1;

            unsigned char arp_add_length=0;
            arp_add_length =  arp_add_length | streamedData[inspectedBytes];            
            inspectedBytes += 1;

            unsigned short arp_opcode=0;
            arp_tmp = streamedData[inspectedBytes+1];
            arp_opcode =  arp_opcode | arp_tmp; 
            
            inspectedBytes += 2;

            unsigned char current_byte=0;
            unsigned char add_section=0;            

            unsigned long long arp_sender_hardware = 0;
            unsigned char arp_sender_hardware_1 = 0;
            unsigned char arp_sender_hardware_2 = 0;
            unsigned char arp_sender_hardware_3 = 0;
            unsigned char arp_sender_hardware_4 = 0;
            unsigned char arp_sender_hardware_5 = 0;
            unsigned char arp_sender_hardware_6 = 0;

            arp_sender_hardware_1 = streamedData[inspectedBytes];

            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_1;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_sender_hardware_2 = streamedData[inspectedBytes+1];
           
            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_2;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_sender_hardware_3 = streamedData[inspectedBytes+2];
          
            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_3;            
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_sender_hardware_4 = streamedData[inspectedBytes+3];
          
            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_4;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_sender_hardware_5 = streamedData[inspectedBytes+4];
           
            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_5;
            arp_sender_hardware = arp_sender_hardware << 8;
            arp_sender_hardware_6 = streamedData[inspectedBytes+5];

            arp_sender_hardware =  arp_sender_hardware | arp_sender_hardware_6;

            inspectedBytes += 6;

            unsigned char arp_sender_protocol_1 =0;
            unsigned char arp_sender_protocol_2 =0;
            unsigned char arp_sender_protocol_3 =0;
            unsigned char arp_sender_protocol_4 =0;
            
            unsigned long long arp_sender_protocol=0;
                        
            arp_sender_protocol_1 = streamedData[inspectedBytes];

            arp_sender_protocol =  arp_sender_protocol | arp_sender_protocol_1;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_sender_protocol_2  = streamedData[inspectedBytes+1];
          
            arp_sender_protocol =  arp_sender_protocol | arp_sender_protocol_2 ;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_sender_protocol_3 = streamedData[inspectedBytes+2];
           
            arp_sender_protocol =  arp_sender_protocol | arp_sender_protocol_3;            
            arp_sender_protocol = arp_sender_protocol << 8;
            arp_sender_protocol_4 = streamedData[inspectedBytes+3];
          
            arp_sender_protocol =  arp_sender_protocol | arp_sender_protocol_4;  

            inspectedBytes += 4;

            unsigned long long target_hw_add = 0;
            unsigned char target_hw_add_1 = streamedData[inspectedBytes];
            unsigned char target_hw_add_2 = streamedData[inspectedBytes+1];
            unsigned char target_hw_add_3 = streamedData[inspectedBytes+2]; 
            unsigned char target_hw_add_4 = streamedData[inspectedBytes+3]; 
            unsigned char target_hw_add_5 = streamedData[inspectedBytes+4]; 
            unsigned char target_hw_add_6 = streamedData[inspectedBytes+5];

            inspectedBytes+=6;

            unsigned long long arp_target_protocol=0;
            unsigned char arp_target_protocol_1=0;
            unsigned char arp_target_protocol_2=0;
            unsigned char arp_target_protocol_3=0;
            unsigned char arp_target_protocol_4=0;

            arp_target_protocol_1 = streamedData[inspectedBytes];
            arp_target_protocol =  arp_target_protocol | arp_target_protocol_1;            
            arp_target_protocol = arp_target_protocol << 8;

            arp_target_protocol_2 = streamedData[inspectedBytes+1];
            arp_target_protocol =  arp_target_protocol | arp_target_protocol_2;            
            arp_target_protocol = arp_target_protocol << 8;

            arp_target_protocol_3 = streamedData[inspectedBytes+2];
            arp_target_protocol =  arp_target_protocol | arp_target_protocol_3;            
            arp_target_protocol = arp_target_protocol << 8;

            arp_target_protocol_4 = streamedData[inspectedBytes+3];
            arp_target_protocol =  arp_target_protocol | arp_target_protocol_4; 

            inspectedBytes+=4;  
            //printf("ARP:\n");  
            main_counter+=28;
            if (is_broadcast == 0 && arp_opcode == 1 ){ //Not a broadcast
                printf("%d.%d.%d.%d -> %d.%d.%d.%d (ARP) who is %d.%d.%d.%d\n",
                arp_sender_protocol_1, arp_sender_protocol_2, arp_sender_protocol_3, arp_sender_protocol_4,
                arp_target_protocol_1, arp_target_protocol_2, arp_target_protocol_3, arp_target_protocol_4,
                arp_target_protocol_1, arp_target_protocol_2, arp_target_protocol_3, arp_target_protocol_4);

            }else if(is_broadcast == 1 && arp_opcode == 1 ){ //Requesting for an adress in bcast
                printf("%d.%d.%d.%d -> (broadcast) (ARP) who is %d.%d.%d.%d\n",
                arp_sender_protocol_1, arp_sender_protocol_2, arp_sender_protocol_3, arp_sender_protocol_4,
                arp_target_protocol_1, arp_target_protocol_2, arp_target_protocol_3, arp_target_protocol_4);
            }else{
                printf("%d.%d.%d.%d -> %d.%d.%d.%d (ARP) %d.%d.%d.%d's hardware address is %x:%x:%x:%x:%x:%x\n",
                arp_sender_protocol_1, arp_sender_protocol_2, arp_sender_protocol_3, arp_sender_protocol_4,
                arp_target_protocol_1, arp_target_protocol_2, arp_target_protocol_3, arp_target_protocol_4,
                arp_sender_protocol_1, arp_sender_protocol_2, arp_sender_protocol_3, arp_sender_protocol_4,
                arp_sender_hardware_1, arp_sender_hardware_2, arp_sender_hardware_3,
                arp_sender_hardware_4, arp_sender_hardware_5, arp_sender_hardware_6);
                // ASK IF IT IS NEEDED TO PROCESS EVERY SINGLE PACKET THAT IS SENT IN OTHER OPCODES
            }
            inspectedBytes+=(current_pkt_size - main_counter)+4;   
            
        }else{
            other_ether_counter++;
            ether_counter++; 
            inspectedBytes += pkt_size-14;//14 Already counted in header + 12 +  
            printf("(unknown packet) (%x:%x:%x:%x:%x:%x, %x:%x:%x:%x:%x:%x, %x:%x)\n",
            ether_src_add_1, ether_src_add_2,ether_src_add_3,ether_src_add_4,ether_src_add_5,ether_src_add_6,
            ether_dest_add_1,ether_dest_add_2,ether_dest_add_3,ether_dest_add_4,ether_dest_add_5,ether_dest_add_6 ,
            (unsigned char) (ether_type >> 8) , (unsigned char)((ether_type<<8)>>8) );

            pkt_size = 0;                   
        }
        ether_id++;
    }
}

void partialPrint(int eth = 0, int broadcasts = 0, int arp_ct=0, int ip_ct = 0, 
                    int udp_ct=0, int tcp_ct=0,int icmp_ct=0, int other_ip_ct=0, 
                    int other_ct=0){

    printf("Ethernet frames: 	%d\n",eth);
    printf("Ethernet broadcast: 	%d\n",broadcasts);
    printf("  ARP packets: 		%d\n",arp_ct);
    printf("  IP packets: 		%d\n",ip_ct);
    printf("    UDP packets: 	%d\n",udp_ct);
    printf("    TCP packets: 	%d\n",tcp_ct);
    printf("    ICMP packets: 	%d\n",icmp_ct);
    printf("    other IP packets: 	%d\n",other_ip_ct);
    printf("  other packets: 	%d\n",other_ct);

}