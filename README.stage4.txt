Stage 4:

a) 1. The function ip_checksum_stage3- 
for computing the checksum (copied the entire code for calculating checksum from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html#idp22752)

2. select() and scoket creation code copied from BEEJ TUTORIAL

3.sendmsg format for sending icmp packet using raw sockets referred from http://www.microhowto.info/howto/send_an_arbitrary_ipv4_datagram_using_a_raw_socket_in_c.html

b) Yes

c) i) As for different IP addresses different routers are used as an exit route. So load is divided among different routers

ii) Yes

iii) There can be more IP addresses that generate the same hash value that maps to the same router. The load imbalance can happen this way. Too much load on one router.

NOTE:
1. I have tested the stage 4, but the ip source address of eth0 differs from the sample output.
As I have taken ip addresses from ethernet interfaces so output will show those IP addresses.

2. ********I have used select() timer of 15 seconds for exiting my program, therefore please wait for 15 seconds before checking the output files till 'exiting' command is displayed in the terminal that implies the program has stopped and its safe to open the output files.

3. I observed that on running this program for very first time when the VM is up for the first time, random packets are read into tunnel. Though I have added a check so that they are ignored but sometimes icmp packets are not processed because of these unwanted packets. So, in case there is problem in running code for very first time, please run it again following the same process. 

4. As there are multiple process please do 'ps ax' on terminal to check if there are no older programs running. if there are older running programs do 'sudo kill -9 pid'. 
