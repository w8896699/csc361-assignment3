This hiahia.c is to to analyze a trace of IP datagrams:



The methods to run it:
  
    ./hiahia trace1.pcapng                 
    ./hiahia trace2.pcapng
    ./hiahia traceroute-frag.pcapng
    ./hiahia win_trace1.pcapng
First argv is program name, second argv is a capture file here i use a sample one downlode from connex

This program is to open a trace file and alalyze the first incomming packets is ICMP or UDP, if it is udp then the trace file is working under linux system, if it is icmp, it's work under win system. Then test its ttl and type to determin if its a connection and use add to list to and used intermidiate router. If its linux system, use the src portnumber to compare between different router to get rrt. If its win system, use seq number.
	A.three ttl
	B.	NO
	C. the sequence for trace1 router2: 192.168.9.5 and router3: 142.104.68.1 is different from others
				   router4: 192.168.10.1 and router5: 192.168.8.6 is different from others
			           router9: 199.212.24.64 and router10: 206.12.3.17 is different from others             
		In trace 1.2 the last router passed is 209.85.249.109 which is not existed in trace 3.4.5
	  The sequence for trace 3 and trace5 router9:206.12.3.17 and router 10:199.212.24.64 are different from other

