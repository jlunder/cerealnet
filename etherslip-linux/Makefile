etherslip_d: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c
	gcc -std=gnu11 -g -O0 -o $@ $^
#	setcap cap_net_raw+ep $@

etherslip: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c
	gcc -std=gnu11 -O2 -o $@ $^
#	setcap cap_net_raw+ep $@
