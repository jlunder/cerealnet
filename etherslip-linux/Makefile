.phony: all clean

all: etherslip_d

clean:
	rm -f etherslip etherslip_d

etherslip_d: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c proto_arp.c
	gcc -std=gnu99 -W -Wall -O0 -g -o $@ $^
#	setcap cap_net_raw+ep $@

etherslip: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c proto_arp.c
	gcc -std=gnu99 -W -Wall -O2 -DNDEBUG -o $@ $^
#	setcap cap_net_raw+ep $@
