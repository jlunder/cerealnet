.phony: all clean

all: etherslip_d

clean:
	rm -f etherslip etherslip_d

etherslip_d: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c
	gcc -std=gnu11 -W -Wall -O0 -g -o $@ $^
#	setcap cap_net_raw+ep $@

etherslip: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c
	gcc -std=gnu11 -W -Wall -O2 -o $@ $^
#	setcap cap_net_raw+ep $@
