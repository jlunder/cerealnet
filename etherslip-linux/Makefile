.phony: all clean

all: etherslip_d

clean:
	rm -f etherslip etherslip_d

etherslip_d: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c proto_arp.c proto_dhcp.c proto_ip.c
	gcc -std=gnu99 -W -Wall -Wno-address-of-packed-member -O0 -g -o $@ $^
#	setcap cap_net_raw+ep $@

etherslip: etherslip.c etherslip.h if_eth.c if_pkt.c if_ser.c proto_arp.c proto_dhcp.c proto_ip.c
	gcc -std=gnu99 -W -Wall -Wno-address-of-packed-member -O2 -DNDEBUG -o $@ $^
#	setcap cap_net_raw+ep $@
