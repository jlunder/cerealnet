# cerealnet
Forward packets between Ethernet and a serial link such as SLIP

# Why did you make this thing?
I made this for vintage computing projects, but you could probably use it to share a
low-bandwidth link between microcontrollers or something.

# Yeah, but there's support in the Linux Kernel for SLIP and PPP already!
Sure, but it was annoying and hard to debug. I'm a programmer, not a sysadmin, C is my
hammer, and isn't this a nail here? Sure looks like a nail to me!

More seriously, I'm trying to network some really old computers and one of the tools
I'm using for this is etherslip, which is a SLIP client that pretends to be Ethernet
hardware to DOS programs. I figured, if I set this up right and bridge SLIP directly
back to real Ethernet, then DHCP and everything will just work transparently!

Wait, DHCP? Well, I want to have a simple, unified setup -- I want the SLIP bridge to
be totally transparent. Typically in days of yore, you'd manually configure a (probably
static) IP address and so forth in the network stacks on both ends of the SLIP link.
Ideally I don't want to have to configure clients, the bridge, or the router they're
plugged into. DHCP isn't supposed to work over SLIP, but it's not as implausible as it
sounds: DHCP uses IP packets already, so the only real problem to solve is really that
the client can't find out the MAC address assigned to it on the other side of the link.
Despite being wrapped in IP, DHCP does by default deal in raw Ethernet addresses
internally.

The etherslip driver on the DOS side clearly has some fake MAC address it exposes to the
DHCP client. In theory, it should be possible to rewrite that to the real address on the
external interface -- essentially, doing the same kind of magic rewriting sometimes done
for protocols like active mode FTP with IP masquerading NAT.

To make all this go it's simplest if each SLIP link is associated with a unique MAC,
which is definitely possible if we can get the card in promiscuous mode -- or if we
can't, we can rewrite the DHCP packet to include a client-id that disambiguates the
connections. Either, way, some kind of rewriting is needed.
