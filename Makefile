default:
	gcc code/dosuid.c -o dosuid
	chown root:root dosuid
	chmod +s dosuid

install:
	cp configs/interfaces /etc/network/interfaces
	cp configs/dnsmasq.conf /etc/dnsmasq.conf
	cp configs/hostapd.conf /etc/hostapd/hostapd.conf
	cp rc.local rc.proxy /etc
	chmod +x /etc/rc.local /etc/rc.proxy
