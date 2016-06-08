import ipaddress
import subprocess
import json

#################
DEBUG = True	#
#################

def createAccessPointConfig(secureInterfaces, untrustedGateway):	
	filenames = []
	for interface in secureInterfaces:
		if(interface["type"] == "WLAN"):
			filename = "hostapd_" + interface["name"] + ".conf"
			f = open(filename, "w+")
			f.write("interface=" + interface["name"] + "\n")
			f.write("driver=" + interface["driver"] + "\n")
			f.write("ssid=" + interface["ssid"] + "\n")
			f.write("channel=" + str(interface["channel"]) + "\n")
			f.write("hw_mode=g\n")
			f.write("auth_algs=1\n")
			f.write("wpa=2\n")
			f.write("wpa_passphrase=" + interface["psk"] + "\n")
			f.write("wmm_enabled=0\n")
			filenames.append(filename)

	return filenames


def createDHCPServerConfig(secureInterfaces, untrustedGateway):
	filename = "dnsmasq.myconf"
	f = open(filename, "w+")
	f.write("no-dhcp-interface=" + untrustedGateway["name"] + "\n")
	for interface in secureInterfaces:
		f.write("interface=" + interface["name"] + "\n")
		rangeStart = str(interface["addr"].network[1])
		rangeEnd = str(interface["addr"].network[1 + interface["dhcp_addrCount"]])
		f.write("dhcp-range=interface:" + interface["name"] + "," + rangeStart + "," + rangeEnd + ",infinite\n")

	return filename

def createForwardingFile(secureInterfaces, untrustedGateway):
	filename = "iptables_forwarding"
	f = open(filename, "w+")

	f.write("iptables -F\n")
	f.write("iptables -X\n")
	f.write("iptables -t nat -F\n")
	f.write("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	f.write("iptables -t nat -A POSTROUTING -o " + untrustedGateway["name"] + " -j MASQUERADE\n")
	for interface in secureInterfaces:
		f.write("iptables -A FORWARD -o " + untrustedGateway["name"]
			+ " -i " + interface["name"] + " -s " + str(interface["addr"].network)
			+ " -m conntrack --ctstate NEW -j ACCEPT\n")

	f.write("sysctl -w net.ipv4.ip_forward=1\n")

	return filename


def createInterfaceString(interface, secure):
	lines = []
	lines.append("auto " + interface["name"])
	lines.append("iface " + interface["name"] + " inet " + ("static" if secure else "dhcp"))
	
	if(secure):
		lines.append("address " + str(interface["addr"].ip))
		lines.append("netmask " + str(interface["addr"].netmask))
		lines.append("post-up service dnsmasq restart")
		if(interface["type"] == "WLAN"):
			lines.append("post-up hostapd /etc/hostapd/hostapd_" + interface["name"] + ".conf")
	else:
		if(interface["type"] == "WLAN"):
			lines.append("wpa-ssid " + interface["ssid"])
			lines.append("wpa-psk " + interface["psk"])
		lines.append("post-up /etc/network/iptables_forwarding")

	return "\n\t\t".join(lines)

def createNetworkFile(secureInterfaces, untrustedGateway):
	filename = "interfaces"
	f = open(filename, "w+") #TODO: richtiges File /etc/network/interfaces
	fileHeader = '''# interfaces(5) file used by ifup(8) and ifdown(8)
#Please note that this file is written to be used with dhcpcd
#For static IP, consult /etc/dhcpcd.conf and 'man dhcpcd.conf'

# Include files from /etc/network/interfaces.d:
source-directory /etc/network/interfaces.d

auto lo
iface lo inet loopback

'''
	f.write(fileHeader)
	for interface in secureInterfaces:
		f.write(createInterfaceString(interface, True))
		f.write("\n\n")
	f.write(createInterfaceString(untrustedGateway, False))

	return filename

def readConfig():
	config = open("secGateClient.conf")
	data = json.load(config)
	secureInterfaces = data["secureInterfaces"]
	untrustedGateway = data["untrustedGateway"]
	for interface in secureInterfaces + [untrustedGateway]:
		if "addr" in interface:
			interface["addr"] = ipaddress.ip_interface(interface["addr"])
		if "dhcp_addrCount" in interface:
			interface["dhcp_addrCount"] = int(interface["dhcp_addrCount"])


	return (secureInterfaces, untrustedGateway)

def activate(networkFile, forwardingFile, apFiles, dhcpFile):
	commands = [
	"cp " + networkFile + " /etc/network/interfaces",
	"cp " + forwardingFile + " /etc/network/iptables_forwarding",
	"cp " + dhcpFile + " /etc/dnsmasq/dnsmasq.conf"
	]

	for f in apFiles:
		commands.append("cp " + f + " /etc/hostapd/" + f)

	commands.append("service network restart")

	for command in commands:
		if DEBUG:
			print(command)
		else:
			subprocess.call(command, shell=True)

def main():
	(secureInterfaces, untrustedGateway) = readConfig()

	networkFile = createNetworkFile(secureInterfaces, untrustedGateway)
	forwardingFile = createForwardingFile(secureInterfaces, untrustedGateway)
	apFiles = createAccessPointConfig(secureInterfaces, untrustedGateway)
	dhcpFile = createDHCPServerConfig(secureInterfaces, untrustedGateway)

	activate(networkFile, forwardingFile, apFiles, dhcpFile)

if __name__ == '__main__':
	main()