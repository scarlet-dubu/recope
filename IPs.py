from ipaddress import *

class IPs:

# Simplifying IP address with CIDR block
    
    def __init__(self, string):

    # Contruct a IPNetwork from a string like 'a.b.c.d/e', 'a.b.c.d' or 'any'.
        try:
            if string.lower().rstrip() == "any":
                self.ipn = ip_network(u'0.0.0.0/0')
            elif string.lower().rstrip() == "any_ipv6":
                self.ipn = IPv6Network(u'::/0')
            else:
                ips = string.split("/")
                if len(ips) >= 2:
                    block = int(ips[1])
                    if ":" in ips[0]:  # Checking if it's an IPv6 address
                        self.ipn = IPv6Network(ips[0] + "/" + str(block))
                    else:
                        self.ipn = ip_network(ips[0] + "/" + str(block))
                else:
                    if ":" in ips[0]:  # Checking if it's an IPv6 address
                        self.ipn = IPv6Network(ips[0] + "/128")
                    else:
                        self.ipn = ip_network(ips[0] + "/32")

            
            

        except ValueError as e:

            print(f"Incorrect string due to {e}.")
    
    def contains(self, ip):
        #Check if the ip is correct, return True if it is

        return (ip in self.ipn)

    def __repr__(self):
        #Print out in String

        return self.ipn.__repr__()

# ip = IP("192.168.1.0/24")
# print(str(ip))

