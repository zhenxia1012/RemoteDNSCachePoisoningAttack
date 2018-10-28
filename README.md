# RemoteDNSCachePoisoningAttack
Remote DNS Cache Poisoning Attack targets the cache of local DNS server and is based on a famous attack called Kaminsky Attack.

## Main Jobs
* Configured attacker machine, user machine, local DNS server Apollo by BIND 9 software.
* Developed a program performing Kaminsky Attack which repeatedly queried the DNS Server for random non-existing name in example.com zone, then flooding the local DNS server with spoofed malicious DNS response.
* Designed a monitor that repeatedly checked the cache of DNS server and stopped the attack when succeed in poisoning the cache.
* Verified the success of Remote DNS Cache Poisoning Attack on user machine.

## DNS Cache Poisoning Attack
Usually, when we ask local DNS server for IP of the host name, such as “www.example.com”, the DNS server would look up its cache at first. If it doesn’t have the answer in its cache, it would ask root server or other DNS server for the answer.
The attack targeted the cache of local DNS server. When local DNS server ask other DNS server for the IP of “www.example.com”, I spoofed the DNS response from other DNS server. If the response arrived at DNS server faster than from real DNS server, local DNS server would keep the spoofed response in its cache for certain period of time. Next time, when a user’s machine wants to resolve the same host name, local DNS server will use the spoofed response in the cache to reply. 
And, this attack would affect a bunch of machines which are in same network and share the same local DNS server.

## Kaminsky Attack
* The attacker queries the DNS Server Apollo for a non-existing name in example.com, such as “twysw.example.com”, where “twysw” is a random name.
* Since the mapping is unavailable in Apollo’s DNS cache, Apollo sends a DNS query to the name server of the example.com domain.
* While Apollo waits for the reply, the attacker floods Apollo with a stream of spoofed DNS response, each trying a different transaction ID, hoping one is correct. In the response, not only does the attacker provide an IP resolution for “twysw.example.com”, the attacker also provides an “Authoritative Nameservers” record, indicating ns.dnslabattacker.net as the name server for the example.com domain. If the spoofed response beats the actual responses and the transaction ID matches with that in the query, Apollo will accept and cache the spoofed answer, and and thus Apollo’s DNS cache is poisoned.
* Even if the spoofed DNS response fails (e.g. the transaction ID does not match or it comes too late), it does not matter, because the next time, the attacker will query a different name, so Apollo has to send out another query, giving the attack another chance to do the spoofing attack. This effectively defeats the caching effect.
* If the attack succeeds, in Apollo’s DNS cache, the name server for example.com will be replaced by the attacker’s name server ns.dnslabattacker.net. To demonstrate the success of this attack, students need to show that such a record is in Apollo’s DNS cache.




