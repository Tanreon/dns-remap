Before use run command below:<br><br>
1. Create new chain <pre>$ iptables -t nat -N dnsmap</pre><br>
2. Enable chain <pre>$ iptables -t nat -A PREROUTING -d <strong>%REMAP_SUBNET%</strong> -j dnsmap</pre>