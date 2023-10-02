#!/bin/bash

# Set config
PREFIXES=(
  # interconnecting network
  '192.168.240.0/24'
  # external networks
  # ...
)

WEBHOOKS_IFACE="webhooks-net"

# delete permit any
/usr/sbin/iptables -C DOCKER-USER -j RETURN 2> /dev/null
if [[ $? -eq 0 ]]
  then /usr/sbin/iptables -D DOCKER-USER -j RETURN
fi

# drop any
/usr/sbin/iptables -C DOCKER-USER -o "$WEBHOOKS_IFACE" -j DROP 2> /dev/null
if [[ $? -eq 1 ]]
  then /usr/sbin/iptables -A DOCKER-USER -o "$WEBHOOKS_IFACE" -j DROP
fi

# permit home PREFIXES
for prefix in "${PREFIXES[@]}"; do
 /usr/sbin/iptables -C DOCKER-USER -s "$prefix" -o "$WEBHOOKS_IFACE" -j RETURN 2> /dev/null
 if [[ $? -eq 1 ]]
  then /usr/sbin/iptables -I DOCKER-USER -s "$prefix" -o "$WEBHOOKS_IFACE" -j RETURN
 fi
done

# permit related,established
/usr/sbin/iptables -C DOCKER-USER -o "$WEBHOOKS_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2> /dev/null
if [[ $? -eq 1 ]]
  then /usr/sbin/iptables -I DOCKER-USER -o "$WEBHOOKS_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

exit 0