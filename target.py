import ipaddress

def expand_targets(itens):
    targets = []
    for t in itens:
        try:
            net = ipaddress.ip_network(t, strict=False)
            targets.extend(str(ip) for ip in net.hosts())
        except ValueError:
            targets.append(t)
    return targets