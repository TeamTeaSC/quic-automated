import json

ROOT_TRAFFIC_RATE_LIMIT = 10000000.0  # 10 Gbps

def write_cmds(f, cmds: list[str]):
    for cmd in cmds:
        f.write(f'{cmd}\n')
    f.write('\n')

def generate_cmds(config_file: str):
    # Read JSON file containing network parameters
    with open(config_file) as f:
        d = json.load(f)
    
    network_configs: dict[str, int] = d.get('network')
    if network_configs is None:
        print("Error: network configs not provided, exiting.")
        return
    
    loss: int = network_configs.get('loss')
    delay: int = network_configs.get('delay')
    bw: int = network_configs.get('bw')

    includeLoss  = (loss != 0)
    includeDelay = (delay != 0)
    

    loss_str =  f'{loss}.000000%'
    delay_str = f'{delay//2}.0ms'
    bw_str =    f'{bw}000.0Kbit'

    # Calculate bandwidth burst
    bw_burst = bw * 10**3 * 1.25
    bw_burst_str = '{:.1f}KB'.format(bw_burst)

    # Generate .sh file with Linux network commands
    sh_file_name = f'loss-{loss}-delay-{delay}-bw-{bw}.sh'
    f = open(sh_file_name, 'w')

    # Delete existing configurations
    cmds = []
    # delete root qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 root')
    # delete ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 ingress') 
    # delete ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 ingress') 
    # delete root qdisc on IFB
    cmds.append('/sbin/tc qdisc del dev ifb6756 root')  
    # disable IFB interface    
    cmds.append('/usr/bin/ip link set dev ifb6756 down')    
    # delete IFB interface
    cmds.append('/usr/bin/ip link delete ifb6756 type ifb') 
    write_cmds(f, cmds)

    # Setup HTB (hierarchical token bucket) and netem on eth0 root
    cmds = []
    # add qdisc to eht0 root with handle 1a64: and classID 1
    cmds.append('/sbin/tc qdisc add dev eth0 root handle 1a64: htb default 1')
    # create HTB class 1a64:1
    cmds.append(('/sbin/tc class add dev eth0 parent 1a64: '
                 'classid 1a64:1 htb rate {ROOT_TRAFFIC_RATE_LIMIT}kbit'))
    # create another HTB class 1a64:104 with provided bw
    cmds.append(('/sbin/tc class add dev eth0 parent 1a64: '
                f'classid 1a64:104 htb rate {bw_str} ceil {bw_str} '
                f'burst {bw_burst_str} cburst {bw_burst_str}'))
    # attach netem qdisc to HTB class 1a64:104 with provided loss and delay
    cmds.append(('/sbin/tc qdisc add dev eth0 parent 1a64:104 handle 2054: '
                f'netem loss {loss_str} delay {delay_str}'))
    # add filter with priority 5, redirecting all traffic to 1a64:104
    cmds.append(('/sbin/tc filter add dev ens192 protocol ip parent 1a64: '
                 'prio 5 u32 match ip dst 0.0.0.0/0 match ip src 0.0.0.0/0 '
                 'flowid 1a64:104'))
    write_cmds(f, cmds)

    # Setup IFB for managing ingress traffic
    cmds = []
    # load IFB kernel module
    cmds.append('modprobe ifb')
    # create new IFB interface ifb6756
    cmds.append('/usr/bin/ip link add ifb6756 type ifb')
    # enable IFB interface
    cmds.append('/usr/bin/ip link set dev ifb6756 up')
    # add ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc add dev eth0 ingress')
    # redirects all ingress traffic to IFB
    cmds.append(('/sbin/tc filter add dev ens192 parent ffff: '
                 'protocol ip u32 match u32 0 0 flowid 1a64: '
                 'action mirred egress redirect dev ifb6756'))
    write_cmds(f, cmds)

    # Setup HTB and netem on IFB
    cmds = []
    # add qdisc to IFB root with handle 1a64: and classID 1
    cmds.append('/sbin/tc qdisc add dev ifb6756 root handle 1a64: htb default 1')
    # create HTB class 1a64:1 
    cmds.append(('/sbin/tc class add dev ifb6756 parent 1a64: '
                f'classid 1a64:1 htb rate {ROOT_TRAFFIC_RATE_LIMIT}kbit'))
    # create another HTB class 1a64:104 with provided bw
    cmds.append(('/sbin/tc class add dev ifb6756 parent 1a64: '
                 f'classid 1a64:104 htb rate {bw_str} ceil {bw_str} '
                 f'burst {bw_burst_str} cburst {bw_burst_str}'))
    # attach netem qdisc to HTB class 1a64:104 with provided loss and delay
    cmds.append(('/sbin/tc qdisc add dev ifb6756 parent 1a64:104 handle 2054: '
                f'netem loss {loss_str} delay {delay_str}'))
    # redirects all ingress traffic to IFB to 1a64:104
    cmds.append(('/sbin/tc filter add dev ifb6756 protocol ip parent 1a64: '
                 'prio 5 u32 match ip dst 0.0.0.0/0 match ip src 0.0.0.0/0 '
                 'flowid 1a64:104'))
    write_cmds(f, cmds)
    
# test
generate_cmds('./network/param.json')