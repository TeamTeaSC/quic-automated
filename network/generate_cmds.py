import json

ROOT_TRAFFIC_RATE_LIMIT = 10000000.0  # 10 Gbps

def write_cmds(f, cmds: list[str]):
    for cmd in cmds:
        f.write(f'{cmd}\n')
    f.write('\n')

# Generates shell commands for provided network parameters.
# Both writes command to file and returns commands as list of strings.
def generate_cmds(config_file: str) -> list[str]:
    # Read JSON file containing network parameters
    with open(config_file) as f:
        d = json.load(f)
    
    network_configs: dict[str, int] = d.get('network')
    if network_configs is None:
        print("Error: network configs not provided, exiting.")
        return
    
    # Extract network parameters
    loss         : float = network_configs.get('loss')
    delay        : int   = network_configs.get('delay')
    bw           : int   = network_configs.get('bw')
    jitter       : int   = network_configs.get('jitter')
    burst_ingress: int   = network_configs.get('burst_ingress')
    burst_egress : int   = network_configs.get('burst_egress')
    
    # Generate commands for each parameter
    include_loss          = (loss != 0)
    include_delay         = (delay != 0)
    include_jitter        = (jitter != 0)
    include_burst_ingress = (burst_ingress != 0)
    include_burst_egress  = (burst_egress != 0)

    loss_str = ' loss {:.6f}%'.format(loss) if include_loss else ''
    delay_str = f' delay {delay//2}.0ms' if include_delay else ''
    bw_str = f'{bw}000.0Kbit'
    jitter_str = f' {jitter}.0ms' if include_jitter else ''
    burst_ingress_str = f' {burst_ingress}%' if include_burst_ingress else ''
    burst_egress_str = f' {burst_egress}%' if include_burst_egress else ''

    # Calculate bandwidth burst
    bw_burst = bw * 10**3 * 1.25
    bw_burst_str = '{:.1f}KB'.format(bw_burst)

    # Generate .sh file with Linux network commands
    jitter_file = f'-jitter-{jitter}' if include_jitter else ''
    burst_ingress_file = f'-burstingress-{burst_ingress}' if include_burst_ingress else ''
    burst_egress_file = f'-burstegress-{burst_egress}' if include_burst_egress else ''

    sh_file_name = (f'loss-{loss}-delay-{delay}-bw-{bw}'
                    f'{jitter_file}{burst_ingress_file}{burst_egress_file}.sh')
    sh_dir = './network'
    f = open(f'{sh_dir}/{sh_file_name}', 'w')

    # Delete existing configurations
    cmds = []
    # delete root qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 root')
    # delete ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 ingress') 
    # delete ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc del dev eth0 ingress') 
    # delete root qdisc on IFB
    cmds.append('/sbin/tc qdisc del dev ifb0 root')  
    # disable IFB interface    
    cmds.append('/usr/bin/ip link set dev ifb0 down')    
    # delete IFB interface
    cmds.append('/usr/bin/ip link delete ifb0 type ifb') 
    write_cmds(f, cmds)

    # Setup HTB (hierarchical token bucket) and netem on eth0 root
    cmds = []
    # add qdisc to eht0 root with handle 1a64: and classID 1
    cmds.append('/sbin/tc qdisc add dev eth0 root handle 1a64: htb default 1')
    # create HTB class 1a64:1
    cmds.append(('/sbin/tc class add dev eth0 parent 1a64: '
                 f'classid 1a64:1 htb rate {ROOT_TRAFFIC_RATE_LIMIT}kbit'))
    # create another HTB class 1a64:104 with provided bw
    cmds.append(('/sbin/tc class add dev eth0 parent 1a64: '
                f'classid 1a64:104 htb rate {bw_str} ceil {bw_str} '
                f'burst {bw_burst_str} cburst {bw_burst_str}'))
    # attach netem qdisc to HTB class 1a64:104 with provided loss, burst egress, delay, jitter
    cmds.append(('/sbin/tc qdisc add dev eth0 parent 1a64:104 handle 2054: '
                f'netem{loss_str}{burst_egress_str}{delay_str}{jitter_str}'))
    # add filter with priority 5, redirecting all traffic to 1a64:104
    cmds.append(('/sbin/tc filter add dev ens192 protocol ip parent 1a64: '
                 'prio 5 u32 match ip dst 0.0.0.0/0 match ip src 0.0.0.0/0 '
                 'flowid 1a64:104'))
    write_cmds(f, cmds)

    # Setup IFB for managing ingress traffic
    cmds = []
    # load IFB kernel module
    cmds.append('modprobe ifb')
    # create new IFB interface ifb0
    cmds.append('/usr/bin/ip link add ifb0 type ifb')
    # enable IFB interface
    cmds.append('/usr/bin/ip link set dev ifb0 up')
    # add ingress qdisc on eth0
    cmds.append('/sbin/tc qdisc add dev eth0 ingress')
    # redirects all ingress traffic to IFB
    cmds.append(('/sbin/tc filter add dev ens192 parent ffff: '
                 'protocol ip u32 match u32 0 0 flowid 1a64: '
                 'action mirred egress redirect dev ifb0'))
    write_cmds(f, cmds)

    # Setup HTB and netem on IFB
    cmds = []
    # add qdisc to IFB root with handle 1a64: and classID 1
    cmds.append('/sbin/tc qdisc add dev ifb0 root handle 1a64: htb default 1')
    # create HTB class 1a64:1 
    cmds.append(('/sbin/tc class add dev ifb0 parent 1a64: '
                f'classid 1a64:1 htb rate {ROOT_TRAFFIC_RATE_LIMIT}kbit'))
    # create another HTB class 1a64:104 with provided bw
    cmds.append(('/sbin/tc class add dev ifb0 parent 1a64: '
                 f'classid 1a64:104 htb rate {bw_str} ceil {bw_str} '
                 f'burst {bw_burst_str} cburst {bw_burst_str}'))
    # attach netem qdisc to HTB class 1a64:104 with provided loss, burst ingress
    cmds.append(('/sbin/tc qdisc add dev ifb0 parent 1a64:104 handle 2054: '
                f'netem{loss_str}{burst_ingress_str}'))
    # redirects all ingress traffic to IFB to 1a64:104
    cmds.append(('/sbin/tc filter add dev ifb0 protocol ip parent 1a64: '
                 'prio 5 u32 match ip dst 0.0.0.0/0 match ip src 0.0.0.0/0 '
                 'flowid 1a64:104'))
    write_cmds(f, cmds)

    return cmds
    
# test
# generate_cmds('./param.json')
