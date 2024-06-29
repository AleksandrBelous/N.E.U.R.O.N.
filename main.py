from sys import argv
from getopt import getopt, error
from subprocess import run


def get_help():
    print(
            "Usage: main.py [options]\n"
            "    -h, --help : Print this help summary page\n"
            "    -s, --sniffer : Flag to create the sniffer[s], any of model 0, 1 or 2\n"
            "    -i, --iface : Set the physical interphase\n"
            "    -v, --virtual : Flag to create virtual interphase[s] and name[s]\n"
            "    -f, --_filter : Set the _filter[s] for _packets\n"
            "    -c, --_count : Set the number of _packets to sniff on interphase[s]\n"
            "    -p, --pcap : Set the .pcap file[s] name to save sniffed _packets\n"
            "    -m, --model : Flag to create the model[s]\n"
            "    -n, --name : Set the name for:\n"
            "                                  - NN model[s]'s save-file[s] name[s]\n"
            "                                  !- virtual interphase[s] name[s]\n"
            "ATTENTION\n"
            "    Only -s or -v at one command, not both !!!\n"
            "EXAMPLES\n"
            "    sudo python3 main.py -s 0 -i 'enp0s7' -f 'tcp and ip' -c 10\n"
            "    sudo python3 main.py -v 'v1,v2,v3' -i 'enp0s7' -f 'tcp and ip,icmp,arp' -c 10,20,30\n"
            )
    exit(0)


def create_sniffer(args: list):
    command = ['sudo', 'python3', 'sniffer.py']
    # print(args)
    for arg, val in args:
        if arg in ('-s', '--sniffer', '-i', '--iface', '-f', '--_filter', '-c', '--_count', '-p', '--pcap'):
            command.append(arg)
            command.append(val)
    run(command)


def create_sniffers():
    ...


def create_model(args: list):
    ...


def main():
    arguments_lst = argv[1:]
    if not arguments_lst:
        get_help()
    try:
        options = "hs:v:i:f:c:p:m:n:"
        long_options = ['help', 'sniffer=', 'virtual=', 'iface=', '_filter=', '_count=', 'pcap=', 'model=', 'name=']
        args, _ = getopt(arguments_lst, options, long_options)
        print(f'args are {args}')
        for arg, val in args:
            print(arg, val)
            if arg in ('-h', '--help'):
                get_help()
            elif arg in ('-s', '--sniffer'):
                create_sniffer(args)
            elif arg in ('-m', '--model'):
                create_model(args)
    except error as err:
        print(str(err))


if __name__ == '__main__':
    main()
