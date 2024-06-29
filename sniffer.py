from getopt import getopt, error
from sys import argv

import Sniffers


def main():
    arguments_lst = argv[1:]
    print('>>>', arguments_lst)
    try:
        options = "s:i:f:c:"
        long_options = ['sniffer=', 'iface=', '_filter=', '_count=']
        args, vals = getopt(arguments_lst, options, long_options)
        print(args)
        sniffer = None
        for arg, val in args:
            print(f'{arg}, {val}, {type(sniffer)}')
            if arg in ('-s', '--sniffer'):
                if val == '0':
                    sniffer = Sniffers.Sniffer()
                    # print(f'{arg}, {val}, {type(sniffer)}')
                elif val == '1':
                    ...
                elif val == '2':
                    ...
                print(f'{arg}, {val}, {type(sniffer)}')
            elif arg in ('-i', '--iface'):
                sniffer.set_iface(val)
            elif arg in ('-f', '--_filter'):
                sniffer.set_filter(val)
            elif arg in ('-c', '--_count'):
                sniffer.set_count(int(val))
        if sniffer:
            sniffer.check_params()
            sniffer.start()
            sniffer.show_packets()
    except error as err:
        print(str(err))


if __name__ == '__main__':
    main()
