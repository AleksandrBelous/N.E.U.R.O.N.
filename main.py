import getopt, sys


def get_help():
    print("Usage: main.py [options]{1,}")


def main():
    arguments_lst = sys.argv[1:]
    options = "hmo:"
    long_options = ["help", "My_file", "Output="]
    try:
        args, vals = getopt.getopt(arguments_lst, options, long_options)
        for arg, val in args:
            if arg in ("-h", "--help"):
                get_help()
            elif arg in ("-m", "--my_file"):
                print("Displaying file_name:", sys.argv[0])
            elif arg in ("-o", "--output"):
                print("Enabling special output mode (% s)" % val)
    except getopt.error as err:
        print(str(err))


if __name__ == '__main__':
    main()
