#!/bin/python3

if __name__ == '__main__':
    m = input('    1 - Start sniffing, require sudo\n'
              '    2 - Start NN\n'
              '>>> '
              )
    if m == '1':
        import DataPrep

        mm = input('    1 - Sniffing in detection mode\n'
                   '    2 - Sniffing for training in normal mode\n'
                   '    3 - Sniffing for training in attack mode\n'
                   '    4 - Catch ans save local traffic\n'
                   '>>> '
                   )
        if mm == '1':
            sn = DataPrep.DataPrep()
            sn.num_pkts_to_sniff = int(input('>>> number packets to catch: '))
            is_v = input('verbose mode? [y/N]')
            is_v = True if is_v == 'y' else False
            while True:
                sn.detecting_mode(is_v)
        if mm == '2' or mm == '3':
            sn_nn = DataPrep.DataPrep()
            sn_nn.num_pkts_to_sniff = int(input('>>> number packets to catch: '))
            is_v = input('verbose mode? [y/N]')
            is_v = True if is_v == 'y' else False
            while True:
                sn_nn.train_mode(is_v)
        if mm == '4':
            sn = DataPrep.DataPrep()
            num = int(input('>>> number packets to catch: '))
            sn.create_pcap_from_net(num)
    if m == '2':
        import NN

        model_name = 'my_model.h5'

        mm = input('    1 - Start pre-training\n'
                   '    2 - Start updating model\n'
                   '    3 - Start predict traffic\n'
                   '>>> '
                   )
        if mm == '1':
            nn = NN.NN()
            nn.model_name = model_name
            nn.epochs = 10
            nn.batch_size = 32
            nn.start_pre_train()
        if mm == '2':
            nn = NN.NN()
            nn.model_name = model_name
            nn.epochs = 10
            nn.batch_size = 32
            while True:
                X, y = nn.get_single_dataset('Xy.txt')
                nn.update_model(X, y)
        if mm == '3':
            nn = NN.NN()
            nn.model_name = model_name
            nn.load_model()
            nn.epochs = 10
            nn.batch_size = 32
            while True:
                single = nn.get_detected('detected.txt')
                print(nn.prediction_to_STDOUT(single))
