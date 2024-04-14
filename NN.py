import tensorflow as tf
import pandas as pd
import os
from sklearn.model_selection import train_test_split


class NN:
    def __init__(self):
        self.X = None
        self.y = None
        self.X_train = None
        self.y_train = None
        self.X_other = None
        self.y_other = None
        self.X_val = None
        self.y_val = None
        self.X_test = None
        self.y_test = None
        self.model = tf.keras.Sequential([
                tf.keras.layers.Dense(10, activation=tf.nn.relu, input_shape=(10,)),
                # tf.keras.layers.Dense(32, activation=tf.nn.relu),
                tf.keras.layers.Dense(1, activation=tf.nn.sigmoid)
                ]
                )
        self.loaded_model = None
        self.model_name = 'model.h5'
        self.epochs = 10
        self.batch_size = 32

    def get_X_y(self):
        dfs = [pd.read_csv('csvs/' + file) for file in os.listdir('csvs/')]
        df = pd.concat(dfs)
        self.y = df['Label'].values
        self.X = df.drop(columns=['Label'])

    def get_train_val_test_data(self):
        self.X_train, self.X_other, self.y_train, self.y_other = train_test_split(self.X, self.y,
                                                                                  train_size=0.7,
                                                                                  random_state=42,
                                                                                  stratify=self.y
                                                                                  )
        self.X_test, self.X_val, self.y_test, self.y_val = train_test_split(self.X_other, self.y_other,
                                                                            test_size=0.5,
                                                                            random_state=42,
                                                                            stratify=self.y_other
                                                                            )

    def train_model_with_val(self):
        learning_rate = 1 * 1e-3
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate),
                           loss=tf.keras.losses.binary_crossentropy,
                           metrics=[tf.keras.metrics.binary_accuracy]
                           )

        self.model.fit(self.X_train, self.y_train, epochs=self.epochs, batch_size=self.batch_size,
                       validation_data=(self.X_val, self.y_val)
                       )
        test_loss, test_acc = self.model.evaluate(self.X_test, self.y_test)
        print('\nTest accuracy:', test_acc)

    def train_model(self):
        learning_rate = 1 * 1e-3
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate),
                           loss=tf.keras.losses.binary_crossentropy,
                           metrics=[tf.keras.metrics.binary_accuracy]
                           )

        self.model.fit(self.X_train, self.y_train, epochs=self.epochs, batch_size=self.batch_size)
        test_loss, test_acc = self.model.evaluate(self.X_other, self.y_other)
        print('\nTest accuracy:', test_acc)

    def get_single_dataset(self, file_name):
        with open(file_name, 'r') as f:
            df = f.readline().split(',')
            X, y = df[0:-1:], (int(df[-1]),)
            X = tuple(float(e) for e in X)
            return X, y

    def get_detected(self, file_name):
        with open(file_name, 'r') as f:
            df = f.readline().split(',')
            return tuple(float(e) for e in df)

    def update_model(self, X, y, epochs=10, batch_size=32):
        """
        update the pretrained model ('loaded_model' attribute) in real time
        :param X: list of network characteristics, shape=(N, 10) for N sniffed packets
        :param y: labels
        :param epochs: number of epochs
        :param batch_size: size of bathes
        :return: None, update the 'loaded_model' attribute
        """
        if self.loaded_model is None:
            self.load_model()
        pred = self.get_single_prediction(X)
        if pred == int(y[0]):
            learning_rate = 1 * 1e-3
            self.loaded_model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate),
                                      loss=tf.keras.losses.binary_crossentropy,
                                      metrics=[tf.keras.metrics.binary_accuracy]
                                      )
            self.loaded_model.fit([X], y, epochs=epochs, batch_size=batch_size)
            self.save_loaded_model()

    def save_model(self):
        self.model.save(self.model_name)

    def save_loaded_model(self):
        self.loaded_model.save(self.model_name)

    def load_model(self):
        self.loaded_model = tf.keras.models.load_model(self.model_name)

    def get_single_prediction(self, single):
        prediction = self.loaded_model.predict([single])
        threshold = 0.5
        return prediction >= threshold

    def prediction_to_STDOUT(self, single):
        if self.get_single_prediction(single):
            return 'Detected anomaly'
        else:
            return 'OK'

    def stress_test(self, file_name):
        with open(file_name, 'r') as f:
            d = f.readlines()
        for s in d[1::]:
            s = s.split(',')[0:-1:]
            s = [float(e) for e in s]
            print(self.prediction_to_STDOUT(s))

    def start_pre_train(self):
        self.get_X_y()
        self.get_train_val_test_data()
        self.train_model()
        self.save_model()


if __name__ == '__main__':
    n = NN()
    n.start_pre_train()
