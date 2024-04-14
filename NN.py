import tensorflow as tf
import pandas as pd
import os
from sklearn.model_selection import train_test_split


class CustomClassifier(tf.keras.Model):
    def __init__(self):
        super(CustomClassifier, self).__init__()
        self.dense1 = tf.keras.layers.Dense(64, activation=tf.nn.relu)
        self.dense2 = tf.keras.layers.Dense(32, activation=tf.nn.relu)
        self.dense3 = tf.keras.layers.Dense(1, activation=tf.nn.sigmoid)

    def call(self, inputs):
        x = self.dense1(inputs)
        x = self.dense2(x)
        output = self.dense3(x)
        return output


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
        self.model = None

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
        self.model = CustomClassifier()
        learning_rate = 1 * 1e-3
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate),
                           loss=tf.keras.losses.binary_crossentropy,
                           metrics=[tf.keras.metrics.binary_accuracy]
                           )

        self.model.fit(self.X_train, self.y_train, epochs=10, batch_size=32, validation_data=(self.X_val, self.y_val))
        test_loss, test_acc = self.model.evaluate(self.X_test, self.y_test)
        print('\nTest accuracy:', test_acc)

    def train_model(self):
        self.model = CustomClassifier()
        learning_rate = 1 * 1e-3
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate),
                           loss=tf.keras.losses.binary_crossentropy,
                           metrics=[tf.keras.metrics.binary_accuracy]
                           )

        self.model.fit(self.X_train, self.y_train, epochs=10, batch_size=32)
        test_loss, test_acc = self.model.evaluate(self.X_other, self.y_other)
        print('\nTest accuracy:', test_acc)

    def save_model(self, file_name):
        self.model.save(file_name)

    def load_model(self, file_name):
        self.model = tf.keras.models.load_model(file_name)


if __name__ == '__main__':
    n = NN()
    n.get_X_y()
    n.get_train_val_test_data()
    n.train_model_with_val()
    n.train_model()
    model_name = 'my_model.h5'
    n.save_model(model_name)
    n.load_model(model_name)
