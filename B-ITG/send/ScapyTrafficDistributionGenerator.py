# %%
# !/usr/bin/env python3
import argparse
import time
import os
from rich import print
import numpy as np
import scipy.special as sp
from scipy.stats import gaussian_kde
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sendp, send
from scapy.layers.inet import Ether, IP, TCP, getmacbyip
from scapy.config import conf

np.random.seed(60)


# %%
# Функция генерации массива (число пакетов в секунду) по выбранному распределению
def generate_distribution(
        dist: str = 'constant',
        median: int = 1000,
        num_seconds: int = 10,
        seed: int = 60,
        params: dict = None
        ) -> np.ndarray:
    if params is None:
        params = dict()
    np.random.seed(seed)
    try:
        if dist == "constant":
            # Для constant просто заполняем массив значением, по умолчанию 1000 п/с.
            value = float(params.get("value", median))
            distribution = np.full(num_seconds, value)

        elif dist == "uniform":
            # Равномерное распределение с нижней и верхней границей.
            # Значения по умолчанию: low=800, high=1200 для среднего около 1000.
            low = float(params.get("low", median * 0.5))
            high = float(params.get("high", median * 1.5))
            distribution = np.random.uniform(low, high, num_seconds)

        elif dist == "exponential":
            # Экспоненциальное распределение с параметром scale.
            # По умолчанию scale=1000, что задаёт среднее значение 1000.
            scale = float(params.get("scale", median))
            distribution = np.random.exponential(scale, num_seconds)

        elif dist == "normal":
            # Нормальное распределение с параметрами mean и std.
            mean = float(params.get("mean", median))
            std = float(params.get("std", median * 0.1))
            distribution = np.random.normal(mean, std, num_seconds)
            # Исключаем отрицательные значения.
            distribution = np.clip(distribution, 0, None)

        elif dist == "pareto":
            # Распределение Парето.
            # Формула для среднего: mean = (a * xm) / (a - 1), a > 1.
            # Выбираем xm так, чтобы получить среднее ≈ 1000.
            alpha = float(params.get("a", 3))
            xm = 1000 * (alpha - 1) / alpha
            distribution = (np.random.pareto(alpha, num_seconds) + 1) * xm

        elif dist == "poisson":
            # Распределение Пуассона с параметром lambda по умолчанию равным 1000.
            weibull_scale = float(params.get("lambda", median))
            distribution = np.random.poisson(weibull_scale, num_seconds)

        elif dist in ["cauchy", "caushy"]:
            # Распределение Коши. Поскольку математическое ожидание не определено,
            # используем сдвиг и масштаб (по умолчанию loc=1000, scale=100)
            loc = float(params.get("loc", median))
            scale = float(params.get("scale", median * 0.1))
            distribution = np.random.standard_cauchy(num_seconds) * scale + loc
            # Ограничиваем выбросы, чтобы избежать слишком экстремальных значений.
            # distribution = np.clip(distribution, 0, 5000)
            # Убираем отрицательные значения, оставляя большие без ограничения.
            distribution = np.clip(distribution, 0, None)

        elif dist == "gamma":
            # Гамма-распределение: mean = k * theta.
            # По умолчанию k=10, theta=100, что даёт среднее 1000.
            k = float(params.get("k", 5))
            theta = float(params.get("theta", 100))
            distribution = np.random.gamma(k, theta, num_seconds)

        elif dist == "weibull":
            # Распределение Вейбулла. Среднее равно weibull_scale * Gamma(1 + 1/alpha).
            # По умолчанию alpha=1.5, weibull_scale вычисляем так, чтобы среднее ≈ 1000.
            alpha = float(params.get("alpha", 1.5))
            gamma_val = sp.gamma(1 + 1 / alpha)
            weibull_scale = float(params.get("lam", 1000 / gamma_val))
            distribution = np.random.weibull(alpha, num_seconds) * weibull_scale

        else:
            raise ValueError("Unsupported distribution type")

        # Округляем до целых чисел (число пакетов в секунду) и возвращаем
        distribution = np.rint(distribution).astype(int)
        return distribution

    except (ValueError, Exception) as e:
        print(f"Exception occurred: {e}")
        return np.zeros(num_seconds)


# %%
# Функция для построения графика распределения
def plot_traffic_history(dist_array, distribution_name):
    plt.figure(figsize=(10, 6))
    plt.plot(dist_array, marker="o", linestyle="-", markersize=2)
    plt.title(f"Распределение количества пакетов в секунду: {distribution_name}")
    plt.xlabel("Время (секунды)")
    plt.ylabel("Пакетов в секунду")
    plt.grid(True)
    plt.show()


# Функция построения гистограммы распределения (с KDE-огибающей) с использованием seaborn
def plot_distribution_histogram(dist_array, distribution_name):
    # plt.figure(figsize=(10, 6))
    # Можно задать количество бинов вручную. Здесь мы используем 50 бинов, равномерно распределённых от минимума до максимума.
    bins = np.linspace(dist_array.min() - 1, dist_array.max() + 1, 50)
    # ax = sns.histplot(
    #     dist_array, bins=bins, kde=True, color="skyblue", edgecolor="black"
    # )
    # ax.set_title(
    #     f"Гистограмма распределения пакетов в секунду: {distribution_name}\nсреднее ≈ {np.mean(dist_array):.2f})"
    # )
    # ax.set_xlabel("Пакетов в секунду")
    # ax.set_ylabel("Количество секунд")
    # plt.show()
    plt.figure(figsize=(8, 6))
    sns.histplot(dist_array, bins=bins, kde=True, color="skyblue", edgecolor="black")
    plt.title(
            f"{distribution_name} распределение (среднее ≈ {np.mean(dist_array):.2f})"
            )
    plt.xlabel("Пакетов/сек")
    plt.ylabel("Число таких секунд")
    plt.tight_layout()
    plt.show()


def plot_density(dist_array, distribution_name):
    density = gaussian_kde(dist_array)
    xs = np.linspace(dist_array.min() - 1, dist_array.max() + 1, 200)

    plt.figure(figsize=(8, 6))
    plt.plot(xs, density(xs), color='skyblue')
    plt.title(f"{distribution_name} распределение (плотность, среднее ≈ {np.mean(dist_array):.2f})")
    plt.xlabel("Пакетов/сек")
    plt.ylabel("Плотность")
    plt.tight_layout()
    plt.show()


def plot_ecdf(dist_array, distribution_name):
    sorted_values = np.sort(dist_array)
    # Для ECDF ось y – равномерно от 0 до 1
    ecdf = np.arange(1, len(sorted_values) + 1) / len(sorted_values)

    plt.figure(figsize=(8, 6))
    plt.plot(sorted_values, ecdf, marker='.', linestyle='none')
    plt.title(f"{distribution_name} распределение (ECDF, среднее ≈ {np.mean(dist_array):.2f})")
    plt.xlabel("Пакетов/сек")
    plt.ylabel("Доля наблюдений")
    plt.tight_layout()
    plt.show()


# %%
# Функция отправки TCP-пакетов по заданному количеству в секунду
def send_packets(dst_ip, dst_port, dist_array, iface="eth0"):
    # Получение MAC-адреса назначения
    dst_mac = getmacbyip(dst_ip)
    print(f"dst_mac = {dst_mac}")
    if dst_mac is None:
        print(f"Не удалось получить MAC-адрес для IP {dst_ip}.")
    else:
        # Создание сокета
        s = conf.L2socket(iface=iface)
        # Формирование базового пакета с Ethernet, IP и TCP слоями
        base_packet = Ether(dst=dst_mac) / IP(dst=dst_ip) / TCP(dport=dst_port)
        for sec, packets in enumerate(dist_array):
            start_time = time.time()
            # print(f"Секунда {sec+1}: отправка {packets} пакетов")
            # Отправляем требуемое количество пакетов в эту секунду
            for _ in range(packets):
                s.send(base_packet)
            # Ждём до окончания текущей секунды
            elapsed = time.time() - start_time
            # print(f"Finished send at {elapsed:.6f} seconds")
            if elapsed < 1:
                time.sleep(1 - elapsed)
        s.close()


# %%
# Парсинг параметров распределения, переданных в виде строки key=value,...
def parse_distribution_params(params_str):
    params = { }
    if params_str:
        for item in params_str.split(","):
            key, value = item.split("=")
            params[key.strip()] = value.strip()
    return params


# %%
def main():
    parser = argparse.ArgumentParser(
            description="Генератор TCP-трафика с использованием Scapy и различных распределений (по умолчанию 10 минут)"
            )
    # Делаем позиционные аргументы опциональными с дефолтными значениями
    parser.add_argument(
            "dst_ip",
            nargs="?",
            default="127.0.0.1",
            help="IP-адрес получателя (по умолчанию 127.0.0.1)",
            )
    parser.add_argument(
            "dst_port",
            nargs="?",
            type=int,
            default=22,
            help="TCP-порт получателя (по умолчанию 22)",
            )
    parser.add_argument(
            "-d",
            "--duration",
            type=int,
            default=600,
            help="Продолжительность отправки в секундах (по умолчанию 600 секунд = 10 минут)",
            )
    parser.add_argument(
            "-t",
            "--type",
            choices=[
                    "constant",
                    "uniform",
                    "exponential",
                    "normal",
                    "pareto",
                    "poisson",
                    "cauchy",
                    "gamma",
                    "weibull",
                    ],
            default="constant",
            help="Тип распределения (по умолчанию constant)",
            )
    # Для constant по умолчанию используем value=1000
    parser.add_argument(
            "-p",
            "--params",
            type=str,
            default="value=1000",
            help="Параметры распределения в формате key=value,key2=value2 (например: mean=1000,std=100). По умолчанию для constant: value=1000",
            )
    # Флаг для загрузки распределения из файла вместо генерации нового
    parser.add_argument(
            "-l",
            "--load",
            action="store_true",
            default="",
            help="Загрузить распределение из файла вместо генерации нового",
            )
    args = parser.parse_args()
    params = parse_distribution_params(args.params)
    filename = f"{args.type}.npy"
    filepath = os.path.join(os.getcwd(), 'numpy-arrays', filename)

    # Если указан флаг --load, пытаемся загрузить данные из файла
    if args.load:
        if os.path.exists(filepath):
            dist_array = np.load(filepath)
            print(f"Загружено распределение из файла {filepath}")
        else:
            print(
                    f"Ошибка: Файл {filepath} не найден. Запустите скрипт без флага --load для генерации распределения."
                    )
            exit(1)
    else:
        # Генерация массива значений (число пакетов в секунду) для каждой секунды
        dist_array = generate_distribution(args.type, args.duration, params)
        np.save(filepath, dist_array)
        print(f"Сгенерирован массив и сохранён в файл {filepath}")

    # params = parse_distribution_params(args.params)
    print(f"Используем распределение {args.type} с параметрами: {params}")

    # Построение гистограммы распределения с использованием seaborn
    plot_distribution_histogram(dist_array, args.type)

    # Отправка пакетов с заданным количеством в каждую секунду
    print(f"Отправка TCP-пакетов на {args.dst_ip}:{args.dst_port}")
    # send_packets(args.dst_ip, args.dst_port, dist_array)


# %%
if __name__ == "__main__":
    main()
