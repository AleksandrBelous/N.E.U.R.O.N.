import os
import numpy as np
import scapy.all as scapy
import scipy.stats as stats
import matplotlib.pyplot as plt

# Поддерживаемые распределения и их параметры для подгонки
distributions = {
        "Constant"   : None,  # Для постоянного значения проверка не требуется
        "Uniform"    : stats.uniform,
        "Exponential": stats.expon,
        "Normal"     : stats.norm,
        "Poisson"    : stats.poisson,
        "Pareto"     : stats.pareto,
        "Cauchy"     : stats.cauchy,
        "Gamma"      : stats.gamma,
        "Weibull"    : stats.weibull_min,
        }


def plot_best_fit(data, results, title):
    best_fit = min((r for r in results.values() if isinstance(r.get("error"), (int, float))), key=lambda x: x["error"])
    best_dist_name = [name for name, result in results.items() if result == best_fit][0]

    # Построение графика
    plt.hist(data, bins=30, density=True, alpha=0.6, color="gray", label="Data")

    if best_dist_name != "Constant":
        dist = distributions[best_dist_name]
        params = best_fit["params"]
        x = np.linspace(min(data), max(data), 1000)
        y = dist.pdf(x, *params)
        plt.plot(x, y, label=f"Best Fit: {best_dist_name}")

    plt.title(f"{title} - Best Fit: {best_dist_name}")
    plt.legend()
    plt.show()


def analyze_distribution(data, title):
    results = { }

    for dist_name, dist in distributions.items():
        if dist_name == "Constant":
            # Проверка на постоянное значение
            if np.allclose(data, data[0]):
                results[dist_name] = { "param": data[0], "error": 0 }
        else:
            try:
                # Оценка параметров распределения
                params = dist.fit(data)

                # Вычисление ошибки (метрика: среднеквадратичное отклонение)
                fitted_data = dist.pdf(data, *params)
                error = np.sum((fitted_data - np.histogram(data, bins=30, density=True)[0]) ** 2)

                results[dist_name] = { "params": params, "error": error }
            except Exception as e:
                results[dist_name] = { "error": str(e) }

    # Визуализация данных и лучшего распределения
    plot_best_fit(data, results, title)
    return results


def analyze_pcap(pcap_file):
    packets = scapy.rdpcap(pcap_file)

    # Извлечение времен пакетов
    timestamps = np.array([pkt.time for pkt in packets])
    inter_arrival_times = np.diff(timestamps)

    # Извлечение длин пакетов
    packet_lengths = np.array([len(pkt) for pkt in packets])

    results = {
            "inter_arrival_times": analyze_distribution(inter_arrival_times, "Inter-Arrival Times"),
            "packet_lengths"     : analyze_distribution(packet_lengths, "Packet Lengths"),
            }

    return results


# Пример использования
if __name__ == "__main__":
    # pcap_path = os.path.join(os.getcwd(), "pcaps", "exponential", "exponential-anomal-15-min.pcap")
    pcap_path = ""
    results = analyze_pcap(pcap_path)

    for metric, result in results.items():
        print(f"\nAnalysis for {metric}:")
        for dist_name, dist_result in result.items():
            print(f"  {dist_name}: {dist_result}")
