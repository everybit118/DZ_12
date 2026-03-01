import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt

DUMP_FILE = "var-1.vmem"

VOL_CMD = "vol"

PLUGIN_PROCESSES = "windows.pslist"
PLUGIN_NETWORK = "windows.netstat"

CSV_PROCESSES = "processes.csv"
CHART_FILE = "connections.png"


def run_volatility(plugin):
    print(f"[*] Запуск плагина: {plugin}...")
    try:
        command = [VOL_CMD, "-r", "json", "-f",  DUMP_FILE, plugin]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка выполнения volatility: {e}")
        print(e.stderr)
        return None
    except json.JSONDecodeError:
        print("Ошибка парсинга JSON ответа volatility.")
        return None


def save_to_csv(data, filename):
    if not data:
        print(f"Нет данных для сохранения в {filename}")
        return
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False, encoding='utf-8-sig')


def visualize_ip_conns(data, outfile):
    if not data:
        print("Нет данных для визуализации")
        return None

    df = pd.DataFrame(data)

    plt.figure(figsize=(10, 6))
    proc_counts = pd.concat([df['LocalAddr'], df['ForeignAddr']], ignore_index=True).value_counts().head(15)

    plt.bar(proc_counts.index, proc_counts.values)
    plt.title('Распределение IP по соединениям (Топ-15)')
    plt.xlabel('IP')
    plt.ylabel('Количество')
    plt.xticks(rotation=90)
    # plt.show()
    plt.savefig(outfile, dpi=300, bbox_inches='tight')
    plt.close()


def main():
    raw_procs = run_volatility(PLUGIN_PROCESSES)
    save_to_csv(raw_procs, CSV_PROCESSES)

    raw_net = run_volatility(PLUGIN_NETWORK)
    visualize_ip_conns(raw_net, CHART_FILE)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        raise e
