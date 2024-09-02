import json
import glob
import argparse
import re
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import seaborn as sns

# Apply the default theme
sns.set_theme()

def parse_path(path):
    match = re.search(r"smoke-(\w+)-(\d+)B.json", path)
    proxy = match.group(1)
    size = match.group(2)

    return proxy, int(size)


def line_graph(paths, metric, agg):
    xticks = list(set(parse_path(p)[1] for p in paths))
    envoy_paths = [p for p in paths if "envoy" in p]
    ebpf_paths = [p for p in paths if "ebpf" in p]

    paths = [envoy_paths, ebpf_paths]

    fig, ax = plt.subplots()
    for ps in paths:
        ps.sort(key=lambda p: parse_path(p)[1])
        ys = []
        xs = []
        proxy = None

        for p in ps:
            with open(p, "r") as file:
                data = json.load(file)
                ys.append(data["metrics"][metric][agg])

                proxy, size = parse_path(p)
                xs.append(size)
        
        print(ys)
        plt.plot(xs, ys, label=proxy)            
    
    plt.title(f"{metric} {agg}")
    plt.xlabel("payload size [B]")
    plt.xticks(xticks)
    plt.ylabel("time [ms]")
    plt.yscale("log")
    plt.yticks([25, 50, 75, 100, 125, 150])
    ax.yaxis.set_major_formatter(ticker.ScalarFormatter())
    plt.legend()
    plt.savefig(f"res/smoke-{metric}.pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--metric", required=True, help="The recorded metric to visualize")
    parser.add_argument("-a", "--agg", default="p(95)", help="The aggregation method")
    args = parser.parse_args()

    files = glob.glob("res/smoke-*.json")

    line_graph(files, args.metric, args.agg)