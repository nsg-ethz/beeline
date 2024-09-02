import json
import glob
import argparse
import re
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import seaborn as sns
import pandas as pd

# Apply the default theme
sns.set_theme(style="whitegrid")

def parse_path(path):
    match = re.search(r"smoke-(\w+)-(\d+)B.json", path)
    proxy = match.group(1)
    size = match.group(2)

    return proxy, int(size)


def load_data(paths):
    rows = []
    for p in paths:
        proxy, payload_size = parse_path(p)
        with open(p, "r") as file:
            data = json.load(file)
            data = data["metrics"]

            for (metric, aggs) in data.items():
                rows.append({
                    "proxy": proxy,
                    "payload_size": payload_size,
                    "metric": metric,
                    **aggs
                })



    df = pd.DataFrame.from_dict(rows)
    df.set_index(["proxy", "payload_size", "metric"], inplace=True)

    return df


def line_graph(paths, metric, agg):
    df = load_data(paths)
    df = df.xs(metric, level="metric")
    # df = df[df.index.get_level_values("payload_size") < 4000]

    g = sns.lineplot(data=df, x="payload_size", y=agg, hue="proxy")
    
    g.set_title(f"{metric} {agg}")
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]")
    plt.yscale("log")
    plt.savefig(f"res/smoke-{metric}.pdf")           
    

def speedup_graph(paths, metric, aggs):
    df = load_data(paths)
    ebpf = df.xs("ebpf", level="proxy")
    envoy = df.xs("envoy", level="proxy")

    speedup = ebpf.copy()
    for agg in aggs:
        speedup[agg] = envoy[agg] / ebpf[agg]

    speedup = speedup.xs(metric, level="metric")
    speedup = speedup.drop("value", axis=1).reset_index()
    speedup = speedup.melt(id_vars=["payload_size"], value_vars=aggs)

    g = sns.catplot(
        data=speedup, kind="bar",
        x="payload_size", y="value", hue="variable",
        errorbar="sd", palette="dark", alpha=.6, height=6
    )

    g.set_titles(f"Speedup {metric}")
    g.set_axis_labels("payload size [B]", "speedup")
    g.despine(left=True)
    g.savefig(f"res/smoke-speedup-{metric}.pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    
    line = subparsers.add_parser("line")
    line.add_argument("-m", "--metric", required=True, help="The recorded metric to visualize")
    line.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

    speedup = subparsers.add_parser("speedup")
    speedup.add_argument("-m", "--metric", required=True, help="The recorded metric to visualize")
    speedup.add_argument("-a", "--agg",  nargs="+", default=["avg", "p(90)", "p(95)"], help="The aggregation funcs")

    args = parser.parse_args()
    files = glob.glob("res/smoke-*.json")

    if args.command == "line":
        line_graph(files, args.metric, args.agg)
    elif args.command == "speedup":
        speedup_graph(files, args.metric, args.agg)
