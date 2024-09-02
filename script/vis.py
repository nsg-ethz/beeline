import json
import glob
import argparse
import re
import os
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import seaborn as sns
import pandas as pd

# Apply the default theme
sns.set_theme(style="whitegrid")

def _parse_path(path):
    match = re.search(r"(\w+)-(\d+)B.*", path)
    proxy = match.group(1)
    size = match.group(2)

    return proxy, int(size)


def _load_summary_data(paths):
    rows = []
    for p in paths:
        proxy, payload_size = _parse_path(p)
        with open(p, "r") as file:
            data = json.load(file)
            data = data["metrics"]

            for (metric, aggs) in data.items():
                rows.append({
                    "proxy": proxy,
                    "payload_size": payload_size,
                    "metric_name": metric,
                    **aggs
                })

    df = pd.DataFrame.from_dict(rows)
    df.set_index(["proxy", "payload_size", "metric_name"], inplace=True)

    # larger payloads are buggy for ebpf
    df = df[df.index.get_level_values("payload_size") < 4000]

    return df


def _load_log_data(paths):
    dfs = []

    for p in paths:
        proxy, payload_size = _parse_path(p)
        df = pd.read_csv(p, engine="pyarrow")
        df["proxy"] = proxy
        df["payload_size"] = payload_size

        dfs.append(df)

    df = pd.concat(dfs)
    df.set_index(["proxy", "payload_size", "metric_name"], inplace=True)

    # larger payloads are buggy for ebpf
    df = df[df.index.get_level_values("payload_size") < 4000]

    return df


def _load_data(paths, aggs):
    if all("summary" in p for p in paths):
        df = _load_summary_data(paths)

        return df, True
    else:
        df = _load_log_data(paths)

        df = df[df["expected_response"].fillna(False)]
        df = df[df["extra_tags"].str.contains("steady").fillna(False)]

        columns = (c for c in df.columns if c != "metric_value")
        df = df.drop(columns, axis=1)

        aggs = [(agg, _aggregate_fn(agg)) for agg in aggs]
        df = df.groupby(level=[0,1,2]).agg(aggs)

        return df, False


def _save_to_path(name, dst):
    plt.tight_layout()
    path = os.path.join(dst, name) if os.path.isdir(dst) else dst
    print("Writing to", path)
    plt.savefig(path)


def _aggregate_fn(name):
    if name in ["avg", "mean"]:
        return np.mean
    elif name == "med":
        return np.median
    elif name == "p(90)":
        return lambda x: np.quantile(x, q=0.9)
    elif name == "p(95)":
        return lambda x: np.quantile(x, q=0.95)
    elif name == "p(99)":
        return lambda x: np.quantile(x, q=0.99)
    elif name in ["count", "sum"]:
        return np.sum
    else:
        raise KeyError(f"Unknown aggregation function: ${name}")


def line_graph(paths, metric, agg, dst):
    df, is_summary = _load_data(paths, [agg])
    df = df.xs(metric, level="metric_name")

    key = agg if is_summary else ("metric_value", agg)
    g = sns.lineplot(data=df, x="payload_size", y=key, hue="proxy", palette="dark", alpha=.6)
    sizes = set(df.index.get_level_values("payload_size"))
    sizes = sorted(sizes)
    
    # g.set_title(f"{metric} {agg}")
    g.set_xlabel("payload size [B]")
    g.set_xticks(sizes)
    g.set_ylabel("time [ms]")
    g.set_xbound(lower=sizes[0], upper=sizes[-1])
    plt.yscale("log")
    _save_to_path(f"stress-{metric}.pdf", dst)           
    

def speedup_graph(paths, metric, aggs, dst):
    df = _load_summary_data(paths)
    ebpf = df.xs("ebpf", level="proxy")
    envoy = df.xs("envoy", level="proxy")

    speedup = ebpf.copy()
    for agg in aggs:
        speedup[agg] = envoy[agg] / ebpf[agg]

    speedup = speedup.xs(metric, level="metric_name")
    speedup = speedup.drop("value", axis=1).reset_index()
    speedup = speedup.melt(id_vars=["payload_size"], value_vars=aggs)

    g = sns.catplot(
        data=speedup, kind="bar",
        x="payload_size", y="value", hue="variable",
        errorbar="sd", palette="dark", alpha=.6
    )

    # plt.title(metric)
    g.set_axis_labels("payload size [B]", "speedup")
    g.legend.set_title(None)
    _save_to_path(f"stress-speedup-{metric}.pdf", dst)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pattern", help="Pattern to find files to consider")
    parser.add_argument("-o", "--output", default="res/vis", help="Can be an output directory or file")

    subparsers = parser.add_subparsers(dest="command")
    
    line = subparsers.add_parser("line")
    line.add_argument("-m", "--metric", required=True, help="The recorded metric to visualize")
    line.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

    speedup = subparsers.add_parser("speedup")
    speedup.add_argument("-m", "--metric", required=True, help="The recorded metric to visualize")
    speedup.add_argument("-a", "--agg",  nargs="+", default=["avg", "p(90)", "p(95)", "max"], help="The aggregation funcs")

    args = parser.parse_args()
    files = glob.glob(args.pattern)

    if args.command == "line":
        line_graph(files, args.metric, args.agg, args.output)
    elif args.command == "speedup":
        speedup_graph(files, args.metric, args.agg, args.output)
