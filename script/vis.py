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
sns.color_palette("tab10")

np.random.seed(1)

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
    name = name.replace("{expected_response:true}", "_exp_res")

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
        raise KeyError(f"Unknown aggregation function: {name}")


def _get_file_paths(name, filename_pattern="*.json"):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return glob.glob(os.path.join(dir_path, "..", "res", "runs", args.name, filename_pattern))


def line_graph(name, metric, agg, dst):
    paths = _get_file_paths(name)
    df, is_summary = _load_data(paths, [agg])
    df = df.xs(metric, level="metric_name")

    key = agg if is_summary else ("metric_value", agg)
    g = sns.lineplot(data=df, x="payload_size", y=key, hue="proxy")
    sizes = set(df.index.get_level_values("payload_size"))
    sizes = sorted(sizes)
    
    # g.set_title(f"{metric} {agg}")
    g.set_xlabel("payload size [B]")
    g.set_xticks(sizes)
    g.set_ylabel("time [ms]")
    g.set_xbound(lower=sizes[0], upper=sizes[-1])
    plt.yscale("log")
    _save_to_path(f"{name}-line-{metric}-{agg}.pdf", dst)           
    

def speedup_graph(name, base, metric, aggs, dst):
    paths = _get_file_paths(name)
    df = _load_summary_data(paths)
    ebpf = df.xs("ebpf", level="proxy")
    envoy = df.xs("envoy", level="proxy")

    if base is not None:
        base = df.xs(base, level="proxy")
    else:
        base = pd.DataFrame(0, index=ebpf.index, columns=ebpf.columns)

    speedup = ebpf.copy()
    for agg in aggs:
        speedup[agg] = (envoy[agg] - base[agg]) / (ebpf[agg] - base[agg])

    speedup = speedup.xs(metric, level="metric_name")
    speedup = speedup.drop("value", axis=1).reset_index()
    speedup = speedup.melt(id_vars=["payload_size"], value_vars=aggs)

    g = sns.catplot(
        data=speedup, kind="bar",
        x="payload_size", y="value", hue="variable",
        errorbar="sd"
    )

    # plt.title(metric)
    g.set_axis_labels("payload size [B]", "speedup")
    g.legend.set_title(None)
    sns.move_legend(g, "upper right")
    _save_to_path(f"{name}-speedup-{metric}.pdf", dst)


def duration_graph(name, proxy, agg, dst):
    paths = _get_file_paths(name)
    df = _load_summary_data(paths)
    df = df.xs(proxy, level="proxy")

    columns = ["http_req_sending", "http_req_waiting", "http_req_receiving"]
    df = df[df.index.get_level_values("metric_name").isin(columns)]
    df = df.drop((c for c in df.columns if c != agg), axis=1)
    df = df.reset_index()
    df = df.pivot(index="payload_size", columns="metric_name", values=agg)

    g = df.plot(kind="bar", stacked=True)
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]")
    
    _save_to_path(f"{name}-duration-{proxy}-{agg}.pdf", dst)


def overhead_graph(name, base, metric, agg, absolute, dst):
    paths = _get_file_paths(name)
    def _preprocess(df):
        df = df[df.index.get_level_values("metric_name") == metric]
        df = df.drop((c for c in df.columns if c != agg), axis=1)
        df = df.reset_index()
        df = df.pivot(index="payload_size", columns="proxy", values=agg)

        return df

    df = _preprocess(_load_summary_data(paths))

    base = df.drop((c for c in df.columns if c != base), axis=1)
    df.drop(base, axis=1, inplace=True)

    proxies = df.columns
    if absolute:
        for p in proxies:
            df[p] = df[p] - base["none"]
    else:
        for p in proxies:
            df[p] = (df[p] - base["none"]) / base["none"] * 100

    # assert(np.all(df["ebpf"] >= 0))
    # assert(np.all(df["envoy"] >= 0))

    df = df[df.index.get_level_values("payload_size") <= 1024]

    g = df.plot(kind="bar")
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]" if absolute else "overhead [%]")
    
    _save_to_path(f"{name}-overhead-{metric}-{agg}.pdf", dst)


def cdf_graph(name, metric, crop, dst):
    paths = _get_file_paths(name)
    df = _load_log_data(paths)
    df = df[df["metric_name"] == metric]

    proxies = df["proxy"].unique()
    if crop > 0:
        for p in proxies:
            start = df.loc[df["proxy"] == p, "timestamp"].min()
            df.drop(df[(df["proxy"] == p) & (df["timestamp"] < start+crop)].index, inplace=True)

    print(df["metric_value"].describe([0.9, 0.95, 0.99]))

    g = sns.ecdfplot(data=df, x="metric_value", hue="proxy")

    g.set_xlabel(metric)
    # g.set_ybound(lower=0.9, upper=1.0)
    plt.xscale("log")
    _save_to_path(f"{name}-cdf-{metric}-@{crop}s.pdf", dst)


def scatter_graph(name, metric, drop_rate, dst):
    paths = _get_file_paths(name)
    df = _load_log_data(paths)
    df = df[df["metric_name"] == metric]

    drop_num = int(drop_rate * len(df))
    if drop_num > 0:
        print(f"Dropping {drop_num} samples ({drop_rate*100}%)")
        df = df.sample(n=len(df)-drop_num).sort_index()

    proxies = df["proxy"].unique()
    for p in proxies:
        df.loc[df["proxy"] == p, "timestamp"] -= df.loc[df["proxy"] == p, "timestamp"].min()

    g = sns.scatterplot(data=df, x="timestamp", y="metric_value", hue="proxy")

    g.set_xlabel("time [s]")
    g.set_ylabel(f"{metric} [ms]")
    plt.yscale("log")

    _save_to_path(f"cdf-{metric}-@{1-drop_rate}%.pdf", dst)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", help="Name of the experiment")
    parser.add_argument("-o", "--output", default="res/vis", help="Can be an output directory or file")

    subparsers = parser.add_subparsers(dest="command")
    
    line = subparsers.add_parser("line")
    line.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    line.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

    speedup = subparsers.add_parser("speedup")
    speedup.add_argument("-b", "--base", required=False, help="The data that serves as the critical path")
    speedup.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    speedup.add_argument("-a", "--agg",  nargs="+", default=["avg", "p(90)", "p(95)", "max"], help="The aggregation funcs")

    duration = subparsers.add_parser("duration")
    duration.add_argument("-p", "--proxy", required=True, help="The recorded proxy to visualize")
    duration.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

    overhead = subparsers.add_parser("overhead")
    overhead.add_argument("-b", "--base", default="none", help="The data that serves as the critical path")
    overhead.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    overhead.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")
    overhead.add_argument("--absolute", default=False, help="Report the overhead in absolute numbers")

    cdf = subparsers.add_parser("cdf")
    cdf.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    cdf.add_argument("-c", "--crop", default=0, help="Crop the given number of seconds from the beginning of the trace")

    scatter = subparsers.add_parser("scatter")
    scatter.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    scatter.add_argument("-d", "--drop", default=0, help="Drop rate of the recorded metric")
    
    args = parser.parse_args()

    if args.command == "line":
        line_graph(args.name, args.metric, args.agg, args.output)
    elif args.command == "speedup":
        speedup_graph(args.name, args.base, args.metric, args.agg, args.output)
    elif args.command == "duration":
        duration_graph(args.name, args.proxy, args.agg, args.output)
    elif args.command == "overhead":
        overhead_graph(args.name, args.base, args.metric, args.agg, args.absolute, args.output)
    elif args.command == "cdf":
        cdf_graph(args.name, args.metric, float(args.crop), args.output)
    elif args.command == "scatter":
        scatter_graph(args.name, args.metric, float(args.drop), args.output)
