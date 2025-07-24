#!/usr/bin/env python

import json
import glob
import argparse
import re
import os
from matplotlib.artist import get
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import seaborn as sns
import pandas as pd
import tqdm

# Apply the default theme
sns.set_theme(style="whitegrid")
sns.color_palette("tab10")

np.random.seed(1)

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--name", help="Name of the experiment")
parser.add_argument("-l", "--legend", default=False, action=argparse.BooleanOptionalAction, help="Rename the legend labels")
parser.add_argument("-o", "--output", default="res/vis", help="Can be an output directory or file")

subparsers = parser.add_subparsers(dest="command")

box_plot = subparsers.add_parser("bp")
box_plot.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")

line = subparsers.add_parser("line")
line.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
line.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

bar = subparsers.add_parser("bar")
bar.add_argument("-m", "--metric", default="iterations", help="The recorded metric to visualize")
bar.add_argument("-a", "--agg", default="rate", help="The aggregation func")

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
cdf.add_argument("-r", "--range", required=False, help="The time range")
cdf_tikz = subparsers.add_parser("cdf_tikz")
cdf_tikz.add_argument("-r", "--range", required=False, help="The time range")

scatter = subparsers.add_parser("scatter")
scatter.add_argument("-p", "--proxy", required=True, help="The recorded proxy to visualize")
scatter.add_argument("-m", "--metric", default="http_req_duration", help="The recorded metric to visualize")
scatter.add_argument("-d", "--drop", default=0, help="Drop rate of the recorded metric")

time_profile = subparsers.add_parser("time_profile")
time_profile.add_argument("-m", "--metric", default="http_req_duration", help="The recorded metric to visualize")
time_profile.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

stats = subparsers.add_parser("stats")
stats = subparsers.add_parser("stats_tikz")

lat = subparsers.add_parser("lat")
lat.add_argument("-a", "--agg", default="mean", help="The aggregation func")
lat_tikz = subparsers.add_parser("lat_tikz")
lat_tikz.add_argument("-r", "--range", required=False, help="The time range")

cpu = subparsers.add_parser("cpu")
cpu_tikz = subparsers.add_parser("cpu_tikz")

rate = subparsers.add_parser("rate")
rate_tikz = subparsers.add_parser("rate_tikz")

dissect = subparsers.add_parser("dissect")
dissect_tikz = subparsers.add_parser("dissect_tikz")
dissect_complexity_tikz = subparsers.add_parser("dissect_complexity_tikz")

percentile = subparsers.add_parser("percentile")
percentile.add_argument("-r", "--range", required=False, help="The time range")

percentile_tikz = subparsers.add_parser("percentile_tikz")
percentile_tikz.add_argument("-r", "--range", required=False, help="The time range")

scaling = subparsers.add_parser("scaling")
scaling.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
scaling.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

complexity = subparsers.add_parser("complexity")
complexity.add_argument("-m", "--metric", default="http_reqs", help="The recorded metric to visualize")
complexity.add_argument("-a", "--agg", default="rate", help="The aggregation func")

complexity_tikz = subparsers.add_parser("complexity_tikz")
complexity_tikz.add_argument("-p", "--policy", help="The policy to visualize")
complexity_tikz.add_argument("-m", "--metric", default="http_reqs", help="The recorded metric to visualize")
complexity_tikz.add_argument("-a", "--agg", default="rate", help="The aggregation func")

args = parser.parse_args()

def thousand_label(x, pos):
    return "%1.0fK" % (x * 1e-3) if x >= 1e3 else "%1.0f" % x


def _parse_k6_path(path):
    match = re.search(r"(\w+)-k6-e(\d+)-*", path)
    proxy = match.group(1)
    epoch = match.group(2)

    return proxy, int(epoch)


def _parse_wrk_path(path):
    match = re.search(r"(\w+)-(?:(\d+)-)?wrk-e(\d+)*.*", path)
    proxy = match.group(1)
    timestamp = match.group(2)
    epoch = match.group(3)

    return proxy, int(timestamp) if timestamp else None, int(epoch)


def _parse_cpu_path(path):
    match = re.search(r"(\w+)-cpu-e(\d+).*", path)
    proxy = match.group(1)
    epoch = match.group(2)

    return proxy, int(epoch)


def _parse_bpf_path(path):
    match = re.search(r"(\w+)-bpf-(\w+).(\w+)-e(\d+).*", path)
    proxy = match.group(1)
    bin = match.group(2)
    func = match.group(3)
    epoch = match.group(4)

    return proxy, bin, func, int(epoch)


def _load_k6_summaries(paths):
    rows = []
    for p in paths:
        proxy, epoch = _parse_k6_path(p)
        with open(p, "r") as file:
            data = json.load(file)
            data = data["metrics"]

            for (metric, aggs) in data.items():
                rows.append({
                    "proxy": proxy,
                    "metric_name": metric,
                    "epoch": epoch,
                    "file": os.path.basename(p),
                    **aggs
                })

    df = pd.DataFrame.from_dict(rows)
    return df


def _load_k6_data(paths, max_epoch=30):
    dfs = []
    epochs = {}
    for p in tqdm.tqdm(paths):
        proxy, epoch = _parse_k6_path(p)
        if epochs.get(proxy, 0) >= max_epoch:
            continue

        try:
            df = pd.read_csv(p, low_memory=False)
            num_failed_res = (df["expected_response"] == False).sum()
            if num_failed_res / len(df) > 0.01:
                continue

            epochs[proxy] = epochs.get(proxy, 0) + 1

            df["proxy"] = proxy
            df["epoch"] = epoch
            # df["file"] = os.path.basename(p),
            df["timestamp"] -= df["timestamp"].min()
            dfs.append(df)
        except Exception as e:
            print(f"Error loading {p}: {e}")

    return pd.concat(dfs)


def _load_wrk_data(paths):
    rows = []
    for p in paths:
        proxy, timestamp, epoch = _parse_wrk_path(p)
        with open(p, "r") as file:
            text = file.read()
            ps = [f"p({p})" for p in range(1, 100)]

            aggs = {}
            for percentile in ps:
                escaped_percentile = re.escape(percentile)
                pattern = rf"{escaped_percentile}:\s*(\d+\.\d+)"
                match = re.search(pattern, text)

                if match is not None:
                    latency = match.group(1)
                    aggs[percentile] = float(latency)

            pattern = "Latency\s*(\d+\.\d+)ms"
            match = re.search(pattern, text)

            if match is not None:
                latency = match.group(1)
                aggs["mean"] = float(latency)

            pattern = r"Requests/sec:\s*(\d+\.\d+)"
            match = re.search(pattern, text)
            if match is None:
                print(f"Could not find rate in {p}")
                continue

            rate = float(match.group(1))

            rows.append({
                "proxy": proxy,
                "timestamp": timestamp,
                "epoch": epoch,
                "rate": rate,
                "metric_name": "http_req_duration",
                "file": os.path.basename(p),
                **aggs
            })

    df = pd.DataFrame.from_dict(rows)

    return df


def _load_cpu_data(paths):
    dfs = []
    for p in paths:
        proxy, epoch = _parse_cpu_path(p)

        df = pd.read_csv(p)
        df["proxy"] = proxy
        df["epoch"] = epoch
        df["file"] = os.path.basename(p)

        dfs.append(df)

    return pd.concat(dfs)


def _load_bpf_data(paths):
    dfs = []
    for p in paths:
        proxy, bin, func, epoch = _parse_bpf_path(p)

        with open(p, "r") as file:
            text = file.read()
            pattern = r"total: (\d+) nsecs, count: (\d+)"
            match = re.search(pattern, text)

            if match is None:
                print(f"Could not find total/count in {p}")
                continue

            total = int(match.group(1))
            count = int(match.group(2))

            df = pd.DataFrame({"proxy": [proxy], "bin": [bin], "file": [os.path.basename(p)], "total": [total], "count": [count], "func": [func], "epoch": [epoch]})
            dfs.append(df)

    return pd.concat(dfs).reset_index(drop=True)


def _load_log_data(paths):
    dfs = []

    for p in paths:
        proxy, payload_size = _parse_k6_path(p)
        df = pd.read_csv(p, engine="pyarrow")
        df["proxy"] = proxy
        df["payload_size"] = payload_size
        df["file"] = os.path.basename(p)

        dfs.append(df)

    df = pd.concat(dfs)

    return df


def _load_data(paths, aggs):
    if all("summary" in p for p in paths):
        df = _load_k6_summaries(paths)

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
    name = name.replace("(", "")
    name = name.replace(")", "")

    plt.tight_layout()
    path = os.path.join(dst, name)
    if os.path.splitext(path)[1] == "":
        path += ".png"

    print("Writing to", path)

    os.makedirs(dst, exist_ok=True)
    plt.savefig(path, dpi=400)
    plt.clf()


def _aggregate_fn(name):
    if name in ["avg", "mean"]:
        return "mean"
    elif name == "med" or name == "p(50)":
        return "median"
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


def _parse_time_range(time_range, min=0, max=2**100):
    if time_range is None:
        return (min, max)

    (start, end) = time_range.split(":")
    start = int(start) if len(start) > 0 else min
    end = int(start) if len(end) > 0 else max
    return (start, end)


def _get_file_paths(name, filename_pattern="*.json"):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return glob.glob(os.path.join(dir_path, "..", "res", "runs", name, filename_pattern))


def _tex_color_name(proxy, fill=False):
    if fill:
        return proxy.replace("_", "") + "fill"
    else:
        return proxy.replace("_", "") + "color"

def _tex_display_name(proxy):
    names = {
        "beeline": "Envoy + \\proj",
        "envoy": "Envoy",
        "envoy_iouring": "Envoy + \\iouring",
        "envoy_l4fp": "Envoy + L4 Fast Path",
        "none": "Vanilla"
    }

    return names[proxy]


def _rename_legend_labels(g):
    print("How do you want to call the proxies?")
    for text in g._legend.texts:
        proxy = text.get_text()
        new_name = input(f"{proxy}: ").strip()
        if len(new_name) > 0:
            text.set_text(new_name)


def box_plot(name, metric, dst):
    paths = _get_file_paths(name)
    df = _load_k6_summaries(paths)
    df = df.xs(metric, level="metric_name")

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    plots = []
    for proxy in order:
        lw = df.loc[proxy, 1024]["min"]
        lq = df.loc[proxy, 1024]["p(25)"]
        uw = df.loc[proxy, 1024]["max"]
        uq = df.loc[proxy, 1024]["p(75)"]
        med = df.loc[proxy, 1024]["med"]

        plot = f"""\\addplot+ [
            boxplot prepared={{
                lower whisker={lw}, lower quartile={lq},
                median={med},
                upper whisker={uw}, upper quartile={uq},
            }},
        ] coordinates {{}};"""
        plots.append(plot)

    tick_labels = ", ".join(order)
    ticks = ", ".join([str(i) for i in range(1, len(order)+1)])
    plots = "\n".join(plots)

    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    ytick={{{ticks}}},
    yticklabels={{{tick_labels}}},
]

{plots}

\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def line_graph(name, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_k6_summaries(paths)
    df = df.xs(metric, level="metric_name")

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    num_samples = df.groupby("proxy").agg({agg: "count"})
    if len(np.unique(num_samples)) > 1:
        raise ValueError(f"Incomplete measurements: {num_samples}")

    g = sns.lineplot(data=df, x="payload_size", y=agg, hue="proxy", marker="o", hue_order=order)
    sizes = set(df.index.get_level_values("payload_size"))
    sizes = sorted(sizes)

    g.set_xscale("log")
    g.set_xlabel("payload size [B]")
    g.set_xticks(sizes)
    g.set_xticklabels([str(s) for s in sizes])
    g.xaxis.set_major_formatter(ticker.FuncFormatter(thousand_label))
    g.set_xbound(lower=sizes[0], upper=sizes[-1])

    g.set_ylabel("time [ms]")
    min_y = df[agg].min()
    max_y = df[agg].max()

    g.set_yticks(np.linspace(min_y, max_y, 5))
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"line-{metric}-{agg}", os.path.join(dst, name))


def bar_graph(name, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_k6_summaries(paths)
    df = df.xs(metric, level="metric_name")

    df[agg] = df[agg] / 1e6

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    g = sns.catplot(data=df, kind="bar", x="proxy", y=agg, errorbar="sd", hue_order=order)

    g.set(xlabel="payload size [B]", ylabel="throughput [MB/s]")

    print(df[agg])

    # max_y = df[agg].max()
    # g.set(yticks=np.linspace(0, max_y, 5))
    # for ax in g.axes.flat:
    #     ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    # sns.move_legend(g, "upper center")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"bar-{metric}-{agg}", os.path.join(dst, name))


def speedup_graph(name, base, metric, aggs, dst):
    paths = _get_file_paths(name)
    df = _load_k6_summaries(paths)
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

    if args.legend:
        _rename_legend_labels(g)

    sns.move_legend(g, "upper right")
    _save_to_path(f"speedup-{metric}", os.path.join(dst, name))


def duration_graph(name, proxy, agg, dst):
    paths = _get_file_paths(name)
    df = _load_k6_summaries(paths)
    df = df.xs(proxy, level="proxy")

    columns = ["http_req_sending", "http_req_waiting", "http_req_receiving"]
    df = df[df.index.get_level_values("metric_name").isin(columns)]
    df = df.drop((c for c in df.columns if c != agg), axis=1)
    df = df.reset_index()
    df = df.pivot(index="payload_size", columns="metric_name", values=agg)

    g = df.plot(kind="bar", stacked=True)
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"duration-{proxy}-{agg}", os.path.join(dst, name))


def overhead_graph(name, base, metric, agg, absolute, dst):
    paths = _get_file_paths(name)
    def _preprocess(df):
        df = df[df.index.get_level_values("metric_name") == metric]
        df = df.drop((c for c in df.columns if c != agg), axis=1)
        df = df.reset_index()
        df = df.pivot(index="payload_size", columns="proxy", values=agg)

        return df

    df = _preprocess(_load_k6_summaries(paths))

    base = df.drop((c for c in df.columns if c != base), axis=1)
    df.drop(base, axis=1, inplace=True)

    proxies = df.columns
    if absolute:
        for p in proxies:
            df[p] = df[p] - base["none"]
    else:
        for p in proxies:
            df[p] = (df[p] - base["none"]) / base["none"] * 100

    # df = df.drop("envoy", axis=1)
    # df = df.drop("splice", axis=1)
    # assert(np.all(df["ebpf"] >= 0))
    # assert(np.all(df["envoy"] >= 0))

    g = df.plot(kind="bar")
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]" if absolute else "overhead [%]")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"overhead-{metric}-{agg}", os.path.join(dst, name))


def cdf_graph(name, time_range, dst):
    (start, end) = _parse_time_range(time_range)
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)
    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    order = df["proxy"].unique()

    g = sns.ecdfplot(data=df, x="metric_value", hue="proxy", hue_order=order)
    g.set_xlabel("Latency [ms]")

    for p, l, h in zip(order, reversed(g.lines), g.legend_.legend_handles):
        if p == "envoy":
            l.set_linestyle("--")
            h.set_linestyle("--")

    if args.legend:
        _rename_legend_labels(g)

    plt.ylim(0.9, 1)
    plt.xlim(0, 2)
    # plt.xscale("log")
    _save_to_path(f"cdf", os.path.join(dst, name))


def cdf_graph_tikz(name, time_range):
    (start, end) = _parse_time_range(time_range)

    plots = []
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)
    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    order = df["proxy"].unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    legend = ",".join([_tex_display_name(p) for p in order])

    def _percentiles(proxy):
        vals = df[df["proxy"] == proxy]["metric_value"]

        ys = np.arange(1, 100)
        xs = np.percentile(vals, ys)
        return (xs, ys)

    print("beeline vs envoy_l4fp:", (_percentiles("beeline")[0] / _percentiles("envoy_l4fp")[0]).mean())
    print("beeline vs envoy:", (_percentiles("beeline")[0] / _percentiles("envoy")[0]).mean())
    if "vanilla" in order:
        print("beeline vs vanilla:", (_percentiles("beeline")[0] / _percentiles("vanilla")[0]).mean())
    print("envoy_l4fp vs envoy:", (_percentiles("envoy_l4fp")[0] / _percentiles("envoy")[0]).mean())

    for i, proxy in enumerate(order):
        color = _tex_color_name(proxy) # predefined in latex
        (xs, ys) = _percentiles(proxy)

        coordinates = [(x, y/100.0) for x, y in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({x}, {y})" for x, y in coordinates])
        plots.append((color, coordinates))

    plots = [f"""\\addplot[{color}, line width=0.3mm] coordinates {{
        {coordinates}
    }};""" for (color, coordinates) in plots]
    plots = "\n".join(plots)

    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
xlabel={{Latency [ms]}},
ylabel={{CDF}},
ymin=0,
axis lines=left,
x tick label style={{
    /pgf/number format/fixed,
    /pgf/number format/precision=1,
    /pgf/number format/1000 sep={{}},
}},
legend columns = 4,
legend style={{at={{(0,1.1)}},draw=none,anchor=south west, /tikz/every even column/.append style={{column sep=0.25cm}}}},
scaled x ticks=false,
xlabel style={{anchor=north}},
xmajorgrids=true,
grid style=dashed,
height=5cm,
width=\\linewidth]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def scatter_graph(name, proxy, metric, drop_rate, dst):
    paths = _get_file_paths(name, "*.csv")
    df = _load_log_data(paths)
    df = df[df["metric_name"] == metric]

    df = df[df["proxy"] == proxy]
    df["timestamp"] -= df["timestamp"].min()

    drop_num = int(drop_rate * len(df))
    if drop_num > 0:
        print(f"Dropping {drop_num} samples ({drop_rate*100}%)")
        df = df.sample(n=len(df)-drop_num).sort_index()

    g = sns.scatterplot(data=df, x="timestamp", y="metric_value", hue="proxy")

    g.set_xlabel("Time [s]")

    min_y = df["metric_value"].min()
    max_y = df["metric_value"].max()
    g.set_yticks(np.linspace(min_y, max_y, 5))
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))
    g.set_ylabel(f"{metric} [ms]")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"scatter-{proxy}-{metric}-@{str(round(100*(1-drop_rate)))}%", os.path.join(dst, name))


def time_profile_graph_tikz(name, metric, agg):
    paths = _get_file_paths(name, "*.csv")
    df = _load_log_data(paths)
    df = df[df["metric_name"] == metric]

    df = df[["proxy", "timestamp", "metric_value"]]
    agg_fn = {"metric_value": _aggregate_fn(agg)}
    df = df.groupby(by=["proxy", "timestamp"]).agg(agg_fn)

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)
    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")
    legend = ",".join(order)

    plots = []
    for i, proxy in enumerate(order):
        color = f"{proxy}color" # predefined in latex
        ys = df["metric_value"].xs(proxy, level="proxy")
        xs = ys.index
        xs -= xs.min()

        coordinates = list(sorted(zip(xs, ys)))
        coordinates = "\n".join([f"({x}, {y})" for x, y in coordinates])

        plot = f"""\\addplot[{color},line width=0.3mm] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
    ylabel={{Latency [ms]}},
    xlabel={{Time [s]}},
    xmin=0, xmax=30,
    axis lines=left,
    xticklabel style={{rotate=-0, yshift=-0.4ex}},
    xlabel style={{anchor=north}},
    xmajorgrids=true,
    grid style=dashed,
    legend pos=north east,
    height=5cm,
    width=\\linewidth
]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def lat_graph(name, agg, dst):
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    df = df.groupby(["proxy", "timestamp"]).agg({"metric_value": "mean"})

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    g = sns.lineplot(data=df, x="timestamp", y="metric_value", hue="proxy", marker="o", hue_order=order)

    g.set_xlabel("rate [req/s]")
    g.set_ylabel("latency [ms]")
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"sn-latency-{agg}", os.path.join(dst, name))


def lat_graph_tikz(name, time_range):
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    df = df.groupby(["proxy", "timestamp"]).agg({"metric_value": "mean"})

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    legend = ",".join(order)

    plots = []
    for i, proxy in enumerate(order):
        color = f"{proxy}color" # predefined in latex
        xs = df.xs(proxy, level="proxy").index.get_level_values("timestamp")
        ys = df.xs(proxy, level="proxy")["metric_value"]

        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{color}, line width=0.3mm] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    (xmin, xmax) = _parse_time_range(time_range, max=df["rate"].max())

    plots = "\n".join(plots)
    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
xlabel={{Time [s]}},
ylabel={{Latency [ms]}},
ymin=0,
xmin={xmin}, xmax={xmax},
axis lines=left,
x tick label style={{
    /pgf/number format/fixed,
    /pgf/number format/precision=1,
    /pgf/number format/1000 sep={{}},
}},
scaled x ticks=false,
xlabel style={{anchor=north}},
xmajorgrids=true,
grid style=dashed,
legend pos=north west,
height=5cm,
width=\\linewidth]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def stats_graph(dst):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "..", "res", "stats", "filters.json")
    df = pd.read_json(path).set_index("name")

    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "..", "res", "stats", "classification.json")
    cl = pd.read_json(path).transpose()

    df["stateless"] = cl["stateless"].astype(bool)
    df["compatible"] = cl["compatible"].astype(bool)

    other_mask = df["count"] < 10
    # other = df[other_mask]
    df = df[~other_mask]
    # other = pd.DataFrame({"count": [other["count"].sum()], "stateless": [False], "compatible": [False]}, index=["other"])
    # df = pd.concat([df, other])

    df["count"] = (df["count"] / df["count"].sum()) * 100

    df["color"] = "not supported"
    df.loc[df["compatible"] & df["stateless"], "color"] = "compatible & stateless"

    g = sns.barplot(data=df, x=df.index, y="count", hue="color")
    g.legend_.set_title(None)
    # g.set_yscale("log")
    plt.xticks(rotation=90)
    _save_to_path("stats", dst)


def stats_graph_tikz():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "..", "res", "stats", "filters.json")
    df = pd.read_json(path).set_index("name")

    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "..", "res", "stats", "classification.json")
    cl = pd.read_json(path).transpose()

    df["stateless"] = cl["stateless"].astype(bool)

    names = df.index.tolist()
    names[names.index("http1bridge")] = "grpc_http1"
    names[names.index("grpc_json_transcoder")] = "grpc_json"
    names[names.index("dynamic_forward_proxy")] = "forward_proxy"
    df = df.reset_index()
    df["name"] = names

    df["count"] = (df["count"] / df["count"].sum()) * 100

    other = df.tail(len(df)-10)
    df = df.head(10)
    other = pd.DataFrame({"count": [other["count"].sum()], "stateless": [False], "name": ["other"]}, index=[len(df)])

    cnt = len(df) + 1
    def _coords(df):
        coords = [f"({count: .1f},{cnt-idx-1})" for (idx, count) in zip(df.index, df["count"])]

        return coords

    supported = df.loc[df["stateless"] == True]
    cnt = supported["count"].sum()
    print(f"Pure filters: {cnt}")
    supported = "\n".join(_coords(supported))

    unsupported = df.loc[df["stateless"] == False]
    unsupported = "\n".join(_coords(unsupported))

    other = "\n".join(_coords(other))

    labels = [name.replace("_", "\\_") for name in list(df["name"]) + ["other"]]
    labels = ",".join(reversed(labels))

    # colors = ["uchu-green-5" if ok else "uchu-red-5" for ok in beelineable]
    # colors = ",".join(colors)

    legend = "Stateless, Stateful"

    supported = f"""\\addplot[draw=uchu-green-5, fill=uchu-green-1] coordinates {{
{supported}
}};"""
    unsupported = f"""\\addplot[draw=uchu-red-5, fill=uchu-red-1] coordinates {{
{unsupported}
}};"""
#    other = f"""\\addplot[draw=uchu-gray-5, fill=uchu-gray-1, forget plot] coordinates {{
#    {other}
#}};"""
    plots = "\n".join([supported, unsupported])

    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[xbar,
enlarge y limits={{abs=0.2,upper}},
height=7.5cm,
width=\\linewidth-45pt,
bar shift=0pt,
axis lines=left,
enlarge x limits={{abs=10pt,upper}},
enlarge y limits={{abs=10pt}},
nodes near coords={{\\pgfmathprintnumber\\pgfplotspointmeta\\%}},
legend pos=south east,
yticklabels={{{labels}}},
ytick={{0, ..., {cnt}}},
xticklabel={{\\pgfmathprintnumber{{\\tick}}\\%}}]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def cpu_graph(name, dst):
    paths = _get_file_paths(name)
    df = _load_cpu_data(paths)

    min_ts = df.groupby(by=["proxy"]).agg({"timestamp": "min"})
    df = df.groupby(by=["proxy", "timestamp"]).agg({"CPUPerc": "sum"}).reset_index()

    order = df["proxy"].unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    for p in order:
        df.loc[df["proxy"] == p, "timestamp"] -= min_ts.loc[p, "timestamp"]

    df = df.set_index(["proxy", "timestamp"])

    g = sns.lineplot(data=df, x="timestamp", y="CPUPerc", hue="proxy", marker="o", hue_order=order)

    g.set_xlabel("time [s]")

    g.set_ylabel("CPU Utilization [%]")

    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    _save_to_path(f"cpu-{name}", os.path.join(dst, name))


def cpu_graph_tikz(name):
    paths = _get_file_paths(name, "*full.csv")
    if len(paths) > 0:
        df = _load_k6_data(paths)
        epochs = df.groupby('proxy')['epoch'].unique()

        paths = []
        for proxy in epochs.index:
            for epoch in epochs[proxy]:
                paths += _get_file_paths(name, f"{proxy}-cpu-e{epoch}.log")
    else:
        paths = _get_file_paths(name, "*cpu*.log")

    df = _load_cpu_data(paths)
    df["timestamp"] /= 1e9
    df = df.round({"timestamp": 0, "CPUPerc": 3})

    min_ts = df.groupby(by=["proxy", "epoch"]).agg({"timestamp": "min"})
    df = df.groupby(by=["proxy", "epoch", "timestamp"]).agg({"CPUPerc": "sum"}).reset_index()

    order = df["proxy"].unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    # Subtract the corresponding minimum timestamp
    for proxy in df["proxy"].unique():
        for epoch in df[df["proxy"] == proxy]["epoch"].unique():
            mask = (df["proxy"] == proxy) & (df["epoch"] == epoch)
            df.loc[mask, "timestamp"] -= min_ts.loc[(proxy, epoch), "timestamp"]

    df = df.groupby(by=["proxy", "timestamp"]).agg({"CPUPerc": "mean"}).reset_index()

    def _usage(proxy, start=None, end=None):
        mask = (df["proxy"] == proxy)
        if start is not None:
            mask &= (df["timestamp"] >= start)
        if end is not None:
            mask &= (df["timestamp"] <= end)

        data = df[mask]
        return data["timestamp"], data["CPUPerc"]

    timestamps = []
    for proxy in order:
        usage = _usage(proxy, start=95, end=100)[1].mean()
        print(proxy, usage)
        ts = df.loc[(df["proxy"] == proxy) & (df["CPUPerc"] >= usage * 0.975), "timestamp"].iloc[0]
        timestamps.append(ts)

    plots = []
    for i, proxy in enumerate(order):
        color = _tex_color_name(proxy) # predefined in latex
        xs, ys = _usage(proxy)

        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{color}, line width=0.3mm] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    timestamps = ",".join([str(ts) for ts in timestamps])
    plots = "\n".join(plots)
    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
xlabel={{Time [s]}},
ylabel={{CPU Utilization [\\#]}},
y tick label style={{
    /pgf/number format/fixed,
    /pgf/number format/precision=1,
    /pgf/number format/1000 sep={{}},
}},
xmin=0, xmax=100,
ymax=36,
axis lines=left,
xticklabel style={{rotate=-0, yshift=-0.4ex}},
xlabel style={{anchor=north}},
xmajorgrids=true,
grid style=dashed,
legend pos=north west,
xtick={{{timestamps}}},
height=5cm,
width=\\linewidth]

{plots}

\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def rate_graph(name, dst):
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    df = df.groupby(["proxy", "timestamp"]).size().reset_index(name="rate")
    num_epochs = num_epochs.reset_index()
    num_epochs.columns = ["proxy", "num_epochs"]

    df = df.merge(num_epochs, on="proxy")
    df["rate"] = df["rate"] / df["num_epochs"]

    order = df["proxy"].unique()
    order = sorted(order)

    g = sns.lineplot(data=df, x="timestamp", y="rate", hue="proxy", marker="o", hue_order=order)
    # g.set(xlim=(200, 1100))
    # g.set(ylim=(None, 50))

    g.set_ylabel("rate [req/s]")
    g.set_xlabel("time [s]")
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"sn-rate", os.path.join(dst, name))


def rate_graph_tikz(name):
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    df = df.groupby(["proxy", "timestamp"]).size().reset_index(name="rate")
    num_epochs = num_epochs.reset_index()
    num_epochs.columns = ["proxy", "num_epochs"]

    df = df.merge(num_epochs, on="proxy")
    df["rate"] = df["rate"] / df["num_epochs"]

    order = df["proxy"].unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    def _rate(proxy, start=None, end=None):
        mask = df["proxy"] == proxy
        if start is not None:
            mask &= df["timestamp"] >= start
        if end is not None:
            mask &= df["timestamp"] <= end

        data = df[mask]
        return data["timestamp"], data["rate"]

    rates = []
    for proxy in order:
        rate = _rate(proxy, start=90, end=100)[1].mean()
        print(proxy, rate)
        rates.append(rate)

    plots = []
    for i, proxy in enumerate(order):
        color = _tex_color_name(proxy) # predefined in latex

        xs, ys = _rate(proxy)
        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{color}, line width=0.3mm] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    rates = ",".join([str(rate) for rate in rates])

    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
xlabel={{Time [s]}},
ylabel={{Throughput [req/s]}},
ymin=1000, ymax=4000,
xmax=100,
axis lines=left,
y tick label style={{
    /pgf/number format/fixed,
    /pgf/number format/precision=1,
    /pgf/number format/1000 sep={{}},
}},
yticklabel={{\\pgfmathparse{{\\tick/1000}}\\pgfmathprintnumber{{\\pgfmathresult}}K}},
scaled x ticks=false,
xlabel style={{anchor=north}},
ytick={{{rates}}},
tick style={{
    grid style=dashed,
}},
grid=major,
ymajorgrids=true,
xmajorgrids=false,
height=5cm,
width=\\linewidth]

{plots}

\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def _load_dissect_df(name):
    def _load_df(complexity):
        avg_req_latency = lambda df, proxy: df[(df["proxy"] == proxy) & (df["metric_name"] == "http_req_duration{expected_response:true}")]["avg"].mean()

        paths = _get_file_paths(f"{name}-c{complexity}_nobpf", "*k6*.json")
        if len(paths) == 0:
            return None

        print("Load complexity", complexity)

        k6 = _load_k6_summaries(paths)

        # l4fp does not have much network stack overhead because its sockets
        # are connected using the eBPF program
        l4fp = avg_req_latency(k6, "envoy_l4fp")
        envoy = avg_req_latency(k6, "envoy")
        beeline = avg_req_latency(k6, "beeline")
        ideal = avg_req_latency(k6, "none_l4fp")
        direct = avg_req_latency(k6, "none")

        print(f"beeline: {beeline}, envoy: {envoy}, lf4p: {l4fp}, direct: {direct}, ideal: {ideal}")

        l4fp -= ideal
        envoy -= ideal
        beeline -= ideal

        print("network stack direct:", direct - ideal)
        print("overhead from using beeline:", beeline)

        ns_envoy = envoy - l4fp
        print("overhead from using envoy:", envoy)
        print("envoy's network stack overhead:", ns_envoy)
        print("overhead from using envoy + L4 FP:", l4fp)

        iters = k6[k6["metric_name"] == "iterations"]["count"].mean()

        # we get the IPC, parsing etc overhead for every single request
        paths = _get_file_paths(f"{name}-c{complexity}", "*bpf*.log")
        df = _load_bpf_data(paths)
        df["mean"] = (df["total"] / iters) / 1e6

        df = df.groupby(by=["proxy", "func"]).agg({"mean": "mean"})

        # add the overhead from traversing the network stack
        df.loc[("envoy", "ipc"), "mean"] += ns_envoy

        # userspace processing contains parsing and I/O -> subtract parsing from processing so it's not represented twice
        df.loc[(slice(None), "user"), "mean"] -= df.loc[(slice(None), "parse"), "mean"].values

        # this is the overhead from running an eBPF program at the sk_msg level
        # the L4 fast path executes this twice as often as beeline
        sk_msg = beeline - df.loc[("beeline", slice(None)), "mean"].sum()
        df.loc[("beeline", "eBPF"), "mean"] = sk_msg
        df.loc[("envoy_l4fp", "eBPF"), "mean"] = 2*sk_msg

        # the remainder of the request duration is unaccounted for
        df.loc[("envoy", "unaccounted"), "mean"] = envoy - df.loc[("envoy", slice(None)), "mean"].sum()
        df.loc[("envoy_l4fp", "unaccounted"), "mean"] = l4fp - df.loc[("envoy_l4fp", slice(None)), "mean"].sum()
        df.loc[("beeline", "unaccounted"), "mean"] = beeline - df.loc[("beeline", slice(None)), "mean"].sum()

        # assert df.loc[("envoy", "unaccounted"), "mean"] < 0.5, f"envoy unaccounted: {df.loc[('envoy', 'unaccounted'), 'mean']}"
        # assert df.loc[("envoy_l4fp", "unaccounted"), "mean"] < 0.5, f"envoy_l4fp unaccounted: {df.loc[('envoy_l4fp', 'unaccounted'), 'mean']}"
        # assert df.loc[("beeline", "unaccounted"), "mean"] < 0.5, f"beeline unaccounted: {df.loc[('beeline', 'unaccounted'), 'mean']}"

        # sanity check that we're not misssing anything
        assert df.loc[("envoy", slice(None)), "mean"].sum().round(5) == envoy.round(5)
        assert df.loc[("envoy_l4fp", slice(None)), "mean"].sum().round(5) == l4fp.round(5)
        assert df.loc[("beeline", slice(None)), "mean"].sum().round(5) == beeline.round(5)

        # unaccounted goes into processing
        rename = {"user": "Processing", "unaccounted": "Processing", "ebpf": "eBPF", "parse": "Parsing", "epoll": "IPC", "ipc": "IPC", "read": "IPC", "write": "IPC"}
        df = df.rename(index=rename, level="func").reset_index()
        df["complexity"] = complexity
        df = df.groupby(by=["proxy", "func", "complexity"]).agg({"mean": "sum"})

        return df

    dfs = []
    for c in range(0, 20):
        df = _load_df(c)
        if df is not None:
            dfs.append(df)

    return pd.concat(dfs)


def dissect_graph(name, dst):
    df = _load_dissect_df(name)

    g = sns.barplot(data=df, x="proxy", y="mean", hue="func")
    g.set(xlabel="proxy", ylabel="overhead [ms]")

    _save_to_path(f"dissect-{name}", os.path.join(dst, name))


def dissect_graph_tikz(name):
    df = load_dissect_df(name)

    order = ["envoy", "l4fp", "beeline"]

    plots = []
    funcs = ["eBPF", "Processing", "Parsing", "IPC"]
    for f in funcs:
        coords = []
        for p in order:
            if (p, f) in df.index:
                v = df.loc[(p, f), "mean"]
                coords.append(f"({p}, {v})")
            else:
                coords.append(f"({p}, 0)")

        coords = " ".join(coords)
        style = "pattern=north west lines, draw=uchu-gray-5, pattern color=uchu-gray-5" if f == "echo" else ""
        plots.append(f"\\addplot+[ybar, {style}] plot coordinates {{{coords}}};")

    plots = "\n".join(plots)
    legend = ",".join(funcs)
    proxies = ",".join(order)

    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
ybar stacked,
ymin=0,
cycle list name=uchu,
every axis plot/.style={{fill}},
bar width=20pt,
ylabel={{latency [ms]}},
symbolic x coords={{{proxies}}},
legend columns = 4,
legend style={{at={{(0,1)}},draw=none,anchor=south west, /tikz/every even column/.append style={{column sep=0.25cm}}}},
xticklabels={{Envoy, {{Envoy + L4\\\\ Fast Path}}, {{Envoy +\\\\\\proj}}}},
xticklabel style={{align=center}},
xtick=data,
enlarge x limits={{abs=1.5cm}},
height=6cm,
width=\\linewidth]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


def dissect_complexity_graph_tikz(name):
    df = _load_dissect_df(name)

    order = ["envoy", "envoy_l4fp", "beeline"]
    complexities = sorted(df.index.get_level_values("complexity").unique())
    symbolic_coords = [f"c{c}" for c in complexities]

    axes = []
    funcs = ["eBPF", "Processing", "Parsing", "IPC"]
    shift = ["-10pt", "0pt", "10pt"]
    func_names = ",".join(funcs)

    for idx, p in enumerate(order):
        plots = []
        for f in funcs:
            coords = []
            for c in complexities:
                if (p, f, c) in df.index:
                    v = df.loc[(p, f, c), "mean"]
                    coords.append(f"(c{c}, {v})")
                else:
                    coords.append(f"(c{c}, 0)")

            coords = " ".join(coords)
            plots.append(f"\\addplot+ coordinates {{{coords}}};")

        hide_axis = "hide axis"
        legend = ""
        if idx == len(order)-1:
            legend = f"\\legend{{{func_names}}}"
            hide_axis = ""

        plots = "\n".join(plots)
        axis = f"""\\begin{{axis}}[bar shift={shift[idx]},{hide_axis}]
            {plots}
            {legend}
        \end{{axis}}
        """
        axes.append(axis)

    axes = "\n".join(axes)
    symbolic_coords = ",".join(symbolic_coords)

    tikz = f"""\\begin{{tikzpicture}}[
    every axis/.style={{
        ybar stacked,
        ymin=0,
        cycle list name=uchu,
        every axis plot/.style={{fill}},
        bar width=10pt,
        ylabel={{latency [ms]}},
        symbolic x coords={{{symbolic_coords}}},
        legend columns = 4,
        legend style={{at={{(0,1)}},draw=none,anchor=south west, /tikz/every even column/.append style={{column sep=0.25cm}}}},
        xticklabel style={{align=center}},
        xtick=data,
        enlarge x limits={{abs=1.5cm}},
        height=5cm,
        width=\\linewidth
    }}
    ]

{axes}

\\end{{tikzpicture}}"""
    print(tikz)


def percentile_graph(name, time_range, dst):
    (start, end) = _parse_time_range(time_range)
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)
    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    aggs = ["p(50)", "p(95)", "p(99)"]
    aggs = [(a, _aggregate_fn(a)) for a in aggs]
    df = df.groupby("proxy")["metric_value"].agg(aggs).reset_index()
    df = df.melt(id_vars="proxy",
                 var_name="percentile",
                 value_name="metric_value")

    order = df["proxy"].unique()
    order = sorted(order)

    g = sns.catplot(data=df, kind="bar", x="percentile", y="metric_value", hue="proxy", hue_order=order)
    g.set_axis_labels("", "Latency [ms]")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"sn-percentile", os.path.join(dst, name))


def percentile_graph_tikz(name, time_range):
    (start, end) = _parse_time_range(time_range)
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)
    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    # print(df[df["metric_value"] > 1000].to_string())

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    aggs = ["p(50)", "p(95)", "p(99)"]
    aggs_fn = [(a, _aggregate_fn(a)) for a in aggs]
    df = df.groupby("proxy")["metric_value"].agg(aggs_fn).reset_index()
    df = df.melt(id_vars="proxy",
                 var_name="percentile",
                 value_name="metric_value")

    order = df["proxy"].unique()
    order = sorted(order)

    if "beeline" in order:
        order.remove("beeline")
        order.insert(0, "beeline")

    legend = ",".join(order)

    plots = []
    for i, proxy in enumerate(order):
        color = f"{proxy}color" # predefined in latex
        fill = f"{proxy}fill" # predefined in latex

        xs = df[df["proxy"] == proxy]["percentile"]
        ys = df[df["proxy"] == proxy]["metric_value"]

        coordinates = [(x, y) for x, y in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{color}, fill={fill}, line width=0.3mm] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[ybar,
ylabel={{latency [ms]}},
ymin=0,
axis lines=left,
symbolic x coords={{{",".join(aggs)}}},
x tick label style={{
    /pgf/number format/fixed,
    /pgf/number format/precision=1,
    /pgf/number format/1000 sep={{}},
}},
scaled x ticks=false,
xtick=data,
enlarge x limits = 0.4,
xlabel style={{anchor=north}},
legend pos=north west,
height=5cm,
bar width=0.3cm,
width=\\linewidth]

{plots}

\\legend{{{legend}}}
\\end{{axis}}
\\end{{tikzpicture}}"""
    print(tikz)


# def scaling_graph(name, metric, agg, dst):
#     dfs = []
#     for i in range(1, 100):
#         paths = _get_file_paths(f"{name}-{i}", "*k6*summary*.json")
#         if len(paths) > 0:
#             df = _load_k6_summaries(paths)
#             df["services"] = i
#             dfs.append(df)

#     df = pd.concat(dfs)
#     df = df[df["metric_name"] == metric]
#     df = df.groupby(["proxy", "services"]).agg({agg: "mean"})
#     print(df)

#     g = sns.lineplot(data=df, x="services", y=agg, hue="proxy", marker="o")
#     g.set(xlabel="#Services", ylabel="Latency [ms]")

#     if args.legend:
#         _rename_legend_labels(g)

#     _save_to_path(f"scaling-{agg}", os.path.join(dst, name))

def scaling_graph(policy, metric, agg, dst):
    def _load_df(name):
        dfs = []
        for i in range(1, 100):
            paths = _get_file_paths(f"{name}-{i}", "*k6*summary*.json")
            if len(paths) > 0:
                df = _load_k6_summaries(paths)
                df["services"] = i
                dfs.append(df)
        return pd.concat(dfs)

    dfs = []
    policies = [("chain-mutate", "mutate"), ("chain-jwt", "jwt"), ("chain", "none")]
    for (name, pol) in policies:
        df = _load_df(name)
        df["policy"] = pol
        dfs.append(df)

    df = pd.concat(dfs)
    df = df[df["metric_name"] == metric]
    df = df.groupby(["proxy", "services", "policy"]).agg({agg: "mean"})

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    df = df.unstack(level=2)
    df.columns = df.columns.droplevel(0)
    df.columns.name = None

    # df['mutate'] = df['mutate'] - df['none']
    # df['jwt'] = df['jwt'] - df['none']
    # df = df.reset_index().melt(id_vars=["proxy", "services"], value_vars=["mutate", "jwt"], var_name="policy", value_name="value")
    df = df.reset_index()


    # df = df[df["policy"] == policy]
    df = df[df["services"] < 30]
    print(df)

    g = sns.catplot(data=df, kind="bar", x="services", y=policy, hue="proxy")
    g.set(xlabel="#Services", ylabel="Latency [ms]")

    plt.yscale("log")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"scaling-{agg}", os.path.join(dst, policy))


def _load_complexity_df(name, metric, agg):
    def _load_df(policy):
        dfs = []
        for i in range(1, 100):
            paths = _get_file_paths(f"{name}-p{policy}-c{i}", "*k6*summary*.json")
            if len(paths) > 0:
                df = _load_k6_summaries(paths)
                df["complexity"] = i
                df["policy"] = policy
                dfs.append(df)

        if len(dfs) == 0:
            return None

        return pd.concat(dfs)

    dfs = []
    for p in range(0, 20):
        df = _load_df(p)
        if df is not None:
            dfs.append(df)

    df = pd.concat(dfs)
    df = df[df["metric_name"] == metric]
    df = df.groupby(["proxy", "policy", "complexity"]).agg({agg: "mean"})
    # df.loc[(slice(None), slice(None), slice(None))] -= df.loc[(slice(None), slice(None), 1)]
    df = df.reset_index()

    return df


def complexity_graph(name, metric, agg, dst):
    df = _load_complexity_df(name, metric, agg)
    policies = sorted(df["policy"].unique())

    g = sns.FacetGrid(df, row="policy", row_order=policies, height=2, aspect=4)
    g.map_dataframe(sns.barplot, x="complexity", y=agg, hue="proxy")
    g.set(xlabel="Policies", ylabel="req/s")

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"complexity-{agg}", os.path.join(dst, name))


def complexity_graph_tikz(name, policy, metric, agg):
    df = _load_complexity_df(name, metric, agg)

    policies = [int(policy)] if policy else sorted(df["policy"].unique())
    for idx, policy in enumerate(policies):
        print(f"policy: {policy}")
        plots = []
        order = df["proxy"].unique()
        order = sorted(order)

        if "beeline" in order:
            order.remove("beeline")
            order.insert(0, "beeline")

        legend = ",".join([_tex_display_name(p) for p in order])

        for proxy in order:
            color = _tex_color_name(proxy, False)
            fill = _tex_color_name(proxy, True)

            xs = df[(df["proxy"] == proxy) & (df["policy"] == policy)]["complexity"]
            ys = df[(df["proxy"] == proxy) & (df["policy"] == policy)][agg]

            coordinates = [(x, y) for x, y in zip(xs, ys)]
            coordinates = sorted(coordinates)
            coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

            plot = f"""\\addplot[{color}, fill={fill}, line width=0.3mm] coordinates {{
                {coordinates}
            }};"""
            plots.append(plot)

        plots = "\n".join(plots)
        legend = f"\\legend{{{legend}}}"
        xlabel = "xlabel={Complexity},"

        if idx > 0:
            legend = ""
        if idx < len(policies)-1:
            xlabel = ""

        tikz = f"""\\begin{{tikzpicture}}
        \\begin{{axis}}[ybar,
        ylabel={{TPut [req/s]}}, {xlabel}
        ymin=0,
        axis lines=left,
        legend columns = 4,
        legend style={{at={{(0,1.1)}},draw=none,anchor=south west, /tikz/every even column/.append style={{column sep=0.25cm}}}},
        y tick label style={{
            /pgf/number format/fixed,
            /pgf/number format/precision=1,
            /pgf/number format/1000 sep={{}},
        }},
        yticklabel={{\\pgfkeys{{/pgf/fpu=true}}\\pgfmathparse{{\\tick/1000}}\\pgfmathprintnumber{{\\pgfmathresult}}K}},
        scaled y ticks=false,
        scaled x ticks=false,
        grid=major,
        ymajorgrids=true,
        xmajorgrids=false,
        tick style={{
            grid style=dashed,
        }},
        xtick=data,
        enlarge x limits = 0.4,
        xlabel style={{anchor=north}},
        height=2.5cm,
        bar width=20pt,
        width=\\linewidth]

        {plots}

        {legend}
        \\end{{axis}}
        \\end{{tikzpicture}}"""
        print(tikz)


if __name__ == "__main__":
    if args.command == "bp":
        box_plot(args.name, args.metric, args.output)
    elif args.command == "line":
        line_graph(args.name, args.metric, args.agg, args.output)
    elif args.command == "bar":
        bar_graph(args.name, args.metric, args.agg, args.output)
    elif args.command == "speedup":
        speedup_graph(args.name, args.base, args.metric, args.agg, args.output)
    elif args.command == "duration":
        duration_graph(args.name, args.proxy, args.agg, args.output)
    elif args.command == "overhead":
        overhead_graph(args.name, args.base, args.metric, args.agg, args.absolute, args.output)
    elif args.command == "cdf":
        cdf_graph(args.name, args.range, args.output)
    elif args.command == "cdf_tikz":
        cdf_graph_tikz(args.name, args.range)
    elif args.command == "scatter":
        scatter_graph(args.name, args.proxy, args.metric, float(args.drop), args.output)
    elif args.command == "time_profile":
        time_profile_graph_tikz(args.name, args.metric, args.agg)
    elif args.command == "lat":
        lat_graph(args.name, args.agg, args.output)
    elif args.command == "lat_tikz":
        lat_graph_tikz(args.name, args.range)
    elif args.command == "stats":
        stats_graph(args.output)
    elif args.command == "stats_tikz":
        stats_graph_tikz()
    elif args.command == "cpu":
        cpu_graph(args.name, args.output)
    elif args.command == "cpu_tikz":
        cpu_graph_tikz(args.name)
    elif args.command == "rate":
        rate_graph(args.name, args.output)
    elif args.command == "rate_tikz":
        rate_graph_tikz(args.name)
    elif args.command == "dissect":
        dissect_graph(args.name, args.output)
    elif args.command == "dissect_tikz":
        dissect_graph_tikz(args.name)
    elif args.command == "dissect_complexity_tikz":
        dissect_complexity_graph_tikz(args.name)
    elif args.command == "percentile":
        percentile_graph(args.name, args.range, args.output)
    elif args.command == "percentile_tikz":
        percentile_graph_tikz(args.name, args.range)
    elif args.command == "scaling":
        scaling_graph(args.name, args.metric, args.agg, args.output)
    elif args.command == "complexity":
        complexity_graph(args.name, args.metric, args.agg, args.output)
    elif args.command == "complexity_tikz":
        complexity_graph_tikz(args.name, args.policy, args.metric, args.agg)
