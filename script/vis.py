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

REWRITE_LEGEND = False

def thousand_label(x, pos): 
    return "%1.0fK" % (x * 1e-3) if x >= 1e3 else "%1.0f" % x

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
                    "file": os.path.basename(p),
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
        df["file"] = os.path.basename(p)

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
    name = name.replace("(", "")
    name = name.replace(")", "")

    # plt.tight_layout()
    path = os.path.join(dst, name)
    if os.path.splitext(path)[1] == "":
        path += ".png"

    print("Writing to", path)

    os.makedirs(dst, exist_ok=True)
    plt.savefig(path, dpi=400)


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
    return glob.glob(os.path.join(dir_path, "..", "res", "runs", name, filename_pattern))


def _rename_legend_labels(g):
    print("How do you want to call the proxies?")
    for text in g._legend.texts:
        proxy = text.get_text()
        new_name = input(f"{proxy}: ").strip()
        if len(new_name) > 0:
            text.set_text(new_name)


def line_graph(name, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_summary_data(paths)
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

    if REWRITE_LEGEND:
        _rename_legend_labels(g)
    
    _save_to_path(f"line-{metric}-{agg}", os.path.join(dst, name))


def bar_graph(name, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_summary_data(paths)
    df = df.xs(metric, level="metric_name")

    df[agg] = df[agg] / 1e6

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    g = sns.catplot(data=df, kind="bar", x="payload_size", y=agg, hue="proxy", errorbar="sd", hue_order=order)
    
    sizes = set(df.index.get_level_values("payload_size"))
    sizes = sorted(sizes)

    g.set(xlabel="payload size [B]", ylabel="throughput [MB/s]")
    
    # g.set_xscale("log")
    # g.set_xlabel("payload size [B]")
    # g.set_xticks(sizes)
    # g.set_xticklabels([str(s) for s in sizes])
    # g.xaxis.set_major_formatter(ticker.FuncFormatter(thousand_label))
    # g.set_xbound(lower=sizes[0], upper=sizes[-1])

    print(df[agg])

    max_y = df[agg].max()
    g.set(yticks=np.linspace(0, max_y, 5))
    for ax in g.axes.flat:
        ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    # sns.move_legend(g, "upper center")

    if REWRITE_LEGEND:
        _rename_legend_labels(g)
    
    _save_to_path(f"bar-{metric}-{agg}", os.path.join(dst, name))           


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
    
    if REWRITE_LEGEND:
        _rename_legend_labels(g)

    sns.move_legend(g, "upper right")
    _save_to_path(f"speedup-{metric}", os.path.join(dst, name))


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
    
    if REWRITE_LEGEND:
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

    # df = df.drop("envoy", axis=1)
    # df = df.drop("splice", axis=1)
    # assert(np.all(df["ebpf"] >= 0))
    # assert(np.all(df["envoy"] >= 0))

    g = df.plot(kind="bar")
    g.set_xlabel("payload size [B]")
    g.set_ylabel("time [ms]" if absolute else "overhead [%]")
    
    if REWRITE_LEGEND:
        _rename_legend_labels(g)
    
    _save_to_path(f"overhead-{metric}-{agg}", os.path.join(dst, name))


def cdf_graph(name, metric, crop, dst):
    paths = _get_file_paths(name, "*.gz")
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
    
    if REWRITE_LEGEND:
        _rename_legend_labels(g)

    plt.xscale("log")
    _save_to_path(f"cdf-{metric}-@{crop}s", os.path.join(dst, name))


def scatter_graph(name, proxy, metric, drop_rate, dst):
    paths = _get_file_paths(name, "*.gz")
    df = _load_log_data(paths)
    df = df[df["metric_name"] == metric]

    df = df[df["proxy"] == proxy]
    df["timestamp"] -= df["timestamp"].min()

    drop_num = int(drop_rate * len(df))
    if drop_num > 0:
        print(f"Dropping {drop_num} samples ({drop_rate*100}%)")
        df = df.sample(n=len(df)-drop_num).sort_index()

    g = sns.scatterplot(data=df, x="timestamp", y="metric_value", hue="proxy")

    g.set_xlabel("time [s]")

    min_y = df["metric_value"].min()
    max_y = df["metric_value"].max()
    g.set_yticks(np.linspace(min_y, max_y, 5))
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))
    g.set_ylabel(f"{metric} [ms]")

    if REWRITE_LEGEND:
        _rename_legend_labels(g)
    
    _save_to_path(f"scatter-{proxy}-{metric}-@{str(round(100*(1-drop_rate)))}%", os.path.join(dst, name))


def surface_graph(name, proxy, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_summary_data(paths)
    df = df[df.index.get_level_values("proxy") == proxy]
    df = df.reset_index().set_index("payload_size")

    val = df[df["metric_name"] == metric][agg]
    rate = df[df["metric_name"] == "http_reqs"]["rate"]
    payload_sizes = val.index

    assert(np.all(val.index == rate.index))

    file = df[df["metric_name"] == metric]["file"]
    stats = pd.DataFrame({"rate": rate, metric: val, "file": file})
    stats = stats.sort_values(by=["payload_size", "rate"])

    # otherwise benchmark was broken
    if np.any(rate < 3000):
        print("Warning: low rate detected")
        print(stats[stats["rate"] < 3000])
        exit(-1)
    else:
        print(stats)

    fig = plt.figure()
    ax = fig.add_subplot(projection="3d")
    ax.plot_trisurf(payload_sizes, rate, val, cmap=plt.cm.viridis, linewidth=0.2)

    ax.set_ylabel("rate [req/s]")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(thousand_label))
    ax.set_yticks([5000, 10000, 15000, 20000])
    ax.set_ylim([5000, 20000])
    ax.set_xlabel("payload size [B]")
    ax.set_xticks([128, 4096, 8192, 16384])
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(thousand_label))
    ax.set_xlim([16384, 128])
    ax.set_zlabel("latency [ms]")
    
    _save_to_path(f"surface-{proxy}-{metric}-{agg}", os.path.join(dst, name))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", help="Name of the experiment")
    parser.add_argument("-l", "--legend", default=False, action=argparse.BooleanOptionalAction, help="Rename the legend labels")
    parser.add_argument("-o", "--output", default="res/vis", help="Can be an output directory or file")

    subparsers = parser.add_subparsers(dest="command")
    
    line = subparsers.add_parser("line")
    line.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    line.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

    bar = subparsers.add_parser("bar")
    bar.add_argument("-m", "--metric", default="data_received", help="The recorded metric to visualize")
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
    cdf.add_argument("-m", "--metric", default="http_req_duration", help="The recorded metric to visualize")
    cdf.add_argument("-c", "--crop", default=0, help="Crop the given number of seconds from the beginning of the trace")

    scatter = subparsers.add_parser("scatter")
    scatter.add_argument("-p", "--proxy", required=True, help="The recorded proxy to visualize")
    scatter.add_argument("-m", "--metric", default="http_req_duration", help="The recorded metric to visualize")
    scatter.add_argument("-d", "--drop", default=0, help="Drop rate of the recorded metric")

    surface = subparsers.add_parser("surface")
    surface.add_argument("-p", "--proxy", required=True, help="The recorded proxy to visualize")
    surface.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
    surface.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")
    
    args = parser.parse_args()

    if args.legend is not False:
        # global REWRITE_LEGEND
        REWRITE_LEGEND = args.legend

    if args.command == "line":
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
        cdf_graph(args.name, args.metric, float(args.crop), args.output)
    elif args.command == "scatter":
        scatter_graph(args.name, args.proxy, args.metric, float(args.drop), args.output)
    elif args.command == "surface":
        surface_graph(args.name, args.proxy, args.metric, args.agg, args.output)
