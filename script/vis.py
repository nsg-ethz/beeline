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

time_profile = subparsers.add_parser("time_profile")
time_profile.add_argument("-m", "--metric", default="http_req_duration", help="The recorded metric to visualize")
time_profile.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

surface = subparsers.add_parser("surface")
surface.add_argument("-p", "--proxy", required=True, help="The recorded proxy to visualize")
surface.add_argument("-m", "--metric", default="http_req_duration{expected_response:true}", help="The recorded metric to visualize")
surface.add_argument("-a", "--agg", default="p(95)", help="The aggregation func")

stats = subparsers.add_parser("stats")
stats = subparsers.add_parser("stats_tikz")

sn = subparsers.add_parser("sn")
sn.add_argument("-a", "--agg", default="p(90)", help="The aggregation func")

sn = subparsers.add_parser("sn_tikz")

args = parser.parse_args()

def thousand_label(x, pos):
    return "%1.0fK" % (x * 1e-3) if x >= 1e3 else "%1.0f" % x


def _parse_k6_path(path):
    match = re.search(r"(\w+)-(\d+)B*.*", path)
    proxy = match.group(1)
    size = match.group(2)

    return proxy, int(size)


def _parse_wrk_path(path):
    match = re.search(r"(\w+)-(\d+).*", path)
    proxy = match.group(1)
    rate = match.group(2)

    return proxy, int(rate)


def _load_k6_data(paths):
    rows = []
    for p in paths:
        proxy, payload_size = _parse_k6_path(p)
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

def _load_wrk_data(paths):
    rows = []
    for p in paths:
        proxy, rate = _parse_wrk_path(p)
        with open(p, "r") as file:
            text = file.read()
            ps = [
                "p(10)",
                "p(25)",
                "p(50)",
                "p(75)",
                "p(90)",
                "p(99)",
                "p(99.9)",
                "p(99.99)",
                "p(99.999)",
            ]

            aggs = {}
            for percentile in ps:
                escaped_percentile = re.escape(percentile)
                pattern = rf"{escaped_percentile}:\s*(\d+\.\d+)"
                match = re.search(pattern, text)

                if match is None:
                    raise ValueError(f"Could not find {percentile} in {p}")

                latency = match.group(1)
                aggs[percentile] = float(latency)

            rows.append({
                "proxy": proxy,
                "rate": rate,
                "metric_name": "http_req_duration",
                "file": os.path.basename(p),
                **aggs
            })

    df = pd.DataFrame.from_dict(rows)
    df.set_index(["proxy", "rate", "metric_name"], inplace=True)

    return df

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
        df = _load_k6_data(paths)

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


def box_plot(name, metric, dst):
    paths = _get_file_paths(name)
    df = _load_k6_data(paths)
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
    df = _load_k6_data(paths)
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
    df = _load_k6_data(paths)
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

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"bar-{metric}-{agg}", os.path.join(dst, name))


def speedup_graph(name, base, metric, aggs, dst):
    paths = _get_file_paths(name)
    df = _load_k6_data(paths)
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
    df = _load_k6_data(paths)
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

    df = _preprocess(_load_k6_data(paths))

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


def cdf_graph(name, metric, crop, dst):
    paths = _get_file_paths(name, "*.csv")
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

    if args.legend:
        _rename_legend_labels(g)

    plt.xscale("log")
    _save_to_path(f"cdf-{metric}-@{crop}s", os.path.join(dst, name))


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

    g.set_xlabel("time [s]")

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
        ylabel={{latency [ms]}},
        xlabel={{time [s]}},
        xmin=0, xmax=30,
        axis lines=left,
        xticklabel style={{rotate=-0, yshift=-0.4ex}},
        xlabel style={{anchor=north}},
        xmajorgrids=true,
        grid style=dashed,
        legend pos=north east,
        height=6cm,
        width=\\linewidth
    ]

    {plots}

    \\legend{{{legend}}}
    \\end{{axis}}
    \\end{{tikzpicture}}"""
    print(tikz)



def surface_graph(name, proxy, metric, agg, dst):
    paths = _get_file_paths(name)
    df = _load_k6_data(paths)
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


def sn_graph(name, agg, dst):
    paths = _get_file_paths(name, "*.log")
    df = _load_wrk_data(paths)

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    g = sns.lineplot(data=df, x="rate", y=agg, hue="proxy", marker="o", hue_order=order)
    rates = set(df.index.get_level_values("rate"))
    rates = sorted(rates)

    shown_rates = rates[::5]  # Take every 5th element

    g.set_xlabel("rate [req/s]")
    g.set_xticks(shown_rates)  # Set ticks only for the selected rates
    g.xaxis.set_major_formatter(ticker.FuncFormatter(thousand_label))
    g.set_xbound(lower=rates[0], upper=rates[-1])

    g.set_yscale("log")
    g.set_ylabel("latency [ms]")
    # min_y = df[agg].min()
    # max_y = df[agg].max()
    # g.set_yticks(np.linspace(min_y, max_y, 5))
    g.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    if args.legend:
        _rename_legend_labels(g)

    _save_to_path(f"sn-latency-{agg}", os.path.join(dst, name))


def sn_graph_tikz(name):
    paths = _get_file_paths(name, "*.log")
    df = _load_wrk_data(paths)
    df = df.xs("http_req_duration", level="metric_name", drop_level=True)

    strawman = df[df.index.get_level_values("proxy") == "strawman"].droplevel("proxy")
    baseline = df[df.index.get_level_values("proxy") == "baseline"].droplevel("proxy")
    beeline = df[df.index.get_level_values("proxy") == "beeline"].droplevel("proxy")

    # print(strawman)
    # print(baseline)
    # print(beeline)

    print("Speedup vs baseline:\n", baseline["p(90)"] / beeline["p(90)"])
    exit()

    order = df.index.get_level_values("proxy").unique()
    order = sorted(order)

    order.remove("beeline")
    order.insert(0, "beeline")

    legend = ",".join(order)

    plots = []
    for i, proxy in enumerate(order):
        color = f"{proxy}color" # predefined in latex
        low = f"low{proxy}"
        high = f"high{proxy}"
        median = f"median{proxy}"

        lines = [
            (low, "p(10)", False),
            (high, "p(90)", False),
            (median, "p(50)", True)
        ]
        for (line, agg, visible) in lines:
            vals = df[agg].xs(proxy, level="proxy")

            coordinates = [(rate, val) for rate, val in zip(vals.index, vals)]
            coordinates = sorted(coordinates)
            coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

            visibility = "" if visible else ",draw=none"
            plot = f"""\\addplot[{color},name path={line},{visibility}, line width=0.3mm, forget plot] coordinates {{
                {coordinates}
            }};"""
            plots.append(plot)

        fill = f"""\\addplot[{color},fill opacity=0.2] fill between[of={low} and {high}];"""
        plots.append(fill)

    plots = "\n".join(plots)
    tikz = f"""\\begin{{tikzpicture}}
\\begin{{axis}}[
xlabel={{requests per second}},
ylabel={{latency [ms]}},
xmin=200, xmax=2600,
ymode=log,
axis lines=left,
xticklabel style={{rotate=-0, yshift=-0.4ex}},
xlabel style={{anchor=north}},
xmajorgrids=true,
grid style=dashed,
legend pos=south east,
height=6cm,
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
    print(f"Pure filters: {supported["count"].sum()}")
    supported = "\n".join(_coords(supported))

    unsupported = df.loc[df["stateless"] == False]
    unsupported = "\n".join(_coords(unsupported))

    other = "\n".join(_coords(other))

    labels = [name.replace("_", "\\_") for name in list(df["name"]) + ["other"]]
    labels = ",".join(reversed(labels))

    # colors = ["uchu-green-5" if ok else "uchu-red-5" for ok in beelineable]
    # colors = ",".join(colors)

    legend = "Pure, With side effects"

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
        cdf_graph(args.name, args.metric, float(args.crop), args.output)
    elif args.command == "scatter":
        scatter_graph(args.name, args.proxy, args.metric, float(args.drop), args.output)
    elif args.command == "time_profile":
        time_profile_graph_tikz(args.name, args.metric, args.agg)
    elif args.command == "surface":
        surface_graph(args.name, args.proxy, args.metric, args.agg, args.output)
    elif args.command == "sn":
        sn_graph(args.name, args.agg, args.output)
    elif args.command == "sn_tikz":
        sn_graph_tikz(args.name)
    elif args.command == "stats":
        stats_graph(args.output)
    elif args.command == "stats_tikz":
        stats_graph_tikz()
