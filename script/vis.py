#!/usr/bin/env python

import json
import glob
import argparse
import re
import os
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

subparsers = parser.add_subparsers(dest="command")

cdf = subparsers.add_parser("cdf")
cdf.add_argument("-r", "--range", required=False, help="The time range")

stats = subparsers.add_parser("stats")
cpu = subparsers.add_parser("cpu")
rate = subparsers.add_parser("rate")

dissect = subparsers.add_parser("dissect")
dissect_complexity = subparsers.add_parser("dissect_complexity")
dissect_complexity.add_argument("-p", "--policy", type=int, required=True, help="The policy to visualize")
dissect_complexity.add_argument("-x", "--proxy", required=True, help="The proxy to visualize")

complexity = subparsers.add_parser("complexity")
complexity.add_argument("-p", "--policy", type=int, required=True, help="The policy to visualize")

lattput = subparsers.add_parser("lattput")

args = parser.parse_args()


def _parse_k6_path(path):
    match = re.search(r"(\w+)-k6-e(\d+)-*", path)
    proxy = match.group(1)
    epoch = match.group(2)

    return proxy, int(epoch)


def _parse_cpu_path(path):
    match = re.search(r"(\w+)-cpu-e(\d+).*", path)
    proxy = match.group(1)
    epoch = match.group(2)

    return proxy, int(epoch)


def _parse_rt_path(path):
    match = re.search(r"(\w+)-rt-(\w+)-e(\d+).*", path)
    proxy = match.group(1)
    func = match.group(2)
    epoch = match.group(3)

    return proxy, func, int(epoch)


def _load_k6_summaries(paths):
    rows = []
    for p in paths:
        proxy, epoch = _parse_k6_path(p)
        with open(p, "r") as file:
            data = json.load(file)
            data = data["metrics"]

            if data["http_req_failed"]["passes"] > 0.03 * data["http_reqs"]["count"]:
                ratio = data["http_req_failed"]["passes"] / data["http_reqs"]["count"]
                print(f"Skipping {p}: {ratio:.2%}")
                continue

            for (metric, aggs) in data.items():
                rows.append({
                    "proxy": proxy,
                    "metric_name": metric,
                    "epoch": epoch,
                    "file": p,
                    **aggs
                })

    df = pd.DataFrame.from_dict(rows)
    return df


def _load_k6_data(paths, max_epoch=30, min_duration=100):
    dfs = []
    epochs = {}
    for p in tqdm.tqdm(paths):
        proxy, epoch = _parse_k6_path(p)
        if epochs.get(proxy, 0) >= max_epoch:
            continue

        try:
            df = pd.read_csv(p, low_memory=False)
            df["proxy"] = proxy
            df["epoch"] = epoch
            # df["file"] = os.path.basename(p),
            df["timestamp"] -= df["timestamp"].min()

            if df["timestamp"].max() < min_duration:
                continue

            epochs[proxy] = epochs.get(proxy, 0) + 1

            dfs.append(df)
        except Exception as e:
            print(f"Error loading {p}: {e}")

    return pd.concat(dfs)


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


def _load_rt_data(paths):
    dfs = []
    for p in paths:
        proxy, func, epoch = _parse_rt_path(p)

        with open(p, "r") as file:
            text = file.read()
            pattern = r"total: (\d+) nsecs, count: (\d+)"
            match = re.search(pattern, text)

            if match is None:
                print(f"Could not find total/count in {p}")
                continue

            total = int(match.group(1))
            count = int(match.group(2))

            df = pd.DataFrame({"proxy": [proxy], "file": [os.path.basename(p)], "total": [total], "count": [count], "func": [func], "epoch": [epoch]})
            dfs.append(df)

    return pd.concat(dfs).reset_index(drop=True)


def _order_proxies(proxies):
    res = []

    if "beeline" in proxies:
        res.append("beeline")

    if "envoy_l4fp" in proxies:
        res.append("envoy_l4fp")

    if "envoy_iouring" in proxies:
        res.append("envoy_iouring")

    if "envoy" in proxies:
        res.append("envoy")

    if "none" in proxies:
        res.append("none")

    return res


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


def _tex_style_name(proxy):
    return proxy.replace("_", "")


def cdf_graph(name, time_range):
    (start, end) = _parse_time_range(time_range)

    plots = []
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)
    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    df = df[df["timestamp"] < 101] # experiment is only 100s long
    df = df[df["metric_value"] < 3000] # we have a timeout of 3s

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    order = _order_proxies(df["proxy"].unique())

    def _percentiles(proxy):
        vals = df[df["proxy"] == proxy]["metric_value"]

        ys = np.arange(0, 100)
        xs = np.percentile(vals, ys)
        return (xs, ys)

    avg_beeline = df[df["proxy"] == "beeline"]["metric_value"].mean()
    avg_envoy = df[df["proxy"] == "envoy"]["metric_value"].mean()
    avg_l4fp = df[df["proxy"] == "envoy_l4fp"]["metric_value"].mean()

    ps_beeline = _percentiles("beeline")[0]
    ps_envoy = _percentiles("envoy")[0]
    ps_l4fp = _percentiles("envoy_l4fp")[0]

    print(f"avg beeline: {avg_beeline} envoy: {avg_envoy} l4fp: {avg_l4fp}")
    print(f"p50 beeline: {ps_beeline[50]} envoy: {ps_envoy[50]} l4fp: {ps_l4fp[50]}")
    print(f"p75 beeline: {ps_beeline[75]} envoy: {ps_envoy[75]} l4fp: {ps_l4fp[75]}")
    print(f"p90 beeline: {ps_beeline[90]} envoy: {ps_envoy[90]} l4fp: {ps_l4fp[90]}")
    print(f"p95 beeline: {ps_beeline[95]} envoy: {ps_envoy[95]} l4fp: {ps_l4fp[95]}")
    print(f"p99 beeline: {ps_beeline[99]} envoy: {ps_envoy[99]} l4fp: {ps_l4fp[99]}")

    for i, proxy in enumerate(order):
        style = _tex_style_name(proxy) # predefined in latex
        (xs, ys) = _percentiles(proxy)

        coordinates = [(x, y/100.0) for x, y in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({x}, {y})" for x, y in coordinates])
        plots.append((style, coordinates))

    plots = [f"""\\addplot[{style}] coordinates {{
        {coordinates}
    }};""" for (style, coordinates) in plots]
    plots = "\n".join(plots)
    print(plots)


def stats_graph():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "..", "res", "stats", "stats.json")

    with open(path, "r") as f:
        data = json.load(f)

    filters = data["filters"]
    df = pd.DataFrame(filters)
    df["supported"] = df["name"].isin(["router", "cors", "ext_authz", "jwt", "compressor"])

    print(f"Repos: {len(df['repo_url'].unique())}")
    print(f"Configs: {len(df['download_url'].unique())}")

    print("Fully compatible configs:", df.groupby("download_url")["supported"].all().values.sum())

    df = df.groupby("name").size().reset_index(name="count").set_index("name")
    df["supported"] = df.index.isin(["router", "cors", "ext_authz", "jwt", "compressor"])

    num_filter_chains = data["filter_chains"]

    names = df.index.tolist()
    names[names.index("http1bridge")] = "grpc_http1"
    names[names.index("grpc_json_transcoder")] = "grpc_json"
    names[names.index("dynamic_forward_proxy")] = "forward_proxy"
    df = df.reset_index()
    df["name"] = names
    df["count"] = (df["count"] / num_filter_chains) * 100

    df = df.sort_values(by="count", ascending=False).head(10).reset_index(drop=True)

    cnt = len(df) + 1
    def _coords(df):
        coords = [f"({count: .1f},{cnt-idx-1})" for (idx, count) in zip(df.index, df["count"])]

        return coords

    supported = df.loc[df["supported"] == True]
    supported = "\n".join(_coords(supported))

    unsupported = df.loc[df["supported"] == False]
    unsupported = "\n".join(_coords(unsupported))

    labels = [name.replace("_", "\\_") for name in list(df["name"]) + ["other"]]
    labels = ",".join(reversed(labels))

    supported = f"""\\addplot[draw=uchu-green-5, fill=uchu-green-1] coordinates {{
{supported}
}};"""
    unsupported = f"""\\addplot[draw=uchu-red-5, fill=uchu-red-1] coordinates {{
{unsupported}
}};"""

    plots = "\n".join([supported, unsupported])
    print(plots)

    print(f"yticklabels={{{labels}}}")


def cpu_graph(name):
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

    order = _order_proxies(df["proxy"].unique())

    # Subtract the corresponding minimum timestamp
    for proxy in order:
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

    plots = []
    for i, proxy in enumerate(order):
        style = _tex_style_name(proxy) # predefined in latex
        xs, ys = _usage(proxy)

        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{style}] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    print(plots)


def rate_graph(name):
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

    order = _order_proxies(df["proxy"].unique())

    for p in order:
        print(f"{p}: {df[df['proxy'] == p]['rate'].max()}")

    def _rate(proxy, start=None, end=None):
        mask = df["proxy"] == proxy
        if start is not None:
            mask &= df["timestamp"] >= start
        if end is not None:
            mask &= df["timestamp"] <= end

        data = df[mask]
        return data["timestamp"], data["rate"]

    plots = []
    for i, proxy in enumerate(order):
        style = _tex_style_name(proxy) # predefined in latex

        xs, ys = _rate(proxy)
        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{style}] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    print(plots)


def _load_dissect_df(name):
    avg_req_latency = lambda df, proxy: df[(df["proxy"] == proxy) & (df["metric_name"] == "http_req_duration{expected_response:true}")]["avg"].mean()

    paths = _get_file_paths(name, "*k6*.json")
    if len(paths) == 0:
        return None

    k6 = _load_k6_summaries(paths)

    # l4fp does not have much network stack overhead because its sockets
    # are connected using the eBPF program
    l4fp = avg_req_latency(k6, "envoy_l4fp")
    envoy = avg_req_latency(k6, "envoy")
    beeline = avg_req_latency(k6, "beeline")

    iters = k6[k6["metric_name"] == "iterations"].set_index("proxy")["count"].rename("reqs")

    # we get the IPC, parsing etc overhead for every single request
    paths = _get_file_paths(name, "*rt*.log")
    df = _load_rt_data(paths)
    df = df.merge(iters, on="proxy")
    df["mean"] = (df["total"] / df["reqs"]) / 1e6

    df = df.groupby(by=["proxy", "func"]).agg({"mean": "mean"})

    # userspace processing contains everything else -> subtract from processing so it's not represented twice
    df.loc[("beeline", "user"), "mean"] -= df.loc[("beeline", "parse"), "mean"]
    for p in ["envoy", "envoy_l4fp"]:
        df.loc[(p, "user"), "mean"] -= df.loc[(p, "parse"), "mean"].sum()
        df.loc[(p, "user"), "mean"] -= df.loc[(p, "ipc"), "mean"].sum()

    ideal = beeline - df.loc[("beeline", slice(None)), "mean"].sum()
    print("request latency:")
    print(f"beeline: {beeline}, envoy: {envoy}, lf4p: {l4fp}, ideal: {ideal}")

    beeline -= ideal
    envoy -= ideal
    l4fp -= ideal

    print("overhead:")
    print(f"beeline: {beeline}, envoy: {envoy}, lf4p: {l4fp}")

    print("measured components total:")
    beeline_comp = df.loc[("beeline", slice(None)), "mean"].sum()
    envoy_comp = df.loc[("envoy", slice(None)), "mean"].sum()
    l4fp_comp = df.loc[("envoy_l4fp", slice(None)), "mean"].sum()
    print(f"beeline: {beeline_comp}, envoy: {envoy_comp}, lf4p: {l4fp_comp}")

    # the remainder of the request duration is unaccounted for
    df.loc[("envoy", "unaccounted"), "mean"] = envoy - df.loc[("envoy", slice(None)), "mean"].sum()
    df.loc[("envoy_l4fp", "unaccounted"), "mean"] = l4fp - df.loc[("envoy_l4fp", slice(None)), "mean"].sum()
    df.loc[("beeline", "unaccounted"), "mean"] = beeline - df.loc[("beeline", slice(None)), "mean"].sum()

    assert 0 <= df.loc[("envoy", "unaccounted"), "mean"].round(2), f"envoy unaccounted: {df.loc[('envoy', 'unaccounted'), 'mean']}"
    assert 0 <= df.loc[("envoy_l4fp", "unaccounted"), "mean"].round(2), f"envoy_l4fp unaccounted: {df.loc[('envoy_l4fp', 'unaccounted'), 'mean']}"
    assert 0 <= df.loc[("beeline", "unaccounted"), "mean"].round(2), f"beeline unaccounted: {df.loc[('beeline', 'unaccounted'), 'mean']}"

    # unaccounted is mostly the overhead of the uprobes, removing it from parsing
    rename = {"user": "Policy Enforcement", "parse": "Parsing", "ipc": "IPC", "unaccounted": "Other"}
    df = df.rename(index=rename, level="func").reset_index()
    df = df.groupby(by=["proxy", "func"]).agg({"mean": "sum"})

    return df


def dissect_graph(name):
    df = _load_dissect_df(name)
    print(df)

    order = ["envoy", "envoy_l4fp", "beeline"]
    plots = []
    funcs = ["Policy Enforcement", "Parsing", "IPC", "Other"]
    for f in funcs:
        coords = []
        for i, p in enumerate(order):
            if (p, f) in df.index:
                v = df.loc[(p, f), "mean"]
                coords.append(f"({i+1}, {v})")
            else:
                coords.append(f"({i+1}, 0)")

        coords = " ".join(coords)
        style = "pattern=north west lines, draw=uchu-gray-5, pattern color=uchu-gray-5" if f == "Other" else ""
        plots.append(f"\\addplot+[ybar, {style}] plot coordinates {{{coords}}};")

    plots = "\n".join(plots)
    print(plots)


def _load_dissect_complexity_df(name, policy):
    paths = _get_file_paths(f"{name}/p{policy}-*", "*k6*summary*.json")
    dfs = []
    for p in paths:
        folder = os.path.dirname(p)
        name = os.path.basename(folder)
        args = [s for s in name.split("-")[1:]]
        args = {args[i]: int(args[i+1]) for i in range(0, len(args), 2)}

        try:
            df = _load_dissect_df(folder)
            df["policy"] = policy
            df["complexity"] = args["n1"] * args["m1"]

            dfs.append(df)
        except Exception as e:
            print(f"Error loading {folder}: {e}")

    df = pd.concat(dfs)
    df = df.groupby(["proxy", "func", "complexity"]).agg({"mean": "mean"})

    return df


def dissect_complexity_graph(name, policy, proxy):
    df = _load_dissect_complexity_df(name, policy)
    complexities = sorted(df.index.get_level_values("complexity").unique())
    funcs = ["Policy Enforcement", "Parsing", "IPC", "Other"]
    line_style = {
        funcs[0]: "uchu-green-5",
        funcs[1]: "uchu-blue-5",
        funcs[2]: "uchu-orange-5",
        funcs[3]: "uchu-gray-5"
    }
    fill_style = {
        funcs[0]: "uchu-green-1",
        funcs[1]: "uchu-blue-1",
        funcs[2]: "uchu-orange-1",
        funcs[3]: "uchu-gray-1"
    }
    stack = {c: 0 for c in complexities}
    plots = []

    max_complexity = max(complexities)
    plots.append(f"\\path[name path=axis] (axis cs:0,0) -- (axis cs:{max_complexity},0);")

    for idx, f in enumerate(funcs):
        coords = []
        for c in complexities:
            if (proxy, f, c) in df.index:
                stack[c] += df.loc[(proxy, f, c), "mean"]
                coords.append(f"({c}, {stack[c]})")
            else:
                coords.append(f"({c}, 0)")

        coords = " ".join(coords)
        pf = funcs[idx-1] if idx > 0 else "axis"

        plots.append(f"\\addplot[name path={f}, {line_style[f]}] coordinates {{{coords}}};")
        plots.append(f"\\addplot[{fill_style[f]}] fill between[of = {f} and {pf}];")

    plots = "\n".join(plots)
    print(plots)


def _load_complexity_df(name, policy, metric, agg):
    paths = _get_file_paths(f"{name}/p{policy}-*", "*k6*summary*.json")
    dfs = []
    for p in paths:
        folder = os.path.dirname(p)
        name = os.path.basename(folder)
        args = [s for s in name.split("-")[1:]]
        args = {args[i]: int(args[i+1]) for i in range(0, len(args), 2)}

        df = _load_k6_summaries([p])
        df["policy"] = policy
        df["complexity"] = args["n1"] * args["m1"]

        dfs.append(df)

    df = pd.concat(dfs)
    df = df[df["metric_name"] == metric]

    num_comps = df.groupby(["proxy", "policy", "complexity"]).size().reset_index(name="count")
    print(num_comps.to_string())

    df = df.groupby(["proxy", "policy", "complexity"]).agg({agg: "mean"})
    df = df.reset_index()

    return df


def complexity_graph(name, policy):
    df = _load_complexity_df(name, policy, "http_reqs", "rate")
    plots = []
    order = _order_proxies(df["proxy"].unique())

    for proxy in order:
        style = _tex_style_name(proxy)

        xs = df[(df["proxy"] == proxy) & (df["policy"] == policy)]["complexity"]
        ys = df[(df["proxy"] == proxy) & (df["policy"] == policy)]["rate"]

        coordinates = [(x, y) for x, y in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{style}] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    print(plots)


def lattput_graph(name):
    paths = _get_file_paths(name, "*full.csv")
    df = _load_k6_data(paths)

    df = df[df["timestamp"] < 101] # experiment is only 100s long
    df = df[df["metric_value"] < 3000] # we have a timeout of 3s

    num_epochs = df.reset_index().groupby("proxy")["epoch"].nunique()
    print("Number of epochs per proxy:")
    print(num_epochs.to_string())

    grouped = df.groupby(["proxy", "timestamp"])

    df = pd.DataFrame({
        "http_req_duration": grouped["metric_value"].mean(),
        "rate": grouped.size()
    }).reset_index()
    num_epochs = num_epochs.reset_index()
    num_epochs.columns = ["proxy", "num_epochs"]

    df = df.merge(num_epochs, on="proxy")
    df["rate"] = np.round(df["rate"] / df["num_epochs"])
    # df = df.groupby(["proxy", "rate"]).agg({"http_req_duration": "mean"}).reset_index()

    order = _order_proxies(df["proxy"].unique())

    plots = []
    for i, proxy in enumerate(order):
        style = _tex_style_name(proxy) # predefined in latex

        pdf = df[df["proxy"] == proxy]
        print(pdf.to_string())
        pdf = pdf[["rate", "http_req_duration"]]
        pdf = pdf.set_index("rate")

        xs = np.arange(20, pdf.index.max(), 25).astype(int)
        pdf_nan = pd.DataFrame(np.NaN, index=xs, columns=["http_req_duration"])
        pdf = pd.concat([pdf, pdf_nan]).sort_index()
        print(pdf.to_string())
        pdf = pdf.interpolate()

        ys = pdf.loc[xs, "http_req_duration"]

        # pdf = pdf.rolling(window=5, min_periods=1).mean()

        # xs = pdf["rate"]
        # ys = pdf["http_req_duration"]

        coordinates = [(rate, val) for rate, val in zip(xs, ys)]
        coordinates = sorted(coordinates)
        coordinates = "\n".join([f"({rate}, {val})" for rate, val in coordinates])

        plot = f"""\\addplot[{style}] coordinates {{
            {coordinates}
        }};"""
        plots.append(plot)

    plots = "\n".join(plots)
    print(plots)


if __name__ == "__main__":
    if args.command == "cdf":
        cdf_graph(args.name, args.range)
    elif args.command == "stats":
        stats_graph()
    elif args.command == "cpu":
        cpu_graph(args.name)
    elif args.command == "rate":
        rate_graph(args.name)
    elif args.command == "dissect":
        dissect_graph(args.name)
    elif args.command == "dissect_complexity":
        dissect_complexity_graph(args.name, args.policy, args.proxy)
    elif args.command == "complexity":
        complexity_graph(args.name, args.policy)
    elif args.command == "lattput":
        lattput_graph(args.name)
