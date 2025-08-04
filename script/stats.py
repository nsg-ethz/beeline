#!/usr/bin/env python

import argparse
from datetime import datetime
from http.client import HTTP_PORT
from github import Github, Auth
import json
import os
from numpy import fix
from pandas.core.generic import T
from peewee import *
import re
import subprocess
import time
import yaml

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command")

search_cmd = subparsers.add_parser("search")
search_cmd.add_argument("--db", default="res/stats/github.db", help="Path to the SQLite database")

count_cmd = subparsers.add_parser("count")
count_cmd.add_argument("--db", default="res/stats/github.db", help="Path to the SQLite database")
count_cmd.add_argument("-p", "--path", help="Path to write the statistics in JSON")
args = parser.parse_args()

db = SqliteDatabase(args.db)

class BaseModel(Model):
    class Meta:
        database = db

class File(BaseModel):
    name = CharField()
    download_url = CharField(unique=True)
    content = CharField(unique=True)


token = os.environ.get("GITHUB_API")
auth = Auth.Token(token)
g = Github(auth=auth)

def search():
    db.connect()
    db.create_tables([File])

    step = 1000
    size = 0
    while size < 20000:
        size_range = f"{size}..{size+step}"
        print(f"Searching for files with size {size_range}")

        res = g.search_code(f"http_filters filename:envoy.yml OR filename:envoy.yaml size:{size_range}")
        print(f"Found {res.totalCount} files")

        if res.totalCount >= 1000 and step > 1:
            print(f"Too many files for size range {size_range}")
            step = max(int(step / 2), 1)
            continue
        else:
            step = 1000
            size += step

        for file in res:
            print(file.download_url)

            try:
                file = File(name=file.name, download_url=file.download_url, content=file.decoded_content)
                file.save()
            except IntegrityError:
                print(f"File {file.name} already exists in the database. Continuing...")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                continue


def sanitize_filter_name(name):
    name = name.replace("envoy.", "")
    name = name.replace("http.", "")
    name = name.replace("filters.", "")
    name = name.replace("extensions.", "")
    name = name.replace("rate_limit", "ratelimit")

    if "extproc" in name:
        name = "ext_proc"

    if name == "rewrite":
        name = "header_mutation"

    if name == "gzip":
        name = "compressor"

    generic_filters = ["lua", "wasm", "header_mutation", "basic_auth", "ext_authz", "ext_proc", "jwt", "router", "oauth2", "grpc_json_transcoder"]
    for gf in generic_filters:
        if gf in name:
            name = gf
            break

        if "decompressor" in name and "compressor" not in name:
            name = "decompressor"
        elif "compressor" in name and "decompressor" not in name:
            name = "compressor"

    return name


def sanitize_config(text):
    text = re.sub(r"{%.*?%}", "", text, flags=re.DOTALL)
    text = re.sub(r"{{-.*?}}", "", text, flags=re.DOTALL)
    text = re.sub(r"{{.*?}}", "placeholder", text, flags=re.DOTALL)

    return text


def count(path):
    db.connect()

    files = File.select()
    print(f"Analysing {len(files)} files...")

    filters = dict()
    http_configs = set()
    num_errors = 0

    def _iter_http_filters(config):
        if isinstance(config, dict):
            for (key, val) in config.items():
                if key == "http_filters" and isinstance(val, list):
                    yield val
                elif isinstance(val, dict) or isinstance(val, list):
                    yield from _iter_http_filters(val)
        elif isinstance(config, list):
            for item in config:
                yield from _iter_http_filters(item)

    def _parse(content):
        nonlocal num_errors

        try:
            configs = yaml.safe_load_all(content)

            for config in configs:
                if not isinstance(config, dict):
                    continue

                if "data" in config:
                    keys = [k for k in config.get("data").keys() if "envoy" in k]
                    if len(keys) != 1:
                        # print(f"Could not find envoy config: {config.get("data").keys()} in {file.download_url}")
                        continue

                    _parse(config.get("data").get(keys[0]))
                    continue

                for http_filters in _iter_http_filters(config):
                    if len(http_filters) > 0:
                        http_configs.add(file.download_url)

                    for http_filter in http_filters:
                        name = http_filter.get("name")
                        if not name:
                            print(f"Unknown http_filter format: {http_filter}")
                            continue
                        http_filter_type = sanitize_filter_name(name)
                        if http_filter_type not in filters:
                            filters[http_filter_type] = 1
                        else:
                            filters[http_filter_type] += 1

            if file.download_url not in http_configs:
                print(f"No http_filters found in {file.download_url}")

        except yaml.YAMLError as e:
            # print(f"Error parsing YAML in file {file.download_url}: {e}")
            num_errors += 1

    for file in files:
        content = sanitize_config(file.content)
        _parse(content)

    print(f"Evaluated {len(http_configs)}/{len(files)} configs, {num_errors} errors occurred")

    filters = [{"name": name, "count": num} for (name, num) in filters.items()]
    filters = sorted(filters, key=lambda x: x["count"], reverse=True)
    for filter in filters:
        print(f"{filter['name']}: {filter['count']}")

    if path:
        try:
            with open(args.path, 'w') as f:
                json.dump(filters, f)
        except Exception as e:
            print(f"Error writing statistics to {args.path}: {e}")


if __name__ == "__main__":
    if args.command == "search":
        search()
    elif args.command == "count":
        count(args.path)
