#!/usr/bin/env python

import argparse
from github import Github, Auth
import json
import os
from peewee import *
import re
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
    repo_url = CharField()
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

        res = g.search_code(f"envoy.filters.network.http_connection_manager extension:yml OR extension:yaml OR extension:json size:{size_range}")
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
                file = File(name=file.name, download_url=file.download_url, repo_url=file.repository.url, content=file.decoded_content)
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

    filters = []
    parsed_files = set()
    num_filter_chains = 0
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

    def _parse(file, content):
        nonlocal num_errors
        nonlocal num_filter_chains

        parsed_files.add(file.download_url)

        try:
            if os.path.splitext(file.name)[1] == ".json":
                configs = json.loads(content)
            else:
                configs = yaml.safe_load_all(content)

            for config in configs:
                if not isinstance(config, dict):
                    continue

                if "data" in config:
                    keys = [k for k in config.get("data").keys() if "envoy" in k]
                    if len(keys) != 1:
                        # print(f"Could not find envoy config: {config.get("data").keys()} in {download_url}")
                        continue

                    _parse(file, config.get("data").get(keys[0]))
                    continue


                for chain in _iter_http_filters(config):
                    if len(chain) > 0:
                        num_filter_chains += 1

                    for http_filter in chain:
                        name = http_filter.get("name")
                        if not name:
                            print(f"Unknown http_filter format: {http_filter}")
                            continue
                        http_filter_type = sanitize_filter_name(name)
                        filters.append({
                            "name": http_filter_type,
                            "repo_url": file.repo_url,
                            "download_url": file.download_url
                        })

            if file.download_url not in parsed_files:
                print(f"No http_filters found in {file.download_url}")
        except Exception as e:
            num_errors += 1

    for file in files:
        if file.download_url not in parsed_files:
            content = sanitize_config(file.content)
            _parse(file, content)

    print(f"Evaluated {len(parsed_files)}/{len(files)} configs, {num_errors} errors occurred, {num_filter_chains} HTTP filter chains")

    stats = dict()
    for filter in filters:
        stats[filter["name"]] = stats.get(filter["name"], 0) + 1

    stats = [{"name": name, "count": num} for (name, num) in stats.items()]
    stats = sorted(stats, key=lambda x: x["count"], reverse=True)
    for filter in stats:
        print(f"{filter['name']}: {filter['count']}")

    if path:
        stats = {
            "files": len(parsed_files),
            "filter_chains": num_filter_chains,
            "errors": num_errors,
            "filters": filters
        }

        try:
            with open(args.path, 'w') as f:
                json.dump(stats, f)
        except Exception as e:
            print(f"Error writing statistics to {args.path}: {e}")


if __name__ == "__main__":
    if args.command == "search":
        search()
    elif args.command == "count":
        count(args.path)
