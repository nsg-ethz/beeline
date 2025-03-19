import argparse
from datetime import datetime
from github import Github, Auth
import os
from numpy import fix
from peewee import *
import re
import subprocess
import time
import yaml

db_path = "res/github.db"
db = SqliteDatabase(db_path)

class BaseModel(Model):
    class Meta:
        database = db

class File(BaseModel):
    name = CharField()
    download_url = CharField(unique=True)
    content = CharField()


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
            step = max(step / 2, 1)
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

    return name


def sanitize_config(text):
    text = re.sub(r"{%.*?%}", "", text, flags=re.DOTALL)
    text = re.sub(r"{{-.*?}}", "", text, flags=re.DOTALL)
    text = re.sub(r"{{.*?}}", "placeholder", text, flags=re.DOTALL)

    return text


def count():
    db.connect()

    files = File.select()
    print(f"Analysing {len(files)} files...")

    filters = dict()
    http_configs = set()
    num_errors = 0

    for file in files:
        if "filter_chains" in file.content:
            content = sanitize_config(file.content)

            try:
                configs = yaml.safe_load_all(content)

                for config in configs:
                    if not isinstance(config, dict):
                        continue

                    static_resources = config.get("static_resources", {})
                    listeners = static_resources.get("listeners", [])
                    if isinstance(listeners, dict):
                        listeners = [listeners]

                    for listener in listeners:
                        chains = listener.get("filter_chains", {})
                        if isinstance(chains, dict):
                            chains = [chains]

                        for chain in chains:
                            chain_filters = chain.get("filters", [])
                            if isinstance(chain_filters, dict):
                                chain_filters = [chain_filters]

                            for filter in chain_filters:
                                name = filter.get("name")
                                if "http_connection_manager" in name.lower():
                                    filter_config = filter.get("config", {})
                                    http_filters = filter_config.get("http_filters", [])

                                    if len(http_filters) > 0:
                                        http_configs.add(file.download_url)

                                    for http_filter in http_filters:
                                        http_filter_type = sanitize_filter_name(http_filter.get("name"))
                                        if http_filter_type not in filters:
                                            filters[http_filter_type] = 1
                                        filters[http_filter_type] += 1
            except yaml.YAMLError as e:
                # print(f"Error parsing YAML in file {file.download_url}: {e}")
                num_errors += 1
                continue

    print(f"Evaluated {len(http_configs)}/{len(files)} configs, {num_errors} errors occurred")
    print(filters)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("search")
    subparsers.add_parser("count")
    args = parser.parse_args()

    if args.command == "search":
        search()
    elif args.command == "count":
        count()
