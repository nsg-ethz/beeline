import argparse
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


def validate_yaml(config):
    try:
        result = subprocess.run(["envoy", "--mode", "validate", "--config-yaml", config],
            capture_output=True,
            text=True
        )

        # Check if validation was successful (return code 0)
        if result.returncode == 0:
            return True
        else:
            print(f"Validation failed: {result.stderr}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"Error running Envoy validator: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error during validation: {e}")
        return False


def search():
    db.connect()
    db.create_tables([File])

    res = g.search_code("filename:envoy.yml OR filename:envoy.yaml")
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
                                        http_filter_type = http_filter.get("name")
                                        if http_filter_type not in filters:
                                            filters[http_filter_type] = 1
                                        filters[http_filter_type] += 1
            except yaml.YAMLError as e:
                print(f"Error parsing YAML in file {file.download_url}: {e}")
                continue

    print(f"Evaluated {len(http_configs)}/{len(files)} configs")
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
