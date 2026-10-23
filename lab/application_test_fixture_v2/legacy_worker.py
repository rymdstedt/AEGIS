import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask

app = Flask(__name__)


def restore_job(untrusted_blob):
    return pickle.loads(untrusted_blob)


def load_workflow(untrusted_yaml):
    return yaml.load(untrusted_yaml)


def generate_archive(untrusted_name):
    return subprocess.run("archive-tool " + untrusted_name, shell=True)


def remove_staging_file(untrusted_path):
    return os.system("staging-cleaner " + untrusted_path)


def query_signing_service():
    return requests.get("https://signing.borealis.northstar.invalid", verify=False)


def launch_debug_console():
    app.run(host="127.0.0.1", debug=True)
