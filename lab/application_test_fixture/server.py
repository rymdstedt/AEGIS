import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask

app = Flask(__name__)


def restore_session(untrusted_bytes):
    return pickle.loads(untrusted_bytes)


def import_settings(untrusted_yaml):
    return yaml.load(untrusted_yaml)


def run_report(report_name):
    return subprocess.run("report-tool " + report_name, shell=True)


def legacy_cleanup(user_path):
    return os.system("cleanup-tool " + user_path)


def fetch_internal_status():
    return requests.get("https://status.northstar.invalid", verify=False)


def start_debug_server():
    app.run(host="127.0.0.1", debug=True)
