from flask import Flask, request
import os

app = Flask(__name__)


@app.get("/diagnostic")
def diagnostic():
    command = request.args.get("command")
    return str(os.system(command))
