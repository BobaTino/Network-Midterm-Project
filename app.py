from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def dashboard():
    try:
        with open("devices.json") as f:
            devices = json.load(f)
    except:
        devices = {}

    return render_template("index.html", devices=devices)

if __name__ == "__main__":
    app.run(debug=True)