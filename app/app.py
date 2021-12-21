from flask import Flask, redirect, url_for, request
import requests, urllib.request
import json
import os
from datetime import datetime

#### Set the name of this honeypot instance here, or in environment variable HONEYPOT_NAME ####
# (use a descriptive name so you know when alerts come in where they were triggered)
honeypot_name = "My log4j honeypot"

#### Set the port you want this honeypot to listen on. Recommend 8080 or 80
#### you can also use environment variable HONEYPOT_PORT
honeypot_port = 8080

if "HONEYPOT_NAME" in os.environ and os.environ["HONEYPOT_NAME"].strip() != "":
    honeypot_name = os.environ["HONEYPOT_NAME"]

if "HONEYPOT_PORT" in os.environ and os.environ["HONEYPOT_PORT"].strip() != "":
    try:
        honeypot_port = int(os.environ["HONEYPOT_PORT"].strip())
    except:
        print("Invalid port: " + os.environ["HONEYPOT_PORT"])
        print("Reverting to port 8080 default")
        honeypot_port = 8080

app = Flask(__name__)

def reportHit(request):
    msgDict = {}
    UTCTIME = str(datetime.utcnow()).rsplit('.')[0].replace(' ', '-').split('-')
    msgDict.update({"timestamp": UTCTIME[2] + "-" + UTCTIME[1] + "-" + UTCTIME[0] + ":" + UTCTIME[3]})
    msgDict.update({"honeypot_name": honeypot_name})
    msgDict.update({"remote_addr": request.remote_addr})
    for header in request.headers:
        msgDict.update({str(header[0]): str(header[1])})
    for fieldname, value in request.form.items():
        msgDict.update({fieldname: value})
    jsonData = json.dumps(msgDict)
    with open('/home/admin/log4j-honeypot-flask/app/log.json', 'a') as log:
        log.write(jsonData + '\n')

login_form = """<html>
<head><title>Transaction</title></head>
<body>
<form method='post' action='/'>
  <input name='submitted_string' type='text' placeholder='transaction'/>
  <input type='submit' name='submit' value='Send'/>
</form>
</body></html>"""

@app.route('/websso/SAML2/SSO/<path:hostname>') # vCenter websso login path
@app.route("/", methods=['POST','GET','HEAD','PUT','DELETE'])
def homepage(hostname="NA"):
    for header in request.headers:
        for field in header:
            if "${" in field:
                reportHit(request)
    if request.method == 'POST':
        for fieldname, value in request.form.items():
            if "${" in value:
                reportHit(request)
        return(login_form)
    else:
        return(login_form)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=honeypot_port)
