from flask import Flask, redirect, url_for, request
import requests, urllib.request
import json
import os

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
    msglines = []
    msglines.append('{"honeypot": "' + honeypot_name + '", "attacker_ip": "' + request.remote_addr + '"')
    for header in request.headers:
        msglines.append(str(header))
    for fieldname, value in request.form.items():
        msglines.append(str((fieldname, value)))
    msg = {'text':'\n '.join(msglines)}
    jsonlines = json.dumps(msg)
    print(jsonlines)

#    response = requests.post(
#        webhook_url, data=json.dumps(msg),
#        headers={'Content-Type': 'application/json'},
#        proxies=urllib.request.getproxies(),
#    )
#    if response.status_code != 200:
#        print('Request to webhook returned an error %s, the response is:\n%s' % (response.status_code, response.text))

login_form = """<html>
<head><title>Transaction</title></head>
<body>
<form method='post' action='/'>
  <input name='transaction' type='text' placeholder='transaction'/>
  <input type='submit' name='submit' value='Send'/>
</form>
</body></html>"""

@app.route('/websso/SAML2/SSO/<path:hostname>') # vCenter websso login path
@app.route("/", methods=['POST','GET','HEAD','PUT','DELETE'])
def homepage(hostname="NA"):
    for header in request.headers:
        print(header)
        for field in header:
            if "${" in field:
                reportHit(request)
    if request.method == 'POST':
        for fieldname, value in request.form.items():
            print(value)
            if "${" in value:
                reportHit(request)
        return(login_form)
    else:
        return(login_form)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=honeypot_port)
