import requests
import base64
import json
import ssl
import websocket
import configargparse
import paho.mqtt.client as mqtt
import random
from datetime import datetime


parser = configargparse.ArgParser(description='Bridge between UDM Pro and MQTT')
parser.add_argument('--mqtt-host', env_var='MQTT_HOST', required=True, help='MQTT server address')
parser.add_argument('--mqtt-port', env_var='MQTT_PORT', default=1883, type=int, help='Defaults to 1883')
parser.add_argument('--mqtt-topic', env_var='MQTT_TOPIC', default='udmp/', help='Topic prefix to be used for subscribing/publishing. Defaults to "udmp/"')
parser.add_argument('--mqtt-user', env_var='MQTT_USER', default='', help='Username for MQTT (optional)')
parser.add_argument('--mqtt-pass', env_var='MQTT_PASS', default='', help='Password for MQTT (optional)')
parser.add_argument('--udmp-user', env_var='UDMP_USER', required=True, default='', help='Username for UDM Pro')
parser.add_argument('--udmp-pass', env_var='UDMP_PASS', required=True, default='', help='Password for UDM Pro')
parser.add_argument('--udmp-url', env_var='UDMP_URL', required=True, default='', help='URL for UDM Pro')

args=parser.parse_args()

token = {}

def login():
    response = requests.post(
        'https://' + args.udmp_url + '/api/auth/login',
        json = { 'username': args.udmp_user, 'password': args.udmp_pass }
    )
    update_token(response)

def update_token(response):
    token['cookie_obj'] = response.cookies
    token['cookie'] = response.headers['Set-Cookie']
    token['token'] = token['cookie'].split(';')[0].split('=')[1]
    token['csrfToken'] = json.loads(base64.b64decode(token['token'].split('.')[1].encode('ascii') + b'=='))['csrfToken']

def get_wan():
    response = requests.get(
        'https://' + args.udmp_url + '/proxy/network/api/s/default/stat/health',
        headers = {
            'x-csrf-token': token['csrfToken']
        },
        cookies = token['cookie_obj']
    )
    update_token(response)

    data = json.loads(response.content)
    for myData in data['data']:
        if myData['subsystem'] == 'wan':
            print(int(myData['tx_bytes-r']) * 8 / 1024 / 1024)
            print(int(myData['rx_bytes-r']) * 8 / 1024 / 1024)

def get_wan_websocket(wsapp, message):
    data = json.loads(message)
    if 'meta' in data:
        if 'rc' in data['meta'] and 'message' in data['meta'] and 'mac' in data['meta']:
            if data['meta']['mac'] == '24:5a:4c:a6:eb:57' and data['meta']['message'] == 'device:sync':
                mqtt_client.publish(args.mqtt_topic + 'down', int(data['data'][0]['wan1']['rx_bytes-r']) * 8 / 1024 / 1024)
                mqtt_client.publish(args.mqtt_topic + 'up', int(data['data'][0]['wan1']['tx_bytes-r']) * 8 / 1024 / 1024)

def on_error(wsapp, err):
    print("Got a an error: ", err)
    mqtt_client.publish(args.mqtt_topic + 'error', 'WS Error')
    mqtt_client.publish(args.mqtt_topic + 'error_time', datetime.today().strftime('%Y-%m-%d-%H:%M:%S'))
    mqtt_client.publish(args.mqtt_topic + 'error_code', err)


client_id = f'udmp-{random.randint(0, 1000)}'
mqtt_client = mqtt.Client(client_id)
if args.mqtt_user != '' or args.mqtt_pass != '':
    mqtt_client.username_pw_set(args.mqtt_user, args.mqtt_pass)
mqtt_client.connect(args.mqtt_host, args.mqtt_port)
mqtt_client.loop_start()

login()
wsapp = websocket.WebSocketApp(
    'wss://' + args.udmp_url + '/proxy/network/wss/s/default/events?clients=v2', 
    on_message = get_wan_websocket,
    on_error=on_error,
    cookie = token['cookie']
)
wsapp.run_forever(
    sslopt={'cert_reqs': ssl.CERT_NONE}
)