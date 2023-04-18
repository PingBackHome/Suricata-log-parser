import http.server
import socketserver
import ujson
import urllib.parse

PORT = 8080
LOG_FILE = "/var/log/suricata/eve.json"


class LogHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            header = "<h1>Suricata EVE Parser</h1>"
            auto_refresh = "<meta http-equiv='refresh' content='5'>"
            logs = ""
            logs += parse_eve_json()
            page_content = header + auto_refresh + logs
            self.wfile.write(page_content.encode())
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/filter":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            content_length = int(self.headers['Content-Length'])
            filter_params = ujson.loads(self.rfile.read(content_length))
            logs = ""
            logs += parse_eve_json(filter_params)
            self.wfile.write(logs.encode())
        else:
            super().do_POST()


def parse_eve_json(filter_params={}):
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    parsed_logs = []
    for line in lines:
        try:
            log = ujson.loads(line)
            parsed_logs.append(log)
        except ujson.JSONDecodeError as e:
            print(f"Error parsing log: {e}")
            continue

    parsed_logs = sorted(parsed_logs, key=lambda x: x.get('timestamp', ''), reverse=True)

    if filter_params:
        filtered_logs = []
        for log in parsed_logs:
            if filter_params.get('src_ip') and filter_params.get('src_ip') != log.get('src_ip'):
                continue
            if filter_params.get('dest_ip') and filter_params.get('dest_ip') != log.get('dest_ip'):
                continue
            if filter_params.get('proto') and filter_params.get('proto') != log.get('proto'):
                continue
            if filter_params.get('start_time') and filter_params.get('start_time') > log.get('timestamp'):
                continue
            if filter_params.get('end_time') and filter_params.get('end_time') < log.get('timestamp'):
                continue
            filtered_logs.append(log)
        parsed_logs = filtered_logs

    output = "<table style='border-collapse: collapse; margin: 0 auto; text-align: center;'>"
    output += "<tr style='border: 1px solid black;'><th>Timestamp</th><th>Source IP</th><th>Source Port</th><th>Destination IP</th><th>Destination Port</th><th>Protocol</th><th>Alert Message</th><th>Impact</th></tr>"
    for log in parsed_logs:
        alert = log.get("alert", {})
        impact = alert.get("severity", 0)
        output += "<tr style='border: 1px solid black;'><td>{}</td><td><a href='https://dnslookup.online/{ip_address}' target='_blank'>{ip_address}</a></td><td>{}</td><td><a href='https://dnslookup.online/{ip_address}' target='_blank'>{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            log.get('timestamp', ''),
            log.get('src_ip', ''),
            log.get('src_port', ''),
            log.get('dest_ip', ''),
            log.get('dest_port', ''),
            log.get('proto', ''),
            alert.get('signature', ''),
            impact,
            ip_address=urllib.parse.quote(log.get('src_ip', 'dest_ip'))
        )
    output += "</table>"
    return output


with socketserver.TCPServer(("", PORT), LogHTTPRequestHandler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()
