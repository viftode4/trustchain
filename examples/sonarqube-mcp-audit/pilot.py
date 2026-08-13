#!/usr/bin/env python3
"""Local synthetic SonarQube MCP audit fixture; no external network access."""
import argparse, json, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXPECTED = {"jsonrpc":"2.0","id":1,"result":{"key":"python:S1234","name":"Synthetic rule"}}
class McpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        assert request["method"]=="tools/call" and request["params"]["name"]=="show_rule"
        body=json.dumps(EXPECTED,separators=(",",":")).encode(); self.send_response(200)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, _format, *_args): return
def post(url,payload,headers=None):
    req=urllib.request.Request(url,data=json.dumps(payload,separators=(",",":")).encode(),headers={"Content-Type":"application/json",**(headers or {})})
    with urllib.request.urlopen(req,timeout=5) as response: return json.load(response)
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--trustchain",default="http://127.0.0.1:18202"); parser.add_argument("--fixture-port",type=int,default=18080); args=parser.parse_args()
    server=ThreadingHTTPServer(("127.0.0.1",args.fixture_port),McpHandler); threading.Thread(target=server.serve_forever,daemon=True).start()
    blocks=[]
    try:
        for correlation,(user,token) in enumerate([("user-alice","synthetic-alice-token"),("user-bob","synthetic-bob-token")],start=1):
            request_payload={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"show_rule","arguments":{"key":"python:S1234"}}}
            started=time.monotonic_ns(); response=post(f"http://127.0.0.1:{args.fixture_port}/mcp",request_payload,{"Authorization":f"Bearer {token}"}); duration_ms=(time.monotonic_ns()-started)//1_000_000
            if response!=EXPECTED: raise SystemExit("MCP response parity failure")
            event={"schema":"sonarqube-mcp-audit/v1","user_id":user,"tool":"show_rule","arguments":{"key":"python:S1234"},"duration_ms":duration_ms,"result":"success","correlation_id":f"synthetic-{correlation}","authorization":"[REDACTED]"}
            if token in json.dumps(event,sort_keys=True): raise SystemExit("token redaction failure")
            blocks.append(post(f"{args.trustchain}/audit",{"transaction":event})["block"])
    finally: server.shutdown()
    assert [b["sequence_number"] for b in blocks]==[1,2]
    assert all(b["block_type"]=="audit" and len(b["block_hash"])==64 and len(b["signature"])==128 for b in blocks)
    print(json.dumps({"response_parity":True,"redaction":True,"events":2},sort_keys=True))
if __name__=="__main__": main()
