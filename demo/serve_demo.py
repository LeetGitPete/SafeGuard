import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving demo files at http://localhost:{PORT}")
        print("Available files:")
        print(f" - http://localhost:{PORT}/clean.html")
        print(f" - http://localhost:{PORT}/structural_injection.html")
        print(f" - http://localhost:{PORT}/semantic_injection.html")
        httpd.serve_forever()
