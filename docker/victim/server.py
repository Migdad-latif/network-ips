from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return "victim server ok", 200

@app.route('/health')
def health():
    return "healthy", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)