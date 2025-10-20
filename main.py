# main.py
from app import app  # pastikan di app.py ada baris: app = Flask(__name__)

# Opsional: untuk debug di lokal
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
