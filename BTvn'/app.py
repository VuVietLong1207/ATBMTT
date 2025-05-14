from flask import Flask, render_template, request, send_file
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def encrypt_file(input_path, output_path, key):
    try:
        key_bytes = key.encode('utf-8').ljust(8)[:8]  # Key phải là 8 bytes
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        with open(input_path, 'rb') as infile:
            plaintext = infile.read()
            padded_plaintext = pad(plaintext, DES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            with open(output_path, 'wb') as outfile:
                outfile.write(ciphertext)
        return True, None
    except Exception as e:
        return False, str(e)

def decrypt_file(input_path, output_path, key):
    try:
        key_bytes = key.encode('utf-8').ljust(8)[:8]  # Key phải là 8 bytes
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        with open(input_path, 'rb') as infile:
            ciphertext = infile.read()
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, DES.block_size)
            with open(output_path, 'wb') as outfile:
                outfile.write(plaintext)
        return True, None
    except Exception as e:
        return False, str(e)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return "Không có file được chọn."
    file = request.files['file']
    key = request.form['key']
    if file.filename == '':
        return "Không có file được chọn."
    if file and allowed_file(file.filename):
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        output_filename = 'encrypted_' + filename
        output_filepath = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        success, error = encrypt_file(filepath, output_filepath, key)
        os.remove(filepath)  # Xóa file gốc sau khi mã hóa
        if success:
            return send_file(output_filepath, as_attachment=True, download_name=output_filename)
        else:
            return f"Lỗi mã hóa: {error}"
    return "Định dạng file không được hỗ trợ."

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return "Không có file được chọn."
    file = request.files['file']
    key = request.form['key']
    if file.filename == '':
        return "Không có file được chọn."
    if file and allowed_file(file.filename):
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        output_filename = 'decrypted_' + filename.replace('encrypted_', '', 1)
        output_filepath = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        success, error = decrypt_file(filepath, output_filepath, key)
        os.remove(filepath)  # Xóa file đã mã hóa sau khi giải mã
        if success:
            return send_file(output_filepath, as_attachment=True, download_name=output_filename)
        else:
            return f"Lỗi giải mã: {error}"
    return "Định dạng file không được hỗ trợ."

if __name__ == '__main__':
    app.run(debug=True)