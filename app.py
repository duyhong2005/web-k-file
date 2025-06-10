from flask import Flask, render_template, request, send_file, redirect, url_for, session
import os
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
SIGNED_FOLDER = 'signed'
LOG_FILE = 'log.txt'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)


def write_log(entry):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(entry + '\n')


def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        return f.readlines()


@app.route('/')
def index():
    private_key = session.get('private_key', '')
    public_key = session.get('public_key', '')
    active_tab = session.get('active_tab', 'sign')
    return render_template('index.html', logs=read_logs(), private_key=private_key, public_key=public_key, active_tab=active_tab)


@app.route('/generate_keys')
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()

    session['private_key'] = private_key
    session['public_key'] = public_key
    session['active_tab'] = 'sign'

    return redirect(url_for('index'))


@app.route('/sign', methods=['POST'])
def sign_file():
    session['active_tab'] = 'sign'

    if 'file' not in request.files:
        session['sign_result'] = 'Lỗi: Không tìm thấy file.'
        session['sign_status'] = 'danger'
        return redirect(url_for('index'))

    file = request.files['file']
    private_key_str = request.form['private_key']

    if file.filename == '':
        session['sign_result'] = 'Lỗi: Chưa chọn file.'
        session['sign_status'] = 'danger'
        return redirect(url_for('index'))

    if file and private_key_str:
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        try:
            key = RSA.import_key(private_key_str.encode())
            with open(filepath, 'rb') as f:
                data = f.read()
            h = SHA256.new(data)
            signature = pkcs1_15.new(key).sign(h)

            sig_filename = filename + '.sig'
            sig_path = os.path.join(SIGNED_FOLDER, sig_filename)
            with open(sig_path, 'wb') as f:
                f.write(signature)

            write_log(f"{datetime.datetime.now()}: Đã ký file: {sig_filename}")
            session['sign_result'] = f'Đã ký file thành công: {sig_filename}'
            session['sign_status'] = 'success'
            session['signed_file'] = sig_filename
        except Exception as e:
            session['sign_result'] = 'Lỗi khi ký file: ' + str(e)
            session['sign_status'] = 'danger'

    return redirect(url_for('index'))


@app.route('/verify', methods=['POST'])
def verify_signature():
    session['active_tab'] = 'verify'

    if 'file' not in request.files or 'signature' not in request.files:
        session['verify_result'] = 'Lỗi: Thiếu file hoặc chữ ký.'
        session['verify_status'] = 'danger'
        return redirect(url_for('index'))

    file = request.files['file']
    sig = request.files['signature']
    public_key_str = request.form['public_key']

    if file.filename == '' or sig.filename == '':
        session['verify_result'] = 'Lỗi: Chưa chọn file hoặc chữ ký.'
        session['verify_status'] = 'danger'
        return redirect(url_for('index'))

    if file and sig and public_key_str:
        try:
            data = file.read()
            signature = sig.read()
            pub_key = RSA.import_key(public_key_str.encode())
            h = SHA256.new(data)
            pkcs1_15.new(pub_key).verify(h, signature)
            session['verify_result'] = '✅ Chữ ký hợp lệ.'
            session['verify_status'] = 'success'
        except Exception as e:
            session['verify_result'] = '❌ Chữ ký không hợp lệ: ' + str(e)
            session['verify_status'] = 'danger'

    return redirect(url_for('index'))


@app.route('/download_signature/<filename>')
def download_signature(filename):
    filepath = os.path.join(SIGNED_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return "File không tồn tại", 404


if __name__ == '__main__':
    app.run(debug=True)
