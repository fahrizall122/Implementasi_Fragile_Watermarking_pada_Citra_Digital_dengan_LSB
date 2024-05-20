import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from PIL import Image
import random
import math

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/images/'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def encrypt(plain, key):
    cipher = []
    len_key = len(key)
    for i in range(len(plain)):
        cipher.append((plain[i] + ord(key[i % len_key])) % 256)
    return cipher

def decrypt(cipher, key):
    plain = []
    len_key = len(key)
    for i in range(len(cipher)):
        plain.append((cipher[i] + 256 - ord(key[i % len_key])) % 256)
    return plain

def shuffle_order(size, shuffle_seed):
    order = list(range(size))
    if shuffle_seed:
        random.seed(shuffle_seed)
        random.shuffle(order)
    return order

def readLSB(image, width, binary, order):
    bit = []
    px = image.load()
    k = 0
    cur = 0
    for pos in order:
        i = pos // width
        j = pos % width
        if binary:
            cur |= (px[i % image.width, j % image.height] & 1) << k
        else:
            cur |= (px[i % image.width, j % image.height][0] & 1) << k
        k += 1
        if k >= 8:
            bit.append(cur)
            k = 0
            cur = 0
    if k > 0:
        bit.append(cur)
    return bit

def extract_lsb(inputpath, key):
    cover = Image.open(inputpath)
    lsb = Image.new("1", cover.size)
    px_cover = cover.load()
    px_lsb = lsb.load()

    seed = sum(ord(k) for k in key)
    cipher = readLSB(cover, cover.width, False, shuffle_order(cover.width * cover.height, seed))
    plain = decrypt(cipher, key)

    k = 0
    positions = shuffle_order(cover.width * cover.height, 0)
    for pos in positions:
        i = pos // cover.width
        j = pos % cover.width
        px_lsb[i, j] = ((plain[k // 8] >> (k % 8)) & 1)
        k += 1
    return lsb

def insert_lsb(inputpath, watermarkpath, key):
    cover = Image.open(inputpath)
    watermark = Image.open(watermarkpath).convert("1")
    output = Image.new(cover.mode, cover.size)
    px_cover = cover.load()
    px_watermark = watermark.load()
    px_output = output.load()
    
    plain = readLSB(watermark, cover.width, True, shuffle_order(cover.width * cover.height, 0))
    cipher = encrypt(plain, key)
    
    k = 0
    seed = sum(ord(k) for k in key)
    positions = shuffle_order(cover.width * cover.height, seed)
    for pos in positions:
        i = pos // cover.width
        j = pos % cover.width
        p = list(px_cover[i, j])
        p[0] = (p[0] & 0b11111110) | ((cipher[k // 8] >> (k % 8)) & 1)
        k += 1
        px_output[i, j] = tuple(p)
    return output

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/insert', methods=['POST'])
def insert():
    if 'cover' not in request.files or 'watermark' not in request.files:
        return redirect(request.url)
    cover = request.files['cover']
    watermark = request.files['watermark']
    key = request.form['key']
    if cover.filename == '' or watermark.filename == '' or key == '':
        return redirect(request.url)
    if cover and allowed_file(cover.filename) and watermark and allowed_file(watermark.filename):
        cover_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cover.filename))
        watermark_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(watermark.filename))
        cover.save(cover_path)
        watermark.save(watermark_path)
        output = insert_lsb(cover_path, watermark_path, key)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output.png')
        output.save(output_path)
        return redirect(url_for('static', filename='images/output.png'))
    return redirect(request.url)

@app.route('/extract', methods=['POST'])
def extract():
    if 'cover' not in request.files or 'key' not in request.form:
        return redirect(request.url)
    cover = request.files['cover']
    key = request.form['key']
    if cover.filename == '' or key == '':
        return redirect(request.url)
    if cover and allowed_file(cover.filename):
        cover_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(cover.filename))
        cover.save(cover_path)
        lsb = extract_lsb(cover_path, key)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'extracted.png')
        lsb.save(output_path)
        return redirect(url_for('static', filename='images/extracted.png'))
    return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True)
