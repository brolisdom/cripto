from flask import Flask, render_template, request
from Crypto.Cipher import DES
from pathlib import Path
from werkzeug.utils import secure_filename

import os

def cifrador_des(bytes_info,operation_mode,key=b'secretos',iv=b'soterces'):
  if operation_mode == 'CBC':
    cipher = DES.new(key,DES.MODE_CBC,iv)
  elif operation_mode == 'CFB':   
    cipher = DES.new(key,DES.MODE_CFB,iv)
  elif operation_mode == 'ECB':
    cipher = DES.new(key,DES.MODE_ECB)
  elif operation_mode == 'OFB': 
    cipher = DES.new(key,DES.MODE_OFB,iv)
  return cipher.encrypt(bytes_info)

def descifrador_des(bytes_info,operation_mode,key=b'secretos',iv=b'soterces'):
  if operation_mode == 'CBC':
    cipher = DES.new(key,DES.MODE_CBC,iv)
  elif operation_mode == 'CFB':   
    cipher = DES.new(key,DES.MODE_CFB,iv)
  elif operation_mode == 'ECB':
    cipher = DES.new(key,DES.MODE_ECB)
  elif operation_mode == 'OFB': 
    cipher = DES.new(key,DES.MODE_OFB,iv)
  return cipher.decrypt(bytes_info)

def add_suffix_path(path,suf):
  path = Path(path)
  path = path.with_name(path.stem + suf + path.suffix)
  return path

def remove_suffix_path(path,suf):
  if str(Path(path).stem).endswith(suf):
    path = Path(path)
    path = path.with_name(path.stem.rstrip(suf) + path.suffix)
  return path

def cifrar_imagen_bmp_des(image_path,operation_mode,key=b'secretos',iv=b'soterces'):
  image = open(image_path,"rb")
  cipher_image_path = add_suffix_path(image_path,f"_{operation_mode}")
  cipher_image = open(cipher_image_path,"wb")
  cipher_image.write(image.read(54))
  bytes_to_cipher = image.read()
  image.close()
  cipher_bytes = cifrador_des(bytes_to_cipher,operation_mode,key,iv)
  cipher_image.write(cipher_bytes)
  cipher_image.close()
  return str(cipher_image_path)

def descifrar_imagen_bmp_des(image_path,operation_mode,key=b'secretos',iv=b'soterces'):
  image = open(image_path,"rb")
  image_path = remove_suffix_path(image_path,f'_{operation_mode}')
  decode_image_path = add_suffix_path(image_path,f"_DEC_{operation_mode}")
  decode_image = open(decode_image_path,"wb")
  decode_image.write(image.read(54))
  bytes_to_decode = image.read()
  image.close()
  decode_bytes = descifrador_des(bytes_to_decode,operation_mode,key,iv)
  decode_image.write(decode_bytes)
  decode_image.close()
  return str(decode_image_path)

def setPath(file):
  filename = secure_filename(file.filename)
  path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
  file.save(path)
  return path

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './static'

@app.route('/')
def cifrado():
  return render_template('cifrado.html')

@app.route('/descifrado')
def descifrado():
  return render_template('descifrado.html')

@app.route('/cifrado_image', methods=['POST'])
def cifrado_image():
  if request.method == "POST": # opcional
    try:
      key = request.form['llave']
      mode = request.form['modo']
      f = request.files['archivo']
      if(key):
        res = cifrar_imagen_bmp_des(setPath(f),mode,key.encode())
      else: 
        res = cifrar_imagen_bmp_des(setPath(f),mode)
      f = secure_filename(f.filename)
      return render_template('result.html', filename=res[7:])
    except:
      return render_template('error.html')

@app.route('/descifrado_image', methods=['POST'])
def descifrado_image():
  if request.method == "POST": # opcional
    try:
      key = request.form['llave']
      mode = request.form['modo']
      f = request.files['archivo']
      if(key):
        res = descifrar_imagen_bmp_des(setPath(f),mode,key.encode())
      else:
        res = descifrar_imagen_bmp_des(setPath(f),mode)
      f = secure_filename(f.filename)
      return render_template('result.html', filename=res[7:])
    except:
      return render_template('error.html')

if __name__ == '__main__':
  app.run(debug=True)