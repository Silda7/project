from pymongo import MongoClient, DESCENDING
import jwt
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response, flash, session
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from os.path import join, dirname
from dotenv import load_dotenv
from bson import ObjectId
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_PRODUK'] = './static/produk'
app.config['UPLOAD_PROFILE'] = './static/profile'

SECRET_KEY = 'SPARTA'
TOKEN_KEY = 'mytoken'

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]


admin_email = "admin@gmail.com"
admin_password = "admin"

pw_hash = hashlib.sha256(admin_password.encode("utf-8")).hexdigest()

db.users.insert_one({
    "name": "Admin",
    "email": admin_email,
    "address": "Admin Address",
    "role": "admin",
    "password": pw_hash
})

@app.route('/', methods = ['GET'])
def main():
    produk_list = db.produk.find()
    return render_template('homepage.html', produk_list=produk_list)

@app.context_processor
def cookies():
    token_receive = request.cookies.get(TOKEN_KEY)
    logged_in = False
    is_admin = None
    is_user = None
    email = None
    address = None
    name = None
    user_id = None
    foto = None

    if token_receive:
        try:
            payload = jwt.decode(
                token_receive,
                SECRET_KEY,
                algorithms=['HS256']
            )
            user_info = db.users.find_one({"email": payload["id"]})
            if user_info:
                logged_in = True
                is_admin = user_info.get("role") == "admin"
                is_user = user_info.get("role") == "customers"
                email = user_info.get("email")
                address = user_info.get("address")
                name = user_info.get("name")
                user_id = user_info.get("_id")
                foto = user_info.get("profile_picture")
        except jwt.ExpiredSignatureError:
            pass
        except jwt.exceptions.DecodeError:
            pass

    return {'logged_in': logged_in, 'is_admin': is_admin, 'foto': foto, 'user_id': user_id,  'is_user': is_user, 'name': name, 'email': email, 'address': address}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get(TOKEN_KEY)
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if data.get("role") != "admin":
                return jsonify({"message": "Admin access required!"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403

        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup')
def signup():
    error_message = request.args.get('error_message', None)
    if cookies().get('logged_in'):
        return redirect(url_for('main'))
    else:
        return render_template('register.html', error_message=error_message)

@app.route('/sign_up/save', methods=['POST'])
def sign_up():
    name = request.form.get('name')
    email = request.form.get('email')
    address = request.form.get('address')
    password = request.form.get('password')
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    existing_user = db.users.find_one({'email': email})

    if existing_user:
        return jsonify({'success': False, 'message': 'Email already registered'})

    doc = {
        "name": name,
        "email": email,
        "address": address,
        "role": 'customers',
        "password": password_hash
    }

    db.users.insert_one(doc)

    return jsonify({'success': True, 'message': 'User registered successfully'})


@app.route('/signin')
def signin():
    if cookies().get('logged_in'):
        return redirect(url_for('main'))
    else:
        return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect(url_for('signin')))
    response.delete_cookie(TOKEN_KEY)
    return response

@app.route('/sign_in', methods=['POST'])
def sign_in():
    email = request.form["email"]
    password = request.form["password"]
    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    result = db.users.find_one(
        {
            "email": email,
            "password": pw_hash,
        }
    )
    if result:
        payload = {
            "id": email,
            "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        response = make_response(redirect(url_for('main')))
        response.set_cookie(TOKEN_KEY, token)
        return response
    else:
        return jsonify({
            "result": "fail",
            "msg": "We could not find a user with that id/password combination",
        })
    
@app.route('/produk')
def show_produk():
    produk_list = db.produk.find()
    return render_template('produk.html', produk_list=produk_list)

@app.route('/edit', methods=['POST'])
def edit_produk():
    if not cookies().get('logged_in'):
        return redirect(url_for('signin'))
        
    product_id = request.form.get('produk_id')
    nama_produk = request.form.get('nama_produk')
    harga_produk = request.form.get('harga_produk')
    deskripsi_produk = request.form.get('deskripsi_produk')

    existing_filename = request.form.get('existing_foto_produk', 'default.jpg')
    filename = existing_filename

    if 'foto_produk' in request.files:
        foto_produk = request.files['foto_produk']
        if foto_produk.filename != '':
            file_extension = foto_produk.filename.rsplit('.', 1)[1].lower() if '.' in foto_produk.filename else 'jpg'
            filename = secure_filename(f"{product_id}.{file_extension}")
            foto_produk.save(os.path.join(app.config['UPLOAD_PRODUK'], filename))

    db.produk.update_one(
        {'_id': ObjectId(product_id)},
        {'$set': {
                'nama_produk': nama_produk,
                'harga_produk': harga_produk,
                'deskripsi_produk': deskripsi_produk,
                'foto_produk': filename if filename != existing_filename else existing_filename
            }
        }
    )

    return redirect(url_for('show_produk'))

@app.route('/add', methods=['POST'])
def add_product():
    nama_produk = request.form['nama_produk']
    harga_produk = request.form['harga_produk']
    deskripsi_produk = request.form['deskripsi_produk']
    store = 'La Ferme-Mart'

    os.makedirs(app.config['UPLOAD_PRODUK'], exist_ok=True)

    foto_produk = request.files['foto_produk'] if 'foto_produk' in request.files else None

    if foto_produk and foto_produk.filename != '':
        file_extension = foto_produk.filename.rsplit('.', 1)[1].lower() if '.' in foto_produk.filename else 'jpg'
        filename = secure_filename(f"{nama_produk}.{file_extension}")
        foto_produk.save(os.path.join(app.config['UPLOAD_PRODUK'], filename))
    else:
        filename = 'default.jpg'

    produk_data = {
        'nama_produk': nama_produk,
        'foto_produk': filename,
        'harga_produk': harga_produk,
        'deskripsi_produk': deskripsi_produk,
        'store': store
    }

    db.produk.insert_one(produk_data)

    return redirect(url_for('show_produk'))

@app.route('/delete', methods=['POST'])
def delete_product():
    product_id = request.form['produk_id']
    db.produk.delete_one({'_id': ObjectId(product_id)})

    return redirect(url_for('show_produk'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not cookies().get('logged_in'):
        return redirect(url_for('signin'))

    edit_mode = bool(request.args.get('edit_mode', False))
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_name = request.form.get('name')
        new_address = request.form.get('address')
        new_email = request.form.get('email')

        existing_user = db.users.find_one({'_id': ObjectId(user_id)})
        if not existing_user:
            flash("User not found!")
            return redirect(url_for('profile'))

        filename = existing_user.get('profile_picture', 'default.jpg')
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture.filename != '':
                file_extension = profile_picture.filename.rsplit('.', 1)[1].lower() if '.' in profile_picture.filename else 'jpg'
                filename = secure_filename(f"{user_id}.{file_extension}")
                profile_picture.save(os.path.join(app.config['UPLOAD_PROFILE'], filename))

        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'name': new_name, 'address': new_address, 'email': new_email, 'profile_picture': filename}}
        )

        return redirect(url_for('profile'))

    return render_template('profile.html', edit_mode=edit_mode)

@app.route('/purchase', methods=['POST'])
def purchase():
    if not cookies().get('logged_in'):
        return redirect(url_for('signin'))
    
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity'))

    product = db.produk.find_one({'_id': ObjectId(product_id)})

    if not product:
        flash("Product not found!")
        return redirect(url_for('main'))

    total_price = int(product['harga_produk']) * quantity
    session['purchase'] = {
        'product_name': product['nama_produk'],
        'store': product['store'],
        'quantity': quantity,
        'total_price': total_price,
        'image': product['foto_produk']
    }

    return redirect(url_for('purchase_page'))

@app.route('/purchase-page')
def purchase_page():
    purchase = session.get('purchase')
    if not purchase:
        flash("No purchase information found!")
        return render_template('purchase.html', purchase=None) 
    return render_template('purchase.html', purchase=purchase)

@app.route('/process-payment', methods=['POST'])
def process_payment():
    token_receive = request.cookies.get(TOKEN_KEY)
    
    if not token_receive:
        flash("You need to be logged in to process payment.")
        return redirect(url_for('signin'))
    
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"email": payload["id"]})
        
        if not user_info:
            flash("User information not found.")
            return redirect(url_for('main'))

    except jwt.ExpiredSignatureError:
        flash("Session expired. Please log in again.")
        return redirect(url_for('signin'))
    except jwt.exceptions.DecodeError:
        flash("Invalid session. Please log in again.")
        return redirect(url_for('signin'))

    payment = int(request.form.get('payment'))
    purchase = session.get('purchase')

    if not purchase:
        flash("No purchase information found!")
        return redirect(url_for('main'))

    if payment == purchase['total_price']:
        db.order_history.insert_one({
            'product_name': purchase['product_name'],
            'store': purchase['store'],
            'quantity': purchase['quantity'],
            'total_price': purchase['total_price'],
            'buyer_name': user_info['name'], 
            'address': user_info['address'], 
            'timestamp': datetime.now(),
            'image': purchase['image'],
            'status': 'Pending'
        })
        session.pop('purchase')
        return redirect(url_for('order_history'))

    else:
        flash("Payment failed! Incorrect amount.")
        return redirect(url_for('purchase_page'))

@app.route('/order-history')
def order_history():
    token_receive = request.cookies.get(TOKEN_KEY)
    if not token_receive:
        flash("You need to be logged in to view order history.")
        return redirect(url_for('signin'))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"email": payload["id"]})

        if not user_info:
            flash("User information not found.")
            return redirect(url_for('signin'))

        order_history = list(db.order_history.find({'buyer_name': user_info['name']}).sort('timestamp', DESCENDING))
        return render_template('order-history.html', order_history=order_history)

    except jwt.ExpiredSignatureError:
        flash("Session expired. Please log in again.")
        return redirect(url_for('signin'))
    except jwt.exceptions.DecodeError:
        flash("Invalid session. Please log in again.")
        return redirect(url_for('signin'))

@app.route('/seller-transaction')
def transactions():
    order_history = list(db.order_history.find().sort('timestamp', DESCENDING))
    return render_template('seller-transaction.html', order_history=order_history)

@app.route('/update-status/<transaction_id>', methods=['POST'])
def update_status(transaction_id):
    new_status = request.form.get('status')
    db.order_history.update_one({'_id': ObjectId(transaction_id)}, {'$set': {'status': new_status}})
    return jsonify(success=True)

@app.route('/delete-transaction/<transaction_id>', methods=['DELETE'])
def delete_transaction(transaction_id):
    try:
        db.order_history.delete_one({'_id': ObjectId(transaction_id)})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
