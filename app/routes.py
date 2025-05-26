# app/routes.py

from flask import render_template
from flask import current_app as app 



from flask import Blueprint, render_template

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@main_bp.route('/index')
def index():
    algorithms = ['RSA', 'ElGamal', 'ECC']
    return render_template('index.html', title='密码学算法演示平台', algorithms=algorithms)
