from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apostas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, nullable=False, default=False)
    approval_expiry = db.Column(db.DateTime, nullable=True)
    apostas = db.relationship('Aposta', backref='user', lazy=True)
    bancas = db.relationship('Banca', backref='user', lazy=True)

class Banca(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    banca_inicial = db.Column(db.Float, nullable=False, default=0.0)
    banca_total = db.Column(db.Float, nullable=False, default=0.0)
    aportes = db.Column(db.Float, nullable=False, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Aposta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10), nullable=False)
    mandante = db.Column(db.String(100), nullable=False)
    visitante = db.Column(db.String(100), nullable=False)
    tipo_jogo = db.Column(db.String(100), nullable=False)
    confianca = db.Column(db.String(10), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    odd = db.Column(db.Float, nullable=False)
    retorno = db.Column(db.Float, nullable=False)
    resultado = db.Column(db.String(10), nullable=False, default="pendente")
    banca_id = db.Column(db.Integer, db.ForeignKey('banca.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()
    if not Banca.query.first():
        banca = Banca(user_id=1, banca_inicial=0.0, banca_total=0.0, aportes=0.0)
        db.session.add(banca)
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=bcrypt.generate_password_hash('admin').decode('utf-8'), is_admin=True, is_approved=True)
        db.session.add(admin_user)
    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(current_user.id)
    banca = Banca.query.filter_by(user_id=user.id).first()
    
    total_green = Aposta.query.filter_by(user_id=current_user.id, resultado="GREEN").count()
    total_red = Aposta.query.filter_by(user_id=current_user.id, resultado="RED").count()
    total_reembolso = Aposta.query.filter_by(user_id=current_user.id, resultado="REEMBOLSO").count()
    
    ultimas_apostas = Aposta.query.filter_by(user_id=current_user.id).order_by(Aposta.id.desc()).limit(10).all()
    
    # Inicializa a banca atual com a banca inicial e aportes
    banca_atual = banca.banca_inicial + banca.aportes
    
    # Calcula os lucros e ajusta a banca atual
    lucro_total = 0
    total_pendente = 0  # Inicializa o total das apostas pendentes
    
    for aposta in Aposta.query.filter_by(user_id=current_user.id).all():
        if aposta.resultado == "GREEN":
            lucro = (aposta.valor * aposta.odd) - aposta.valor  # Lucro é o retorno menos o valor apostado
            lucro_total += lucro
            banca_atual += lucro  # Adiciona o lucro à banca atual
        elif aposta.resultado == "RED":
            lucro = -aposta.valor  # Lucro é o valor apostado negativo
            lucro_total += lucro
            banca_atual += lucro  # Subtrai o valor apostado da banca atual
        elif aposta.resultado == "REEMBOLSO":
            # Em caso de reembolso, não altera a banca_atual
            pass
        elif aposta.resultado == "pendente":
            total_pendente += aposta.valor  # Adiciona o valor da aposta pendente
    
    # Subtrai o valor das apostas pendentes da banca atual
    banca_atual -= total_pendente

    return render_template('index.html', banca=banca, banca_atual=banca_atual, total_green=total_green, total_red=total_red, total_reembolso=total_reembolso, ultimas_apostas=ultimas_apostas, lucro=lucro_total)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registrado com sucesso. Por favor, faça login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_approved and (user.approval_expiry is None or user.approval_expiry > datetime.utcnow()):
                login_user(user)
                flash("Login realizado com sucesso.", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Acesso não autorizado ou aprovação expirada. Aguarde a aprovação do administrador.", "danger")
        else:
            flash("Login ou senha incorretos.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout realizado com sucesso.", "success")
    return redirect(url_for('login'))

@app.route('/configurar_banca', methods=['GET', 'POST'])
@login_required
def configurar_banca():
    user = User.query.get(current_user.id)
    banca = Banca.query.filter_by(user_id=user.id).first()
    if request.method == 'POST':
        banca_inicial = float(request.form.get('banca_inicial', 0))
        valor_aporte = float(request.form.get('valor_aporte', 0))
        
        if banca_inicial == 0 and valor_aporte == 0:
            banca.banca_inicial = 0.0
            banca.banca_total = 0.0
            banca.aportes = 0.0
            flash("Banca resetada com sucesso.", "success")
        else:
            if 'banca_inicial' in request.form:
                banca.banca_inicial = banca_inicial
                banca.banca_total = banca.banca_inicial + banca.aportes
                flash("Banca inicial configurada com sucesso.", "success")
            elif 'valor_aporte' in request.form:
                banca.aportes += valor_aporte
                banca.banca_total += valor_aporte
                flash("Aporte adicionado com sucesso.", "success")
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('configurar_banca.html', banca=banca)

@app.route('/reset_banca', methods=['POST'])
@login_required
def reset_banca():
    user = User.query.get(current_user.id)
    banca = Banca.query.filter_by(user_id=user.id).first()
    banca.banca_inicial = 0.0
    banca.banca_total = 0.0
    banca.aportes = 0.0
    db.session.commit()
    flash("Banca resetada com sucesso.", "success")
    return redirect(url_for('dashboard'))

@app.route('/adicionar', methods=['GET', 'POST'])
@login_required
def adicionar():
    user = User.query.get(current_user.id)
    banca = Banca.query.filter_by(user_id=user.id).first()
    if request.method == 'POST':
        data = request.form['data']
        mandante = request.form['mandante']
        visitante = request.form['visitante']
        tipo_jogo = request.form['tipo_jogo']
        confianca = request.form['confianca']
        valor = float(request.form['valor'])
        odd = float(request.form['odd'])
        retorno = valor * odd
        aposta = Aposta(data=data, mandante=mandante, visitante=visitante, tipo_jogo=tipo_jogo, confianca=confianca, valor=valor, odd=odd, retorno=retorno, banca_id=banca.id, user_id=user.id)
        db.session.add(aposta)
        db.session.commit()
        flash("Aposta adicionada com sucesso.", "success")
        return redirect(url_for('dashboard'))
    return render_template('adicionar.html', banca=banca)

@app.route('/listar', methods=['GET', 'POST'])
@login_required
def listar():
    user = User.query.get(current_user.id)
    banca = Banca.query.filter_by(user_id=user.id).first()
    try:
        if request.method == 'POST':
            if 'index' in request.form and 'resultado' in request.form:
                aposta_id = int(request.form['index'])
                novo_resultado = request.form['resultado']
                aposta = Aposta.query.get(aposta_id)
                if aposta.user_id != user.id:
                    flash("Você não tem permissão para alterar esta aposta.", "danger")
                    return redirect(url_for('listar'))

                resultado_atual = aposta.resultado

                # Verifica se o status anterior não era "RED"
                if resultado_atual != "RED" and novo_resultado == "RED":
                    # Subtrai o valor da aposta da banca total
                    banca.banca_total -= aposta.valor
                elif resultado_atual == "RED" and novo_resultado != "RED":
                    # Adiciona o valor da aposta de volta à banca total
                    banca.banca_total += aposta.valor

                aposta.resultado = novo_resultado
                db.session.commit()
                flash("Resultado atualizado com sucesso.", "success")
            elif 'remover' in request.form:
                aposta_id = int(request.form['remover'])
                aposta = Aposta.query.get(aposta_id)
                if aposta.user_id != user.id:
                    flash("Você não tem permissão para remover esta aposta.", "danger")
                    return redirect(url_for('listar'))

                # Verifica o status da aposta antes de removê-la
                if aposta.resultado == "RED":
                    banca.banca_total += aposta.valor
                elif aposta.resultado == "GREEN":
                    banca.banca_total -= (aposta.valor * aposta.odd) - aposta.valor

                db.session.delete(aposta)
                db.session.commit()
                flash("Aposta removida com sucesso.", "success")
            
            # Recalcular a banca total após a remoção
            recalcular_banca_total(user.id)
            return redirect(url_for('listar'))

        apostas = Aposta.query.filter_by(user_id=user.id).all()
        return render_template('listar.html', apostas=apostas, banca=banca)
    except Exception as e:
        flash(f"Erro ao listar apostas: {str(e)}", "danger")
        return redirect(url_for('dashboard'))


@app.route('/recalcular_banca', methods=['POST'])
@login_required
def recalcular_banca():
    user_id = current_user.id
    recalcular_banca_total(user_id)
    flash("Banca recalculada com sucesso.", "success")
    return redirect(url_for('dashboard'))

def recalcular_banca_total(user_id):
    banca = Banca.query.filter_by(user_id=user_id).first()
    banca_total = banca.banca_inicial + banca.aportes
    for aposta in Aposta.query.filter_by(user_id=user_id).all():
        if aposta.resultado == "GREEN":
            banca_total += (aposta.valor * aposta.odd) - aposta.valor
        elif aposta.resultado == "RED":
            banca_total -= aposta.valor
    banca.banca_total = banca_total
    db.session.commit()



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Acesso não autorizado.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        approval_expiry_str = request.form.get('approval_expiry')
        approval_expiry = datetime.strptime(approval_expiry_str, '%d/%m/%Y %H:%M')
        user = User.query.get(user_id)
        if user:
            user.is_approved = True
            user.approval_expiry = approval_expiry
            db.session.commit()
            flash(f"Usuário {user.username} aprovado com sucesso até {approval_expiry}.", "success")
    
    users = User.query.filter_by(is_approved=False).all()
    all_users = User.query.all()  # Para listar todos os usuários

    return render_template('admin.html', users=users, all_users=all_users)

@app.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, is_admin='is_admin' in request.form)
        db.session.add(new_user)
        db.session.commit()
        flash(f"Usuário {new_user.username} criado com sucesso.", "success")
        return redirect(url_for('admin'))
    
    return render_template('create_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.is_admin = 'is_admin' in request.form
        user.is_approved = 'is_approved' in request.form
        approval_expiry_str = request.form.get('approval_expiry')
        if approval_expiry_str:
            user.approval_expiry = datetime.strptime(approval_expiry_str, '%d/%m/%Y %H:%M')
        else:
            user.approval_expiry = None

        if 'new_password' in request.form and request.form['new_password']:
            new_password = request.form['new_password']
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        db.session.commit()
        flash(f"Usuário {user.username} atualizado com sucesso.", "success")
        return redirect(url_for('admin'))
    
    return render_template('edit_user.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
