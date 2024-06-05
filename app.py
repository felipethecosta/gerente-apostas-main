from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from mongoengine import Document, StringField, BooleanField, DateTimeField, FloatField, ReferenceField, ListField, connect, DynamicDocument
from mongoengine.signals import pre_save
from bson.objectid import ObjectId
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Configurações do MongoDB usando uma string de conexão
app.config['MONGODB_SETTINGS'] = {
    'db': 'gerente-apostas',
    'host': 'mongodb+srv://nsnunes01:1pNO2JJzZTotwsmB@cluster0.tqvnk7i.mongodb.net/gerente-apostas?retryWrites=true&w=majority'
}
# Inicializa a conexão com o MongoDB e define o alias
connect(alias='gerente-apostas', host=app.config['MONGODB_SETTINGS']['host'])

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Definir coleção para cada modelo
class User(UserMixin, DynamicDocument):
    username = StringField(required=True, unique=True, max_length=150)
    password = StringField(required=True, max_length=150)
    is_admin = BooleanField(default=False)
    is_approved = BooleanField(required=True, default=False)
    approval_expiry = DateTimeField()
    apostas = ListField(ReferenceField('Aposta'))
    bancas = ListField(ReferenceField('Banca'))
    createdAt = DateTimeField(default=datetime.utcnow)
    updatedAt = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'users',
        'db_alias': 'gerente-apostas'
    }

class Banca(DynamicDocument):
    banca_inicial = FloatField(required=True, default=0.0)
    banca_total = FloatField(required=True, default=0.0)
    aportes = FloatField(required=True, default=0.0)
    user = ReferenceField(User, required=True)
    username = StringField(required=True)
    createdAt = DateTimeField(default=datetime.utcnow)
    updatedAt = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'bancas',
        'db_alias': 'gerente-apostas'
    }

class Aposta(DynamicDocument):
    data = StringField(required=True, max_length=10)
    mandante = StringField(required=True, max_length=100)
    visitante = StringField(required=True, max_length=100)
    tipo_jogo = StringField(required=True, max_length=100)
    confianca = StringField(required=True, max_length=10)
    valor = FloatField(required=True)
    odd = FloatField(required=True)
    retorno = FloatField(required=True)
    resultado = StringField(required=True, default="pendente", max_length=10)
    banca = ReferenceField(Banca, required=True)
    user = ReferenceField(User, required=True)
    username = StringField(required=True)
    createdAt = DateTimeField(default=datetime.utcnow)
    updatedAt = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'apostas',
        'db_alias': 'gerente-apostas'
    }

# Atualiza o campo updatedAt antes de salvar o documento
def update_updatedAt(sender, document, **kwargs):
    document.updatedAt = datetime.utcnow()

pre_save.connect(update_updatedAt, sender=User)
pre_save.connect(update_updatedAt, sender=Banca)
pre_save.connect(update_updatedAt, sender=Aposta)

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

@app.before_first_request
def create_tables():
    if not User.objects(username='admin').first():
        admin_user = User(username='admin', password=bcrypt.generate_password_hash('admin').decode('utf-8'), is_admin=True, is_approved=True)
        admin_user.save()
    
    admin_user = User.objects(username='admin').first()
    
    if not Banca.objects.first():
        banca = Banca(user=admin_user, username=admin_user.username, banca_inicial=0.0, banca_total=0.0, aportes=0.0)
        banca.save()

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

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = User.objects(pk=current_user.id).first()
    banca = Banca.objects(user=user).first()

    if not banca:
        flash("Nenhuma banca encontrada para o usuário.", "danger")
        return redirect(url_for('configurar_banca'))

    if request.method == 'POST':
        if 'index' in request.form and 'resultado' in request.form:
            aposta_id = request.form['index']
            novo_resultado = request.form['resultado']
            aposta = Aposta.objects(pk=aposta_id).first()
            if aposta.user.pk != user.pk:
                flash("Você não tem permissão para alterar esta aposta.", "danger")
                return redirect(url_for('dashboard'))

            resultado_atual = aposta.resultado

            if resultado_atual != "RED" and novo_resultado == "RED":
                banca.banca_total -= aposta.valor
            elif resultado_atual == "RED" and novo_resultado != "RED":
                banca.banca_total += aposta.valor

            aposta.resultado = novo_resultado
            aposta.save()
            flash("Resultado atualizado com sucesso.", "success")

    total_green = Aposta.objects(user=current_user.id, resultado="GREEN").count()
    total_red = Aposta.objects(user=current_user.id, resultado="RED").count()
    total_reembolso = Aposta.objects(user=current_user.id, resultado="REEMBOLSO").count()

    ultimas_apostas = Aposta.objects(user=current_user.id).order_by('-id')[:10]

    banca_atual = banca.banca_inicial + banca.aportes

    lucro_total = 0
    total_pendente = 0

    for aposta in Aposta.objects(user=current_user.id):
        if aposta.resultado == "GREEN":
            lucro = (aposta.valor * aposta.odd) - aposta.valor
            lucro_total += lucro
            banca_atual += lucro
        elif aposta.resultado == "RED":
            lucro = -aposta.valor
            lucro_total += lucro
            banca_atual += lucro
        elif aposta.resultado == "REEMBOLSO":
            pass
        elif aposta.resultado == "pendente":
            total_pendente += aposta.valor

    banca_atual -= total_pendente

    return render_template('index.html', banca=banca, banca_atual=banca_atual, total_green=total_green, total_red=total_red, total_reembolso=total_reembolso, ultimas_apostas=ultimas_apostas, lucro=lucro_total)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        new_user.save()
        flash("Registrado com sucesso. Por favor, faça login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.objects(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_approved and (user.approval_expiry is None or user.approval_expiry > datetime.utcnow()):
                login_user(user)

                # Verifica se o usuário tem uma banca associada, senão cria uma
                if not Banca.objects(user=user).first():
                    banca = Banca(user=user, username=user.username, banca_inicial=0.0, banca_total=0.0, aportes=0.0)
                    banca.save()

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
    user = User.objects(pk=current_user.id).first()
    banca = Banca.objects(user=user).first()
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
        
        banca.save()
        return redirect(url_for('dashboard'))
    return render_template('configurar_banca.html', banca=banca)

@app.route('/reset_banca', methods=['POST'])
@login_required
def reset_banca():
    user = User.objects(pk=current_user.id).first()
    banca = Banca.objects(user=user).first()
    banca.banca_inicial = 0.0
    banca.banca_total = 0.0
    banca.aportes = 0.0
    banca.save()
    flash("Banca resetada com sucesso.", "success")
    return redirect(url_for('dashboard'))

@app.route('/adicionar', methods=['GET', 'POST'])
@login_required
def adicionar():
    user = User.objects(pk=current_user.id).first()
    banca = Banca.objects(user=user).first()
    if request.method == 'POST':
        data = request.form['data']
        mandante = request.form['mandante']
        visitante = request.form['visitante']
        tipo_jogo = request.form['tipo_jogo']
        confianca = request.form['confianca']
        valor = float(request.form['valor'])
        odd = float(request.form['odd'])
        retorno = valor * odd
        aposta = Aposta(data=data, mandante=mandante, visitante=visitante, tipo_jogo=tipo_jogo, confianca=confianca, valor=valor, odd=odd, retorno=retorno, banca=banca, user=user, username=user.username)
        aposta.save()
        flash("Aposta adicionada com sucesso.", "success")
        return redirect(url_for('dashboard'))
    return render_template('adicionar.html', banca=banca)

@app.route('/listar', methods=['GET', 'POST'])
@login_required
def listar():
    user = User.objects(pk=current_user.id).first()
    banca = Banca.objects(user=user).first()
    try:
        if request.method == 'POST':
            if 'index' in request.form and 'resultado' in request.form:
                aposta_id = request.form['index']
                novo_resultado = request.form['resultado']
                aposta = Aposta.objects(pk=aposta_id).first()
                if aposta.user.pk != user.pk:
                    flash("Você não tem permissão para alterar esta aposta.", "danger")
                    return redirect(url_for('listar'))

                resultado_atual = aposta.resultado

                if resultado_atual != "RED" and novo_resultado == "RED":
                    banca.banca_total -= aposta.valor
                elif resultado_atual == "RED" and novo_resultado != "RED":
                    banca.banca_total += aposta.valor

                aposta.resultado = novo_resultado
                aposta.save()
                flash("Resultado atualizado com sucesso.", "success")
            
            elif 'remover' in request.form:
                aposta_id = request.form['remover']
                aposta = Aposta.objects(pk=aposta_id).first()
                if aposta.user.pk != user.pk:
                    flash("Você não tem permissão para remover esta aposta.", "danger")
                    return redirect(url_for('listar'))

                if aposta.resultado == "RED":
                    banca.banca_total += aposta.valor
                elif aposta.resultado == "GREEN":
                    banca.banca_total -= (aposta.valor * aposta.odd) - aposta.valor

                aposta.delete()
                flash("Aposta removida com sucesso.", "success")
            
            recalcular_banca_total(user.pk)
            return redirect(url_for('listar'))

        apostas = Aposta.objects(user=user)
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
    banca = Banca.objects(user=user_id).first()
    banca_total = banca.banca_inicial + banca.aportes
    for aposta in Aposta.objects(user=user_id):
        if aposta.resultado == "GREEN":
            banca_total += (aposta.valor * aposta.odd) - aposta.valor
        elif aposta.resultado == "RED":
            banca_total -= aposta.valor
    banca.banca_total = banca_total
    banca.save()

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
def admin(*args, **kwargs):
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        approval_expiry_str = request.form.get('approval_expiry')
        approval_expiry = datetime.strptime(approval_expiry_str, '%d/%m/%Y %H:%M')
        user = User.objects(pk=user_id).first()
        if user:
            user.is_approved = True
            user.approval_expiry = approval_expiry
            user.save()
            flash(f"Usuário {user.username} aprovado com sucesso até {approval_expiry}.", "success")
    
    users = User.objects(is_approved=False)
    all_users = User.objects()

    return render_template('admin.html', users=users, all_users=all_users)

@app.route('/create_user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, is_admin='is_admin' in request.form)
        new_user.save()
        flash(f"Usuário {new_user.username} criado com sucesso.", "success")
        return redirect(url_for('admin'))
    
    return render_template('create_user.html')

@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.objects(pk=user_id).first()
    if not user:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for('admin'))

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
        
        user.save()
        flash(f"Usuário {user.username} atualizado com sucesso.", "success")
        return redirect(url_for('admin'))
    
    return render_template('edit_user.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
