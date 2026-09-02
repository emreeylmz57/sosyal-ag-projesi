import os
import sys
import uuid
import urllib.parse
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # <--- Dosya adlarını güvenli hale getirmek için şart!
from sqlalchemy import func, event


app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False # JSON yanıtlarında Türkçe karakterlerin bozulmasını engeller

# Flask istek ve yanıtlarının her zaman UTF-8 olmasını sağlayan sarmalayıcı
@app.after_request
def add_header(response):
    response.headers['Content-Type'] = 'application/vnd.api+json; charset=utf-8' if response.is_json else 'text/html; charset=utf-8'
    return response
app.config['SECRET_KEY'] = 'gizli-ve-guvenli-bir-anahtar-cumlesi'

# ---------------------------------------------------------
# FLASK-LOGIN KURULUMU
# ---------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Lütfen bu sayfaya erişmek için önce giriş yapın.'
login_manager.login_message_category = 'error'

# ---------------------------------------------------------
# SQL SERVER BAĞLANTI AYARI
# ---------------------------------------------------------
params = urllib.parse.quote_plus(
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=(localdb)\MSSQLLocalDB;"
    r"DATABASE=VeriTabaniProjesi;"
    r"Trusted_Connection=yes;"
    r"ClientCharset=UTF8;"  # <--- İşte bu parametre SQL Server'dan veri okunurken ve yazılırken Türkçe karakterlerin bozulmasını engeller!
)

app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
from sqlalchemy import event
@app.before_request
def check_if_banned():
    if 'user_id' in session:
        current_u = User.query.get(session['user_id'])
        if current_u:
            # Aktif ban kontrolü (Süresi geçmemiş veya sınırsız banlar)
            active_ban = Ban.query.filter(
                Ban.user_id == current_u.id,
                (Ban.expires_at > datetime.utcnow() + timedelta(hours=3)) | (Ban.expires_at == None)
            ).first()

            if active_ban:
                session.clear() # Oturumu kapat
                flash('Hesabınız aktif bir ban nedeniyle askıya alınmıştır!', 'error')
                return redirect(url_for('login'))
# ---------------------------------------------------------
# PROFİL RESMİ YÜKLEME AYARLARI
# ---------------------------------------------------------
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'profile_pics')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------------------------------------------
# VERİTABANI MODELLERİ VE ARA TABLOLAR
# ---------------------------------------------------------

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete="CASCADE"), primary_key=True)
)

class Friendship(db.Model):
    __tablename__ = 'friendships'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    # Saatleri +3 saat (Türkiye saati) yapacak şekilde güncelledik:
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_friend_requests', lazy='dynamic', cascade='all, delete-orphan'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_friend_requests', lazy='dynamic', cascade='all, delete-orphan'))

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    # Saatleri +3 saat (Türkiye saati) yaptık:
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    # Türkçe karakter desteği için String yerine Unicode yaptık:
    username = db.Column(db.Unicode(150), nullable=False)
    action = db.Column(db.Unicode(100), nullable=False)
    details = db.Column(db.UnicodeText, nullable=False)
    target_user = db.Column(db.Unicode(150), nullable=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Türkçe karakterler için Unicode kullanıldı:
    content = db.Column(db.Unicode(500), nullable=False) 
    is_read = db.Column(db.Boolean, default=False)
    # Saatleri +3 saat (Türkiye saati) yaptık:
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

class Block(db.Model):
    __tablename__ = 'blocks'
    
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Saatleri +3 saat yaptık:
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    blocker = db.relationship('User', foreign_keys=[blocker_id], primaryjoin='Block.blocker_id == User.id')
    blocked = db.relationship('User', foreign_keys=[blocked_id], primaryjoin='Block.blocked_id == User.id')

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Türkçe karakterler için UnicodeText yapıldı:
    reason = db.Column(db.UnicodeText, nullable=False)
    # Saatleri +3 saat yaptık:
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    # Tekrarlayan mükerrer tanımlar temizlendi:
    reporter = db.relationship('User', foreign_keys=[reporter_id], primaryjoin='Report.reporter_id == User.id')
    reported = db.relationship('User', foreign_keys=[reported_id], primaryjoin='Report.reported_id == User.id')

def log_action(user, action, details, target_user=None):
    username_to_log = user.username if user else "Misafir/Sistem"

    new_log = AuditLog(
        username=username_to_log,
        action=action,
        target_user=target_user,
        details=details
    )
    db.session.add(new_log)
    db.session.commit()
class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    # Türkçe karakter desteği için db.Unicode kullanıldı:
    name = db.Column(db.Unicode(80), unique=True, nullable=False)
    description = db.Column(db.Unicode(255), nullable=True) # <-- Rol açıklaması
    priority = db.Column(db.Integer, default=99, nullable=False)
    color = db.Column(db.String(10), default='#333333', nullable=False)
    
    can_delete_users = db.Column(db.Boolean, default=False, nullable=False)
    can_edit_points = db.Column(db.Boolean, default=False, nullable=False)
    can_assign_roles = db.Column(db.Boolean, default=False, nullable=False)

    can_grant_delete_permission = db.Column(db.Boolean, default=False, nullable=False)
    can_grant_points_permission = db.Column(db.Boolean, default=False, nullable=False)
    can_grant_role_permission = db.Column(db.Boolean, default=False, nullable=False)
    # Role modeline eklenecek alanlar:
    can_ban_users = db.Column(db.Boolean, default=False)
    can_grant_ban_permission = db.Column(db.Boolean, default=False)

class DeletedUser(db.Model):
    __tablename__ = 'deleted_users'
    
    id = db.Column(db.Integer, primary_key=True)
    original_id = db.Column(db.Integer, nullable=False)
    # Türkçe karakterler için db.Unicode kullanıldı:
    username = db.Column(db.Unicode(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    points = db.Column(db.Integer, default=0, nullable=False)
    profile_pic = db.Column(db.String(200), nullable=False, default='default.png')
    # Silinme saati Türkiye saatine (+3 saat) ayarlandı:
    deleted_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
from datetime import datetime, timedelta

class Ban(db.Model):
    __tablename__ = 'bans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)     # Banlanan kullanıcı
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)    # Banı veren kullanıcı/yetkili
    reason = db.Column(db.Unicode(500), nullable=True)                             # Ban sebebi
    expires_at = db.Column(db.DateTime, nullable=True)                             # Sınırsız için None olacak
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)                    # Banın atıldığı tarih

    # İlişkiler
    user = db.relationship('User', foreign_keys=[user_id], backref='bans_received')
    admin = db.relationship('User', foreign_keys=[admin_id], backref='bans_given')
class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.UnicodeText, nullable=False)
    visibility = db.Column(db.String(20), default='public')
    image_file = db.Column(db.String(200), nullable=True) # <--- Dosya / Resim yolu için eklendi!
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    is_edited = db.Column(db.Boolean, default=False)  # <--- Gönderi düzenlendi bilgisi eklendi
    
    author = db.relationship('User', foreign_keys=[user_id], backref=db.backref('posts', cascade='all, delete-orphan'))
    likes = db.relationship('PostLike', backref='post', cascade='all, delete-orphan')
    comments = db.relationship('PostComment', backref='post', cascade='all, delete-orphan', order_by='PostComment.created_at.asc()')
class PostLike(db.Model):
    __tablename__ = 'post_likes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

class PostComment(db.Model):
    __tablename__ = 'post_comments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    content = db.Column(db.UnicodeText, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    is_edited = db.Column(db.Boolean, default=False)  # <--- Yorum düzenlendi bilgisi eklendi
    
    author = db.relationship('User', foreign_keys=[user_id])
class PostReport(db.Model):
    __tablename__ = 'post_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reason = db.Column(db.UnicodeText, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    
    post = db.relationship('Post', backref=db.backref('reports', cascade='all, delete-orphan'))
    reporter = db.relationship('User', foreign_keys=[reporter_id])
class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Bildirimi alacak kullanıcı
    content = db.Column(db.UnicodeText, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    
    recipient = db.relationship('User', foreign_keys=[user_id], backref=db.backref('notifications', cascade='all, delete-orphan'))

    # --- BİLDİRİM YARDIMCI FONKSİYONU ---
def create_notification(user_id, content):
    """Kullanıcıya bildirim gönderen yardımcı fonksiyon"""
    try:
        notif = Notification(user_id=user_id, content=content)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        print("Bildirim hatası:", e)
        
class DeletedPost(db.Model):
    __tablename__ = 'deleted_post' # veya veritabanındaki tablo adınız neyse
    
    id = db.Column(db.Integer, primary_key=True)
    original_id = db.Column(db.Integer)
    content = db.Column(db.Text, nullable=False)
    visibility = db.Column(db.String(20), default='public')
    author_id = db.Column(db.Integer, nullable=False)
    deleted_by_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    delete_reason = db.Column(db.Text)  # <--- İŞTE BU SATIR EKSİK OLDUĞU İÇİN PATLIYOR

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    # Türkçe karakter desteği için db.Unicode kullanıldı:
    username = db.Column(db.Unicode(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0, nullable=False)
    profile_pic = db.Column(db.String(200), nullable=False, default='default.png')

    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                            backref=db.backref('users', lazy=True))

    can_delete_users = db.Column(db.Boolean, default=False, nullable=False)
    can_edit_points = db.Column(db.Boolean, default=False, nullable=False)
    can_assign_roles = db.Column(db.Boolean, default=False, nullable=False)

    can_grant_delete_permission = db.Column(db.Boolean, default=False, nullable=False)
    can_grant_points_permission = db.Column(db.Boolean, default=False, nullable=False)
    can_grant_role_permission = db.Column(db.Boolean, default=False, nullable=False)
    
    # Ban yetkileri
    can_ban_users = db.Column(db.Boolean, default=False)
    can_grant_ban_permission = db.Column(db.Boolean, default=False)

    # --- YENİ EKLENEN CEVAP SİLME YETKİLERİ ---
    can_delete_comments = db.Column(db.Boolean, default=False, nullable=False)
    can_grant_delete_comments_permission = db.Column(db.Boolean, default=False, nullable=False)

    def can_delegate_comment_delete(self):
        # Admin veya başkalarına cevap silme yetkisi verebilme hakkı olanlar
        return self.is_admin or self.can_grant_delete_comments_permission

    def set_password(self, password):
        self.password_hash = password

    def check_password(self, password):
        return self.password_hash == password

    @property
    def sorted_roles(self):
        return sorted(self.roles, key=lambda r: r.priority)

    def has_delete_permission(self):
        if self.is_admin or self.can_delete_users:
            return True
        return any(role.can_delete_users for role in self.roles)

    def has_points_permission(self):
        if self.is_admin or self.can_edit_points:
            return True
        return any(role.can_edit_points for role in self.roles)

    def has_assign_role_permission(self):
        if self.is_admin or self.can_assign_roles:
            return True
        return any(role.can_assign_roles for role in self.roles)

    def can_delegate_delete(self):
        if self.is_admin or self.can_grant_delete_permission:
            return True
        return any(role.can_grant_delete_permission for role in self.roles)

    def can_delegate_points(self):
        if self.is_admin or self.can_grant_points_permission:
            return True
        return any(role.can_grant_points_permission for role in self.roles)

    def can_delegate_role(self):
        if self.is_admin or self.can_grant_role_permission:
            return True
        return any(role.can_grant_role_permission for role in self.roles)

    def get_priority(self):
        if self.is_admin:
            return 0
        if self.roles:
            return min(role.priority for role in self.roles)
        return 999
    def is_blocked_by_or_blocking(self, target_user):
        block = Block.query.filter(
            ((Block.blocker_id == self.id) & (Block.blocked_id == target_user.id)) |
            ((Block.blocker_id == target_user.id) & (Block.blocked_id == self.id))
        ).first()
        return block is not None

    # --- ARKADAŞLIK YARDIMCI METOTLARI ---
    def is_friends_with(self, target_user):
        return Friendship.query.filter(
            ((Friendship.sender_id == self.id) & (Friendship.receiver_id == target_user.id)) |
            ((Friendship.sender_id == target_user.id) & (Friendship.receiver_id == self.id)),
            Friendship.status == 'accepted'
        ).first() is not None

    def get_friendship_status(self, target_user):
        if self.id == target_user.id:
            return 'self'
        friendship = Friendship.query.filter(
            ((Friendship.sender_id == self.id) & (Friendship.receiver_id == target_user.id)) |
            ((Friendship.sender_id == target_user.id) & (Friendship.receiver_id == self.id))
        ).first()

        if not friendship:
            return 'none'
        if friendship.status == 'accepted':
            return 'friends'
        if friendship.status == 'pending':
            if friendship.sender_id == self.id:
                return 'sent_pending'
            else:
                return 'received_pending'
        return 'none'

    def get_friends(self):
        accepted_friendships = Friendship.query.filter(
            ((Friendship.sender_id == self.id) | (Friendship.receiver_id == self.id)),
            Friendship.status == 'accepted'
        ).all()
        
        friends = []
        for f in accepted_friendships:
            if f.sender_id == self.id:
                friends.append(User.query.get(f.receiver_id))
            else:
                friends.append(User.query.get(f.sender_id))
        return friends

    def get_pending_requests(self):
        return Friendship.query.filter_by(receiver_id=self.id, status='pending').all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------
# SAYFA ROTALARI (ROUTES)
# ---------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        user_obj = User.query.get(session['user_id'])
        
        all_users = []
        if user_obj and (user_obj.is_admin or user_obj.has_delete_permission() or 
                         user_obj.has_points_permission() or user_obj.has_assign_role_permission()):
            all_users = User.query.all()
            
        all_roles = Role.query.order_by(Role.priority.asc()).all()
        
        # Okunmamış toplam mesaj sayısı
        total_unread = Message.query.filter_by(receiver_id=user_obj.id, is_read=False).count()
        
        # Okunmamış toplam bildirim sayısı
        try:
            total_unread_notifs = Notification.query.filter_by(user_id=user_obj.id, is_read=False).count()
        except:
            total_unread_notifs = 0
        
        # Gelen arkadaşlık istekleri sayısı
        try:
            incoming_requests_count = Friendship.query.filter_by(receiver_id=user_obj.id, status='pending').count()
        except:
            incoming_requests_count = 0
            
        # Şikayet ve Ban Logları verileri (Admin VEYA Cevap Silme Yetkisi Olanlar için)
        reports = []
        post_reports = []
        ban_logs = []
        pending_reports_count = 0
        
        if user_obj and (user_obj.is_admin or user_obj.can_delete_comments):
            try:
                # Sadece adminler kullanıcı şikayetlerini ve ban loglarını görür
                if user_obj.is_admin:
                    reports = Report.query.all()
                    ban_logs = BanLog.query.order_by(BanLog.created_at.desc()).limit(15).all() if 'BanLog' in globals() or 'BanLog' in locals() else []
                
                # Gönderi şikayetlerini hem adminler hem de cevap silme yetkisi olanlar görebilir
                post_reports = PostReport.query.all() if 'PostReport' in globals() or 'PostReport' in locals() else []
                
                pending_reports_count = len(reports) + len(post_reports)
            except:
                pending_reports_count = 0
        
        # Sosyal Akış İçin Gönderileri Çekme Mantığı:
        # 1. Kullanıcının arkadaşlarının ID listesini alıyoruz
        friend_ids = [f.id for f in user_obj.get_friends()] if hasattr(user_obj, 'get_friends') else []
        friend_ids.append(user_obj.id) # Kendi gönderilerini de her zaman görebilmesi için
        
        # 2. Herkese açık ('public') veya sadece arkadaşlara özel olup ('friends') arkadaşı/kendisi tarafından atılan gönderiler
        posts = Post.query.filter(
            db.or_(
                Post.visibility == 'public',
                db.and_(Post.visibility == 'friends', Post.user_id.in_(friend_ids))
            )
        ).order_by(Post.created_at.desc()).all()
        
        return render_template(
            'index.html', 
            user=user_obj, 
            all_users=all_users, 
            all_roles=all_roles, 
            total_unread=total_unread,
            total_unread_notifs=total_unread_notifs,
            incoming_requests_count=incoming_requests_count,
            pending_reports_count=pending_reports_count,
            reports=reports,
            post_reports=post_reports,
            ban_logs=ban_logs,
            posts=posts,
            now=datetime.utcnow() + timedelta(hours=3)
        )
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash('Tüm alanları doldurmanız gerekmektedir!', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Bu kullanıcı adı veya e-posta zaten kullanımda!', 'error')
            return redirect(url_for('register'))

        try:
            new_user = User(username=username, email=email, points=0)
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.flush()
            
            log_action(new_user, "Kayıt Olma", f"'{username}' isimli yeni kullanıcı sisteme kayıt oldu.")
            db.session.commit()

            flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            login_user(user)
            
            log_action(user, "Giriş Yapma", f"'{user.username}' sisteme giriş yaptı.")
            db.session.commit()
            
            flash('Başarıyla giriş yapıldı!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Hatalı kullanıcı adı veya şifre!', 'error')

    return render_template('login.html')

@app.route('/search_users')
def search_users():
    if 'user_id' not in session:
        return jsonify([])

    current_u = User.query.get(session['user_id'])
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    users = User.query.filter(User.username.ilike(f"%{query}%")).limit(5).all()

    results = []
    for u in users:
        profile_link = url_for('user_profile', user_id=u.id)
        friend_status = current_u.get_friendship_status(u) if current_u else 'none'

        results.append({
            'id': u.id,
            'username': u.username,
            'profile_pic': getattr(u, 'profile_pic', 'default.png'),
            'profile_url': profile_link,
            'friend_status': friend_status
        })

    return jsonify(results)

@app.route('/admin/stats')
def admin_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_obj = User.query.get(session['user_id'])
    
    if not user_obj or not (user_obj.is_admin or 
                           user_obj.has_delete_permission() or 
                           user_obj.has_points_permission() or 
                           user_obj.has_assign_role_permission()):
        return jsonify({'error': 'Forbidden'}), 403

    # 1. En Aktif 5 Kullanıcı
    top_users = db.session.query(
        AuditLog.username, func.count(AuditLog.id).label('count')
    ).group_by(AuditLog.username).order_by(func.count(AuditLog.id).desc()).limit(5).all()

    # 2. Son 7 Günlük Girişler (Veritabanındaki En Son Tarihe Göre Otomatik Ayarlanır)
    latest_log = db.session.query(func.max(AuditLog.timestamp)).scalar()
    
    if latest_log:
        end_date = latest_log.date()
    else:
        end_date = datetime.utcnow().date()
        
    seven_days_ago = end_date - timedelta(days=6)
    
    # Eyleminde "Giriş" geçen tüm logları esnek bir şekilde çekiyoruz
    all_logins = AuditLog.query.filter(
        AuditLog.action.ilike("%Giriş%")
    ).all()

    # Tarihlere göre Python içinde güvenle gruplayalım
    login_dict = {}
    for log in all_logins:
        if log.timestamp:
            log_date = log.timestamp.date()
            if seven_days_ago <= log_date <= end_date:
                login_dict[log_date] = login_dict.get(log_date, 0) + 1

    # Aralıktaki 7 günün her biri için liste hazırlıyoruz
    daily_logins = []
    for i in range(7):
        current_date = seven_days_ago + timedelta(days=i)
        count = login_dict.get(current_date, 0)
        daily_logins.append({'date': str(current_date), 'count': count})

    return jsonify({
        'top_users': [{'username': u[0], 'count': u[1]} for u in top_users],
        'daily_logins': daily_logins
    })
@app.route('/messages', methods=['GET'])
@app.route('/messages/<int:recipient_id>', methods=['GET'])
def messages(recipient_id=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_u = User.query.get(session['user_id'])
    
    # Toplam okunmamış mesaj sayısını hesaplayalım
    total_unread = Message.query.filter_by(receiver_id=current_u.id, is_read=False).count()
    
    # SADECE aranızda karşılıklı mesaj geçmişi olan kullanıcıların ID'lerini alıyoruz
    sent_to_ids = db.session.query(Message.receiver_id).filter(Message.sender_id == current_u.id)
    received_from_ids = db.session.query(Message.sender_id).filter(Message.receiver_id == current_u.id)
    chatted_user_ids = set([u[0] for u in sent_to_ids.union(received_from_ids).all()])
    
    # Not: Buradaki 'chatted_user_ids.add(recipient_id)' satırı kaldırılmıştır. 
    # Böylece mesajı olmayan veya geçmişi temizlenen kullanıcı sol listede GÖRÜNMEYECEKTİR.

    # Sadece mesaj geçmişi olan kullanıcıları veritabanından çekiyoruz
    chat_users_raw = User.query.filter(User.id.in_(chatted_user_ids)).all() if chatted_user_ids else []
    
    # Her bir sohbet için okunmamış mesaj sayısını hesaplayalım
    chat_users = []
    for friend in chat_users_raw:
        if friend.id == current_u.id:
            continue
        unread_count = Message.query.filter_by(sender_id=friend.id, receiver_id=current_u.id, is_read=False).count()
        friend.unread_count = unread_count
        chat_users.append(friend)

    active_recipient = None
    chat_messages = []
    am_i_blocked = False
    is_any_blocked = False
    
    if recipient_id:
        active_recipient = User.query.get_or_404(recipient_id)
        
        am_i_blocked = Block.query.filter_by(blocker_id=active_recipient.id, blocked_id=current_u.id).first() is not None
        blocked_by_me = Block.query.filter_by(blocker_id=current_u.id, blocked_id=active_recipient.id).first() is not None
        is_any_blocked = am_i_blocked or blocked_by_me
            
        chat_messages = Message.query.filter(
            ((Message.sender_id == current_u.id) & (Message.receiver_id == active_recipient.id)) |
            ((Message.sender_id == active_recipient.id) & (Message.receiver_id == current_u.id))
        ).order_by(Message.timestamp.asc()).all()
        
        # Okunmamış mesajları okundu yap
        unread_msgs = Message.query.filter_by(sender_id=active_recipient.id, receiver_id=current_u.id, is_read=False).all()
        for msg in unread_msgs:
            msg.is_read = True
        db.session.commit()
        
        total_unread = Message.query.filter_by(receiver_id=current_u.id, is_read=False).count()

    return render_template(
        'messages.html', 
        user=current_u, 
        friends=chat_users, 
        active_recipient=active_recipient, 
        chat_messages=chat_messages,
        am_i_blocked=am_i_blocked,
        is_any_blocked=is_any_blocked,
        total_unread=total_unread
    )
import unicodedata

@app.route('/send_message/<int:recipient_id>', methods=['POST'])
def send_message(recipient_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    recipient = User.query.get_or_404(recipient_id)

    # Karşılıklı engelleme kontrolü
    is_blocked_by_me = Block.query.filter_by(blocker_id=current_u.id, blocked_id=recipient.id).first()
    is_blocking_me = Block.query.filter_by(blocker_id=recipient.id, blocked_id=current_u.id).first()

    if is_blocked_by_me or is_blocking_me:
        flash('Engellenmiş kullanıcılarla mesajlaşamazsınız!', 'error')
        return redirect(url_for('messages', recipient_id=recipient_id))
    
    # Gelen veriyi UTF-8'e zorla ve temizle
    if request.is_json:
        data = request.get_json()
        raw_content = data.get('content', '') if data else ''
    else:
        raw_content = request.form.get('content', '')

    # Python/Flask form verisini okurken oluşan karakter kaymasını önlemek için çevrim:
    try:
        if isinstance(raw_content, str):
            fixed_content = raw_content.encode('latin1').decode('utf-8')
        else:
            fixed_content = str(raw_content)
    except Exception:
        fixed_content = str(raw_content)

    # Unicode karakterleri normalize et (Türkçe karakterlerin bozulmasını engeller)
    content = unicodedata.normalize('NFKC', fixed_content).strip()
    
    if not content:
        flash('Boş mesaj gönderilemez!', 'error')
        return redirect(url_for('messages', recipient_id=recipient_id))
        
    try:
        new_msg = Message(
            sender_id=current_u.id,
            receiver_id=recipient.id,
            content=content,
            is_read=False,
            timestamp=datetime.utcnow() + timedelta(hours=3)
        )
        db.session.add(new_msg)
        db.session.commit()
        print("BAŞARILI: Mesaj veritabanına başarıyla kaydedildi ve commit edildi.")
    except Exception as e:
        db.session.rollback()
        print(f"VERİTABANI KRİTİK HATASI: {str(e)}")
        flash(f'Mesaj gönderilemedi: {str(e)}', 'error')
        
    return redirect(url_for('messages', recipient_id=recipient_id))
@app.route('/block_user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_u = User.query.get(session['user_id'])
    target_u = User.query.get_or_404(user_id)
    
    if current_u.id == target_u.id:
        flash('Kendinizi engelleyemezsiniz!', 'error')
        return redirect(url_for('index'))
        
    existing_block = Block.query.filter_by(blocker_id=current_u.id, blocked_id=target_u.id).first()
    if not existing_block:
        new_block = Block(blocker_id=current_u.id, blocked_id=target_u.id)
        db.session.add(new_block)
        db.session.commit()
        flash(f"'{target_u.username}' başarıyla engellendi.", 'success')
    
    return redirect(url_for('messages', recipient_id=user_id))

@app.route('/unblock_user/<int:user_id>', methods=['POST'])
def unblock_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_u = User.query.get(session['user_id'])
    target_u = User.query.get_or_404(user_id)
    
    existing_block = Block.query.filter_by(blocker_id=current_u.id, blocked_id=target_u.id).first()
    if existing_block:
        db.session.delete(existing_block)
        db.session.commit()
        flash(f"'{target_u.username}' adlı kullanıcının engeli kaldırıldı.", 'success')
    
    return redirect(url_for('messages', recipient_id=user_id))
# Tek bir mesajı silme (Admin veya mesajın sahibi silebilir)
@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    msg = Message.query.get_or_404(message_id)
    
    # Sadece admin veya mesajı gönderen kişi silebilir
    if current_u.is_admin or current_u.id == msg.sender_id:
        recipient_id = msg.receiver_id if msg.sender_id == current_u.id else msg.sender_id
        # Eğer admin başkasının sohbetindeyse doğru alıcıya geri dönebilmek için:
        if current_u.is_admin:
            recipient_id = msg.receiver_id if msg.sender_id == current_u.id else msg.sender_id
            
        try:
            db.session.delete(msg)
            db.session.commit()
            flash('Mesaj başarıyla silindi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Mesaj silinirken hata oluştu: {str(e)}', 'error')
            
        # Hangi kullanıcıyla sohbet ediliyorsa oraya yönlendir
        return redirect(url_for('messages', recipient_id=msg.receiver_id if current_u.id == msg.sender_id else msg.sender_id))
    else:
        flash('Bu mesajı silme yetkiniz yok!', 'error')
        return redirect(url_for('messages'))

# Belirli bir sohbet geçmişinin tamamını silme (Sadece Admin)
@app.route('/clear_chat/<int:recipient_id>', methods=['POST'])
def clear_chat(recipient_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    
    # Sadece adminler tüm sohbeti temizleyebilir
    if not current_u.is_admin:
        flash('Bu işlemi yapmaya yetkiniz yok!', 'error')
        return redirect(url_for('messages', recipient_id=recipient_id))
        
    try:
        # İki kullanıcı arasındaki tüm mesajları bul ve sil
        messages_to_delete = Message.query.filter(
            ((Message.sender_id == current_u.id) & (Message.receiver_id == recipient_id)) |
            ((Message.sender_id == recipient_id) & (Message.receiver_id == current_u.id))
        ).all()
        
        for msg in messages_to_delete:
            db.session.delete(msg)
            
        db.session.commit()
        flash('Sohbet geçmişi tamamen temizlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Sohbet temizlenirken hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('messages', recipient_id=recipient_id))

@app.route('/report_user/<int:user_id>', methods=['POST'])
def report_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    target_u = User.query.get_or_404(user_id)
    reason = request.form.get('reason', '').strip()
    
    if not reason:
        flash('Lütfen şikayet sebebini belirtin.', 'error')
        return redirect(url_for('messages', recipient_id=user_id))
        
    try:
        new_report = Report(
            reporter_id=current_u.id,
            reported_id=target_u.id,
            reason=reason
        )
        db.session.add(new_report)
        log_action(current_u, "Kullanıcı Şikayeti", f"'{target_u.username}' şikayet edildi. Sebep: {reason}", target_user=target_u.username)
        db.session.commit()
        flash('Şikayetiniz yönetim ekibine iletildi. Teşekkür ederiz.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Şikayet gönderilirken bir hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('messages', recipient_id=user_id))
@app.route('/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    target_user = User.query.get_or_404(user_id)

    # Yetki kontrolü (Admin veya ban yetkisi olanlar)
    if not current_u.is_admin and not current_u.can_ban_users:
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    duration = request.form.get('duration') # '1', '24', '48', '72', 'unlimited'
    raw_reason = request.form.get('reason', '')
    
    # Türkçe karakter güvenliği için çevrim
    try:
        reason = raw_reason.encode('latin1').decode('utf-8').strip()
    except Exception:
        reason = raw_reason.strip()

    expires_at = None
    now = datetime.utcnow() + timedelta(hours=3) # Türkiye saat dilimi

    if duration == '1':
        expires_at = now + timedelta(hours=1)
    elif duration == '24':
        expires_at = now + timedelta(hours=24)
    elif duration == '48':
        expires_at = now + timedelta(hours=48)
    elif duration == '72':
        expires_at = now + timedelta(hours=72)
    elif duration == 'unlimited':
        expires_at = None # Sınırsız
    else:
        flash('Geçersiz ban süresi!', 'error')
        return redirect(url_for('index'))

    # Yeni ban kaydı oluştur
    new_ban = Ban(
        user_id=target_user.id,
        admin_id=current_u.id,
        reason=reason,
        expires_at=expires_at,
        timestamp=now
    )
    db.session.add(new_ban)
    db.session.commit()

    flash(f'{target_user.username} adlı kullanıcı başarıyla banlandı.', 'success')
    return redirect(request.referrer or url_for('index'))
@app.route('/update_ban_permissions/<int:user_id>', methods=['POST'])
def update_ban_permissions(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_u = User.query.get(session['user_id'])
    target_user = User.query.get_or_404(user_id)

    # İşlemi yapan admin mi veya "yetki verme" yetkisi var mı?
    if not current_u.is_admin and not current_u.can_grant_ban_permission:
        flash('Bu yetkiyi verme izniniz yok!', 'error')
        return redirect(url_for('index'))

    # Hedef kişinin kendisi üzerinde işlem yapmasını engelle
    if current_u.id == target_user.id:
        flash('Kendi yetkilerinizi değiştiremezsiniz!', 'error')
        return redirect(request.referrer)

    # Formdan gelen checkbox verilerini al ve veritabanına kaydet
    target_user.can_ban_users = 'can_ban_users' in request.form
    target_user.can_grant_ban_permission = 'can_grant_ban_permission' in request.form

    db.session.commit()
    flash(f'{target_user.username} adlı kullanıcının ban yetkileri başarıyla güncellendi.', 'success')
    return redirect(request.referrer)

@app.route('/create_role', methods=['GET', 'POST']) # Sizin rota adresiniz neyse (örn: /manage_roles)
def create_role():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    
    # Rol yönetim sayfasına erişim yetkisi kontrolü
    if not current_u or not (current_u.is_admin or current_u.has_assign_role_permission()):
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_role = Role() 
        new_role.name = request.form.get('name')
        new_role.priority = request.form.get('priority', type=int, default=10)
        new_role.color = request.form.get('color', '#333333')
        new_role.description = request.form.get('description', '')

        # GÜVENLİK KONTROLÜ:
        if current_u.is_admin:
            # Sadece Adminler role özel yetkiler tanımlayabilir
            new_role.can_delete_users = 'can_delete_users' in request.form
            new_role.can_grant_delete_permission = 'can_grant_delete_permission' in request.form
            new_role.can_edit_points = 'can_edit_points' in request.form
            new_role.can_grant_points_permission = 'can_grant_points_permission' in request.form
            new_role.can_assign_roles = 'can_assign_roles' in request.form
            new_role.can_grant_role_permission = 'can_grant_role_permission' in request.form
            # Yeni eklenen ban yetkileri
            new_role.can_ban_users = 'can_ban_users' in request.form
            new_role.can_grant_ban_permission = 'can_grant_ban_permission' in request.form
        else:
            # Admin dışındaki herkes sadece SAF/YETKİSİZ rol oluşturabilir!
            new_role.can_delete_users = False
            new_role.can_grant_delete_permission = False
            new_role.can_edit_points = False
            new_role.can_grant_points_permission = False
            new_role.can_assign_roles = False
            new_role.can_grant_role_permission = False
            # Yeni eklenen ban yetkileri varsayılan olarak kapalı
            new_role.can_ban_users = False
            new_role.can_grant_ban_permission = False

        db.session.add(new_role)
        db.session.commit()
        
        flash('Rol başarıyla oluşturuldu!', 'success')
        return redirect(url_for('manage_roles'))
@app.route('/remove_ban/<int:ban_id>', methods=['POST'])
def remove_ban(ban_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_u = User.query.get(session['user_id'])
    
    # Sadece admin veya ban kaldırma yetkisi olanlar silebilir
    if not current_u.is_admin and not current_u.can_ban_users:
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    ban_record = Ban.query.get_or_404(ban_id)
    db.session.delete(ban_record)
    db.session.commit()
    
    flash('Ban kaydı başarıyla kaldırıldı.', 'success')
    return redirect(request.referrer or url_for('index'))

    return render_template('roles.html') # Veya rol oluşturma sayfanız hangi şablonu kullanıyorsa
@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    
    # DÜZELTME: Admin VEYA cevap silme yetkisi olanlar erişebilir
    if not current_u or not (current_u.is_admin or current_u.can_delete_comments):
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    # 1. Kullanıcı şikayetlerini çekiyoruz (Sadece Adminler görebilir, yetkililer için boş liste döner)
    reports = []
    if current_u.is_admin:
        try:
            if hasattr(Report, 'created_at') and Report.created_at is not None:
                reports = Report.query.order_by(Report.created_at.desc()).all()
            else:
                reports = Report.query.all()
        except Exception:
            reports = []
    
    # 2. Gönderi şikayetlerini çekiyoruz (Adminler ve cevap silme yetkisi olanlar görebilir)
    try:
        if hasattr(PostReport, 'created_at') and PostReport.created_at is not None:
            post_reports = PostReport.query.order_by(PostReport.created_at.desc()).all()
        else:
            post_reports = PostReport.query.all()
    except Exception:
        post_reports = []
    
    return render_template(
        'admin_reports.html', 
        user=current_u, 
        reports=reports, 
        post_reports=post_reports,
        now=datetime.utcnow() + timedelta(hours=3)
    )

# Kullanıcı Şikayetini Kaldırma / Silme ("Kaldır / Çözüldü" butonu için)
@app.route('/admin/reports/delete/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    if not current_u or not current_u.is_admin:
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    report = Report.query.get_or_404(report_id)
    try:
        db.session.delete(report)
        db.session.commit()
        flash('Şikayet kaydı başarıyla kaldırıldı.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_reports'))

# Toplu Gönderi Onaylama
@app.route('/admin/bulk_approve_posts', methods=['POST'])
def bulk_approve_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    report_ids = request.form.getlist('post_report_ids')
    if report_ids:
        reports = PostReport.query.filter(PostReport.id.in_(report_ids)).all()
        for rep in reports:
            if rep.post and hasattr(rep.post, 'is_approved'):
                rep.post.is_approved = True
            db.session.delete(rep)
        db.session.commit()
        flash('Seçili gönderiler topluca onaylandı.', 'success')
    else:
        flash('Hiçbir gönderi seçilmedi.', 'error')
        
    return redirect(url_for('admin_reports'))

# Gönderi Şikayet Etme Rotası
@app.route('/report_post/<int:post_id>', methods=['POST'])
def report_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    reason = request.form.get('reason', 'Sebep belirtilmedi').strip()
    user_id = session['user_id']
    
    existing = PostReport.query.filter_by(post_id=post_id, reporter_id=user_id).first()
    if not existing:
        new_report = PostReport(post_id=post_id, reporter_id=user_id, reason=reason)
        db.session.add(new_report)
        db.session.commit()
        flash('Gönderi başarıyla şikayet edildi. Yöneticiler inceleyecektir.', 'success')
    else:
        flash('Bu gönderiyi zaten şikayet ettiniz.', 'error')
        
    return redirect(url_for('index'))

@app.route('/api/notifications')
def get_notifications():
    if 'user_id' not in session:
        return jsonify({'notifications': [], 'unread_count': 0})
        
    try:
        user_id = session['user_id']
        notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(15).all()
        unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        
        notif_list = [{
            'id': n.id,
            'content': n.content,
            'is_read': n.is_read,
            'created_at': n.created_at.strftime('%d.%m.%Y %H:%M') if n.created_at else ''
        } for n in notifications]
        
        return jsonify({'notifications': notif_list, 'unread_count': unread_count})
    except Exception as e:
        print("API Bildirim Hatası:", str(e))
        return jsonify({'notifications': [], 'unread_count': 0})

@app.route('/notifications/mark_read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return jsonify({'status': 'unauthorized'})
        
    user_id = session['user_id']
    Notification.query.filter_by(user_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/admin/reports/full')
def admin_reports_full():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    reports = Report.query.all()
    post_reports = PostReport.query.all() if 'PostReport' in globals() or 'PostReport' in locals() else []
    
    return render_template('admin_reports_full.html', user=user_obj, reports=reports, post_reports=post_reports)

# Şikayeti Kaldır ("Şikayeti Kaldır" butonu için)
@app.route('/resolve_post_report/<int:report_id>', methods=['GET', 'POST'])
def resolve_post_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not (user_obj.is_admin or user_obj.can_delete_comments):
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    try:
        report = PostReport.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        flash('Şikayet başarıyla kaldırıldı.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Şikayet kaldırılırken bir hata oluştu: {str(e)}', 'error')
        
    # Düzenleme: Kullanıcı nereden geldiyse (Ana sayfa çekmecesi veya tam sayfa) oraya döner
    return redirect(request.referrer or url_for('admin_reports'))
# Şikayet edilen gönderiyi onaylar, şikayet kaydını temizler
@app.route('/approve_reported_post/<int:report_id>', methods=['POST'])
def approve_reported_post(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    # Admin VEYA cevap silme yetkisi olanlar erişebilir
    if not user_obj or not (user_obj.is_admin or user_obj.can_delete_comments):
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    report = PostReport.query.get_or_404(report_id)
    if report.post and hasattr(report.post, 'is_approved'):
        report.post.is_approved = True
        
    db.session.delete(report)
    db.session.commit()
    
    flash('Gönderi onaylandı ve şikayet kaydı temizlendi.', 'success')
    return redirect(request.referrer or url_for('index'))
# Şikayet Edilen Gönderiyi Çöp Kutusuna Taşı ("Gönderiyi Sil" butonu için)
@app.route('/admin/delete_reported_post/<int:post_id>', methods=['POST'])
def delete_reported_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    # Admin VEYA cevap silme yetkisi olanlar erişebilir
    if not user_obj or not (user_obj.is_admin or user_obj.can_delete_comments):
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    post = Post.query.get_or_404(post_id)
    delete_reason = request.form.get('delete_reason', 'Şikayet sebebiyle yetkili tarafından silindi').strip()
    
    try:
        trash_item = DeletedPost(
            original_id=post.id,
            content=post.content,
            visibility=post.visibility,
            author_id=post.user_id,
            deleted_by_id=user_obj.id,
            created_at=post.created_at,
            delete_reason=delete_reason
        )
        db.session.add(trash_item)
        
        PostReport.query.filter_by(post_id=post.id).delete()
        db.session.delete(post)
        db.session.commit()
        
        flash('Sakıncalı gönderi çöp kutusuna taşındı ve ilgili şikayetler temizlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'İşlem sırasında hata oluştu: {str(e)}', 'error')
        
    return redirect(request.referrer or url_for('index'))

# Toplu Gönderi Silme
@app.route('/admin/bulk_delete_posts', methods=['POST'])
def bulk_delete_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    report_ids = request.form.getlist('post_report_ids')
    if report_ids:
        reports = PostReport.query.filter(PostReport.id.in_(report_ids)).all()
        for rep in reports:
            if rep.post:
                db.session.delete(rep.post)
            db.session.delete(rep)
        db.session.commit()
        flash('Seçili gönderiler ve şikayetleri tamamen silindi.', 'success')
    else:
        flash('Hiçbir gönderi seçilmedi.', 'error')
        
    return redirect(url_for('admin_reports'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    post = Post.query.get_or_404(post_id)
    
    delete_reason = request.form.get('delete_reason', 'Sebep belirtilmedi').strip()
    
    # Kendi gönderisi, admin VEYA özel cevap silme yetkisi olanlar silebilir
    if current_u.id == post.user_id or current_u.is_admin or current_u.can_delete_comments:
        try:
            trash_item = DeletedPost(
                original_id=post.id,
                content=post.content,
                visibility=post.visibility,
                author_id=post.user_id,
                deleted_by_id=current_u.id,
                created_at=post.created_at,
                delete_reason=delete_reason
            )
            db.session.add(trash_item)
            db.session.flush() # ID'yi anında almak için
            
            # Kimin sildiğini yetkisine göre dinamik olarak belirliyoruz
            if current_u.id == post.user_id:
                silen_detay = "Kendiniz"
            elif current_u.is_admin:
                silen_detay = f"Admin (@{current_u.username})"
            else:
                silen_detay = f"Yetkili Yetkili (@{current_u.username})"
            
            # Bildirim metnine içeriğin bir kısmını ve silen kişiyi ekliyoruz
            icerik_ozet = post.content[:40] + "..." if len(post.content) > 40 else post.content
            bildirim_metni = f"🗑️ {silen_detay} bir gönderinizi sildi. İçerik: \"{icerik_ozet}\" | Sebep: \"{delete_reason}\""
            
            create_notification(post.user_id, bildirim_metni)
            
            PostReport.query.filter_by(post_id=post.id).delete()
            db.session.delete(post)
            db.session.commit()
            
            flash('Gönderi çöp kutusuna başarıyla taşındı.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Silme işleminde hata oluştu: {str(e)}', 'error')
    else:
        flash('Bu gönderiyi silme yetkiniz yok!', 'error')
        
    return redirect(url_for('index'))

# Silinen Gönderiler Listesi (Admin Paneli)
@app.route('/admin/deleted_posts', methods=['GET'])
def admin_deleted_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    if not current_u or not current_u.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    deleted_posts = DeletedPost.query.order_by(DeletedPost.deleted_at.desc()).all()
    
    # Saatlere 3 saat ekleyelim (Türkiye saati / UTC+3 uyumu için)
    for item in deleted_posts:
        if item.deleted_at:
            item.deleted_at += timedelta(hours=3)
    
    return render_template(
        'admin_deleted_posts.html', 
        user=current_u, 
        deleted_posts=deleted_posts, 
        User=User
    )
# Gönderiyi Geri Yükleme
@app.route('/admin/restore_post/<int:del_id>', methods=['POST'])
def restore_post(del_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    if not current_u or not current_u.is_admin:
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    trash_item = DeletedPost.query.get_or_404(del_id)
    
    try:
        restored_post = Post(
            content=trash_item.content,
            visibility=trash_item.visibility,
            user_id=trash_item.author_id,
            created_at=trash_item.created_at or datetime.utcnow()
        )
        
        if hasattr(restored_post, 'is_approved'):
            restored_post.is_approved = True
            
        db.session.add(restored_post)
        db.session.delete(trash_item)
        db.session.commit()
        
        flash('Gönderi başarıyla akışa geri yüklendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Geri yükleme sırasında hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_deleted_posts'))

# Yorumu Silme Rotası (Kendi yorumu veya Admin silebilir)
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    comment = PostComment.query.get_or_404(comment_id)
    
    # Yorum silinmeden önce ait olduğu post_id'yi kaydediyoruz
    post_id = comment.post_id
    
    if current_u.id == comment.user_id or current_u.is_admin:
        try:
            db.session.delete(comment)
            db.session.commit()
            flash('Yorum başarıyla silindi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Yorum silinirken hata oluştu: {str(e)}', 'error')
    else:
        flash('Bu yorumu silme yetkiniz yok!', 'error')
        
    # Yorum silindikten sonra direkt ilgili gönderinin hizasında kalmasını sağlıyoruz
    return redirect(url_for('index') + f'#post-{post_id}')
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_single_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    post = Post.query.get_or_404(post_id)
    user_obj = User.query.get(session['user_id'])
    
    # Yetki kontrolü (Gizlilik kurallarına göre)
    is_admin = user_obj.is_admin or user_obj.has_delete_permission() or user_obj.has_points_permission()
    is_owner = (user_obj.id == post.user_id)
    
    # Arkadaş kontrolü / Gizlilik filtresi
    if post.visibility == 'private' and not is_owner and not is_admin:
        flash('Bu gönderiyi görüntüleme yetkiniz yok.', 'error')
        return redirect(url_for('index'))

    # YENİ YORUM EKLEME İŞLEMİ (POST)
    if request.method == 'POST' and request.form.get('form_type') == 'add_comment':
        content = request.form.get('content')
        if content and content.strip():
            new_comment = PostComment(
                content=content.strip(),
                user_id=user_obj.id,
                post_id=post.id
            )
            db.session.add(new_comment)
            db.session.commit()
            flash('Yorumunuz başarıyla eklendi.', 'success')
        else:
            flash('Yorum içeriği boş olamaz.', 'error')
        return redirect(url_for('view_single_post', post_id=post.id))

    return render_template(
        'single_post.html', 
        post=post, 
        current_user=user_obj, 
        is_admin=is_admin, 
        is_owner=is_owner
    )
# ---------------------------------------------------------
# ARKADAŞLIK ROTALARI (FRIENDSHIP ROUTES)
# ---------------------------------------------------------


@app.route('/friends')
def friends_list():
  if 'user_id' not in session:
    return redirect(url_for('login'))

  user_obj = User.query.get(session['user_id'])
  friends = user_obj.get_friends()
  pending_requests = user_obj.get_pending_requests()

  return render_template(
      'friends.html',
      user=user_obj,
      friends=friends,
      pending_requests=pending_requests,
  )


@app.route('/send_friend_request/<int:user_id>', methods=['POST'])
def send_friend_request(user_id):
  if 'user_id' not in session:
    return redirect(url_for('login'))

  current_u = User.query.get(session['user_id'])
  target_u = User.query.get_or_404(user_id)

  if current_u.id == target_u.id:
    flash('Kendinize arkadaşlık isteği gönderemezsiniz.', 'error')
    return redirect(request.referrer or url_for('user_profile', user_id=user_id))

  status = current_u.get_friendship_status(target_u)
  if status != 'none':
    flash(
        'Bu kullanıcıyla zaten mevcut bir arkadaşlık veya işlem durumunuz'
        ' bulunuyor.',
        'info',
    )
    return redirect(request.referrer or url_for('user_profile', user_id=user_id))

  try:
    new_request = Friendship(
        sender_id=current_u.id, receiver_id=target_u.id, status='pending'
    )
    db.session.add(new_request)
    log_action(
        current_u,
        'Arkadaşlık İsteği',
        f"'{target_u.username}' kullanıcısına arkadaşlık isteği gönderildi.",
        target_user=target_u.username,
    )
    db.session.commit()
    flash(
        f"Harika! '{target_u.username}' adlı kullanıcıya arkadaşlık isteğiniz"
        ' başarıyla iletildi.',
        'success',
    )
  except Exception as e:
    db.session.rollback()
    flash(f'İstek gönderilirken bir hata oluştu: {str(e)}', 'error')

  return redirect(request.referrer or url_for('user_profile', user_id=user_id))


@app.route(
    '/respond_friend_request/<int:request_id>/<string:action>', methods=['POST']
)
def respond_friend_request(request_id, action):
  if 'user_id' not in session:
    return redirect(url_for('login'))

  current_u = User.query.get(session['user_id'])
  f_request = Friendship.query.get_or_404(request_id)

  if f_request.receiver_id != current_u.id:
    flash('Bu işlem için yetkiniz yok!', 'error')
    return redirect(url_for('friends_list'))

  sender_user = User.query.get(f_request.sender_id)

  if action == 'accept':
    f_request.status = 'accepted'
    log_action(
        current_u,
        'Arkadaşlık Kabulü',
        f"'{sender_user.username}' kullanıcısının arkadaşlık isteği kabul"
        ' edildi.',
        target_user=sender_user.username,
    )
    flash(f"'{sender_user.username}' ile artık arkadaşsınız!", 'success')
  elif action == 'reject':
    db.session.delete(f_request)
    log_action(
        current_u,
        'Arkadaşlık Reddi',
        f"'{sender_user.username}' kullanıcısının arkadaşlık isteği reddedildi.",
        target_user=sender_user.username,
    )
    flash(f"'{sender_user.username}' kullanıcısının isteği reddedildi.", 'info')

  db.session.commit()
  return redirect(request.referrer or url_for('friends_list'))


@app.route('/remove_friend/<int:user_id>', methods=['POST'])
def remove_friend(user_id):
  if 'user_id' not in session:
    return redirect(url_for('login'))

  current_u = User.query.get(session['user_id'])
  target_u = User.query.get_or_404(user_id)

  friendship = Friendship.query.filter(
      (
          (Friendship.sender_id == current_u.id)
          & (Friendship.receiver_id == target_u.id)
      )
      | (
          (Friendship.sender_id == target_u.id)
          & (Friendship.receiver_id == current_u.id)
      ),
      Friendship.status == 'accepted',
  ).first()

  if friendship:
    db.session.delete(friendship)
    log_action(
        current_u,
        'Arkadaşlıktan Çıkarma',
        f"'{target_u.username}' arkadaş listenizden çıkarıldı.",
        target_user=target_u.username,
    )
    db.session.commit()
    flash(f"'{target_u.username}' arkadaş listenizden çıkarıldı.", 'success')

  return redirect(request.referrer or url_for('user_profile', user_id=user_id))


@app.route('/cancel_friend_request/<int:user_id>', methods=['POST'])
def cancel_friend_request(user_id):
  if 'user_id' not in session:
    return redirect(url_for('login'))

  current_u = User.query.get(session['user_id'])
  target_u = User.query.get_or_404(user_id)

  # Oturum açan kullanıcının bu kişiye gönderdiği 'pending' (bekleyen) isteği buluyoruz
  request_to_cancel = Friendship.query.filter_by(
      sender_id=current_u.id, receiver_id=target_u.id, status='pending'
  ).first()

  if request_to_cancel:
    try:
      db.session.delete(request_to_cancel)
      log_action(
          current_u,
          'İstek İptali',
          f"'{target_u.username}' kullanıcısına gönderilen arkadaşlık isteği"
          ' iptal edildi.',
          target_user=target_u.username,
      )
      db.session.commit()
      flash(
          f"'{target_u.username}' kişisine gönderdiğiniz arkadaşlık isteği"
          ' iptal edildi.',
          'info',
      )
    except Exception as e:
      db.session.rollback()
      flash(f'İstek iptal edilirken bir hata oluştu: {str(e)}', 'error')

  # İşlem bittikten sonra kullanıcının bastığı sayfaya (veya profil sayfasına) geri döndürür
  return redirect(request.referrer or url_for('user_profile', user_id=user_id))


# --- TEK VE DÜZGÜN API ROTASI ---
# --- API ROTASI ---
@app.route('/api/friends_and_requests')
def api_friends_and_requests():
  if 'user_id' not in session:
    return jsonify({'error': 'Unauthorized'}), 401

  user = User.query.get(session['user_id'])

  incoming_requests = []
  received = getattr(user, 'received_requests', None) or getattr(
      user, 'received_friend_requests', []
  )
  for req in received:
    if req.status == 'pending':
      sender = User.query.get(req.sender_id)
      if sender:
        incoming_requests.append({
            'id': req.id,
            'sender_id': sender.id,
            'username': sender.username,
        })

  outgoing_requests = []
  sent = getattr(user, 'sent_requests', None) or getattr(
      user, 'sent_friend_requests', []
  )
  for req in sent:
    if req.status == 'pending':
      receiver = User.query.get(req.receiver_id)
      if receiver:
        outgoing_requests.append({
            'id': req.id,
            'receiver_id': receiver.id, # <-- Bu satırı ekleyin
            'username': receiver.username,
        })

  # Arkadaş listesini 'accepted' (kabul edilmiş) ilişki tablosundan doğrudan çekiyoruz
  friends_list = []
  accepted_friendships = Friendship.query.filter(
      ((Friendship.sender_id == user.id) | (Friendship.receiver_id == user.id))
      & (Friendship.status == 'accepted')
  ).all()

  for f_rel in accepted_friendships:
    # Karşı taraftaki kullanıcının ID'sini bul
    friend_id = (
        f_rel.receiver_id if f_rel.sender_id == user.id else f_rel.sender_id
    )
    friend_user = User.query.get(friend_id)
    if friend_user:
      friends_list.append({
          'id': friend_user.id,
          'username': friend_user.username,
          'profile_pic': getattr(friend_user, 'profile_pic', None),
      })

  return jsonify({
      'incoming': incoming_requests,
      'outgoing': outgoing_requests,
      'friends': friends_list,
  })
@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@app.route('/user_profile/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    target_user = User.query.get_or_404(user_id)
    all_roles = Role.query.all()
    
    friend_status = user_obj.get_friendship_status(target_user)
    
    # Süresi dolan banları kontrol edebilmek için anlık zamanı +3 saat ekleyerek gönderiyoruz
    current_time = datetime.utcnow() + timedelta(hours=3)
    
    # --- GÖNDERİ VE YORUM YETKİLENDİRME MANTIĞI ---
    is_self = (user_obj.id == target_user.id)
    is_admin = user_obj.is_admin or user_obj.has_delete_permission() or user_obj.has_points_permission() # Admin veya yetkili mi?
    is_friend = (friend_status == 'friends') # Arkadaş mı?
    
    # --- ADMIN / YETKİLİ İŞLEMLERİ (POST) ---
    if request.method == 'POST' and is_admin:
        action_type = request.form.get('action_type')  # 'posts', 'comments' veya 'add_points'
        
        # 1. Toplu Gönderi veya Yorum Silme
        if action_type in ['posts', 'comments']:
            selected_ids = request.form.getlist('selected_items')  # Seçilen ID'lerin listesi
            if selected_ids:
                if action_type == 'posts':
                    Post.query.filter(
                        Post.id.in_(selected_ids), 
                        Post.user_id == target_user.id
                    ).delete(synchronize_session=False)
                    flash('Seçilen gönderiler başarıyla silindi.', 'success')
                    
                elif action_type == 'comments':
                    PostComment.query.filter(
                        PostComment.id.in_(selected_ids), 
                        PostComment.user_id == target_user.id
                    ).delete(synchronize_session=False)
                    flash('Seçilen yorumlar başarıyla silindi.', 'success')
                    
                db.session.commit()
            else:
                flash('İşlem için herhangi bir içerik seçilmedi.', 'error')

        # 2. Profilden Puan Ekleme (Eğer puan verme yetkisi varsa)
        elif action_type == 'add_points' and user_obj.has_points_permission():
            try:
                points_to_add = int(request.form.get('points', 0))
                target_user.points = (target_user.points or 0) + points_to_add
                db.session.commit()
                flash(f'Başarıyla {points_to_add} puan eklendi.', 'success')
            except ValueError:
                flash('Geçersiz puan miktarı!', 'error')

        return redirect(url_for('user_profile', user_id=target_user.id))

    # 1. Gönderi Filtreleme:
    if is_self or is_admin:
        # Admin ve hesap sahibi her şeyi (public, friends, private) görür
        posts = Post.query.filter_by(user_id=target_user.id).order_by(Post.created_at.desc()).all()
    elif is_friend:
        # Arkadaşı ise public ve friends olanları görür
        posts = Post.query.filter(
            Post.user_id == target_user.id,
            Post.visibility.in_(['public', 'friends'])
        ).order_by(Post.created_at.desc()).all()
    else:
        # Yabancı ise sadece public olanları görür
        posts = Post.query.filter_by(user_id=target_user.id, visibility='public').order_by(Post.created_at.desc()).all()

    # 2. Yorumlar: Kullanıcının yaptığı tüm yorumlar
    comments = PostComment.query.filter_by(user_id=target_user.id).order_by(PostComment.created_at.desc()).all()
    
    # 3. Moderatörün Eylemleri (Bu kullanıcının arşivden sildiği gönderiler) ve Saat Ayarı (+3 Saat)
    mod_deleted_posts = DeletedPost.query.filter_by(deleted_by_id=target_user.id).order_by(DeletedPost.deleted_at.desc()).all()
    for item in mod_deleted_posts:
        if item.deleted_at:
            item.deleted_at += timedelta(hours=3)

    # 4. Bu kullanıcının uyguladığı banlar (Ban tablosundan admin_id eşleşmesi)
    admin_bans = Ban.query.filter_by(admin_id=target_user.id).order_by(Ban.timestamp.desc()).all()
    for b in admin_bans:
        if b.timestamp:
            b.timestamp += timedelta(hours=3)

    # 5. Kullanıcının Sitedeki Diğer Yetki Hareketleri (AuditLog tablosu üzerinden)
    user_audit_logs = AuditLog.query.filter_by(username=target_user.username).order_by(AuditLog.timestamp.desc()).all()
    for log in user_audit_logs:
        if log.timestamp:
            log.timestamp += timedelta(hours=3)
    # ---------------------------------------------

    return render_template(
        'user_profile.html', 
        user=target_user, 
        current_user=user_obj, 
        all_roles=all_roles, 
        friend_status=friend_status,
        now=current_time,
        posts=posts,                      # Gönderiler şablona eklendi
        comments=comments,                # Yorumlar şablona eklendi
        mod_deleted_posts=mod_deleted_posts, # Sildiği gönderiler şablona eklendi
        admin_bans=admin_bans,            # Attığı banlar şablona eklendi
        user_audit_logs=user_audit_logs,  # Audit Log hareketleri şablona eklendi
        is_admin=is_admin                 # Admin kontrolü şablona eklendi
    )
# ---------------------------------------------------------
# KULLANICI YÖNETİMİ (AYRI SAYFA)
# ---------------------------------------------------------
@app.route('/admin/users', methods=['GET'])
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    if not user_obj or not (user_obj.is_admin or 
                           user_obj.has_delete_permission() or 
                           user_obj.has_points_permission() or 
                           user_obj.has_assign_role_permission()):
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    all_users = User.query.all()
    return render_template('admin_users.html', user=user_obj, all_users=all_users)
from datetime import datetime, timedelta

@app.route('/admin/bans')
def admin_bans():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_u = User.query.get(session['user_id'])
    if not current_u.is_admin:
        flash('Bu sayfaya erişim yetkiniz yalnızca adminlere aittir!', 'error')
        return redirect(url_for('index'))

    # Tüm ban kayıtlarını en yeniden eskiye doğru getir
    all_bans = Ban.query.order_by(Ban.timestamp.desc()).all()
    
    # Süresi dolan banları kontrol edebilmek için anlık zamanı +3 saat ekleyerek gönderiyoruz
    current_time = datetime.utcnow() + timedelta(hours=3)
    
    return render_template('admin_bans.html', all_bans=all_bans, now=current_time)

# ---------------------------------------------------------
# ŞİFRE DEĞİŞTİRME
# ---------------------------------------------------------
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not user_obj.check_password(old_password):
            flash('Mevcut şifreniz yanlış!', 'error')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('Yeni şifreler birbiriyle eşleşmiyor!', 'error')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash('Yeni şifreniz en az 6 karakter olmalıdır!', 'error')
            return redirect(url_for('change_password'))
            
        user_obj.set_password(new_password)
        db.session.commit()
        
        log_action(user_obj, "Şifre Değiştirme", f"'{user_obj.username}' şifresini değiştirdi.")
        flash('Şifreniz başarıyla güncellendi!', 'success')
        return redirect(url_for('index'))
        
    return render_template('change_password.html', user=user_obj)
import os
from werkzeug.utils import secure_filename

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Lütfen önce giriş yapın.', 'error')
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    if not user_obj:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()

        if new_username and new_username != user_obj.username:
            if User.query.filter_by(username=new_username).first():
                flash(f"'{new_username}' kullanıcı adı zaten alınmış!", 'error')
            else:
                user_obj.username = new_username

        if new_email and new_email != user_obj.email:
            if User.query.filter_by(email=new_email).first():
                flash(f"'{new_email}' adresi zaten başka bir hesap tarafından kullanılıyor!", 'error')
            else:
                user_obj.email = new_email

        # === PROFİL RESMİ YÜKLEME MANTIĞI (DÜZELTİLDİ) ===
        file = request.files.get('profile_pic')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            unique_filename = f"user_{user_obj.id}_{int(datetime.now().timestamp())}_{filename}"
            
            # Flask'ın kendi kök dizinini baz alarak mutlak yol (absolute path) oluşturuyoruz
            upload_folder = os.path.join(app.root_path, 'static', 'profile_pics')
            os.makedirs(upload_folder, exist_ok=True)
            
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)
            
            # Eski resmi klasörden temizle (varsa ve default değilse)
            if user_obj.profile_pic and user_obj.profile_pic != 'default.png':
                old_pic_path = os.path.join(upload_folder, user_obj.profile_pic)
                if os.path.exists(old_pic_path):
                    try:
                        os.remove(old_pic_path)
                    except:
                        pass
            
            user_obj.profile_pic = unique_filename

        db.session.commit()
        flash('Profiliniz başarıyla güncellendi!', 'success')
        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user_obj)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    
    # 1. Genel Yetki Kontrolü: Admin veya Rol Atama Yetkisi yoksa içeri giremez
    if not user_obj or not (user_obj.is_admin or user_obj.has_assign_role_permission()):
        flash('Kullanıcı düzenleme yetkiniz yok!', 'error')
        return redirect(url_for('admin_users'))

    user_to_edit = User.query.get_or_404(user_id)

    # 2. Hiyerarşik Rol Havuzu Belirleme (Admin her şeyi verebilir, alt yetkililer sadece kendi seviyesinin üstündekileri)
    if user_obj.is_admin:
        assignable_roles = Role.query.order_by(Role.priority.asc()).all()
    else:
        user_priority = user_obj.get_priority()
        assignable_roles = Role.query.filter(Role.priority > user_priority).order_by(Role.priority.asc()).all()

    if request.method == 'POST':
        try:
            eski_username = user_to_edit.username
            eski_email = user_to_edit.email
            eski_points = user_to_edit.points
            eski_roller = [r.name for r in user_to_edit.roles]

            # 3. TEMEL BİLGİLER VE HESAP YÖNETİMİ -> Sadece Admin Değiştirebilir
            if user_obj.is_admin:
                new_username = request.form.get('username', '').strip()
                new_email = request.form.get('email', '').strip()
                new_password = request.form.get('password', '').strip()
                new_points = request.form.get('points', type=int, default=0)
                
                # Çakışma Kontrolü
                existing_user = User.query.filter(
                    ((User.username == new_username) | (User.email == new_email)),
                    User.id != user_id
                ).first()

                if existing_user:
                    flash('Bu kullanıcı adı veya e-posta başka bir kullanıcı tarafından kullanılıyor!', 'error')
                    return render_template('edit_user.html', user_to_edit=user_to_edit, user=user_obj, assignable_roles=assignable_roles)

                user_to_edit.username = new_username
                user_to_edit.email = new_email
                user_to_edit.points = new_points

                if new_password:
                    user_to_edit.set_password(new_password)

                user_to_edit.is_admin = 'is_admin' in request.form

            # --- EK YETKİ DELEGASYONLARI (Admin veya ilgili yetkiyi verebilme hakkı olanlar güncelleyebilir) ---
            if user_obj.is_admin or user_obj.can_delegate_delete():
                user_to_edit.can_delete_users = 'can_delete_users' in request.form
                user_to_edit.can_grant_delete_permission = 'can_grant_delete_permission' in request.form

            if user_obj.is_admin or user_obj.can_delegate_points():
                user_to_edit.can_edit_points = 'can_edit_points' in request.form
                user_to_edit.can_grant_points_permission = 'can_grant_points_permission' in request.form

            if user_obj.is_admin or user_obj.can_delegate_role():
                user_to_edit.can_assign_roles = 'can_assign_roles' in request.form
                user_to_edit.can_grant_role_permission = 'can_grant_role_permission' in request.form

            # Cevap Silme Yetki Delegasyonu Düzeltildi
            if user_obj.is_admin or user_obj.can_delegate_comment_delete():
                user_to_edit.can_delete_comments = 'can_delete_comments' in request.form
                user_to_edit.can_grant_delete_comments_permission = 'can_grant_delete_comments_permission' in request.form

            # 4. ROL ATAMALARI -> Admin veya Rol Verme Yetkisi Olanlar Yapabilir
            if user_obj.is_admin or user_obj.has_assign_role_permission():
                selected_role_ids = request.form.getlist('role_ids', type=int)
                selected_roles = Role.query.filter(Role.id.in_(selected_role_ids)).all() if selected_role_ids else []

                # Admin değilse üst/eşit seviye rol atama engeli
                if not user_obj.is_admin:
                    user_priority = user_obj.get_priority()
                    for role in selected_roles:
                        if role.priority <= user_priority:
                            flash(f"Kendi seviyenizdeki veya daha üst seviyedeki '{role.name}' rolünü atayamazsınız!", 'error')
                            return render_template('edit_user.html', user_to_edit=user_to_edit, user=user_obj, assignable_roles=assignable_roles)

                    # Kendi rollerini değiştirirken altındaki rollere dokunamama kontrolü
                    if user_obj.id == user_to_edit.id:
                        unmodifiable_roles = [r for r in user_to_edit.roles if r.priority <= user_obj.get_priority()]
                        final_roles = list(set(unmodifiable_roles + selected_roles))
                        user_to_edit.roles = final_roles
                    else:
                        user_to_edit.roles = selected_roles
                else:
                    user_to_edit.roles = selected_roles

            # 5. LOGLAMA VE KAYIT
            yeni_roller = [r.name for r in user_to_edit.roles]
            rol_degisimleri = []
            for rol in yeni_roller:
                if rol not in eski_roller:
                    rol_degisimleri.append(f"'{rol}' rolü eklendi")
            for rol in eski_roller:
                if rol not in yeni_roller:
                    rol_degisimleri.append(f"'{rol}' rolü kaldırıldı")

            if rol_degisimleri:
                log_action(user_obj, "Rol Değişikliği", f"'{eski_username}' kullanıcısının rolleri güncellendi: {', '.join(rol_degisimleri)}.", target_user=user_to_edit.username)

            if user_obj.is_admin:
                detaylar = []
                if eski_username != user_to_edit.username:
                    detaylar.append(f"adı '{eski_username}' iken '{user_to_edit.username}' olarak değiştirildi")
                if eski_email != user_to_edit.email:
                    detaylar.append("e-postası güncellendi")
                if eski_points != user_to_edit.points:
                    detaylar.append(f"puanı {eski_points}'den {user_to_edit.points}'e getirildi")

                if detaylar:
                    log_action(user_obj, "Kullanıcı Düzenleme", f"'{eski_username}' adlı kullanıcının {', '.join(detaylar)}.", target_user=user_to_edit.username)

            db.session.commit()
            flash(f'{user_to_edit.username} kullanıcısının bilgileri başarıyla güncellendi.', 'success')
            return redirect(url_for('edit_user', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            flash(f'Güncelleme sırasında bir hata oluştu: {str(e)}', 'error')

    return render_template('edit_user.html', user_to_edit=user_to_edit, user=user_obj, assignable_roles=assignable_roles)
# ---------------------------------------------------------
# ROL YÖNETİMİ
# ---------------------------------------------------------
@app.route('/roles', methods=['GET', 'POST'])
def manage_roles():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    if not user_obj or not (user_obj.is_admin or user_obj.has_assign_role_permission()):
        flash('Rol yönetimi yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_priority = user_obj.get_priority()

        try:
            if 'create_role' in request.form:
                role_name = request.form['name'].strip()
                role_desc = request.form.get('description', '').strip() # <-- Açıklama buraya eklendi
                priority = request.form.get('priority', type=int, default=10)
                color = request.form.get('color', default='#333333')
                
                can_delete = 'can_delete_users' in request.form
                can_points = 'can_edit_points' in request.form
                can_assign = 'can_assign_roles' in request.form
                
                grant_delete = 'can_grant_delete_permission' in request.form
                grant_points = 'can_grant_points_permission' in request.form
                grant_role = 'can_grant_role_permission' in request.form

                if not user_obj.is_admin and priority <= user_priority:
                    flash(f'Kendi öncelik seviyenizden ({user_priority}) daha yüksek veya eşit öncelikte bir rol oluşturamazsınız!', 'error')
                    return redirect(url_for('manage_roles'))

                existing = Role.query.filter_by(name=role_name).first()
                if existing:
                    flash('Bu isimde bir rol zaten mevcut!', 'error')
                else:
                    new_role = Role(
                        name=role_name,
                        description=role_desc, # <-- Yeni rol nesnesine aktarıldı
                        priority=priority,
                        color=color,
                        can_delete_users=can_delete,
                        can_edit_points=can_points,
                        can_assign_roles=can_assign,
                        can_grant_delete_permission=grant_delete,
                        can_grant_points_permission=grant_points,
                        can_grant_role_permission=grant_role
                    )
                    db.session.add(new_role)
                    log_action(user_obj, "Rol Oluşturma", f"'{role_name}' adlı yeni rol oluşturuldu.")
                    db.session.commit()
                    flash(f'"{role_name}" rolü başarıyla oluşturuldu.', 'success')
                    return redirect(url_for('manage_roles'))

                existing = Role.query.filter_by(name=role_name).first()
                if existing:
                    flash('Bu isimde bir rol zaten mevcut!', 'error')
                else:
                    new_role = Role(
                        name=role_name,
                        priority=priority,
                        color=color,
                        can_delete_users=can_delete,
                        can_edit_points=can_points,
                        can_assign_roles=can_assign,
                        can_grant_delete_permission=grant_delete,
                        can_grant_points_permission=grant_points,
                        can_grant_role_permission=grant_role
                    )
                    db.session.add(new_role)
                    log_action(user_obj, "Rol Oluşturma", f"'{role_name}' adlı yeni rol oluşturuldu.")
                    db.session.commit()
                    flash(f'"{role_name}" rolü başarıyla oluşturuldu.', 'success')

            elif 'update_priorities' in request.form:
                roles = Role.query.all()
                for r in roles:
                    p_val = request.form.get(f'priority_{r.id}', type=int)
                    c_val = request.form.get(f'color_{r.id}')
                    
                    if p_val is not None:
                        if not user_obj.is_admin and p_val <= user_priority:
                            flash(f'"{r.name}" rolünün önceliğini kendi seviyenizden ({user_priority}) yüksek veya eşit bir değere güncelleyemezsiniz!', 'error')
                            continue
                        r.priority = p_val
                        
                    if c_val:
                        r.color = c_val
                        
                log_action(user_obj, "Rol Güncelleme", "Rol sıralamaları ve renkleri güncellendi.")
                db.session.commit()
                flash('Rol sıralamaları ve renkleri başarıyla güncellendi.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'İşlem sırasında bir hata oluştu: {str(e)}', 'error')

        return redirect(url_for('manage_roles'))

    roles = Role.query.order_by(Role.priority.asc()).all()
    return render_template('roles.html', roles=roles, user=user_obj)

@app.route('/edit_role/<int:role_id>', methods=['GET', 'POST'])
def edit_role(role_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    # GÜNCELLEME: Artık hem Adminler hem de rol verme yetkisi olanlar bu sayfaya girebilir!
    if not user_obj or not (user_obj.is_admin or user_obj.has_assign_role_permission()):
        flash('Bu işlem için yetkiniz gereklidir!', 'error')
        return redirect(url_for('index'))

    role_to_edit = Role.query.get_or_404(role_id)

    if request.method == 'POST':
        try:
            new_name = request.form['name'].strip()
            role_to_edit.priority = request.form.get('priority', type=int, default=10)
            role_to_edit.color = request.form.get('color', default='#333333')
            role_to_edit.description = request.form.get('description', '')
            
            # GÜVENLİK: Yetkileri SADECE ADMİN değiştirebilir!
            # Rol verme yetkisi olanlar bu alanları değiştiremez, mevcut yetkileri korunur.
            if user_obj.is_admin:
                role_to_edit.can_delete_users = 'can_delete_users' in request.form
                role_to_edit.can_edit_points = 'can_edit_points' in request.form
                role_to_edit.can_assign_roles = 'can_assign_roles' in request.form
                
                role_to_edit.can_grant_delete_permission = 'can_grant_delete_permission' in request.form
                role_to_edit.can_grant_points_permission = 'can_grant_points_permission' in request.form
                role_to_edit.can_grant_role_permission = 'can_grant_role_permission' in request.form

            existing = Role.query.filter(Role.name == new_name, Role.id != role_id).first()
            if existing:
                flash('Bu rol ismi başka bir rol tarafından kullanılıyor!', 'error')
            else:
                role_to_edit.name = new_name
                log_action(user_obj, "Rol Düzenleme", f"'{new_name}' rolünün detayları güncellendi.")
                db.session.commit()
                
                flash('Rol başarıyla güncellendi.', 'success')
                return redirect(url_for('manage_roles'))
        except Exception as e:
            db.session.rollback()
            flash(f'Rol güncellenirken hata oluştu: {str(e)}', 'error')

    return render_template('edit_role.html', role=role_to_edit, user=user_obj)
@app.route('/update_role_priorities', methods=['POST'])
def update_role_priorities():
    if 'user_id' not in session:
        return {'success': False}, 401

    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        return {'success': False}, 403

    try:
        data = request.get_json()
        
        # Tablodaki yeni görsel sıraya göre rolleri ID'leriyle birlikte listeleyelim
        ordered_roles = []
        for key, value in data.items():
            if key.startswith('priority_'):
                role_id = int(key.split('_')[1])
                # value burada arayüzdeki satır sırasıdır (index + 1)
                ordered_roles.append({'id': role_id, 'ui_index': int(value)})

        # Arayüzdeki görsel sıraya (ui_index) göre dizelim
        ordered_roles.sort(key=lambda x: x['ui_index'])

        # Rolleri sırayla inceleyip sizin kurallarınızı uygulayalım
        for i, item in enumerate(ordered_roles):
            current_role = Role.query.get(item['id'])
            if not current_role:
                continue

            # Eğer listedeki ilk rol değilse, bir üstündeki (önceki) role bakıyoruz
            if i > 0:
                prev_role_id = ordered_roles[i - 1]['id']
                prev_role = Role.query.get(prev_role_id)
                
                if prev_role:
                    # KURAL 1 & 2:
                    # Üstündeki rol ile öncelikleri aynı mı? (Aynı önceliğin altındaysa artış yok)
                    if current_role.priority == prev_role.priority:
                        pass # Önceliği olduğu gibi kalır, değiştirmiyoruz.
                    else:
                        # Farklı önceliğin altındaysa: Üstündeki rolün önceliğine göre 1 arttır
                        # (Not: Eğer üst üste aynı değere sıkışma olmasın derseniz üsttekinden büyük olacak şekilde ayarlanır)
                        if current_role.priority <= prev_role.priority:
                            current_role.priority = prev_role.priority + 1
            else:
                # En üste konulan rol için özel bir kural gerekmiyorsa mevcut priority'si korunur
                pass

        db.session.commit()
        return {'success': True}
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}
@app.route('/update_single_role_priority', methods=['POST'])
def update_single_role_priority():
    if 'user_id' not in session:
        return {'success': False}, 401

    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        return {'success': False}, 403

    try:
        data = request.get_json()
        role_id = data.get('role_id')
        reference_id = data.get('reference_id')
        position = data.get('position')

        role = Role.query.get(role_id)
        if not role:
            return {'success': False, 'error': 'Rol bulunamadı'}

        if reference_id:
            ref_role = Role.query.get(reference_id)
            if ref_role:
                # Komşusunun önceliğine göre yeni önceliği belirliyoruz
                if position == 'after':
                    # Üstündekinin altındaysa, üsttekinin önceliği ile aynı veya hemen bir üstü yapılır
                    role.priority = ref_role.priority
                else:
                    role.priority = ref_role.priority
        else:
            # En üste bırakıldıysa en küçük öncelikten daha küçük yapılır veya 1 verilir
            min_priority = db.session.query(db.func.min(Role.priority)).scalar() or 1
            role.priority = max(1, min_priority - 1)

        db.session.commit()
        return {'success': True}
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}
@app.route('/delete_role/<int:role_id>', methods=['POST'])
def delete_role(role_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Rol silmek için admin yetkisi gereklidir!', 'error')
        return redirect(url_for('index'))

    role_to_delete = Role.query.get_or_404(role_id)
    role_name = role_to_delete.name
    
    try:
        db.session.delete(role_to_delete)
        log_action(user_obj, "Rol Silme", f"'{role_name}' rolü silindi.")
        db.session.commit()
        flash(f'"{role_name}" rolü başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Rol silinirken bir hata oluştu: {str(e)}', 'error')

    return redirect(url_for('manage_roles'))

# ---------------------------------------------------------
# KULLANICI DÜZENLEME VE ÖZEL YETKİ İŞLEMLERİ
# ---------------------------------------------------------
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])
    
    if not user_obj or not (user_obj.is_admin or user_obj.has_assign_role_permission()):
        flash('Yeni kullanıcı ekleme yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    if user_obj.is_admin:
        assignable_roles = Role.query.order_by(Role.priority.asc()).all()
    else:
        user_priority = user_obj.get_priority()
        assignable_roles = Role.query.filter(Role.priority > user_priority).order_by(Role.priority.asc()).all()

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        points = request.form.get('points', type=int, default=0)
        
        selected_role_ids = request.form.getlist('role_ids', type=int)
        selected_roles = Role.query.filter(Role.id.in_(selected_role_ids)).all() if selected_role_ids else []

        if not user_obj.is_admin:
            user_priority = user_obj.get_priority()
            for role in selected_roles:
                if role.priority <= user_priority:
                    flash('Kendi yetki seviyenizdeki veya daha üst seviyedeki bir rolü yeni kullanıcıya atayamazsınız!', 'error')
                    return render_template('add_user.html', user=user_obj, assignable_roles=assignable_roles)

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Bu kullanıcı adı veya e-posta zaten kullanımda!', 'error')
            return render_template('add_user.html', user=user_obj, assignable_roles=assignable_roles)

        try:
            new_user = User(username=username, email=email, points=points)
            new_user.set_password(password)
            new_user.roles = selected_roles

            # 1. Silme Yetkileri
            if user_obj.is_admin or user_obj.can_delegate_delete():
                # Başkasına silme yetkisi verebilme izni var mı?
                can_grant_del = 'can_grant_delete_permission' in request.form
                new_user.can_grant_delete_permission = can_grant_del
                
                # Eğer düzenleyen kişinin başkasına yetki verme hakkı varsa, 
                # hedef kullanıcıya silme yetkisi ("can_delete_users") verebilir. 
                # (Kendisinin silme yetkisinin olup olmaması başkasına verebilme yetkisini engellemez, 
                # çünkü bu kişi bir "yetki dağıtıcı/admin yardımcısı" rolündedir.)
                if can_grant_del or user_obj.is_admin:
                    new_user.can_delete_users = 'can_delete_users' in request.form
                else:
                    # Eğer yetki verme hakkı yoksa, sadece kendi temel yetkisi varsa kendi seçimine bırakılır
                    if user_obj.can_delete_users:
                        new_user.can_delete_users = 'can_delete_users' in request.form

            # 2. Puan Değiştirme Yetkileri
            if user_obj.is_admin or user_obj.can_delegate_points():
                can_grant_pts = 'can_grant_points_permission' in request.form
                new_user.can_grant_points_permission = can_grant_pts
                
                if can_grant_pts or user_obj.is_admin:
                    new_user.can_edit_points = 'can_edit_points' in request.form
                else:
                    if user_obj.can_edit_points:
                        new_user.can_edit_points = 'can_edit_points' in request.form

            # 3. Rol Atama Yetkileri
            if user_obj.is_admin or user_obj.can_delegate_role():
                can_grant_role = 'can_grant_role_permission' in request.form
                new_user.can_grant_role_permission = can_grant_role
                
                if can_grant_role or user_obj.is_admin:
                    new_user.can_assign_roles = 'can_assign_roles' in request.form
                else:
                    if user_obj.can_assign_roles:
                        new_user.can_assign_roles = 'can_assign_roles' in request.form

            if user_obj.is_admin:
                new_user.is_admin = 'is_admin' in request.form

            db.session.add(new_user)
            
            rol_isimleri = ", ".join([r.name for r in selected_roles]) if selected_roles else "Rol verilmedi"
            
            log_action(user_obj, "Kullanıcı Ekleme", 
                       f"'{username}' adlı yeni kullanıcı oluşturuldu. (Başlangıç Puanı: {points}, Atanan Roller: {rol_isimleri})",
                       target_user=username)
            
            db.session.commit()

            flash(f'"{username}" adlı kullanıcı başarıyla oluşturuldu.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kullanıcı eklenirken bir hata oluştu: {str(e)}', 'error')

    return render_template('add_user.html', user=user_obj, assignable_roles=assignable_roles)

@app.route('/update_points/<int:user_id>', methods=['POST'])
def update_points(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_obj = User.query.get(session['user_id'])

    if user_obj and user_obj.has_points_permission():
        user_to_update = User.query.get_or_404(user_id)
        new_points = request.form.get('points', type=int)

        if new_points is not None:
            try:
                eski_puan = user_to_update.points
                user_to_update.points = new_points
                
                log_action(user_obj, "Puan Değişikliği", 
                           f"'{user_to_update.username}' kullanıcısının puanı {eski_puan}'dan {new_points}'e güncellendi.",
                           target_user=user_to_update.username)
                db.session.commit()
                
                flash(f'{user_to_update.username} kullanıcısının puanı güncellendi.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Puan güncellenirken hata oluştu: {str(e)}', 'error')
        else:
            flash('Geçersiz puan değeri!', 'error')
    else:
        flash('Puan değiştirme yetkiniz yok!', 'error')

    # Kullanıcının geldiği sayfaya geri dönmesini sağlıyoruz (Eğer yoksa admin_users'a gider)
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    if not current_u.has_delete_permission():
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.is_admin and not current_u.is_admin:
        flash('Admin hesabını silemezsiniz!', 'error')
        return redirect(url_for('user_profile', user_id=user_id))
        
    try:
        # Silinen kullanıcıyı arşive (DeletedUser) kaydediyoruz
        archived_user = DeletedUser(
            original_id=user_to_delete.id,
            username=user_to_delete.username,
            email=user_to_delete.email,
            password_hash=user_to_delete.password_hash,
            points=user_to_delete.points,
            profile_pic=user_to_delete.profile_pic
        )
        db.session.add(archived_user)
        
        # İlişkili arkadaşlıkları, mesajları veya rolleri temizleyebilir ya da bırakabilirsiniz
        # Şimdi ana tablodan siliyoruz
        db.session.delete(user_to_delete)
        
        log_action(current_u, "Kullanıcı Silme (Arşivlendi)", f"'{user_to_delete.username}' hesabı silindi ve arşive kaldırıldı.", target_user=user_to_delete.username)
        db.session.commit()
        
        flash(f"'{user_to_delete.username}' hesabı silindi ve çöp kutusuna taşındı.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Hesap silinirken hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_users'))

@app.route('/toggle_role/<int:user_id>/<int:role_id>', methods=['POST'])
def toggle_role(user_id, role_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    user = User.query.get_or_404(user_id)
    role = Role.query.get_or_404(role_id)
    
    if role in user.roles:
        user.roles.remove(role)
        flash(f"'{role.name}' rolü kullanıcıdan kaldırıldı.", 'success')
    else:
        user.roles.append(role)
        flash(f"'{role.name}' rolü kullanıcıya eklendi.", 'success')
        
    db.session.commit()
    return redirect(url_for('user_profile', user_id=user.id))

@app.route('/delete-profile-pic', methods=['POST'])
def delete_profile_pic():
    if 'user_id' not in session:
        flash('Lütfen önce giriş yapın.', 'error')
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    
    if user_obj and user_obj.profile_pic and user_obj.profile_pic != 'default.png':
        # Daha önce app.root_path kullandığımız için yolu güvenli hale getiriyoruz
        upload_folder = os.path.join(app.root_path, 'static', 'profile_pics')
        file_path = os.path.join(upload_folder, user_obj.profile_pic)
        
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
        
        # 'default.png' yerine None yapıyoruz ki harf avatarı (M harfi) görünsün
        user_obj.profile_pic = None
        db.session.commit()
        flash('Profil resminiz başarıyla silindi.', 'success')
    else:
        flash('Silinecek özel bir profil resmi bulunamadı.', 'error')

    return redirect(url_for('edit_profile'))
@app.route('/admin/deleted_users')
def admin_deleted_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
        
    deleted_list = DeletedUser.query.order_by(DeletedUser.deleted_at.desc()).all()
    return render_template('deleted_users.html', deleted_users=deleted_list, user=user_obj)

@app.route('/admin/restore_user/<int:del_id>', methods=['POST'])
def restore_user(del_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu işlem için admin yetkisi gereklidir!', 'error')
        return redirect(url_for('index'))
        
    archived_user = DeletedUser.query.get_or_404(del_id)
    
    # Kullanıcı adı veya e-posta çakışması var mı kontrol edelim
    existing = User.query.filter((User.username == archived_user.username) | (User.email == archived_user.email)).first()
    if existing:
        flash(f"Bu kullanıcı adı veya e-posta ile kayıtlı aktif bir hesap olduğu için '{archived_user.username}' geri yüklenemedi!", 'error')
        return redirect(url_for('admin_deleted_users'))
        
    try:
        restored_user = User(
            username=archived_user.username,
            email=archived_user.email,
            password_hash=archived_user.password_hash,
            points=archived_user.points,
            profile_pic=archived_user.profile_pic
        )
        db.session.add(restored_user)
        db.session.delete(archived_user)
        
        log_action(user_obj, "Hesap Geri Yükleme", f"'{archived_user.username}' hesabı arşivden geri açıldı.", target_user=archived_user.username)
        db.session.commit()
        
        flash(f"'{archived_user.username}' hesabı başarıyla geri yüklendi.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Geri yükleme sırasında hata oluştu: {str(e)}', 'error')
        
    return redirect(url_for('admin_deleted_users'))

@app.route('/admin_delete_profile_pic/<int:user_id>', methods=['POST'])
def admin_delete_profile_pic(user_id):
    if 'user_id' not in session:
        flash('Lütfen önce giriş yapın.', 'error')
        return redirect(url_for('login'))
    
    current_admin = User.query.get(session['user_id'])
    if not current_admin or not getattr(current_admin, 'is_admin', False):
        flash('Bu işlem için yetkiniz yok!', 'error')
        return redirect(url_for('admin_users'))

    target_user = User.query.get_or_404(user_id)
    
    if target_user.profile_pic and target_user.profile_pic != 'default.png':
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], target_user.profile_pic)
        if os.path.exists(filepath):
            os.remove(filepath)
            
        target_user.profile_pic = 'default.png'
        db.session.commit()
        
        log_action(current_admin, "Profil Resmi Silme", f"'{target_user.username}' kullanıcısının resmi silindi.", target_user=target_user.username)
        flash(f"{target_user.username} kullanıcısının profil resmi silindi.", "success")
    else:
        flash("Kullanıcının zaten özel bir profil resmi yok.", "error")

    return redirect(url_for('admin_users'))
import os
from werkzeug.utils import secure_filename

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    content = request.form.get('content', '').strip()
    visibility = request.form.get('visibility', 'public') # 'public' veya 'friends'
    
    # --- DOSYA / RESİM YÜKLEME MANTIĞI ---
    image_filename = None
    file = request.files.get('post_file') # HTML'deki input name="post_file" ile eşleşmeli
    
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        # Benzersiz bir dosya adı oluşturuyoruz
        image_filename = f"post_{user_obj.id}_{int(datetime.now().timestamp())}_{filename}"
        
        upload_folder = os.path.join(app.root_path, 'static', 'post_uploads')
        os.makedirs(upload_folder, exist_ok=True)
        
        file_path = os.path.join(upload_folder, image_filename)
        file.save(file_path)

    # İster yazı olsun ister dosya, en az biri varsa gönderiyi kaydediyoruz
    if content or image_filename:
        new_post = Post(
            user_id=user_obj.id, 
            content=content, 
            visibility=visibility, 
            image_file=image_filename
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Gönderiniz başarıyla paylaşıldı!', 'success')
    else:
        flash('Gönderi içeriği veya dosyası boş olamaz!', 'error')
        
    return redirect(url_for('index'))

@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return jsonify({'status': 'unauthorized'}), 401
        
    user_id = session['user_id']
    post = Post.query.get_or_404(post_id)
    existing_like = PostLike.query.filter_by(user_id=user_id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        liked = False
    else:
        new_like = PostLike(user_id=user_id, post_id=post_id)
        db.session.add(new_like)
        liked = True
        
        # Beğeni bildirimi (Kendi gönderisi değilse)
        if post.user_id != user_id:
            liker = User.query.get(user_id)
            if liker and 'create_notification' in globals():
                create_notification(post.user_id, f"❤️ @{liker.username} gönderini beğendi.")
        
    db.session.commit()
    
    likes_count = len(post.likes) if hasattr(post, 'likes') else 0
    return jsonify({'status': 'success', 'liked': liked, 'likes_count': likes_count})

@app.route('/comment_post/<int:post_id>', methods=['POST'])
def comment_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    content = request.form.get('comment_content', '').strip()
    if content:
        post = Post.query.get_or_404(post_id)
        new_comment = PostComment(user_id=session['user_id'], post_id=post_id, content=content)
        db.session.add(new_comment)
        db.session.commit()
        
        # Yorum bildirimi (Kendi gönderisi değilse)
        if post.user_id != session['user_id']:
            commenter = User.query.get(session['user_id'])
            if commenter:
                create_notification(post.user_id, f"💬 @{commenter.username} gönderine yorum yaptı: \"{content[:30]}...\"")
                
        flash('Yorumunuz eklendi.', 'success')
        
    # Yönlendirmeyi ilgili postun id'sine çapa (anchor) ekleyerek yapıyoruz:
    return redirect(url_for('index') + f'#post-{post_id}')

@app.route('/repost_post/<int:post_id>', methods=['POST'])
def repost_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    original_post = Post.query.get_or_404(post_id)
    user_id = session['user_id']
    
    # Paylaşım (Repost) mantığı: Orijinal içeriği kendi akışında genel olarak paylaşma
    repost_content = f"🔄 Paylaşılan Gönderi (@{original_post.author.username}):\n\"{original_post.content}\""
    new_post = Post(user_id=user_id, content=repost_content, visibility='public')
    db.session.add(new_post)
    db.session.commit()
    
    # Repost bildirimi (Kendi gönderisi değilse orijinal sahibine bildir)
    if original_post.user_id != user_id:
        reposter = User.query.get(user_id)
        if reposter:
            create_notification(original_post.user_id, f"🔄 @{reposter.username} gönderini paylaştı (repost).")
    
    flash('Gönderi profilinizde/akışınızda paylaşıldı!', 'success')
    return redirect(url_for('index'))

@app.route('/resolve_all_post_reports/<int:post_id>', methods=['POST'])
def resolve_all_post_reports(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_obj = User.query.get(session['user_id'])
    if not user_obj or not user_obj.is_admin:
        flash('Bu işlem için yetkiniz yok.', 'error')
        return redirect(url_for('index'))
        
    # Gönderiye ait tüm şikayetleri sil/çöz
    reports_to_resolve = Report.query.filter_by(post_id=post_id).all()
    for rep in reports_to_resolve:
        db.session.delete(rep)
        
    db.session.commit()
    flash('Gönderiye ait tüm şikayetler kaldırıldı.', 'success')
    return redirect(url_for('admin_reports'))

# Gönderi Düzenleme Rotası
@app.route('/edit_post/<int:post_id>', methods=['POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    post = Post.query.get_or_404(post_id)
    
    if current_u.id == post.user_id:
        new_content = request.form.get('content', '').strip()
        if new_content:
            post.content = new_content
            post.is_edited = True  # Düzenlendi işaretle
            db.session.commit()
            flash('Gönderi başarıyla güncellendi.', 'success')
        else:
            flash('Gönderi içeriği boş olamaz.', 'error')
    else:
        flash('Bu gönderiyi düzenleme yetkiniz yok!', 'error')
        
    # Gönderi düzenlendikten sonra sayfanın en üste gitmesini önleyip direkt bu gönderinin hizasında kalmasını sağlıyoruz
    return redirect(url_for('index') + f'#post-{post_id}')

# Yorum Düzenleme Rotası
@app.route('/edit_comment/<int:comment_id>', methods=['POST'])
def edit_comment(comment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    current_u = User.query.get(session['user_id'])
    comment = PostComment.query.get_or_404(comment_id)
    
    # Yorumun ait olduğu post_id'yi kaydediyoruz
    post_id = comment.post_id
    
    if current_u.id == comment.user_id:
        new_content = request.form.get('comment_content', '').strip()
        if new_content:
            comment.content = new_content
            comment.is_edited = True  # Düzenlendi işaretle
            db.session.commit()
            flash('Yorum başarıyla güncellendi.', 'success')
        else:
            flash('Yorum içeriği boş olamaz.', 'error')
    else:
        flash('Bu yorumu düzenleme yetkiniz yok!', 'error')
        
    # Güncelleme sonrası kullanıcıyı hangi sayfadan geldiyse (tekil gönderi sayfası dahil) oraya döndürüyoruz
    return redirect(request.referrer or url_for('index'))
# ---------------------------------------------------------
# SİSTEM LOGLARI ROTASI
# ---------------------------------------------------------
@app.route('/logs', methods=['GET'])
def view_logs():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    user_obj = User.query.get(session['user_id'])
    
    if not user_obj or not user_obj.is_admin:
        flash('Bu sayfayı sadece adminler görebilir!', 'error')
        return redirect(url_for('index'))
    
    selected_action = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    target_user_filter = request.args.get('target_user', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    action_types = db.session.query(AuditLog.action.distinct()).all()
    action_types = [a[0] for a in action_types if a[0]]

    query = AuditLog.query
    
    if selected_action:
        query = query.filter(AuditLog.action == selected_action)
    if user_filter:
        query = query.filter(AuditLog.username.ilike(f"%{user_filter}%"))
    if target_user_filter:
        query = query.filter(AuditLog.target_user.ilike(f"%{target_user_filter}%"))
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date + " 23:59:59")
        
    logs = query.order_by(AuditLog.timestamp.desc()).all()
    
    return render_template(
        'logs.html', 
        logs=logs, 
        user=user_obj, 
        action_types=action_types, 
        selected_action=selected_action
    )

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_obj = User.query.get(session['user_id'])
        if user_obj:
            try:
                log_action(user_obj, "Çıkış Yapma", f"'{user_obj.username}' oturumu kapattı.")
                db.session.commit()
            except:
                db.session.rollback()
            
    session.pop('user_id', None)
    logout_user()
    flash('Oturum kapatıldı.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)