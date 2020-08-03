from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class HomeService(db.Model):
    __tablename__ = "home_service"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)
    auth_type = db.Column(db.String(20))
    auth_endpoint = db.Column(db.String(150))

class OIDCService(db.Model):
    __tablename__ = "oidc_service"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(50))
    scope = db.Column(db.String(50))
    home_service_id = db.Column(db.Integer, 
            db.ForeignKey('home_service.id', ondelete='CASCADE'))
    home_service = db.relationship('HomeService')

class OneXService(db.Model):
    __tablename__ = "onex_service"

    id = db.Column(db.Integer, primary_key=True)
    home_service_id = db.Column(db.Integer, 
        db.ForeignKey('home_service.id', ondelete='CASCADE'))
    home_service = db.relationship('HomeService')



