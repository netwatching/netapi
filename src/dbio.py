import json

import sqlalchemy as sql
from decouple import config
from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker
from sqlalchemy import asc, desc
from src.models import Category, Device, Feature, Value_Numeric, Value_String, Alert, Aggregator, Module, Type, \
    Aggregator_To_Type
from sqlalchemy.dialects.mysql import insert
from src.crypt import Crypt

import mysql.connector


class DBIO:
    def __init__(self, db_path: str):
        self.crypt = Crypt()
        if db_path != '':
            self.db_path = db_path
            self.engine = sql.create_engine(self.db_path)
            self.session = sessionmaker(bind=self.engine)
            self.connection = mysql.connector.connect(host=config("DBurl"),
                                                      database=config("DBdatabase"),
                                                      user=config("DBuser"),
                                                      password=config("DBpassword"),
                                                      auth_plugin='mysql_native_password')

    def add_value_numeric(self, cursor, device_id: int, feature_name: str, key: str, value):
        args = (device_id, feature_name, key, value)
        cursor.callproc('insValnByFeaNameAndDev', args)

    def add_value_string(self, cursor, device_id: int, feature_name: str, key: str, value):
        args = (device_id, feature_name, key, value)
        cursor.callproc('insValsByFeaNameAndDev', args)

    def add_event(self, cursor, timestamp, severity: str, problem: str, hostname: str, ip: str = None):
        args = (timestamp, severity, problem, hostname, ip)
        cursor.callproc('insAleWithTimestampAndSeverityAndProblemByDevHostnameOrIp', args)

    def add_feature(self, feature: str, device_id: int):
        with self.session.begin() as session:
            d = session.query(Device).select_from(Device).filter(Device.id == device_id).all()
            f = Feature(feature=feature, device=d[0])
            session.add(f)
            feature_id = session.query(Feature.id).select_from(Feature).filter(Feature.feature == feature).filter(
                Feature.device_id == device_id).all()[0][0]
            session.commit()
        return feature_id

    def add_device(self, device: str, category: int, ip: str = None):
        with self.session.begin() as session:
            cat = session.query(Category).filter(Category.category == category).first()
            if not cat:
                raise HTTPException(status_code=400, detail="Bad Parameter")

            d = Device(device=device, category=cat, ip=ip)
            session.add(d)
            session.commit()
            session.close()

    def get_full_devices(self):
        with self.session.begin() as session:
            devices = session.query(Device).all()
            session.close()
        return devices

    def get_devices(self, page, amount):
        with self.session.begin() as session:
            cat = session.query(Category).filter(Category.category == "Internal").first()
            if page and amount:
                devices = session \
                    .query(Device.id, Device.category_id, Device.device, Category.category) \
                    .join(Category, Device.category_id == Category.id) \
                    .filter(Device.category_id != cat.id) \
                    .order_by(Device.id.asc()) \
                    .offset(((page - 1) * amount)) \
                    .limit(amount) \
                    .all()
            else:
                devices = session \
                    .query(Device.id, Device.category_id, Device.device, Category.category) \
                    .join(Category, Device.category_id == Category.id) \
                    .filter(Device.category_id != cat.id) \
                    .order_by(Device.id.asc()) \
                    .all()
            count = session \
                .query(Device.id) \
                .filter(Device.category_id != cat.id) \
                .count()
            session.close()
        return [devices, count]

    def get_devices_by_categories(self, categories, page, amount):
        cats = list(map(int, categories))
        with self.session.begin() as session:
            if page and amount:
                devices = session \
                    .query(Device.id, Device.category_id, Device.device, Category.category) \
                    .join(Category, Device.category_id == Category.id) \
                    .filter(Device.category_id.in_(cats)) \
                    .order_by(Device.id.asc()) \
                    .offset(((page - 1) * amount)) \
                    .limit(amount) \
                    .all()
            else:
                devices = session \
                    .query(Device.id, Device.category_id, Device.device, Category.category) \
                    .join(Category, Device.category_id == Category.id) \
                    .filter(Device.category_id.in_(cats)) \
                    .order_by(Device.id.asc()) \
                    .all()
            count = session \
                .query(Device.id) \
                .filter(Device.category_id.in_(cats)) \
                .count()
            session.close()
        return [devices, count]

    def get_device_by_id(self, id: int):
        with self.session.begin() as session:
            devices = session \
                .query(Category.category, Device.id, Device.category_id, Device.device, Category.category) \
                .filter(Device.id == id) \
                .join(Category, Device.category_id == Category.id) \
                .all()
            session.close()
        return devices

    def get_device_features_by_id(self, id: int):
        with self.session.begin() as session:
            feat = session.query(Feature).filter(Feature.device_id == id).all()
            session.close()
        return feat

    def get_features(self):
        with self.session.begin() as session:
            feat = session.query(Feature.id, Feature.feature, Feature.device_id).all()
            session.close()
        return feat

    def get_categories(self):
        with self.session.begin() as session:
            cat = session.query(Category.id, Category.category).all()
            session.close()
        return cat

    def get_alerts(self):
        with self.session.begin() as session:
            alert = session \
                .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                .order_by(Alert.timestamp.desc()) \
                .all()
            session.close()
        return alert

    def get_alerts_by_device_id(self, did, sever, page, amount):
        with self.session.begin() as session:
            if page and amount:
                alert = session \
                    .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.device_id == did) \
                    .filter(Alert.severity >= sever) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit(amount) \
                    .all()
            else:
                alert = session \
                    .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.device_id == did) \
                    .filter(Alert.severity >= sever) \
                    .order_by(Alert.timestamp.desc()) \
                    .all()

            count = session \
                .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                .filter(Alert.device_id == did) \
                .filter(Alert.severity >= sever) \
                .count()

        session.close()
        return [alert, count]

    def get_alerts_by_device_id_and_severity_time(self, did, severities, page, amount):
        sevs = list(map(int, severities))
        with self.session.begin() as session:
            if page and amount:
                alert = session \
                    .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.device_id == did) \
                    .filter(Alert.severity.in_(sevs)) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit(amount) \
                    .all()
            else:
                alert = session \
                    .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.device_id == did) \
                    .filter(Alert.severity.in_(sevs)) \
                    .order_by(Alert.timestamp.desc()) \
                    .all()

            count = session \
                .query(Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                .filter(Alert.device_id == did) \
                .filter(Alert.severity.in_(sevs)) \
                .count()

        session.close()
        return [alert, count]

    def set_aggregator_version(self, id, version):
        with self.session.begin() as session:
            aggregator = session.query(Aggregator).filter(Aggregator.id == id).first()
            aggregator.version = version
            session.commit()
            session.close()

    def get_alerts_by_severity(self, sever, page: int, amount: int):
        with self.session.begin() as session:
            if page and amount:
                alerts = session \
                    .query(Device.device, Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.severity >= sever) \
                    .join(Device, Device.id == Alert.device_id) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit((amount)) \
                    .all()
            else:
                alerts = session \
                    .query(Device.device, Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .filter(Alert.severity >= sever) \
                    .join(Device, Device.id == Alert.device_id) \
                    .order_by(Alert.timestamp.desc()) \
                    .all()

            count = session \
                .query(Alert) \
                .filter(Alert.severity >= sever) \
                .count()
            session.close()
        return [alerts, count]

    def get_alerts_by_id(self, aid):
        with self.session.begin() as session:
            alerts = session \
                .query(Device.device, Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                .join(Device, Device.id == Alert.device_id) \
                .filter(Alert.id == aid) \
                .all()
            session.close()
        return alerts[0]

    def get_modules(self):
        with self.session.begin() as session:
            alert = session \
                .query(Type) \
                .order_by(Type.id) \
                .all()
            session.close()
        return alert

    def insert_aggregator_modules(self, data, aid):
        try:
            modules = data["modules"]
        except KeyError:
            raise HTTPException(status_code=400, detail="Bad Parameter")

        for d in modules:
            with self.session.begin() as session:
                sth = insert(Type).values(type=d["id"],
                                          config_signature=self.crypt.encrypt(json.dumps(d["config_signature"]),
                                                                              config("cryptokey")),
                                          config_fields=self.crypt.encrypt(json.dumps(d["config_fields"]),
                                                                           config("cryptokey")))
                on_duplicate_sth = sth.on_duplicate_key_update(
                    config_signature=self.crypt.encrypt(json.dumps(d["config_signature"]), config("cryptokey")),
                    config_fields=self.crypt.encrypt(json.dumps(d["config_fields"]), config("cryptokey")))
                session.execute(on_duplicate_sth)

                aggregator = session.query(Aggregator).filter(Aggregator.id == aid).first()

                typ = session.query(Type).filter(Type.type == d["id"]).first()
                sth = insert(Aggregator_To_Type).values(type_id=typ.id, aggregator_id=aggregator.id)
                on_duplicate_sth = sth.on_duplicate_key_update(type_id=typ.id, aggregator_id=aggregator.id)
                session.execute(on_duplicate_sth)
            session.commit()
            session.close()

    def get_alerts_by_severity_type(self, severities: dict, page: int, amount: int):
        sevs = list(map(int, severities))
        with self.session.begin() as session:
            if page and amount:
                alerts = session \
                    .query(Device.device, Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .join(Device, Device.id == Alert.device_id) \
                    .filter(Alert.severity.in_(sevs)) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit((amount)) \
                    .all()
            else:
                alerts = session \
                    .query(Device.device, Alert.id, Alert.timestamp, Alert.device_id, Alert.problem, Alert.severity) \
                    .join(Device, Device.id == Alert.device_id) \
                    .filter(Alert.severity.in_(sevs)) \
                    .order_by(Alert.timestamp.desc()) \
                    .all()

            count = session \
                .query(Alert) \
                .filter(Alert.severity.in_(sevs)) \
                .count()
            session.close()
            return [alerts, count]

    def add_category(self, category: int):
        with self.session.begin() as session:
            d = Category(category=category)
            session.add(d)
            session.commit()
            session.close()

    def get_aggregator_devices(self, aggregator_id: int):
        with self.session.begin() as session:
            ag2type = session \
                .query(Aggregator_To_Type.id) \
                .filter(Aggregator_To_Type.aggregator_id == aggregator_id) \
                .all()
            session.close()
            return ag2type

    def check_token(self, token: str):
        with self.session.begin() as session:
            ag = session.query(Aggregator).filter(Aggregator.token == token).first()
            session.close()
            return ag

    def add_aggregator(self, token: str):
        with self.session.begin() as session:
            ag = Aggregator(token=token, version="created")
            session.add(ag)
            session.commit()
            session.close()
