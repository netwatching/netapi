import json

import sqlalchemy as sql
from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker
from sqlalchemy import asc, desc
from src.models import Category, Device, Feature, Value_Numeric, Value_String, Alert, Aggregator, Module, Type, \
    Aggregator_To_Type
from sqlalchemy.dialects.mysql import insert

import mysql.connector
from mysql.connector import Error


class DBIO:
    def __init__(self, db_path: str):
        if db_path != '':
            self.db_path = db_path
            self.engine = sql.create_engine(self.db_path)
            self.session = sessionmaker(bind=self.engine)
            self.connection = mysql.connector.connect(host='palguin.htl-vil.local', database='netdb', user='netdb',
                                                      password='NPlyaVeGq5rse715JvD6',
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
            id = session.query(Feature.id).select_from(Feature).filter(Feature.feature == feature).filter(
                Feature.device_id == device_id).all()[0][0]
            session.commit()
        return id

    def add_device(self, device: str, category: int, ip: str = None):
        with self.session.begin() as session:
            cat = session.query(Category).filter(Category.category == category).first()
            if not cat:
                raise HTTPException(status_code=400, detail="Bad Parameter")

            d = Device(device=device, category=cat, ip=ip)
            session.add(d)
            session.commit()
            session.close()
        return

    def get_full_devices(self):
        with self.session.begin() as session:
            devices = session.query(Device).all()
            session.close()
        return devices

    def get_devices(self):
        with self.session.begin() as session:
            devices = session \
                .query(Device.id, Device.category_id, Device.device, Category.category) \
                .join(Category, Device.category_id == Category.id) \
                .order_by(Device.id.asc()) \
                .all()
            session.close()
        return devices

    def get_device_by_id(self, id: int):
        with self.session.begin() as session:
            devices = session \
                .query(Category.category, Device) \
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

    def set_aggregator_version(self, id, version):
        with self.session.begin() as session:
            aggregator = session.query(Aggregator).filter(Aggregator.id == id).first()
            aggregator.version = version
            session.commit()
            session.close()
        return

    def get_alerts_by_severity(self, sever, page: int, amount: int):
        with self.session.begin() as session:
            if page and amount:
                alerts = session \
                    .query(Device.device, Alert) \
                    .filter(Alert.severity >= sever) \
                    .join(Device, Device.id == Alert.device_id) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit((amount)) \
                    .all()
            else:
                alerts = session \
                    .query(Device.device, Alert) \
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
                .query(Device.device, Alert) \
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
        for d in data["modules"]:
            with self.session.begin() as session:
                sth = insert(Type).values(type=d["id"], config_signature=d["config_signature"],
                                          config_fields=d["config_fields"])
                on_duplicate_sth = sth.on_duplicate_key_update(config_signature=d["config_signature"],
                                                               config_fields=d["config_fields"])
                session.execute(on_duplicate_sth)

                aggregator = session.query(Aggregator).filter(Aggregator.id == aid).first()

                type = session.query(Type).filter(Type.type == d["id"]).first()
                sth = insert(Aggregator_To_Type).values(type_id=type.id, aggregator_id=aggregator.id)
                on_duplicate_sth = sth.on_duplicate_key_update(type_id=type.id, aggregator_id=aggregator.id)
                session.execute(on_duplicate_sth)
            session.commit()
            session.close()
        return

    def get_alerts_by_severity_type(self, severities: dict, page: int, amount: int):
        sevs = list(map(int, severities))
        with self.session.begin() as session:
            if page and amount:
                alerts = session \
                    .query(Device.device, Alert) \
                    .join(Device, Device.id == Alert.device_id) \
                    .filter(Alert.severity.in_(sevs)) \
                    .order_by(Alert.timestamp.desc()) \
                    .offset(((page - 1) * amount)) \
                    .limit((amount)) \
                    .all()
            else:
                alerts = session \
                    .query(Device.device, Alert) \
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
