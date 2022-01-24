import asyncio
import json
from datetime import datetime

import redis
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
            self.redis_indices = ["in_bytes", "in_unicast_packets", "in_non_unicast_packets",
                                  "in_discards", "in_errors", "in_unknown_protocols",
                                  "out_bytes", "out_unicast_packets", "out_non_unicast_packets",
                                  "out_discards", "out_errors"]

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

    def redis_insert_live_data(self, data):
        hostname = data["device"]
        database_index = -1

        for interface_index in data["data"]:
            if interface_index == "in_bytes":
                database_index = 0
            elif interface_index == "in_unicast_packets":
                database_index = 1
            elif interface_index == "in_non_unicast_packets":
                database_index = 2
            elif interface_index == "in_discards":
                database_index = 3
            elif interface_index == "in_errors":
                database_index = 4
            elif interface_index == "in_unknown_protocolls":
                database_index = 5
            elif interface_index == "out_bytes":
                database_index = 6
            elif interface_index == "out_unicast_packets":
                database_index = 7
            elif interface_index == "out_non_unicast_packets":
                database_index = 8
            elif interface_index == "out_discards":
                database_index = 9
            elif interface_index == "out_errors":
                database_index = 10

            if database_index != -1:
                self.redis_insert(hostname, data["data"][interface_index], database_index)

    def redis_insert(self, hostname: str, values: list, database_index: int):
        pool = redis.ConnectionPool(host="palguin.htl-vil.local", port="6379",
                                    password="WVFz.S9U:q4Y`]DGq5;2%7[H/t/WRymGR[r)@uA2mfq=ULvfcssHy5ef9HV",
                                    username="default",
                                    db=database_index)
        r = redis.Redis(connection_pool=pool)
        r.zadd(hostname, values)
        pool.connection_class()

    async def thread_insertIntoDatabase(self):
        await asyncio.sleep(300)

        for i in range(0, len(self.redis_indices)):
            pool = redis.ConnectionPool(host="palguin.htl-vil.local", port="6379",
                                        password="WVFz.S9U:q4Y`]DGq5;2%7[H/t/WRymGR[r)@uA2mfq=ULvfcssHy5ef9HV",
                                        username="default",
                                        db=i)
            r = redis.Redis(connection_pool=pool)

            for key in r.scan_iter():
                scores = r.zrange(key, 0, -1, withscores=True)

                avg_score = 0
                for score in scores:
                    avg_score += score[1]
                avg_score /= len(scores)

                with self.session.begin() as session:
                    device_id = session.query(func.netdb.insDevByCat(key, 3)).all()

                    device_id = device_id[0][0]
                    feature = self.redis_indices[i]
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    query = f"Call insValnByFeaNameAndDev({device_id}, \"{feature}\", \"{timestamp}\", {avg_score})"
                    session.execute(query)
