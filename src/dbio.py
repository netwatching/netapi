import sqlalchemy as sql
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker
from src.models import Category, Device, Feature, Value_Numeric, Value_String


class DBIO:
    def __init__(self, db_path: str):
        if db_path != '':
            self.db_path = db_path
            self.engine = sql.create_engine(self.db_path)
            self.session = sessionmaker(bind=self.engine)

    def add_value_numeric(self, feature_id: int, key: str, value):
        # print(f'Value_Numeric: Key: {key} - Value: {value} - feature_id: {feature_id}')
        with self.session.begin() as session:
            f = session.query(Feature).select_from(Feature).filter(Feature.id == feature_id).all()
            vn = Value_Numeric(key=key, value=value, feature=f[0])
            session.add(vn)
            session.commit()

    def add_value_string(self, feature_id: int, key: str, value: str):
        # print(f'Value_String: Key: {key} - Value: {value} - feature_id: {feature_id}')
        with self.session.begin() as session:
            f = session.query(Feature).select_from(Feature).filter(Feature.id == feature_id).all()
            vs = Value_String(key=key, value=value, feature=f[0])
            session.add(vs)
            session.commit()

    def add_feature(self, feature: str, device_id: int):
        # print(f'Feature: feature: {feature} - device_id: {device_id}')
        with self.session.begin() as session:
            d = session.query(Device).select_from(Device).filter(Device.id == device_id).all()
            f = Feature(feature=feature, device=d[0])
            session.add(f)
            id = session.query(Feature.id).select_from(Feature).filter(Feature.feature == feature).filter(Feature.device_id == device_id).all()[0][0]
            session.commit()
        return id

    def add_device(self, device: str, category_id: int, config_signature, config_fields):
        # print(f'Device: device: {device} - category_id: {category_id} - config_signature: {config_signature} - config_fields: {config_fields}')
        with self.session.begin() as session:
            cat = session.query(Category).select_from(Category).filter(Category.id == 1).all()
            if len(cat) < 1:
                session.add(Category(category='testing', config_signature=None, config_fields=None))
            cat = session.query(Category).select_from(Category).filter(Category.id == 1).all()
            d = Device(device=device, config_signature=config_signature, config_fields=config_fields, category=cat[0])
            session.add(d)
            id = session.query(Device.id).select_from(Device).filter(Device.device == device).filter(Device.category_id == category_id).all()[0][0]
            session.commit()
        return id

