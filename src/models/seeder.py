import random

import faker.exceptions
import pymongo
from decouple import config
from faker import Faker
from pymodm import connection

from src.models.device import Category, Data

details = f'mongodb://{config("mDBuser")}:{config("mDBpassword")}@{config("mDBurl")}:{config("mDBport")}/{config("mDBdatabase")}?authSource=admin'
connection.connect(details)
faker = Faker()

# Counts
category_count = 100
device_count = 20
ports_count = 20

# Category
category_template = "test_category_{}"

# Device
device_hostname_template = "test_hostname_{}"
device_ip_template = "test_domain_or_ip_{}"

# Static System
static_data_system_template = {
    "system": {
        # "name": "HTL-R154-PoE-Access",
        "uptime": 3019345000,
        "description": "SG350X-48MP 48-Port Gigabit PoE Stackable Managed Switch",
        "contact": "florian.schmidt@htl-villach.at",
        "location": "HTL-R154-PoE-Access"
    }
}

# Static Interface
static_data_interface_template = {
    # "index": "1",
    # "description": "GigabitEthernet1/0/1",
    "type": "ethernetCsmacd",
    "mtu": "9000",
    "speed": "1000000000",
    # "mac_address": "04:5f:b9:5e:55:b7",
    "admin_status": "up",
    "operating_status": "up",
    "last_change": "2022-01-01 00:00:00",
    "blade": "1",
    "slot": "0",
    # "port": "1",
    "definition": "GigabitEthernet"
}

# Static Neighbor
static_data_neighbor_template = [
    {
        # "local_mac": "04:5F:B9:5E:55:B6",
        # "local_port": "GigabitEthernet1/0/1",
        "remote_host": "R-1OG-122",
        # "remote_chassis_id": "68:d7:9a:4a:89:59",
        # "remote_port": "68:d7:9a:4a:89:59",
        "remote_system_description": "UAP-nanoHD, 5.60.23.13051",
        "remote_system_capability": "W"
    }
]


def clear():
    pymongo_client = pymongo.MongoClient(details)
    pymongo_client.drop_database("netdb")


def seed_categories(count):
    categories = []
    for i in range(0, count):
        category = Category(category=category_template.format(str(i))).save()
        categories.append(category)
    return categories


def seed_static_data(count):
    static_data = []

    system = static_data_system_template
    system["name"] = faker.domain_word()
    static_data.append(Data(key="system", value=system).save())

    try:
        sourc_mac = faker.unique.mac_address()
        target
    except faker.exceptions.UniquenessException:
        return

    for i in range(0, count):
        interface = static_data_interface_template
        interface["index"] = str(i)
        interface["port"] = str(i)
        interface["description"] = f"GigabitEthernet{i}"
        interface["mac_address"] = str(sourc_mac)


def seed_devices(count, category):


def seeder(category_count, device_count, port_count):
    categories = seed_categories(category_count)

    for category in categories:
        seed_devices(device_count, category)



