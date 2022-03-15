import random

import faker.exceptions
import pymongo
from decouple import config
from faker import Faker
from pymodm import connection

from src.models.device import Category, Data, Device

details = f'mongodb://{config("mDBuser")}:{config("mDBpassword")}@{config("mDBurl")}:{config("mDBport")}/{config("mDBdatabase")}?authSource=admin'
connection.connect(details)
fake = Faker()

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
    # "name": "HTL-R154-PoE-Access",
    "uptime": 3019345000,
    "description": "SG350X-48MP 48-Port Gigabit PoE Stackable Managed Switch",
    "contact": "florian.schmidt@htl-villach.at",
    "location": "HTL-R154-PoE-Access"
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


def seed_static_data(count, macs):
    static_data = []

    system = static_data_system_template
    system["name"] = fake.domain_word()
    system = {
        "system": system
    }
    static_data.append(Data(key="system", data=system).save())

    interfaces = {}
    neighbors = {}
    currently_used_macs = []
    for i in range(0, count):
        interface = dict(static_data_interface_template)
        interface["index"] = str(i)
        interface["port"] = str(i)
        interface["description"] = f"GigabitEthernet{str(i)}"

        random.shuffle(macs)
        for mac in macs:
            if mac["used"] is False:
                interface["mac_address"] = mac["mac"]
                mac["used"] = True
                currently_used_macs.append(mac["mac"])
                break

        neighbor = None
        if random.randint(1, 100) <= 15:
            random.shuffle(macs)
            for mac in macs:
                if mac["used"] is True and mac["mac"] not in currently_used_macs:
                    neighbor = static_data_neighbor_template[:]
                    neighbor[0]["local_port"] = interface["description"]
                    neighbor[0]["local_mac"] = interface["mac_address"]

                    neighbor[0]["remote_chassis_id"] = mac["mac"]
                    neighbor[0]["remote_port"] = mac["mac"]
                    break

        interfaces[interface["description"]] = dict(interface)
        if neighbor is not None:
            neighbors[interface["description"]] = neighbor[:]

    static_data.append(Data(key="network_interfaces", data=interfaces).save())
    if neighbors:
        static_data.append(Data(key="neighbors", data=neighbors).save())
    return static_data


def __create_macs__(count):
    try:
        macs = []
        for i in range(0, count):
            macs.append(
                {
                    "mac": fake.unique.mac_address(),
                    "used": False
                }
            )
    # except faker.exceptions.UniquenessException:
    #     return macs
    # return macs
    finally:
        return macs


def seed_devices(count, port_count, category, macs):
    for i in range(0, count):
        Device(
            hostname=device_hostname_template.format(str(i) + str(category.pk)),
            ip=device_ip_template.format(str(i) + str(category.pk)),
            category=category,
            static=seed_static_data(port_count, macs)
        ).save()


def seeder(category_count, device_count, port_count):
    clear()
    Faker.seed(0)
    fake.unique.clear()

    macs = __create_macs__(category_count * device_count * port_count)
    categories = seed_categories(category_count)
    for category in categories:
        seed_devices(device_count, port_count, category, macs)


seeder(category_count, device_count, ports_count)
