import json
import psycopg2
from nvd_parser import main_parser

def load_config():
    with open('<config>', 'r') as file:
        config = json.load(file)
    return config


def create_table_CVE(conn):
    with conn.cursor() as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_table (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR,
            description VARCHAR,
            cvss FLOAT
        )
        """)
        conn.commit()


def insert_data(conn, data):
    with conn.cursor() as cur:
        tup = ','.join(cur.mogrify("(%s,%s,%s)",x).decode('utf-8') for x in data)
        cur.execute("INSERT INTO cve_table (cve_id, description, cvss) VALUES "+tup)
        conn.commit()


def main_cve_DB():
    config = load_config()
    try:
        print("Подключение к БД")
        conn = psycopg2.connect(
            host=config['database']['ip'],
            database='',
            user='',
            password='',
            port=5432
        )

    except Exception as e:
        exit(f"Ошибка подключения к базе данных: {e}")

    if conn:
        create_table_CVE(conn)  
        with conn.cursor() as cur:
            query_del_cve_table = "TRUNCATE TABLE cve_table;"
            cur.execute(query_del_cve_table)
            conn.commit
        
        
    print("Обновление базы данных уязвимостей NIST...")
    data_to_insert = main_parser()
        
    insert_data(conn, data_to_insert)

    conn.close()