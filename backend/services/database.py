import sqlite3
import json
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), '../threat_data.db')

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp_epoch REAL,
                timestamp_formatted TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                ack_completeness_ratio REAL,
                half_duplex_burst_score REAL,
                handshake_stub_flag INTEGER,
                retransmission_blindness_index REAL,
                threat_score REAL,
                severity TEXT,
                category TEXT,
                threat_type TEXT,
                explanation TEXT
            )
        ''')
        conn.commit()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def save_alert(alert_dict: dict):
    pkt = alert_dict['packet']
    ana = alert_dict['analysis']
    with get_db() as conn:
        conn.execute('''
            INSERT OR REPLACE INTO alerts 
            (id, timestamp_epoch, timestamp_formatted, source_ip, dest_ip, dest_port, protocol, packet_size, ack_completeness_ratio, half_duplex_burst_score, handshake_stub_flag, retransmission_blindness_index, threat_score, severity, category, threat_type, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_dict['id'], pkt['timestamp_epoch'], pkt['timestamp_formatted'], 
            pkt['source_ip'], pkt['dest_ip'], pkt['dest_port'], pkt['protocol'], pkt['packet_size'],
            pkt.get('ack_completeness_ratio', 0.0), pkt.get('half_duplex_burst_score', 0.0), pkt.get('handshake_stub_flag', 0), pkt.get('retransmission_blindness_index', 0.0),
            ana['threat_score'], ana['severity'], ana['category'], ana.get('threat_type', ''), ana['explanation']
        ))
        conn.commit()

def get_history(limit: int = 100):
    with get_db() as conn:
        cursor = conn.execute('SELECT * FROM alerts ORDER BY timestamp_epoch DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]

init_db()
