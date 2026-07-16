import sqlite3
conn = sqlite3.connect('panoptes.db')
c = conn.cursor()
c.execute("UPDATE sessions SET start_time = '2025-01-01 00:00:00.000000' WHERE risk_score = 0.0 AND is_anomalous = 1")
conn.commit()
print(c.rowcount, 'rows updated')
