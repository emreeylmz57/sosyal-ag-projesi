import sqlite3
import os

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database.db')
sql_path = os.path.join(basedir, 'ssms_uyumlu.sql')

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

with open(sql_path, 'w', encoding='utf-8') as f:
    # SQL Server için tablo oluşturma script'i (T-SQL)
    f.write("""-- SQL Server için Tablo Oluşturma Scripti
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user')
BEGIN
    CREATE TABLE [user] (
        id INT IDENTITY(1,1) PRIMARY KEY,
        username NVARCHAR(80) NOT NULL UNIQUE,
        email NVARCHAR(120) NOT NULL UNIQUE,
        password_hash NVARCHAR(256) NOT NULL
    );
END
GO

""")

    # Kayıtları alma ve INSERT cümleleri üretme
    cursor.execute("SELECT username, email, password_hash FROM [user]")
    rows = cursor.fetchall()
    
    if rows:
        f.write("-- Kullanıcı Kayıtları\n")
        for row in rows:
            username = row[0].replace("'", "''")
            email = row[1].replace("'", "''")
            password = row[2].replace("'", "''")
            f.write(f"INSERT INTO [user] (username, email, password_hash) VALUES (N'{username}', N'{email}', N'{password}');\n")
        f.write("GO\n")

conn.close()
print("SQL Server uyumlu script oluşturuldu: ssms_uyumlu.sql")