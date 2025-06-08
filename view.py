import sqlite3

def reset_students_table():
    conn = sqlite3.connect('bus.db')
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS students;")

    cursor.execute('''
        CREATE TABLE students (
            registration_number TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            fee_status TEXT,
            bus_id INTEGER,
            seat_number TEXT,
            route_code TEXT,
            driver_registration TEXT,
            FOREIGN KEY (bus_id) REFERENCES buses(id),
            FOREIGN KEY (route_code) REFERENCES routes(route_code),
            FOREIGN KEY (driver_registration) REFERENCES drivers(registration_number)
        );
    ''')

    conn.commit()
    print("students table dropped and recreated.")
    conn.close()

if __name__ == "__main__":
    reset_students_table()
