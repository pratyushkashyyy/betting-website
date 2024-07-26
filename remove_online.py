import sqlite3
import time

def get_database():
    return sqlite3.connect('betting.db')

def background_task():
    while True:
        # time.sleep(40)
            try:
                db = get_database()
                cursor = db.cursor()
                cursor.execute("""
                    UPDATE users
                    SET is_online = 0
                    WHERE is_online = 1
                """)
                db.commit()
                time.sleep(40)
            except Exception as e:
                print(f"Error in background task: {e}")
            finally:
                db.close()

if __name__ == "__main__":
    background_task()