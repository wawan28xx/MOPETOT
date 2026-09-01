import asyncio
import os

from database.db import DB_PATH, init_db


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    asyncio.run(init_db())
    print("DB initialized:", DB_PATH)
