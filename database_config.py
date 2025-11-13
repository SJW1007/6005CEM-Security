import os
from typing import Any, Dict

import mysql.connector
from dotenv import load_dotenv
from mysql.connector.connection import MySQLConnection


load_dotenv()

_DEFAULT_DB_CONFIG: Dict[str, Any] = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cad"),
    # "auth_plugin": os.getenv("DB_AUTH_PLUGIN", "mysql_native_password"),
}


def get_database_config() -> Dict[str, Any]:
    """
    Returns a copy of the database configuration loaded from environment variables.
    """
    return _DEFAULT_DB_CONFIG.copy()


def get_database_connection(**overrides: Any) -> MySQLConnection:
    """
    Create a MySQL database connection using environment variables.

    Optional keyword arguments override values from the environment configuration.
    """
    config = get_database_config()
    config.update(overrides)
    return mysql.connector.connect(**config)


