import mysql.connector
import os
from dotenv import load_dotenv

class DatabaseCommunication :

    """
        Class to communicate with the database
    """

    # If True, the application will connect to the database in production mode
    # docker run -d -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=banshy_db -e MYSQL_USER=user -e MYSQL_PASSWORD=password -p 3333:3306 --name mysql-container mysql:8
    __PRODUCTION = True

    # Connection and cursor
    __connection = None
    __cursor = None

    def __init__(self):

        """
            Constructor
            Connect to the database and create the table if it does not exist
            The table has the following columns : hash (sha1), isSafe (boolean)
        """

        # Load the environment variables
        load_dotenv()

        if self.__PRODUCTION:

            # Connect to the database
            self.__connection = mysql.connector.connect(
                host = "mysql-db",
                user = os.getenv('MYSQL_USER'),
                password = os.getenv('MYSQL_PASSWORD'),
                database = os.getenv('MYSQL_DATABASE'),
                auth_plugin = 'mysql_native_password'
            )

        else:

            self.__connection = mysql.connector.connect(
                host = "localhost",
                user = "user",
                port = 3333,
                password = "password",
                database = "banshy_db",
                auth_plugin = 'mysql_native_password'
            )
        
        # Create the cursor to execute the queries
        self.__cursor = self.__connection.cursor()

        # Create the table with the following columns : hash (sha1), isSafe (boolean)
        self.__cursor.execute("CREATE TABLE IF NOT EXISTS Files (hash BINARY(40) PRIMARY KEY, isSafe BOOLEAN)")

    def check_file(self, hash: str) -> bool:

        """
            Check if a file is in the database
            + hash -> hash of the file
            ⮕ Return True if the file is safe, False otherwise
        """

        self.__cursor.execute("SELECT isSafe FROM Files WHERE hash = %s", (hash,))
        return self.__cursor.fetchone()

    def add_file(self, hash: str, isSafe: bool) -> None:

        """
            Add a file to the database
            + hash -> hash of the file
            + isSafe -> True if the file is safe, False otherwise
        """

        self.__cursor.execute("INSERT INTO Files (hash, isSafe) VALUES(%s, %s)", (hash, isSafe))
        self.__connection.commit()

    def close(self) -> None:

        """
            Close the connection to the database
        """

        self.__cursor.close()
        self.__connection.close()