import pymysql.cursors

def obtenerconexion():
    connection = pymysql.connect(host='localhost',
                            user='root',
                            password='',
                            database='servicioshogar',
                            cursorclass=pymysql.cursors.DictCursor)
    return connection
