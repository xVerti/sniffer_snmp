import sqlite3

def afficher_contenu_db(nom_db):
    try:
        # 1. Connexion à la base de données
        conn = sqlite3.connect(nom_db)
        cursor = conn.cursor()
        
        # 2. Récupérer la liste des tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        if not tables:
            print("Aucune table trouvée dans la base de données.")
            return

        # 3. Parcourir chaque table et afficher les données
        for table_nom in tables:
            table = table_nom[0]
            print(f"\n--- TABLE : {table} ---")
            
            # Récupérer les données
            cursor.execute(f"SELECT * FROM {table}")
            lignes = cursor.fetchall()
            
            # Récupérer les noms des colonnes
            noms_colonnes = [description[0] for description in cursor.description]
            print(f"Colonnes: {noms_colonnes}")
            
            for ligne in lignes:
                print(ligne)
                
    except sqlite3.Error as e:
        print(f"Erreur lors de la lecture de la base de données : {e}")
    finally:
        if conn:
            conn.close()

# Utilisation
afficher_contenu_db('test.db')