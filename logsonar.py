import json
import os
import glob

def load_state(state_file):
    """Charge la dernière position de lecture"""
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            return json.load(f)
    return {}

def save_state(state_file, state):
    """Sauvegarde la position pour le prochain passage"""
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=4)

def read_new_logs(log_dir="/var/lib/docker/containers/"):
    """Lit uniquement les nouvelles lignes de tous les conteneurs Docker"""
    state = load_state('state.json')
    new_entries = []
    log_files = glob.glob(os.path.join(log_dir, "*/*-json.log"))

    for log_file in log_files:
        # L'identifiant du conteneur est le nom du fichier
        container_id = os.path.basename(log_file).split('-')[0]
        
        # On récupère la dernière position lue (en octets/bytes) pour ce fichier
        last_byte = state.get(log_file, 0)
        
        # Taille actuelle du fichier
        current_size = os.path.getsize(log_file)

        # Si Docker a fait tourner les logs (fichier plus petit qu'avant), on recommence au début
        if current_size < last_byte:
            last_byte = 0

        if current_size > last_byte:
            with open(log_file, 'r') as f:
                # On se place directement là où on en était
                f.seek(last_byte)
                
                # On lit que la nouveauté
                new_lines = f.readlines()
                
                for line in new_lines:
                    try:
                        log_data = json.loads(line.strip())
                        log_data['container_id'] = container_id # Super pratique pour filtrer plus tard
                        new_entries.append(log_data)
                    except json.JSONDecodeError:
                        pass # Ignore les lignes cassées (rare mais possible)
                
                # On met à jour la position dans notre mémoire
                state[log_file] = f.tell()

    save_state('state.json', state)
    return new_entries

# --- TEST TEMPORAIRE ---
if __name__ == "__main__":
    print("LogSonar : Scan en cours...")
    logs = read_new_logs()
    print(f"LogSonar : {len(logs)} nouvelles lignes détectées.")
    for log in logs[-3:]: # Affiche les 3 dernières pour le test
        print(f"[{log.get('container_id', '?')}] {log.get('log', '').strip()}")