"""
Le projet consiste à automatiser l’analyse de log pour :
    - comprendre ce qui se passe sur le système
    - détecter les erreurs ou les anomalies
    - extraire des statistiques utiles

Le projet va se décomposer en plusieurs étapes:
    - Lire un fichier de logs
    - Extraire des données utiles
    - Analyser le comportement
    - Détecter des anomalies
    - Visualiser les résultats
    - Automatiser et modulariser

Les compétences acquis au suite de projets sont multiples: traiter des données réelles (souvent sales, longues et mal structurés),
concevoir un outil autonome avec une vraie logique de traitement, pour enfin penser comme un ingénieur système (observation, diagnostic, performance)
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import matplotlib.pyplot as plt


# On ouvre le fichier filepath et on le lit en 'r' ce qui veut dire que tout est en string
# On lit toutes les lignes du fichier et on met chaque ligne dans la liste lines (les lignes sont en string)
def read_log(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    return lines


# la fonction parsing sert à séparer tout les tokens d'une ligne afin de les mettre dans des listes a l'intérieur d'un dictionnaire qui référencera tout les tokens: ip, datetime, method...
def parsing(lines):
    res = {
        "ip": [], "datetime": [], "method": [], "url": [], "status": [], "size": [], "user_agent": []
    }
    for line in lines:

        parts = line.split('"')                 # On découpe la ligne en plusieurs parties, la ou il y a des ''
        left = parts[0].split()                 # La première partie est l'adresse IP avec la date (et les deux tirets mais qu'on utilise quasi jamais: c'est le champ ident et le nom d'utilisateur authentifié)
        request = parts[1].split()              # La deuxième partie concernant la requete avec la method / l'url et le status

        res["ip"].append(left[0])               # On ajoute l'adresse IP dans le dictionnaire

        tempdate = left[-2][1:] + left[-1][:-1] # On rassemble la date et la différence d'heure UTC (heure international)
        tempdate = datetime.strptime(tempdate, "%d/%b/%Y:%H:%M:%S%z")   # On convertir notre heure str en objet datetime plus facilement manipulable
        res["datetime"].append(tempdate)

        res["method"].append(request[0])

        res["url"].append(request[1])

        extra = parts[2].strip().split()        # Récupération du code HTTP et de la taille dans parts[2]
        if len(extra) >= 2:
            res["status"].append(extra[0])
            res["size"].append(extra[1])
        else:
            res["status"].append("-")
            res["size"].append("-")

        if len(parts) > 5:                      # User-Agent, si présent car certain client ne peuvent rien renvoyer 
            res["user_agent"].append(parts[5].strip())
        else:
            res["user_agent"].append("-")

    return res


# Fonction qui renvoies les 5 IP faisant le plus de requete 
def top5IP(IPS):
    return Counter(IPS).most_common(5)


# Fonction qui renvoie les codes HTTP les plus fréquents
def top5Status(status):
    return Counter(status).most_common(5)


# Fonction afin de déterminer les appareils des User-Agent et d'en fournir un pourcentage mobile/desktop/bot
def userAnalysis(userAgent):
    res = {'Bot': 0, 'Mobile': 0, 'Desktop': 0, 'Chrome': 0, 'Firefox': 0, 'Bing': 0, 'Pourcentage mobile': '', "Pourcentage desktop": '', "Pourcentage bot": ''}
    for line in userAgent:
        ua = line.lower()                                               # mets tout en minuscules pour éviter de tester avec majuscule et sans
        if "chrome" in ua: res["Chrome"] += 1
        elif "firefox" in ua: res["Firefox"] += 1
        elif "bing" in ua: res["Bing"] += 1
        if "android" in ua or "iphone" in ua or "mobile" in ua: res["Mobile"] += 1
        elif "windows" in ua: res["Desktop"] += 1
        if "bot" in ua: res["Bot"] += 1
    total = res['Bot'] + res['Mobile'] + res['Desktop']
    res['Pourcentage mobile'] = int((res['Mobile']*100)/total)          # On calcule le pourcentage en fonction des mobiles, des desktop et des bots
    res['Pourcentage desktop'] = int((res['Desktop']*100)/total)
    res['Pourcentage bot'] =  int((res['Bot']*100)/total)
    return res


# Affiche un graphique circulaire de la répartition Mobile/Desktop/Bot.
def plot_userAnalysis(res):

    labels = ['Mobile', 'Desktop', 'Bot']                      # On récupère les pourcentages
    sizes = [
        res['Pourcentage mobile'],
        res['Pourcentage desktop'],
        res['Pourcentage bot']
    ]
    colors = ['#66b3ff', '#99ff99', '#ff9999']

    plt.figure(figsize=(6,6))
    plt.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        startangle=140, colors=colors, shadow=True
    )
    plt.title("Répartition des utilisateurs (User-Agent)")
    plt.axis('equal')                                           # cercle parfait
    plt.show()



# Fonction pour détecter de potentiel DDOS ou adresse malveillante (généralement bot) essayant de faire de la brute force
def requestAnalysis(dic):
    data = defaultdict(list)                    # Initialise le dictionnaire de liste vide ca nous évite de mettre pleins de conditions dans la boucle

    for i in range(len(dic["ip"])):             # On regroupe les datetimes par ip
        ip = dic["ip"][i]
        t = dic["datetime"][i]
        data[ip].append(t)

    WINDOW = 60                                  # On définit la fentre de suspection: 60 secondes
    SUSPECT = 30                               # plus de 30 requêtes par minute = suspect
    alerts = {}                                  # dictionnaire pour les IPs suspectes

    for ip, times in data.items():               # On parcourt chaque IP
        times.sort()                             # On tries les datetime dans l'ordre croissant
        start = 0                                # début de la fenetre        
        maxi = 0                                 # Pour garder le réel nombre de requete et pas juste la valeur de dépassement                 
        
        for end in range(len(times)):                                               # Maintenant on fait glisser notre fenetre pour parcourir les daate time et les vérifier

            while times[end] - times[start] > timedelta(seconds=WINDOW):
                start += 1                                                          # on avance la fenêtre
            window_size = end - start + 1
            if window_size > maxi:
                maxi = window_size
            
            if maxi > SUSPECT:                                                               # Permet de garder le vrai pic de requete visionner
                alerts[ip] = maxi

    for ip in alerts.keys():

        uas = [ua.lower() for i, ua in enumerate(dic["user_agent"]) if dic["ip"][i] == ip]      # trouver tous les user-agent de cette IP
        
        is_bot = any("bot" in ua or "crawler" in ua or "spider" in ua for ua in uas)            # vérifier si un user-agent contient "bot", "crawler" ou "spider"

        if is_bot:
            alerts[ip] = f"{alerts[ip]} requêtes (bot probable)"
        else:
            alerts[ip] = f"{alerts[ip]} requêtes (trafic suspect)"
    return alerts


# Affiche un graphique de l'évolution du nombre de requêtes par seconde
def plot_globalTraffic(dic):
    times = dic["datetime"]
    seconds = [t.replace(microsecond=0) for t in times]         # On tronque à la seconde près
    counts = Counter(seconds)
    sorted_times = sorted(counts.keys())
    values = [counts[t] for t in sorted_times]

    plt.figure(figsize=(10,5))
    plt.plot(sorted_times, values, color='royalblue', marker='o', linewidth=1)
    plt.title("Trafic global : nombre de requêtes par seconde")
    plt.xlabel("Temps (seconde)")
    plt.ylabel("Nombre de requêtes")
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


# Fonction pour afficher les analyses proprement avec les listes
def showList(count):
    for ele in count:
        print(f"{ele[0]:20} : {ele[1]}")        # Pour aligner sur la même colonne: "plus pro"
    print("")

# Fonction pour afficher les analyses utilisant des dictionnaires
def showDict(dic):
    if len(dic) == 0:
        print("")
        print("                 Aucune IP suspecte")
    else:
        for k, v in dic.items():
            print(f"{k:20} : {v}")
    print("")

if __name__ == "__main__":                      # exécute ce code seulement si le fichier est lancé directement, et pas importé depuis un autre module
    lines = read_log("logApache.txt")           # lit le fichier et récupère les lignes
    dic = parsing(lines)
    print("\n")
    print("----------------Top 5 des adresses IP----------------")
    showList(top5IP(dic["ip"]))
    print("-----------------Top 5 des codes HTTP----------------")
    showList(top5Status(dic["status"]))
    print("---------------Analyse des Utilisateurs--------------")
    ua = userAnalysis(dic["user_agent"])
    showDict(ua)
    plot_userAnalysis(ua)
    print("-----------------Analyse des requêtes----------------")
    ra = requestAnalysis(dic)
    showDict(ra)
    plot_globalTraffic(dic)

