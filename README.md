# 🛡️ NetSentinel

> Sonde passive d'analyse de flux TCP/IP et de détection statistique d'anomalies réseau (*From Data to Systems* — ElmasCore).

NetSentinel inspecte des trames Ethernet/IPv4/TCP hors bande (captures `.pcap` standard issues de `tcpdump` ou `Wireshark`) et combine des signatures comportementales réseau avec un étalonnage statistique en ligne (**algorithme de Welford** + **Z-Score** protégé contre l'empoisonnement de baseline).

---

## 1. Choix technique et architecture

### Pourquoi Go (bibliothèque standard pure en v0.1) ?
Pour une sonde d'inspection réseau, **Go** offre le meilleur compromis entre sûreté mémoire, décodage binaire déterministe (`encoding/binary`, `net/netip`), concurrence légère et distribution sous forme d'un binaire statique unique sans dépendance `libpcap` C obligatoire pour rejouer et auditer des captures sur Linux comme sur Windows.

### Découpage par domaine métier (`ELMAS.md`)

```text
NetSentinel/
├── cmd/netsentinel/          # Entrée CLI (lecture PCAP ou simulation étalonnée)
└── internal/
    ├── packet/               # Décodage binaire Ethernet/IPv4/TCP et lecteur .pcap natif
    ├── baseline/             # Moments glissants de Welford et Z-Score robuste au démarrage à froid
    └── detection/            # Scoring de balayage de ports (port sweep) et rafales SYN flood
```

Le flux de dépendances est strictement unidirectionnel : `cmd/netsentinel` → `detection` → (`packet`, `baseline`). Toutes les fonctions d'analyse et de calcul statistique sont **pures** (zéro mutation d'état global, zéro effet de bord caché).

---

## 2. Méthodologie statistique & détection

1. **Variance en ligne de Welford** (`internal/baseline`) : calcul incrémental numériquement stable de la moyenne $\mu$ et de la variance corrigée $s^2$ du volume `SYN-only` par fenêtre temporelle, sans conserver l'historique brut en mémoire.
2. **Garde-fou de démarrage à froid** : aucun Z-Score n'est déclenché avant 5 fenêtres d'observation afin d'éviter les faux positifs initiaux.
3. **Protection contre l'empoisonnement de baseline** : lorsqu'une fenêtre est classée `CRITICAL`, ses compteurs sont signalés mais exclus de la mise à jour de Welford afin qu'une attaque prolongée ne devienne pas la nouvelle « normale ».
4. **Signatures couplées** (`internal/detection`) :
   - `port_scan_sweep` : cardinalité anormalement élevée de ports de destination distincts touchés par une même IP source.
   - `syn_flood_burst` : volume élevé de segments `SYN` sans `ACK` doublé d'un déséquilibre fort du ratio `SYN / SYN-ACK`.

---

## 3. Lancement rapide

### Prérequis
- **Go 1.24+**

### Exécuter la démonstration synthétique
Simule 6 fenêtres de trafic HTTPS normal suivies d'un balayage de ports puis d'une rafale SYN flood :

```bash
go run ./cmd/netsentinel --demo
```

### Analyser une capture `.pcap` réelle (Wireshark / tcpdump)
```bash
go run ./cmd/netsentinel --pcap chemin/vers/capture.pcap --window 5
```

### Lancer la suite de tests unitaires
```bash
go test -v ./...
```

---

## 4. Feuille de route
- [x] Décodeur binaire Ethernet / IPv4 / TCP sans dépendance C
- [x] Lecteur de flux `.pcap` (little-endian & big-endian)
- [x] Baseline statistique de Welford + Z-Score anti-empoisonnement
- [ ] Capture temps réel optionnelle sur interface Linux (`AF_PACKET`)
- [ ] Export JSON Lines & webhook d'alerte structuré
