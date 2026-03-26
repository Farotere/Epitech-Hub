# Rapport d'audit de securite — Hub Projets (hub.nice-tek.eu)

**Auditeur :** Leo Drevon
**Date :** 26 mars 2026
**Cible :** https://hub.nice-tek.eu (frontend) / https://api-hub.nice-tek.eu (API)
**Contexte :** Audit de securite autorise dans le cadre d'un projet Epitech

---

## Resume executif

Ce rapport presente les resultats d'un audit de securite realise sur la plateforme Hub Projets. L'audit a permis d'identifier **15 vulnerabilites**, dont **1 faille critique** permettant le **vol de session de n'importe quel utilisateur**, y compris les administrateurs.

La faille principale (XSS via le parametre `redirectTo`) a ete exploitee avec succes pour :
- Voler le token d'un etudiant (Antony Poliautre) en 1 clic
- Voler le token de l'administrateur (Renaud Juliani)
- Acceder a l'ensemble des donnees de la plateforme (20 projets, 21 emails, notes et credits)

| Severite | Nombre de failles |
|----------|------------------|
| CRITIQUE | 1 |
| ELEVEE | 1 |
| MOYENNE | 8 |
| FAIBLE | 5 |

---

## Architecture de la plateforme

Pour comprendre les failles, voici comment le site fonctionne :

- **Le site web** (hub.nice-tek.eu) est la partie visible — c'est la ou les etudiants se connectent et soumettent leurs projets
- **L'API** (api-hub.nice-tek.eu) est le "cerveau" — elle traite les donnees, verifie les droits, stocke en base de donnees
- **nginx** est le "gardien a l'entree" — il recoit toutes les requetes et les transmet au bon endroit
- **MongoDB** est la "base de donnees" — elle stocke tous les projets, utilisateurs, etc.
- **Microsoft OAuth** est le systeme de connexion — les utilisateurs se connectent avec leur compte Epitech Microsoft
- **Le token JWT** est le "badge d'acces" — apres connexion, l'utilisateur recoit un badge numerique qui prouve son identite pendant 24h

---

## Faille 1 — Vol de session via lien piege (CRITIQUE)

### Problematique
> *Est-il possible de prendre le controle du compte d'un autre utilisateur simplement en lui envoyant un lien ?*

### Ce que j'ai trouve
Oui. La page de connexion du site (`/auth/callback`) accepte un parametre `redirectTo` dans l'URL. Ce parametre est cense rediriger l'utilisateur vers le tableau de bord apres connexion. Mais **aucune verification** n'est faite sur ce parametre.

En mettant `javascript:` au lieu d'une URL normale, on peut **executer du code** dans le navigateur de la victime, comme si c'etait le site lui-meme qui le faisait.

### Comment j'ai fait (logique d'attaque)
1. **Decouverte** : J'ai telecharge et analyse le code JavaScript du site (disponible publiquement). J'ai trouve que la page `/auth/callback` fait `router.push(redirectTo)` sans aucun filtre
2. **Test** : J'ai mis `javascript:alert(document.cookie)` dans le parametre → une popup est apparue sur le site. Preuve que du code s'execute
3. **Escalade** : J'ai remplace par `javascript:alert(localStorage.getItem('token'))` → le token JWT (badge d'acces) s'affiche en clair
4. **Exfiltration** : J'ai cree un lien qui envoie silencieusement le token vers mon serveur (webhook.site puis Discord) → le token est vole sans que la victime ne voie quoi que ce soit
5. **Exploitation** : Avec le token vole, j'ai pu creer un projet au nom de la victime, acceder a ses donnees, injecter le lien malveillant dans le projet de la victime pour couvrir mon identité puis attendre que l'admin clique dessus. Pour ensuite devenir admin a mon tour.

### Attaque realisee
- Vol du token de **Antony Poliautre** (etudiant) → creation d'un projet a son nom qu'il n'a jamais cree
- Vol du token de **Renaud Juliani** (administrateur) → acces a tous les projets, emails, notes et credits de 21 etudiants

### Preuve
```
URL envoyee a la victime :
https://hub.nice-tek.eu/auth/callback?redirectTo=javascript:alert(localStorage.getItem('token'))

Resultat : Le token JWT complet s'affiche dans une popup
Resultat avec exfiltration : Le token arrive sur webhook.site/Discord
```

### Solution recommandee
- **Valider le parametre `redirectTo`** : n'accepter que les URLs qui commencent par `/` (chemins internes). Rejeter tout ce qui contient `javascript:`, `data:`, `http://`, `https://` vers un domaine externe
- **Exemple de code correctif** :
```javascript
// AVANT (vulnerable)
router.push(redirectTo || "/dashboard")

// APRES (securise)
const safe = redirectTo && redirectTo.startsWith('/') && !redirectTo.startsWith('//')
  ? redirectTo : "/dashboard";
router.push(safe);
```

---

## Faille 2 — Serveur web obsolete vulnerable au deni de service (ELEVEE)

### Problematique
> *Le serveur web est-il a jour et protege contre les attaques connues ?*

### Ce que j'ai trouve
Non. Le serveur utilise **nginx 1.22.1**, une version sortie en 2022 qui n'est plus maintenue. Cette version est vulnerable a **CVE-2023-44487** (score de gravite 7.5/10), une faille qui a ete massivement exploitee en 2023 pour rendre des sites inaccessibles.

### Comment j'ai fait
1. J'ai regarde les en-tetes HTTP du serveur → `server: nginx/1.22.1`
2. J'ai verifie que le protocole HTTP/2 est active → confirme
3. J'ai croise avec la base de donnees des failles connues → CVE-2023-44487 s'applique
4. J'ai verifie avec l'outil `h2load` → le serveur montre des signes de surcharge ("Process Request Failure")

### Ce que ca permet
Un attaquant peut envoyer des milliers de requetes speciales (HTTP/2 Rapid Reset) qui surchargent le serveur. Le site devient inaccessible pour tous les utilisateurs pendant la duree de l'attaque.

### Solution recommandee
- **Mettre a jour nginx** vers la version 1.26.x ou superieure
- **En attendant** : ajouter `http2_max_concurrent_streams 32;` dans la configuration nginx pour limiter l'impact

---

## Faille 3 — Le badge d'acces contient des informations lisibles par tous (MOYENNE)

### Problematique
> *Les informations dans le token JWT sont-elles protegees ?*

### Ce que j'ai trouve
Non. Le token JWT (badge d'acces) contient en clair : le nom, l'email, le role (etudiant/admin), et l'identifiant de l'utilisateur. N'importe qui peut lire ces informations en decodant le token (c'est du Base64, pas du chiffrement).

### Comment j'ai fait
```
Token : eyJhbGciOiJIUzI1NiIs...
Decode : {"id":"69bd5687...","name":"Leo Drevon","email":"leo.drevon@epitech.eu","role":"student"}
```
Il suffit de copier-coller le token dans un decodeur Base64 pour lire toutes les informations.

### Pourquoi c'est un probleme
Le token est visible dans la barre d'URL du navigateur, dans l'historique, dans les logs du serveur. Toute personne qui voit le token peut connaitre le nom, l'email et le role de l'utilisateur.

### Solution recommandee
- **Ne pas mettre d'informations sensibles dans le token** : stocker seulement un identifiant opaque (ex: un UUID) et recuperer les informations cote serveur
- **Ou chiffrer le contenu du token** (JWE au lieu de JWS) pour que seul le serveur puisse le lire

---

## Faille 4 — Le badge d'acces est visible dans la barre d'URL (MOYENNE)

### Problematique
> *Le token JWT est-il transmis de maniere securisee apres la connexion ?*

### Ce que j'ai trouve
Non. Apres la connexion Microsoft, le serveur redirige vers :
```
https://hub.nice-tek.eu/auth/callback?token=eyJhbGciOiJIUzI1NiIs...
```
Le token complet est dans l'URL, visible dans la barre d'adresse.

### Pourquoi c'est un probleme
- Le token est enregistre dans **l'historique du navigateur** (accessible par toute personne ayant acces a l'ordinateur)
- Le token apparait dans les **logs du serveur nginx** (access.log)
- Si l'utilisateur partage son ecran ou fait une capture d'ecran, le token est expose
- Le token peut fuiter via le **header Referer** quand l'utilisateur clique sur un lien externe

### Solution recommandee
- **Transmettre le token via un fragment d'URL** (`#token=...`) — le fragment n'est pas envoye au serveur et n'apparait pas dans les logs
- **Ou utiliser un code temporaire** : le serveur envoie un code jetable dans l'URL, le frontend l'echange contre le vrai token via un appel API securise

---

## Faille 5 — Pas de protection Referrer-Policy sur le site (MOYENNE)

### Problematique
> *L'URL de la page est-elle protegee quand l'utilisateur navigue vers un site externe ?*

### Ce que j'ai trouve
Non. Le site `hub.nice-tek.eu` n'a aucun en-tete `Referrer-Policy`. Quand un utilisateur clique sur un lien externe depuis le site, le navigateur envoie l'URL complete de la page au site de destination. Si l'URL contient le token (cf. Faille 5), le token fuite.

### Comment j'ai fait
```bash
curl -sI https://hub.nice-tek.eu/ | grep referrer
# → aucun resultat — pas de Referrer-Policy
```

### Solution recommandee
- Ajouter l'en-tete `Referrer-Policy: no-referrer` ou `strict-origin` sur toutes les pages du frontend

---

## Faille 6 — L'API accepte du contenu dangereux sans le nettoyer (MOYENNE)

### Problematique
> *L'API verifie-t-elle que les donnees envoyees par les utilisateurs sont saines ?*

### Ce que j'ai trouve
Non. L'API accepte et stocke en base de donnees du code HTML, JavaScript, et des formules Excel sans aucun nettoyage. Par exemple, on peut creer un projet avec le nom `<script>alert(1)</script>` — c'est accepte tel quel.

### Comment j'ai fait
```bash
curl -X POST "$API/api/projects" -d '{"name":"<script>alert(1)</script>",...}'
# → Accepte et stocke en base
```

### Pourquoi c'est un probleme actuellement limite
Le site web utilise React qui echappe automatiquement le contenu dangereux a l'affichage. Mais si les donnees sont affichees dans un autre contexte (email, export, application tierce), le code malveillant pourrait s'executer.

### Solution recommandee
- **Nettoyer les donnees cote serveur** (sanitization) avec une librairie comme `sanitize-html` ou `DOMPurify`
- Ne jamais faire confiance aux donnees envoyees par le client

---

## Faille 7 — On peut ajouter n'importe qui comme membre d'un projet (MOYENNE)

### Problematique
> *Un etudiant peut-il associer d'autres personnes a son projet sans leur accord ?*

### Ce que j'ai trouve
Oui. L'endpoint de modification de projet accepte n'importe quel email dans le champ `members`, meme si la personne n'existe pas dans le systeme ou n'a pas donne son accord.

### Comment j'ai fait
```bash
curl -X PUT "$API/api/projects/:id" -d '{"members":[{"email":"admin@epitech.eu"}],...}'
# → admin@epitech.eu est ajoute comme membre
```

### Solution recommandee
- **Verifier que l'email existe** dans la base de donnees avant de l'ajouter
- **Envoyer une demande de confirmation** a la personne ajoutee
- **Limiter les emails** au domaine `@epitech.eu`

---

## Faille 8 — Pas de limite sur la creation de projets (MOYENNE)

### Problematique
> *Un utilisateur peut-il surcharger le systeme en creant des centaines de projets ?*

### Ce que j'ai trouve
Oui. Aucune limite n'est imposee sur le nombre de projets qu'un utilisateur peut creer. En combinant avec le rate limit (100 requetes par 15 minutes), un attaquant peut creer environ 9 600 projets par jour.

### Solution recommandee
- **Limiter le nombre de projets** par utilisateur (ex: maximum 5 projets en attente)
- **Ajouter un CAPTCHA** ou une validation humaine apres un certain nombre de soumissions

---

## Faille 9 — Pas de deconnexion cote serveur (MOYENNE)

### Problematique
> *Si un badge d'acces (token) est vole, peut-on le revoquer ?*

### Ce que j'ai trouve
Non. Il n'existe aucun mecanisme de deconnexion cote serveur. Le bouton "Deconnexion" du site supprime le token du navigateur, mais le token lui-meme reste **valide pendant 24h**. Un attaquant qui a copie le token peut continuer a l'utiliser.

### Solution recommandee
- **Implementer un systeme de blacklist de tokens** : quand un utilisateur se deconnecte, son token est ajoute a une liste noire cote serveur
- **Reduire la duree de validite** du token (ex: 1h au lieu de 24h) avec un systeme de refresh token

---

## Faille 10 — Le badge d'acces fonctionne depuis n'importe quel ordinateur (MOYENNE)

### Problematique
> *Un token vole peut-il etre utilise depuis une autre machine ?*

### Ce que j'ai trouve
Oui. Le token ne contient aucune information sur l'adresse IP de l'utilisateur. J'ai obtenu un token depuis mon ordinateur, puis je l'ai utilise avec succes depuis un VPN (adresse IP completement differente).

### Solution recommandee
- **Lier le token a l'adresse IP** : le serveur verifie que le token est utilise depuis la meme IP que celle de la connexion initiale
- **Ou utiliser une empreinte de navigateur** (fingerprint) pour detecter les changements de machine

---

## Faille 11 — Pas de limite de taille sur les champs de liste (MOYENNE)

### Problematique
> *Peut-on surcharger le systeme en envoyant des quantites massives de donnees dans un seul projet ?*

### Ce que j'ai trouve
Oui. Les champs `technologies` et `links.other` acceptent un nombre illimite d'elements. J'ai pu creer un projet avec 1000 technologies et 50 liens sans aucune erreur.

### Solution recommandee
- **Limiter le nombre d'elements** (ex: maximum 10 technologies, 5 liens)
- **Limiter la taille totale** du document envoye

---

## Faille 12 — Validation manquante sur les champs numeriques (FAIBLE)

### Problematique
> *Les champs numeriques sont-ils correctement valides ?*

### Ce que j'ai trouve
Non. Le champ `studentCount` (nombre d'etudiants) accepte des valeurs negatives. Un projet peut etre cree avec `-1` etudiants. (Marche qu'en faisant un call API sinon bloqué sur le front)

### Solution recommandee
- Ajouter une validation `studentCount >= 1` cote serveur

---

## Faille 13 — Difference de temps de reponse selon l'existence d'un projet (FAIBLE)

### Problematique
> *Un attaquant peut-il deviner si un projet existe sans y avoir acces ?*

### Ce que j'ai trouve
Oui. Le serveur repond en ~0.59s pour un projet existant et ~0.81s pour un projet inexistant. Cette difference permet de determiner si un identifiant de projet est valide.

### Solution recommandee
- **Uniformiser les temps de reponse** : renvoyer la meme erreur en un temps constant, que le projet existe ou non

---

## Faille 14 — Informations techniques exposees (FAIBLE)

### Problematique
> *Le site revele-t-il des informations techniques qui pourraient aider un attaquant ?*

### Ce que j'ai trouve
Oui. Les en-tetes HTTP et les messages d'erreur revelent :

| Information exposee | Risque |
|---|---|
| Version du serveur : `nginx/1.22.1` | Permet de chercher les failles connues pour cette version |
| Framework : `Next.js` | Permet d'adapter les attaques au framework |
| Messages d'erreur Express detailles | Revelent la technologie backend |
| Identifiants Azure AD (Tenant ID, Client ID) | Facilitent le phishing cible |
| Pas de Content-Security-Policy sur le site | Le navigateur n'a pas de regles de securite supplementaires |

### Solution recommandee
- **Masquer la version du serveur** : `server_tokens off;` dans nginx
- **Retirer le header `x-powered-by`** : `app.disable('x-powered-by')` dans Express
- **Ajouter une Content-Security-Policy** sur le frontend
- **Utiliser des messages d'erreur generiques** en production

---

## Faille 15 — L'API accepte les requetes de n'importe quel site web (FAIBLE)

### Problematique
> *Est-ce qu'un site web malveillant peut communiquer avec l'API du Hub ?*

### Ce que j'ai trouve
Oui. L'API repond avec `Access-Control-Allow-Origin: *`, ce qui signifie qu'elle accepte les requetes venant de n'importe quel site web. C'est une mauvaise pratique, mais dans ce contexte l'impact est faible car un attaquant qui possede un token peut de toute facon l'utiliser directement via un outil en ligne de commande (curl), sans passer par un navigateur.

### Solution recommandee
- Remplacer `*` par le domaine exact : `Access-Control-Allow-Origin: https://hub.nice-tek.eu`

---

## Synthese des attaques realisees

### Attaque 1 — Vol de session d'un etudiant
```
1. J'envoie un lien piege a la victime (Antony Poliautre)
2. Antony clique → son token est envoye sur mon serveur Discord
3. Avec son token, je cree un projet a son nom qu'il n'a jamais soumis
```
**Resultat : J'ai pris le controle du compte d'Antony**

### Attaque 2 — Vol de session de l'administrateur
```
1. J'envoie le meme type de lien piege a l'administrateur (Renaud Juliani)
2. Renaud clique → son token admin arrive sur mon Discord
3. Avec son token, j'accede a TOUTES les donnees de la plateforme
```
**Resultat : J'ai obtenu les donnees de 21 etudiants (noms, emails, projets, notes)**

### Donnees recuperees avec le token admin
| Donnee | Quantite |
|--------|----------|
| Projets (tous les etudiants) | 20 |
| Emails uniques | 21 |
| Export CSV (notes et credits) | Complet |
| Workshops | 3 |

---

## Chaine d'attaque complete

```
                    Lien piege envoye par email/Discord
                                  |
                                  v
        La victime clique (elle est connectee au site)
                                  |
                                  v
           Le code JavaScript s'execute sur hub.nice-tek.eu
                                  |
                                  v
         Le token (badge d'acces) est envoye a l'attaquant
                                  |
                                  v
    L'attaquant utilise le token depuis son propre ordinateur
     (possible car : CORS *, pas de binding IP, pas de logout)
                                  |
                                  v
              Acces total au compte de la victime
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
            Si c'est un etudiant :      Si c'est un admin :
            - Lire ses projets          - Lire TOUS les projets
            - Creer/supprimer           - Exporter le CSV complet
              des projets               - Voir toutes les notes
              a son nom                 - Gerer les workshops
                                        - Gerer les cycles
```

---

## Tableau recapitulatif des recommandations

| Priorite | Action | Faille corrigee |
|----------|--------|----------------|
| URGENTE | Valider le parametre `redirectTo` (n'accepter que les chemins internes commencant par `/`) | Faille 1 (XSS/vol de session) |
| FAIBLE | Remplacer `Access-Control-Allow-Origin: *` par le domaine exact `https://hub.nice-tek.eu` | Faille 2 (CORS) |
| HAUTE | Mettre a jour nginx vers la version 1.26.x ou superieure | Faille 3 (CVE DoS) |
| HAUTE | Transmettre le token via un fragment (`#`) ou un code temporaire au lieu de la query string | Faille 4, 5 (token expose) |
| HAUTE | Implementer un systeme de logout cote serveur (blacklist de tokens) | Faille 10 (pas de revocation) |
| MOYENNE | Ajouter `Referrer-Policy: no-referrer` sur le frontend | Faille 6 (fuite Referer) |
| MOYENNE | Nettoyer les donnees utilisateur cote serveur (sanitization) | Faille 7 (contenu dangereux) |
| MOYENNE | Verifier l'existence des emails avant ajout comme membre | Faille 8 (membres arbitraires) |
| MOYENNE | Limiter le nombre de projets par utilisateur | Faille 9 (creation illimitee) |
| MOYENNE | Lier le token a l'adresse IP | Faille 11 (token reutilisable) |
| MOYENNE | Limiter la taille des arrays (technologies, liens) | Faille 12 (arrays illimites) |
| FAIBLE | Valider `studentCount >= 1` | Faille 13 (valeur negative) |
| FAIBLE | Uniformiser les temps de reponse | Faille 14 (timing attack) |
| FAIBLE | Masquer les versions et informations techniques | Faille 15 (info disclosure) |

---

## Tests effectues sans resultat (protections fonctionnelles)

Ces tests montrent que certaines protections sont bien en place. Chaque test a ete realise methodiquement pour verifier si la faille existait.

### Authentification & Autorisation
| Test realise | Resultat | Explication simple |
|---|---|---|
| Forger un faux badge admin (JWT alg=none) | Bloque | Le serveur verifie la signature — les tokens sans signature sont rejetes |
| Forger un badge avec signature vide | Bloque | Le serveur rejette les tokens mal formes |
| Deviner le secret de signature (brute-force) | Echec | Teste avec 14 millions de mots de passe (rockyou.txt) + wordlist cible + brute-force 6 caracteres. Secret suffisamment complexe |
| Modifier le role dans le token (student → admin) | Bloque | Le token est signe — toute modification invalide la signature |
| Acceder aux pages admin sans etre admin | Bloque | Le serveur verifie le role sur chaque requete API |
| Se connecter avec un token expire | Bloque | Le serveur verifie la date d'expiration |
| Injecter un faux token dans localStorage | Bloque | Le frontend appelle /api/users/me pour valider → le serveur rejette → deconnexion |

### XSS (Cross-Site Scripting)
| Test realise | Resultat | Explication simple |
|---|---|---|
| XSS dans le nom du projet (`<script>alert(1)</script>`) | Stocke mais pas execute | React echappe le contenu a l'affichage — le code s'affiche en texte |
| XSS dans la description (`<svg onload=alert(1)>`) | Stocke mais pas execute | Meme raison — React protege |
| XSS dans les objectifs (`<iframe src=javascript:...>`) | Stocke mais pas execute | Meme raison |
| XSS dans les technologies (`<img onerror=alert(1)>`) | Stocke mais pas execute | Meme raison |
| XSS via `javascript:` dans links.other | Bloque | Les liens sont rendus avec `target="_blank" rel="noopener noreferrer"` → ouvre about:blank |
| XSS via `data:text/html` dans links.other | Bloque | Les navigateurs modernes bloquent les data: URI dans les liens top-level |
| XSS reflechie via l'URL (`/projects/<script>`) | Bloque | React echappe les parametres de route |
| XSS via SVG upload | Non testable | Pas de fonctionnalite d'upload disponible pour les etudiants |

### Injection & Manipulation de donnees
| Test realise | Resultat | Explication simple |
|---|---|---|
| Injection NoSQL ($ne, $gt, $regex, $where) | Non exploitable | Les operateurs MongoDB passent la validation mais la verification metier (cycle ferme) empeche d'atteindre la base |
| Prototype pollution (__proto__, constructor) | Bloque | Les champs sont ignores par le serveur |
| Mass assignment (status → approved) | Bloque | Le serveur utilise une whitelist de champs modifiables |
| Mass assignment (credits, submittedBy, _id) | Bloque | Ces champs sont ignores ou forces par le serveur |
| Mass assignment (changeHistory) | Bloque | Le serveur ignore ce champ |
| Mass assignment (externalRequestStatus) | Bloque | Le serveur ignore ce champ |
| Injection CRLF dans les en-tetes | Bloque | nginx rejette les caracteres speciaux |
| Null byte injection dans les champs texte | Accepte | Le serveur stocke `test\x00admin` tel quel — impact faible (troncature possible dans d'autres systemes) |

### IDOR & Acces aux donnees d'autres utilisateurs
| Test realise | Resultat | Explication simple |
|---|---|---|
| Lire le projet d'un autre utilisateur (GET /api/projects/:id) | Bloque | Le serveur repond "Non autorise" — verification d'ownership |
| Modifier le projet d'un autre utilisateur (PUT) | Bloque | Le serveur repond "Non autorise a modifier ce projet" |
| Supprimer le projet d'un autre utilisateur (DELETE) | Bloque | Verification d'ownership cote serveur |
| Enumeration d'IDs de projets (brute-force ObjectID) | Echec | 36 IDs testes autour des IDs connus — aucun projet d'autre utilisateur trouve |

### Infrastructure & Reseau
| Test realise | Resultat | Explication simple |
|---|---|---|
| Path traversal via nginx (..%2f) | Bloque | nginx rejette avec erreur 400 |
| Path traversal double-encode (..%252f) | Bloque | Le serveur retourne 404 |
| HTTP Request Smuggling (CL.TE) | Bloque | nginx gere correctement les en-tetes |
| Host header injection | Bloque | Retourne 404 avec un Host different |
| Methodes HTTP non standard (PROPFIND, COPY, etc.) | Bloque | Le serveur rejette les methodes inconnues |
| SSRF via validate-github | Non exploitable | L'endpoint verifie le format GitHub strict (`github.com/user/repo` uniquement) — impossible de rediriger vers localhost. Teste aussi avec des URLs GitHub contenant des redirections (301) — rejete |
| SSRF via redirect GitHub (301) | Bloque | Les URLs GitHub avec des paths complexes (`/tree/master`, `/orgs/...`) sont rejetees — le format strict empeche tout contournement |
| SSRF via creation de projet (liens externes) | Bloque | Le serveur ne fetch pas les URLs des projets (teste avec requestcatcher.com — aucune requete recue) |
| Acces aux fichiers sensibles (.env, package.json, .git) | Bloque | Tous retournent 404 sur les deux domaines |
| Websocket / Server-Sent Events | Non disponible | Aucun endpoint ws/events/stream |
| GraphQL | Non disponible | Aucun endpoint graphql |
| Contourner le rate limit (X-Forwarded-For, X-Real-IP) | Bloque | Le rate limit est base sur l'adresse IP reelle |
| Open redirect sur d'autres pages (/, /dashboard) | Non exploitable | Seul /auth/callback a le parametre redirectTo |

### Autres tests
| Test realise | Resultat | Explication simple |
|---|---|---|
| CSV Injection (formules Excel dans les champs) | Stocke mais pas execute | Les tableurs modernes (LibreOffice Calc, Google Sheets) traitent le CSV comme du texte |
| ReDoS (regex denial of service sur validate-github) | Non exploitable | La regex rejette en temps normal (~0.6s) — pas de backtracking catastrophique |
| Race condition (2 PUT simultanes) | Detecte mais pas exploitable | Mongoose gere le conflit de version — une requete echoue proprement |
| Type confusion (objet au lieu de string dans name) | Accepte | Le serveur stocke `[object Object]` — pas d'impact critique |
| Unicode/homoglyph dans les noms | Accepte | Le serveur accepte des caracteres grecs ressemblant a du latin — tromperie visuelle possible |
| Email tres long dans studentEmails (500+ chars) | Accepte | Pas de limite de longueur sur les emails — 511 caracteres acceptes |
| HTTP Parameter Pollution (double param status) | Pas d'impact | Le serveur prend le premier parametre |
| Changer le role d'un utilisateur (en admin) | Non disponible | Aucun endpoint PUT/PATCH sur /api/users |
| Supprimer un utilisateur | Non disponible | Aucun endpoint DELETE sur /api/users |
| Account takeover (modifier email/nom) | Non disponible | Aucun endpoint de modification de profil |
| `javascript:` dans links.github / links.projectGithub | Bloque | Le serveur valide que les URLs sont des URLs GitHub valides — `javascript:` est rejete |
| Upload de fichier malveillant (PDF avec JS) en admin | Upload accepte mais pas accessible | Le PDF est stocke (`simulated-subjects/xxx.pdf`) mais aucune URL publique ne permet d'y acceder — pas de XSS via PDF |
| Upload de fichiers non-PDF en admin | Bloque | Le serveur n'accepte que les fichiers PDF — HTML, SVG, TXT rejetes |
| Injection dans le parametre state OAuth | Bloque | Le serveur ignore le parametre state — il n'est pas transmis a Microsoft dans le redirect |
| Formules dangereuses dans l'export CSV admin | Non exploitable | Le CSV exporte ne contient que des tirets (`-`) dans les champs de grade, pas de formules injectees par des utilisateurs |
