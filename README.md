# SentinelX — version de démonstration

Plateforme SaaS de QA, cybersécurité et performance (voir `Cahier_des_charges_SentinelX.pdf`).
Cette version couvre les pages et les fonctions de base. Elle n'est pas prête pour la production.

## Lancer l'application

Prérequis : Node.js 20 ou plus récent.

```bash
npm run setup   # une seule fois : dépendances + création de la base
npm start       # compile le frontend et démarre le serveur
```

Ouvrir ensuite http://localhost:3000

`npm run reset` vide la base de démonstration.

## Parcours de démonstration

1. Créer un compte (crée l'organisation, vous en êtes administrateur).
2. Créer un projet, puis ajouter une application (URL d'un site qui vous appartient).
3. Déclarer l'autorisation d'audit sur l'application.
4. Lancer un audit (QA, Sécurité, Performance) et ouvrir le détail.
5. Télécharger le rapport PDF, JSON ou CSV.
6. Qualifier une vulnérabilité, activer le monitoring, ajouter un collaborateur, changer de formule.

## Ce qui fonctionne

| Domaine | Contenu |
|---|---|
| Comptes | Inscription, connexion, déconnexion, profil, changement de mot de passe, sessions révocables |
| Multi-tenant | Une organisation par compte, 4 rôles, isolation des données par organisation |
| Projets | Projets, applications, environnements, autorisation d'audit tracée |
| QA | Accessibilité de la page, structure HTML, images, formulaires, liens cassés |
| Sécurité | HTTPS, certificat TLS, en-têtes, cookies, contenu mixte, fichiers `.git` et `.env` exposés |
| Performance | Temps moyen, P95, P99, débit, taux d'erreur sur 10 requêtes |
| Monitoring | Vérification périodique, incidents regroupés, notifications |
| Rapports | PDF, JSON, CSV, comparaison avec l'audit précédent |
| Abonnement | 3 formules, quotas appliqués côté serveur (changement de formule sans paiement) |

## Sécurité de la plateforme

- Mots de passe hachés avec Argon2id, blocage après 5 échecs de connexion.
- Cookie de session `HttpOnly` + `SameSite=Strict`, en-tête obligatoire sur les requêtes modifiantes (CSRF).
- Toutes les requêtes en base filtrent sur l'organisation de la session.
- Protection SSRF : adresses internes refusées, y compris après résolution DNS et à chaque redirection.
- Aucun audit sans autorisation déclarée ; actions sensibles journalisées.

## Écarts avec le cahier des charges

| Prévu | Dans cette version |
|---|---|
| PostgreSQL | SQLite via Prisma (changer `provider` dans `server/prisma/schema.prisma`) |
| Redis + BullMQ, workers en conteneurs | Exécution dans le processus du serveur |
| Playwright, OWASP ZAP, Semgrep, Trivy, k6, Lighthouse | Contrôles écrits en Node.js, passifs uniquement |
| Tests multi-navigateurs, visuels, de charge | Non réalisés |
| Module API Security (OpenAPI) | Non réalisé |
| 2FA, vérification d'e-mail, mot de passe oublié | Non réalisés |
| Notifications par e-mail, paiement | Non réalisés (notifications dans l'application uniquement) |
| Super Administrateur | Non réalisé |
| Tests automatisés, CI/CD, Docker | Non réalisés |

Pour auditer un laboratoire local (Juice Shop, DVWA), démarrer le serveur avec la variable
`ALLOW_PRIVATE_TARGETS=true`. Ne jamais l'activer sur un serveur exposé.

## Structure

```
server/   API Fastify + TypeScript, Prisma, moteurs d'audit (src/engine.ts)
web/      Frontend React + TypeScript + Vite
```
