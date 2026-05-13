import { readFile } from "fs/promises";
import { join } from "path";

export async function detectStack(projectPath) {
  const result = {
    symfony: { detected: false, version: null },
    nextjs: { detected: false, version: null },
    php: false,
    typescript: false,
  };

  // Symfony via composer.json
  try {
    const raw = await readFile(join(projectPath, "composer.json"), "utf-8");
    const composer = JSON.parse(raw);
    const sfVersion = composer?.require?.["symfony/framework-bundle"] ?? null;
    if (sfVersion) {
      result.symfony.detected = true;
      result.symfony.version = sfVersion;
    }
    if (composer?.require?.["php"] || sfVersion) {
      result.php = true;
    }
  } catch {
    // composer.json absent ou invalide — pas de Symfony
  }

  // Next.js + TypeScript via package.json
  try {
    const raw = await readFile(join(projectPath, "package.json"), "utf-8");
    const pkg = JSON.parse(raw);
    const allDeps = { ...pkg?.dependencies, ...pkg?.devDependencies };

    const nextVersion = allDeps?.["next"] ?? null;
    if (nextVersion) {
      result.nextjs.detected = true;
      result.nextjs.version = nextVersion;
    }

    if (allDeps?.["typescript"]) {
      result.typescript = true;
    }
  } catch {
    // package.json absent ou invalide — pas de Next.js
  }

  return result;
}

export const VULN_PATTERNS = {
  php: [
    {
      name: "SQL Injection (concatenation directe)",
      regex:
        /\$(?:db|pdo|conn|mysqli|query|sql)\s*[.=]+\s*['"].*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i,
      severity: "CRITICAL",
      fix: "Utiliser les prepared statements PDO — jamais de variables $_GET/$_POST dans la requete",
    },
    {
      name: "eval() avec variable",
      regex: /eval\s*\(\s*\$(?![^)]*'[^)]*')[^)]+\)/,
      severity: "CRITICAL",
      fix: "Supprimer eval() — jamais de code dynamique execute",
    },
    {
      name: "system() / passthru() / shell_exec()",
      regex: /(?:system|passthru|shell_exec|exec|popen)\s*\(\s*\$/,
      severity: "CRITICAL",
      fix: "Ne jamais passer de variables utilisateur a des fonctions systeme",
    },
    {
      name: "Command injection via backtick",
      regex: /`[^`]*\$(?:_GET|_POST|_REQUEST)[^`]*`/,
      severity: "CRITICAL",
      fix: "Supprimer les backticks avec variables — utiliser proc_open() avec escapeshellarg()",
    },
    {
      name: "Doctrine raw query avec variable",
      regex: /->createQuery\s*\(\s*['"`].*\$[a-zA-Z_]+/,
      severity: "CRITICAL",
      fix: "Utiliser ->setParameter() au lieu de concaténer la variable dans le DQL",
    },
    {
      name: "unserialize() sur input user",
      regex:
        /unserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|request|input)/,
      severity: "CRITICAL",
      fix: "Ne jamais unserialize() de la donnée user — utiliser json_decode()",
    },
    {
      name: "Hash faible (md5/sha1) pour password",
      regex: /(?:md5|sha1)\s*\(\s*\$(?:password|pwd|pass|secret)/i,
      severity: "HIGH",
      fix: "Utiliser password_hash() avec PASSWORD_BCRYPT ou PASSWORD_ARGON2ID",
    },
    {
      name: "APP_SECRET hardcodé",
      regex: /APP_SECRET\s*=\s*['"](?:changeme|secret|password|123|test)/i,
      severity: "CRITICAL",
      fix: 'Générer un APP_SECRET aléatoire via `php -r "echo bin2hex(random_bytes(16));"`',
    },
  ],
  ts: [
    {
      name: "dangerouslySetInnerHTML avec variable",
      regex:
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:\s*(?!['"`])[^}]+\}\s*\}/,
      severity: "HIGH",
      fix: "Sanitiser avec DOMPurify avant dangerouslySetInnerHTML ou eviter entierement",
    },
    {
      name: "innerHTML avec variable",
      regex: /\.innerHTML\s*=\s*(?!['"`])[^;]+;/,
      severity: "HIGH",
      fix: "Utiliser textContent pour du texte, ou DOMPurify pour du HTML",
    },
    {
      name: "eval() avec variable",
      regex: /\beval\s*\(\s*(?!['"`])[^)]+\)/,
      severity: "CRITICAL",
      fix: "Supprimer eval() — jamais de code dynamique execute",
    },
    {
      name: "Command injection (child_process avec variable)",
      regex:
        /(?:exec|execSync|spawn|spawnSync)\s*\([^,)]*(?:\$\{|[+])[^,)]*[,)]/,
      severity: "CRITICAL",
      fix: "Utiliser spawn() avec tableau d'arguments — jamais de template string dans exec",
    },
    {
      name: "JWT avec alg:none",
      regex: /jwt\.(?:sign|verify)\s*\([^)]*algorithm:\s*['"]none['"]/i,
      severity: "CRITICAL",
      fix: "Utiliser HS256 ou RS256 — jamais alg:none",
    },
    {
      name: "fetch serveur vers URL user (SSRF)",
      regex:
        /fetch\s*\(\s*(?:req\.body|req\.query|searchParams\.get|formData\.get)/,
      severity: "HIGH",
      fix: "Whitelister les domaines avant le fetch ou bloquer les IP privées",
    },
    {
      name: "Console.log avec password/token",
      regex:
        /console\.(?:log|info|debug)\s*\([^)]*(?:password|token|secret|apiKey)/i,
      severity: "MEDIUM",
      fix: "Retirer le log — risque de fuite dans les logs prod",
    },
  ],
};
