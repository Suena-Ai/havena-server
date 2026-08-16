const { chromium } = require("playwright");
const robotsParser = require("robots-parser");
async function verifierAutorisationRobot(url) {
  try {
    const origine = new URL(url).origin;
    const robotsUrl = `${origine}/robots.txt`;

    console.log(`🤖 HAVENA vérifie : ${robotsUrl}`);

    const response = await fetch(robotsUrl);

    // Aucun fichier robots.txt
    if (response.status === 404) {
      console.log(`✅ Aucun robots.txt : ${url}`);
      return true;
    }

    // HAVENA ne prend aucun risque si le fichier est inaccessible
    if (!response.ok) {
      console.log(
        `⚠️ robots.txt inaccessible (${response.status}) : ${url}`
      );
      return false;
    }

    const robotsTxt = await response.text();

    const robots = robotsParser(
      robotsUrl,
      robotsTxt
    );

    const autorise = robots.isAllowed(
      url,
      "HAVENA-Bot"
    );

    if (autorise === false) {
      console.log(
        `⛔ HAVENA : accès interdit par robots.txt → ${url}`
      );
      return false;
    }

    console.log(
      `✅ HAVENA : accès autorisé → ${url}`
    );

    return true;
  } catch (error) {
    console.log(
      `⚠️ HAVENA : impossible de vérifier robots.txt → ${url}`,
      error.message
    );

    return false;
  }
}
/* ======================================================
   HAVENA MASTER GUIDE
   MOTEUR NAVIGATEUR - RECHERCHE DE VOLS
====================================================== */

function normaliserPrix(valeur) {
  if (valeur === null || valeur === undefined) {
    return null;
  }

  const texte = String(valeur)
    .replace(/\s/g, "")
    .replace(/[^\d,.]/g, "")
    .replace(",", ".");

  const prix = Number.parseFloat(texte);

  return Number.isFinite(prix) ? prix : null;
}

function normaliserOffreVol(offre, partenaire) {
  const prix = normaliserPrix(
    offre?.prix ?? offre?.price
  );

  if (prix === null) {
    return null;
  }

  return {
    partenaire: partenaire.nom,

    compagnie:
      offre?.compagnie ||
      offre?.airline ||
      "",

    prix,

    devise:
      offre?.devise ||
      offre?.currency ||
      "EUR",

    depart:
      offre?.depart ||
      offre?.departure ||
      "",

    arrivee:
      offre?.arrivee ||
      offre?.arrival ||
      "",

    heureDepart:
      offre?.heureDepart ||
      "",

    heureArrivee:
      offre?.heureArrivee ||
      "",

    duree:
      offre?.duree ||
      "",

    escales:
      offre?.escales ?? null,

    bagages:
      offre?.bagages ||
      "",

    lien:
      offre?.lien ||
      offre?.url ||
      partenaire.url ||
      "",

    source:
      "navigation_partenaire",

    verifieA:
      new Date().toISOString(),
  };
}

/* ======================================================
   ROBOT D'UN PARTENAIRE
====================================================== */

async function rechercherChezPartenaire(
  partenaire,
  recherche
) {
  /*
    Sécurité HAVENA :
    on n'exécute l'automatisation que pour
    les partenaires explicitement marqués
    comme autorisés.
  */

  if (!partenaire?.actif) {
    return {
      partenaire: partenaire?.nom || "Inconnu",
      statut: "ignore",
      raison: "Partenaire désactivé",
      offres: [],
    };
  }

  if (partenaire?.automatisationAutorisee !== true) {
    return {
      partenaire: partenaire.nom,
      statut: "lien_uniquement",
      raison:
        "Automatisation non autorisée ou non validée",
      offres: [],
      lien: partenaire.url || "",
    };
  }

  let browser;

  try {


    /* ----------------------------------------------
       Construction de l'adresse de recherche
    ---------------------------------------------- */

    const searchUrl =
      await partenaire.construireUrl(
        recherche
      );

    console.log(
      `HAVENA vols → ${partenaire.nom}`,
      searchUrl
    );
    const robotAutorise =
  await verifierAutorisationRobot(
    searchUrl
  );

if (!robotAutorise) {
  return {
    partenaire: partenaire.nom,
    statut: "robots_bloque",
    raison:
      "Navigation refusée par robots.txt ou vérification impossible",
    offres: [],
    lien: searchUrl,
  };
}
   browser = await chromium.launch({
  headless: true,

  args: [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-http2",
  ],
});

    const context =
      await browser.newContext({
        locale: "fr-FR",

        viewport: {
          width: 1440,
          height: 1000,
        },
      });

    const page =
      await context.newPage();

    page.setDefaultTimeout(30000);
    await page.goto(searchUrl, {
      waitUntil: "domcontentloaded",
      timeout: 45000,
    });

    /* ----------------------------------------------
       Gestion éventuelle du formulaire
    ---------------------------------------------- */

    if (
      typeof partenaire.preparerRecherche ===
      "function"
    ) {
      await partenaire.preparerRecherche(
        page,
        recherche
      );
    }

    /* ----------------------------------------------
       Attente des résultats
    ---------------------------------------------- */

    if (
      partenaire.selecteurResultats
    ) {
      await page.waitForSelector(
        partenaire.selecteurResultats,
        {
          timeout: 30000,
        }
      );
    }

    /* ----------------------------------------------
       Extraction des tarifs
    ---------------------------------------------- */

    const offresBrutes =
      await partenaire.extraireOffres(
        page,
        recherche
      );

    const offres =
      (Array.isArray(offresBrutes)
        ? offresBrutes
        : [])
        .map((offre) =>
          normaliserOffreVol(
            offre,
            partenaire
          )
        )
        .filter(Boolean);

    return {
      partenaire:
        partenaire.nom,

      statut: "ok",

      nombreOffres:
        offres.length,

      offres,
    };
  } catch (error) {
    console.error(
      `HAVENA - erreur ${partenaire?.nom}:`,
      error.message
    );

    return {
      partenaire:
        partenaire?.nom ||
        "Inconnu",

      statut: "indisponible",

      raison:
        error.message,

      offres: [],

      lien:
        partenaire?.url ||
        "",
    };
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

/* ======================================================
   ORCHESTRATEUR VOLS HAVENA
====================================================== */

async function rechercherVolsHAVENA(
  partenaires,
  recherche
) {
  if (
    !Array.isArray(partenaires)
  ) {
    throw new Error(
      "La liste des partenaires vols est invalide."
    );
  }

  const executions =
    partenaires.map(
      (partenaire) =>
        rechercherChezPartenaire(
          partenaire,
          recherche
        )
    );

  /*
    Tous les robots partent en parallèle.
    Un partenaire en panne ne bloque pas
    les autres.
  */

  const resultats =
    await Promise.allSettled(
      executions
    );

  const offres = [];
  const sources = [];

  for (const resultat of resultats) {
    if (
      resultat.status ===
      "fulfilled"
    ) {
      const source =
        resultat.value;

      sources.push(source);

      if (
        Array.isArray(
          source.offres
        )
      ) {
        offres.push(
          ...source.offres
        );
      }
    }
  }

  /*
    Classement HAVENA :
    le moins cher en premier.
  */

  offres.sort(
    (a, b) =>
      a.prix - b.prix
  );

  return {
    ok: true,

    recherche,

    nombreOffres:
      offres.length,

    offres,

    sources,

    meilleurPrix:
      offres.length > 0
        ? offres[0]
        : null,

    rechercheEffectueeA:
      new Date().toISOString(),
  };
}

module.exports = {
  rechercherVolsHAVENA,
  rechercherChezPartenaire,
  normaliserOffreVol,
};
