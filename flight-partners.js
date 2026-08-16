const KLM = {
  nom: "KLM",
  url: "https://www.klm.fr/",
  actif: true,
  automatisationAutorisee: true,

  async construireUrl() {
    return "https://www.klm.fr/";
  },

  async preparerRecherche(page, recherche) {
    console.log(
      "KLM - recherche demandée :",
      recherche
    );

    /*
      La prochaine étape sera de remplir
      automatiquement le formulaire KLM :
      départ, destination, dates et voyageurs.
    */
  },

  selecteurResultats: "body",

  async extraireOffres(page, recherche) {
    const textePage =
      await page.locator("body").innerText();

    const prixTrouves = [
      ...textePage.matchAll(
        /(\d[\d\s]*)\s*EUR/g
      ),
    ];

    const prix = prixTrouves
      .map((match) => {
        const valeur = Number(
          match[1].replace(/\s/g, "")
        );

        return Number.isFinite(valeur)
          ? valeur
          : null;
      })
      .filter((valeur) => valeur !== null)
      .filter((valeur) => valeur >= 50);

    const prixUniques =
      [...new Set(prix)].sort(
        (a, b) => a - b
      );

    console.log(
      "KLM - prix détectés :",
      prixUniques
    );

    return prixUniques.map(
      (prix) => ({
        compagnie: "KLM / partenaires",
        prix,
        devise: "EUR",

        depart:
          recherche.depart || "",

        arrivee:
          recherche.destination || "",

        lien:
          page.url(),
      })
    );
  },
};

const SOURCES_VOLS_HAVENA = [
  KLM,
];

module.exports = {
  SOURCES_VOLS_HAVENA,
};