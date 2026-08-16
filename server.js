const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto");
const supabase = require("./supabase");
const Stripe = require("stripe");
const transporter = require("./mailer");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const {
  rechercherVolsHAVENA,
} = require("./flight-scraper");
const { SOURCES_VOLS_HAVENA } = require("./flight-partners");
dotenv.config();
const { getSovrnApprovedMerchants } = require("./sovrn");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const FRONTEND_URL = "https://www.havena1.fr";
const BACKEND_URL = "https://havena-server.onrender.com";
// ======================================================
// SOVRN - TEST DES MARCHANDS APPROUVES VOYAGE
// ======================================================

app.get("/api/sovrn/merchants-test", async (req, res) => {
  try {
    const data = await getSovrnApprovedMerchants({
      category: "TV",
      page: 1,
      pageSize: 50,
    });

    return res.status(200).json({
      ok: true,
      category: "TV",
      data,
    });
  } catch (error) {
    console.error("Erreur API Sovrn :", error);

    return res.status(500).json({
      ok: false,
      message: error.message,
    });
  }
});
const RESET_PASSWORD_SECRET =
  process.env.RESET_PASSWORD_SECRET ||
  process.env.STRIPE_WEBHOOK_SECRET ||
  "havena-reset-secret";

function normalizeEmail(email = "") {
  return String(email || "").trim().toLowerCase();
}

function unixToIso(value) {
  if (!value) return null;
  return new Date(Number(value) * 1000).toISOString();
}
function parseHavenaDate(value) {
  if (!value) return null;

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  date.setHours(12, 0, 0, 0);
  return date;
}

function calculateNights(dateDebut, dateFin) {
  const start = parseHavenaDate(dateDebut);
  const end = parseHavenaDate(dateFin);

  if (!start || !end) {
    return 0;
  }

  const diffMs = end.getTime() - start.getTime();
  const nights = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  return nights > 0 ? nights : 0;
}

function toMoneyNumber(value) {
  if (value === null || value === undefined) return 0;

  const cleaned = String(value)
    .replace(",", ".")
    .replace(/[^\d.]/g, "");

  const number = Number(cleaned);

  return Number.isFinite(number) ? number : 0;
}

function calculateReservationAmounts({
  prixParNuit,
  acomptePourcentage,
  dateDebut,
  dateFin,
}) {
  const nuits = calculateNights(dateDebut, dateFin);
  const prixNuit = toMoneyNumber(prixParNuit);
  const pourcentage = toMoneyNumber(acomptePourcentage || 20);

  const total = Math.round(nuits * prixNuit * 100) / 100;
  const acompte = Math.round((total * pourcentage) / 100 * 100) / 100;
  const solde = Math.round((total - acompte) * 100) / 100;

  return {
    nuits,
    prix_par_nuit: prixNuit,
    acompte_pourcentage: pourcentage,
    montant_total: total,
    acompte,
    solde_restant: solde,
  };
}

function containsForbiddenContactInfo(text = "") {
  const value = String(text || "").toLowerCase().trim();

  const phoneRegex =
    /(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?)?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}/i;

  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/i;

  const linkRegex =
    /(https?:\/\/|www\.|\.com\b|\.fr\b|\.net\b|\.org\b|t\.me\b|wa\.me\b)/i;

  const forbiddenWords = [
    "telephone",
    "téléphone",
    "tel",
    "numéro",
    "numero",
    "appelle-moi",
    "appelez-moi",
    "contacte-moi",
    "contactez-moi",
    "sms",
    "mail",
    "email",
    "e-mail",
    "gmail",
    "outlook",
    "hotmail",
    "yahoo",
    "whatsapp",
    "telegram",
    "snap",
    "snapchat",
    "instagram",
    "insta",
    "facebook",
    "messenger",
    "discord",
    "signal",
    "tiktok",
    "linkedin",
    "hors plateforme",
    "hors plate-forme",
    "en dehors",
    "à l’extérieur",
    "a l'exterieur",
    "extérieur",
    "exterieur",
  ];

  const hasForbiddenWord = forbiddenWords.some((word) => {
    const escapedWord = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    if (word === "tel") {
      return new RegExp(
        `(^|\\s|[.,;:!?()\\-])${escapedWord}(\\s|$|[.,;:!?()\\-])`,
        "i"
      ).test(value);
    }

    return value.includes(word);
  });

  return (
    phoneRegex.test(text) ||
    emailRegex.test(text) ||
    linkRegex.test(text) ||
    hasForbiddenWord
  );
}

function buildEmailConfirmToken(email) {
  const normalizedEmail = normalizeEmail(email);
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24;
  const payload = `confirm-email|${normalizedEmail}|${expiresAt}`;
  const signature = crypto
    .createHmac("sha256", RESET_PASSWORD_SECRET)
    .update(payload)
    .digest("hex");

  return Buffer.from(`${payload}|${signature}`).toString("base64url");
}

function verifyEmailConfirmToken(token, email) {
  try {
    if (!token) {
      return { ok: false, message: "Token manquant" };
    }

    const decoded = Buffer.from(String(token), "base64url").toString("utf8");
    const [type, tokenEmail, expiresAtRaw, signature] = decoded.split("|");

    if (type !== "confirm-email" || !tokenEmail || !expiresAtRaw || !signature) {
      return { ok: false, message: "Token invalide" };
    }

    const normalizedEmail = normalizeEmail(email);

    if (tokenEmail !== normalizedEmail) {
      return { ok: false, message: "Email invalide pour ce lien" };
    }

    const payload = `${type}|${tokenEmail}|${expiresAtRaw}`;
    const expectedSignature = crypto
      .createHmac("sha256", RESET_PASSWORD_SECRET)
      .update(payload)
      .digest("hex");

    if (signature !== expectedSignature) {
      return { ok: false, message: "Signature invalide" };
    }

    const expiresAt = Number(expiresAtRaw);

    if (!expiresAt || Date.now() > expiresAt) {
      return { ok: false, message: "Lien expiré" };
    }

    return { ok: true };
  } catch (error) {
    return { ok: false, message: "Token invalide" };
  }
}

function buildResetPasswordToken(email) {
  const normalizedEmail = normalizeEmail(email);
  const expiresAt = Date.now() + 1000 * 60 * 30;
  const payload = `${normalizedEmail}|${expiresAt}`;
  const signature = crypto
    .createHmac("sha256", RESET_PASSWORD_SECRET)
    .update(payload)
    .digest("hex");

  return Buffer.from(`${payload}|${signature}`).toString("base64url");
}

function verifyResetPasswordToken(token, email) {
  try {
    if (!token) {
      return { ok: false, message: "Token manquant" };
    }

    const decoded = Buffer.from(String(token), "base64url").toString("utf8");
    const [tokenEmail, expiresAtRaw, signature] = decoded.split("|");

    if (!tokenEmail || !expiresAtRaw || !signature) {
      return { ok: false, message: "Token invalide" };
    }

    const normalizedEmail = normalizeEmail(email);

    if (tokenEmail !== normalizedEmail) {
      return { ok: false, message: "Email invalide pour ce lien" };
    }

    const payload = `${tokenEmail}|${expiresAtRaw}`;
    const expectedSignature = crypto
      .createHmac("sha256", RESET_PASSWORD_SECRET)
      .update(payload)
      .digest("hex");

    if (signature !== expectedSignature) {
      return { ok: false, message: "Signature invalide" };
    }

    const expiresAt = Number(expiresAtRaw);

    if (!expiresAt || Date.now() > expiresAt) {
      return { ok: false, message: "Lien expiré" };
    }

    return { ok: true };
  } catch (error) {
    return { ok: false, message: "Token invalide" };
  }
}

async function getUserByEmail(email) {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) return null;

  const { data } = await supabase
    .from("havena_users")
    .select("id, email, role, first_name, last_name, email_confirmed")
    .eq("email", normalizedEmail)
    .maybeSingle();

  return data || null;
}

async function upsertProfessionalSubscriptionFromStripe(subscription, fallbackEmail = "", fallbackRole = "") {
  if (!subscription || !subscription.id) return;

  let email = normalizeEmail(subscription?.metadata?.email || fallbackEmail);
  let role = String(subscription?.metadata?.role || fallbackRole || "").trim().toLowerCase();

  const customerId =
    typeof subscription.customer === "string"
      ? subscription.customer
      : subscription.customer?.id || "";

  if (!email && customerId) {
    try {
      const customer = await stripe.customers.retrieve(customerId);
      email = normalizeEmail(customer?.email || "");
    } catch (error) {
      console.error("Erreur récupération customer Stripe :", error.message);
    }
  }

  const firstItem = subscription.items?.data?.[0] || null;
  const stripePriceId = firstItem?.price?.id || "";

  const payload = {
    email,
    role,
    stripe_customer_id: customerId || null,
    stripe_subscription_id: subscription.id,
    stripe_price_id: stripePriceId || null,
    status: subscription.status || "inactive",
    current_period_start:
      unixToIso(subscription.current_period_start) ||
      unixToIso(firstItem?.current_period_start),
    current_period_end:
      unixToIso(subscription.current_period_end) ||
      unixToIso(firstItem?.current_period_end),
    cancel_at_period_end: !!subscription.cancel_at_period_end,
    updated_at: new Date().toISOString(),
  };

  const { error } = await supabase
    .from("professional_subscriptions")
    .upsert(payload, { onConflict: "stripe_subscription_id" });

  if (error) {
    console.error("Erreur upsert abonnement professionnel :", error);
  }
}

async function isProfessionalSubscriptionActive(email) {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) return false;

  const nowIso = new Date().toISOString();

  const { data, error } = await supabase
    .from("professional_subscriptions")
    .select("*")
    .eq("email", normalizedEmail)
    .in("status", ["active", "trialing"])
    .gte("current_period_end", nowIso)
    .order("current_period_end", { ascending: false })
    .limit(1);

  if (error) {
    console.error("Erreur vérification abonnement actif :", error);
    return false;
  }

  return !!(data && data.length > 0);
}

async function deactivateAdsForEmail(email) {
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail) return;

  await supabase
    .from("partner_ads")
    .update({
      is_active: false,
      updated_at: new Date().toISOString(),
    })
    .eq("owner_email", normalizedEmail);
}

app.use(cors());

app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const signature = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Erreur signature webhook Stripe :", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        const checkoutType = session?.metadata?.type || "";
        const reservationId = session?.metadata?.reservationId || "";
        const logementId = session?.metadata?.logementId || "";

        if (checkoutType === "havena_professional_subscription") {
          const subscriptionId = session.subscription;
          const email = normalizeEmail(session?.metadata?.email || session.customer_email || "");
          const role = String(session?.metadata?.role || "").trim().toLowerCase();

          if (subscriptionId) {
            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            await upsertProfessionalSubscriptionFromStripe(subscription, email, role);
          }

          return res.json({ received: true });
        }

     if (reservationId) {
  const { data: reservationBefore } = await supabase
    .from("reservations")
    .select("*")
    .eq("id", reservationId)
    .maybeSingle();

  if (
    reservationBefore?.payment_status === "paid" &&
    reservationBefore?.confirmation_envoyee_client &&
    reservationBefore?.confirmation_envoyee_hebergeur
  ) {
    return res.json({ received: true });
  }

  await supabase
    .from("reservations")
    .update({
      payment_status: "paid",
      statut: "confirmée",
    })
    .eq("id", reservationId);

  const { data: reservation } = await supabase
    .from("reservations")
    .select("*")
    .eq("id", reservationId)
    .single();

  let logement = null;

  if (logementId) {
    const { data: logementData } = await supabase
      .from("logements")
      .select("*")
      .eq("id", logementId)
      .single();

    logement = logementData || null;
  }

  const datesText = String(reservation?.dates || "");
  const dateParts = datesText
    .split(/au|à|-|→/i)
    .map((part) => part.trim())
    .filter(Boolean);

  const dateDebut = dateParts[0] || "";
  const dateFin = dateParts[1] || "";

  const calcul =
    logement && dateDebut && dateFin
      ? calculateReservationAmounts({
          prixParNuit: logement.prix_par_nuit,
          acomptePourcentage: logement.acompte_pourcentage || 20,
          dateDebut,
          dateFin,
        })
      : null;

  const montantTotal =
    calcul?.montant_total || toMoneyNumber(reservation?.montant);

  const acomptePaye =
    calcul?.acompte || toMoneyNumber(reservation?.acompte);

  const soldeRestant = Math.max(
    0,
    Math.round((montantTotal - acomptePaye) * 100) / 100
  );

  const nombreNuits = calcul?.nuits || "";

  if (logementId && dateDebut && dateFin) {
    const { data: existingBlocage } = await supabase
      .from("logement_disponibilites")
      .select("id")
      .eq("logement_id", logementId)
      .eq("date_debut", dateDebut)
      .eq("date_fin", dateFin)
      .limit(1);

    if (!existingBlocage || existingBlocage.length === 0) {
      await supabase.from("logement_disponibilites").insert([
        {
          logement_id: logementId,
          hebergeur_email: logement?.hebergeur_email || "",
          date_debut: dateDebut,
          date_fin: dateFin,
          statut: "reserve",
          type_periode: "reservation",
          note: `Réservation confirmée HAVENA #${reservationId} - acompte payé`,
        },
      ]);
    }
  }

  const recuClient =
    `Bonjour ${reservation?.prenom || ""},\n\n` +
    `Votre acompte a bien été payé et votre réservation HAVENA est confirmée.\n\n` +
    `Récapitulatif de réservation :\n` +
    `Logement : ${logement?.titre || "Logement réservé"}\n` +
    `Ville : ${reservation?.ville || logement?.ville || ""}\n` +
    `Type : ${reservation?.type || logement?.type || ""}\n` +
    `Dates : ${reservation?.dates || ""}\n` +
    `${nombreNuits ? `Nombre de nuits : ${nombreNuits}\n` : ""}` +
    `Prix total du séjour : ${montantTotal} €\n` +
    `Acompte payé : ${acomptePaye} €\n` +
    `Solde restant : ${soldeRestant} €\n\n` +
    `Ce message vaut reçu de paiement de l’acompte.\n\n` +
    `Merci,\nHAVENA`;

  const recuHebergeur =
    `Bonjour ${logement?.hebergeur_nom || "Hébergeur"},\n\n` +
    `Une réservation a été confirmée pour votre logement sur HAVENA.\n\n` +
    `Récapitulatif de réservation :\n` +
    `Logement : ${logement?.titre || ""}\n` +
    `Ville : ${reservation?.ville || logement?.ville || ""}\n` +
    `Type : ${reservation?.type || logement?.type || ""}\n` +
    `Dates : ${reservation?.dates || ""}\n` +
    `${nombreNuits ? `Nombre de nuits : ${nombreNuits}\n` : ""}` +
    `Prix total du séjour : ${montantTotal} €\n` +
    `Acompte payé : ${acomptePaye} €\n` +
    `Solde restant : ${soldeRestant} €\n\n` +
    `Client : ${reservation?.prenom || ""} ${reservation?.nom || ""}\n` +
    `Email client : ${reservation?.email || ""}\n` +
    `Téléphone client : ${reservation?.telephone || ""}\n\n` +
    `La période a été bloquée automatiquement dans HAVENA.\n\n` +
    `HAVENA`;

  if (reservation?.email) {
    try {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: reservation.email,
        subject: "Acompte payé - Réservation HAVENA confirmée",
        text: recuClient,
      });

      await supabase
        .from("reservations")
        .update({ confirmation_envoyee_client: true })
        .eq("id", reservationId);
    } catch (mailError) {
      console.error("Erreur mail reçu client :", mailError);
    }
  }

  if (logement?.hebergeur_email) {
    try {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: logement.hebergeur_email,
        subject: "Nouvelle réservation confirmée - Acompte payé",
        text: recuHebergeur,
      });

      await supabase
        .from("reservations")
        .update({ confirmation_envoyee_hebergeur: true })
        .eq("id", reservationId);
    } catch (mailError) {
      console.error("Erreur mail reçu hébergeur :", mailError);
    }
  }
}

      }

      if (
        event.type === "customer.subscription.created" ||
        event.type === "customer.subscription.updated"
      ) {
        const subscription = event.data.object;
        await upsertProfessionalSubscriptionFromStripe(subscription);
      }

      if (event.type === "customer.subscription.deleted") {
        const subscription = event.data.object;
        await upsertProfessionalSubscriptionFromStripe(subscription);

        const email = normalizeEmail(subscription?.metadata?.email || "");

        if (email) {
          await deactivateAdsForEmail(email);
        }
      }

      if (event.type === "invoice.payment_failed") {
        const invoice = event.data.object;
        const subscriptionId =
          typeof invoice.subscription === "string"
            ? invoice.subscription
            : invoice.subscription?.id;

        if (subscriptionId) {
          const subscription = await stripe.subscriptions.retrieve(subscriptionId);
          await upsertProfessionalSubscriptionFromStripe(subscription);

          const email = normalizeEmail(subscription?.metadata?.email || "");
          if (email && subscription.status !== "active" && subscription.status !== "trialing") {
            await deactivateAdsForEmail(email);
          }
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("Erreur traitement webhook Stripe :", err);
      return res.status(500).json({
        ok: false,
        message: "Erreur webhook Stripe",
      });
    }
  }
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "HAVENA server opérationnel",
  });
});

/* =========================
   AUTH HAVENA
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      accept_promotions,
      accept_promotions_at,
    } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({
        ok: false,
        message: "Prénom, nom, adresse email et mot de passe obligatoires.",
      });
    }

    const normalizedEmail = normalizeEmail(email);

    const { data: existingUser, error: existingError } = await supabase
      .from("havena_users")
      .select("id, email")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (existingError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateur",
        error: existingError.message,
      });
    }

    if (existingUser) {
      return res.status(409).json({
        ok: false,
        message:
          "Cette adresse email possède déjà un compte HAVENA. Veuillez vous connecter.",
      });
    }

    const hashedPassword = await bcrypt.hash(
      String(password),
      12
    );

    const newUser = {
      first_name: String(firstName).trim(),
      last_name: String(lastName).trim(),
      email: normalizedEmail,
      password: hashedPassword,

      // Valeur technique unique pour tous les comptes HAVENA.
      // Il n'existe plus plusieurs types de comptes.
      role: "user",

      phone: "",
      contact_email: normalizedEmail,
      contact_profile_completed: false,
      contact_updated_at: new Date().toISOString(),

      email_confirmed: false,
      created_at: new Date().toISOString(),

      accept_promotions: Boolean(accept_promotions),
      accept_promotions_at: accept_promotions
        ? accept_promotions_at || new Date().toISOString()
        : null,

      unsubscribed_promotions_at: null,
    };

    const { data, error } = await supabase
      .from("havena_users")
      .insert([newUser])
      .select(`
        id,
        first_name,
        last_name,
        email,
        email_confirmed,
        created_at
      `)
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur création utilisateur",
        error: error.message,
      });
    }

    const confirmToken =
      buildEmailConfirmToken(normalizedEmail);

    const confirmLink =
      `${FRONTEND_URL}/confirm-email?token=${encodeURIComponent(
        confirmToken
      )}&email=${encodeURIComponent(normalizedEmail)}`;

    try {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: normalizedEmail,
        subject: "Confirmez votre adresse email - HAVENA",
        text:
          `Bonjour ${String(firstName).trim()},\n\n` +
          `Votre compte HAVENA a bien été créé.\n\n` +
          `Pour activer votre compte, cliquez sur ce lien :\n` +
          `${confirmLink}\n\n` +
          `Ce lien est valable 24 heures.\n\n` +
          `Si vous n’êtes pas à l’origine de cette inscription, ignorez cet email.\n\n` +
          `HAVENA`,
      });
    } catch (mailError) {
      console.error(
        "Erreur envoi email confirmation :",
        mailError
      );
    }

    return res.status(201).json({
      ok: true,
      message: "Compte créé",
      user: data,
    });
  } catch (err) {
    console.error("Erreur serveur register :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.post("/api/auth/promotions-consent", async (req, res) => {
  try {
    const { email, accept_promotions } = req.body;

    const normalizedEmail = String(email || "").trim().toLowerCase();

    if (!normalizedEmail) {
      return res.status(400).json({
        ok: false,
        message: "Email obligatoire",
      });
    }

    const acceptPromotions = accept_promotions === true;

    const updates = acceptPromotions
      ? {
          accept_promotions: true,
          accept_promotions_at: new Date().toISOString(),
          unsubscribed_promotions_at: null,
        }
      : {
          accept_promotions: false,
          accept_promotions_at: null,
          unsubscribed_promotions_at: new Date().toISOString(),
        };

    const { data, error } = await supabase
      .from("havena_users")
      .update(updates)
      .eq("email", normalizedEmail)
      .select(
        "id, email, role, accept_promotions, accept_promotions_at, unsubscribed_promotions_at"
      )
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur mise à jour consentement promotions",
        error: error.message,
      });
    }

    if (!data) {
      return res.status(404).json({
        ok: false,
        message: "Utilisateur introuvable",
      });
    }

    return res.json({
      ok: true,
      user: data,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur consentement promotions",
      error: error.message,
    });
  }
});

app.post("/api/partner-promotions/send-daily-emails", async (req, res) => {
  try {
    const secret =
      req.headers["x-havena-sync-secret"] ||
      req.headers["x-sync-secret"] ||
      req.query.secret;

    if (process.env.HAVENA_SYNC_SECRET && secret !== process.env.HAVENA_SYNC_SECRET) {
      return res.status(401).json({
        ok: false,
        message: "Accès refusé",
      });
    }

    const promotionsUrl = `${FRONTEND_URL}/#promotions-partenaires`;

    const { data: promotions, error: promotionsError } = await supabase
      .from("partner_promotions")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(8);

    if (promotionsError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture promotions",
        error: promotionsError.message,
      });
    }

    const activePromotions = (promotions || []).filter((promo) => {
      return promo.is_active !== false && promo.active !== false;
    });

    if (activePromotions.length === 0) {
      return res.json({
        ok: true,
        message: "Aucune promotion active, aucun email envoyé.",
        sent: 0,
      });
    }

    const { data: users, error: usersError } = await supabase
      .from("havena_users")
      .select("id, email, first_name, role, accept_promotions, unsubscribed_promotions_at")
      .eq("accept_promotions", true)
      .is("unsubscribed_promotions_at", null);

    if (usersError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateurs",
        error: usersError.message,
      });
    }

    const acceptedUsers = (users || []).filter((user) => Boolean(user.email));

    if (acceptedUsers.length === 0) {
      return res.json({
        ok: true,
        message: "Aucun utilisateur inscrit aux promotions.",
        sent: 0,
      });
    }

    const promotionLines = activePromotions
      .map((promo) => {
        const partnerName =
          promo.partner_name ||
          promo.name ||
          promo.title ||
          "Partenaire HAVENA";

        const promoTitle =
          promo.title ||
          promo.name ||
          promo.description ||
          "Offre spéciale officielle";

        return `• ${partnerName} — ${promoTitle}`;
      })
      .join("\n");

    let sent = 0;
    let failed = 0;

    for (const user of acceptedUsers) {
      try {
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: user.email,
          subject: "Nouvelles promotions HAVENA disponibles",
          text:
            `Bonjour${user.first_name ? " " + user.first_name : ""},\n\n` +
            `De nouvelles promotions HAVENA sont disponibles aujourd’hui.\n\n` +
            `${promotionLines}\n\n` +
            `Pour découvrir les offres, cliquez ici :\n` +
            `${promotionsUrl}\n\n` +
            `HAVENA ne transmet pas vos coordonnées personnelles à ses partenaires.\n` +
            `Les offres partenaires vous sont présentées par HAVENA.\n\n` +
            `Si une offre vous intéresse, vous pourrez cliquer depuis HAVENA sur le bouton partenaire affilié.\n\n` +
            `HAVENA`,
        });

        sent += 1;
      } catch (mailError) {
        failed += 1;
        console.error("Erreur envoi email promotion HAVENA :", mailError);
      }
    }

    return res.json({
      ok: true,
      message: "Emails promotions HAVENA envoyés.",
      promotions: activePromotions.length,
      users: acceptedUsers.length,
      sent,
      failed,
    });
  } catch (error) {
    console.error("Erreur route emails promotions HAVENA :", error);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur emails promotions HAVENA",
      error: error.message,
    });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        message: "Adresse email et mot de passe obligatoires.",
      });
    }

    const normalizedEmail = normalizeEmail(email);

    const { data: user, error } = await supabase
      .from("havena_users")
      .select(`
        id,
        email,
        password,
        first_name,
        last_name,
        email_confirmed,
        accept_promotions,
        accept_promotions_at,
        unsubscribed_promotions_at
      `)
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateur",
        error: error.message,
      });
    }

    if (!user) {
      return res.status(404).json({
        ok: false,
        message: "Aucun compte trouvé avec cette adresse email.",
      });
    }

    if (!user.email_confirmed) {
      return res.status(403).json({
        ok: false,
        message:
          "Veuillez confirmer votre adresse email avant de vous connecter.",
      });
    }

    const storedPassword = String(user.password || "");
    const incomingPassword = String(password || "");

    let passwordIsValid = false;

    if (
      storedPassword.startsWith("$2a$") ||
      storedPassword.startsWith("$2b$")
    ) {
      passwordIsValid = await bcrypt.compare(
        incomingPassword,
        storedPassword
      );
    } else {
      passwordIsValid = storedPassword === incomingPassword;

      if (passwordIsValid) {
        const hashedPassword = await bcrypt.hash(
          incomingPassword,
          12
        );

        await supabase
          .from("havena_users")
          .update({
            password: hashedPassword,
          })
          .eq("email", normalizedEmail);
      }
    }

    if (!passwordIsValid) {
      return res.status(401).json({
        ok: false,
        message: "Mot de passe incorrect.",
      });
    }

    return res.json({
      ok: true,
      message: "Connexion autorisée",
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        email_confirmed: user.email_confirmed,
        accept_promotions: user.accept_promotions,
        accept_promotions_at: user.accept_promotions_at,
        unsubscribed_promotions_at:
          user.unsubscribed_promotions_at,
      },
    });
  } catch (err) {
    console.error("Erreur serveur login :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.get("/api/auth/confirm-email", async (req, res) => {
  try {
    const { token, email } = req.query;
    const normalizedEmail = normalizeEmail(email);

    if (!token || !normalizedEmail) {
      return res.status(400).json({
        ok: false,
        message: "Lien de confirmation invalide.",
      });
    }

    const verification = verifyEmailConfirmToken(token, normalizedEmail);

    if (!verification.ok) {
      return res.status(400).json({
        ok: false,
        message: verification.message || "Lien de confirmation invalide ou expiré.",
      });
    }

    const { data, error } = await supabase
      .from("havena_users")
      .update({
        email_confirmed: true,
      })
      .eq("email", normalizedEmail)
      .select("id, email, role, email_confirmed")
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur confirmation email.",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Adresse email confirmée avec succès.",
      user: data,
    });
  } catch (err) {
    console.error("Erreur serveur confirmation email :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur confirmation email.",
    });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail) {
      return res.status(400).json({
        ok: false,
        message: "Adresse email manquante",
      });
    }

    const { data: user, error } = await supabase
      .from("havena_users")
      .select("id, email")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateur",
        error: error.message,
      });
    }

    if (user) {
      const token = buildResetPasswordToken(normalizedEmail);
      const resetLink = `${FRONTEND_URL}/reset-password?token=${encodeURIComponent(
        token
      )}&email=${encodeURIComponent(normalizedEmail)}`;

      try {
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: normalizedEmail,
          subject: "Réinitialisation du mot de passe - HAVENA",
          text:
            `Bonjour,\n\n` +
            `Vous avez demandé la réinitialisation de votre mot de passe HAVENA.\n\n` +
            `Cliquez sur ce lien pour choisir un nouveau mot de passe :\n` +
            `${resetLink}\n\n` +
            `Ce lien expire dans 30 minutes.\n\n` +
            `Si vous n’êtes pas à l’origine de cette demande, ignorez simplement cet email.\n\n` +
            `HAVENA`,
        });
      } catch (mailError) {
        console.error("Erreur envoi mail reset password :", mailError);
      }
    }

    return res.json({
      ok: true,
      message:
        "Si cette adresse email existe, un lien de réinitialisation sera envoyé.",
    });
  } catch (err) {
    console.error("Erreur serveur forgot-password :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    const normalizedEmail = normalizeEmail(email);
    const normalizedPassword = String(newPassword || "").trim();

    if (!normalizedEmail || !token || !normalizedPassword) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const verification = verifyResetPasswordToken(token, normalizedEmail);

    if (!verification.ok) {
      return res.status(400).json({
        ok: false,
        message: verification.message || "Lien invalide ou expiré",
      });
    }

    const { data: user, error: readError } = await supabase
      .from("havena_users")
      .select("id, email")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (readError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateur",
        error: readError.message,
      });
    }

    if (!user) {
      return res.status(404).json({
        ok: false,
        message: "Compte introuvable",
      });
    }

    const hashedPassword = await bcrypt.hash(normalizedPassword, 12);

    const { error: updateError } = await supabase
      .from("havena_users")
      .update({
        password: hashedPassword,
      })
      .eq("email", normalizedEmail);

    if (updateError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur mise à jour mot de passe",
        error: updateError.message,
      });
    }

    return res.json({
      ok: true,
      message: "Mot de passe réinitialisé avec succès",
    });
  } catch (err) {
    console.error("Erreur serveur reset-password :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

/* =========================
   STRIPE ABONNEMENT HAVENA PRO 39,90 €
========================= */

app.post("/api/stripe/havena-pro/create-checkout-session", async (req, res) => {
  try {
    const { email, role } = req.body;

    const normalizedEmail = normalizeEmail(email);
    const normalizedRole = String(role || "").trim().toLowerCase();

    if (!normalizedEmail || !normalizedRole) {
      return res.status(400).json({
        ok: false,
        message: "Email et rôle obligatoires.",
      });
    }

    if (!["employeur", "hebergeur", "partenaire"].includes(normalizedRole)) {
      return res.status(403).json({
        ok: false,
        message: "Abonnement réservé aux professionnels HAVENA.",
      });
    }

    if (!process.env.STRIPE_HAVENA_PRO_PRICE_ID) {
      return res.status(500).json({
        ok: false,
        message: "STRIPE_HAVENA_PRO_PRICE_ID manquant côté serveur.",
      });
    }

    const user = await getUserByEmail(normalizedEmail);

    if (!user && normalizedRole !== "partenaire") {
      return res.status(404).json({
        ok: false,
        message: "Compte professionnel introuvable.",
      });
    }

    if (user && user.role !== normalizedRole) {
      return res.status(403).json({
        ok: false,
        message: `Cette adresse email est liée au profil "${user.role}".`,
      });
    }

    if (user && !user.email_confirmed) {
      return res.status(403).json({
        ok: false,
        message: "Adresse email non confirmée.",
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: normalizedEmail,
      line_items: [
        {
          price: process.env.STRIPE_HAVENA_PRO_PRICE_ID,
          quantity: 1,
        },
      ],
      metadata: {
        type: "havena_professional_subscription",
        email: normalizedEmail,
        role: normalizedRole,
      },
      subscription_data: {
        metadata: {
          type: "havena_professional_subscription",
          email: normalizedEmail,
          role: normalizedRole,
        },
      },
      success_url: `${FRONTEND_URL}/${normalizedRole}?subscription=success`,
      cancel_url: `${FRONTEND_URL}/${normalizedRole}?subscription=cancel`,
    });

    return res.json({
      ok: true,
      url: session.url,
    });
  } catch (err) {
    console.error("Erreur création abonnement HAVENA Pro :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur création abonnement HAVENA Pro.",
      error: err.message,
    });
  }
});

app.get("/api/pro-subscription/status", async (req, res) => {
  try {
    const email = normalizeEmail(req.query.email);

    if (!email) {
      return res.status(400).json({
        ok: false,
        active: false,
        message: "Email manquant.",
      });
    }

    const nowIso = new Date().toISOString();

    const { data, error } = await supabase
      .from("professional_subscriptions")
      .select("*")
      .eq("email", email)
      .in("status", ["active", "trialing", "past_due", "canceled", "unpaid"])
      .order("updated_at", { ascending: false })
      .limit(1);

    if (error) {
      return res.status(500).json({
        ok: false,
        active: false,
        message: "Erreur vérification abonnement.",
        error: error.message,
      });
    }

    const subscription = data?.[0] || null;
    const active =
      !!subscription &&
      ["active", "trialing"].includes(subscription.status) &&
      (!subscription.current_period_end ||
        subscription.current_period_end >= nowIso);

    return res.json({
      ok: true,
      active,
      subscription,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      active: false,
      message: "Erreur serveur abonnement.",
      error: err.message,
    });
  }
});

/* =========================
   STRIPE CONNECT HEBERGEUR
   0 % COMMISSION HAVENA
========================= */

app.post("/api/stripe/connect/start", async (req, res) => {
  try {
    const { hebergeurEmail } = req.body;

    if (!hebergeurEmail || !String(hebergeurEmail).trim()) {
      return res.status(400).json({
        ok: false,
        message: "Email hébergeur manquant",
      });
    }

    const normalizedEmail = normalizeEmail(hebergeurEmail);

    const { data: existingUser, error: userError } = await supabase
      .from("havena_users")
      .select("id, email, role, stripe_account_id")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (userError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture utilisateur hébergeur",
        error: userError.message,
      });
    }

    if (!existingUser) {
      return res.status(404).json({
        ok: false,
        message: "Compte hébergeur introuvable",
      });
    }

    if (existingUser.role !== "hebergeur") {
      return res.status(403).json({
        ok: false,
        message: "Ce compte n’est pas un profil hébergeur",
      });
    }

    let stripeAccountId = existingUser.stripe_account_id || "";

    if (!stripeAccountId) {
      const account = await stripe.accounts.create({
        type: "express",
        email: normalizedEmail,
      });

      stripeAccountId = account.id;

      await supabase
        .from("havena_users")
        .update({
          stripe_account_id: stripeAccountId,
        })
        .eq("email", normalizedEmail);
    }

    await supabase
      .from("logements")
      .update({
        stripe_account_id: stripeAccountId,
      })
      .eq("hebergeur_email", normalizedEmail);

    const accountLink = await stripe.accountLinks.create({
      account: stripeAccountId,
      refresh_url: `${FRONTEND_URL}/hebergeur/stripe-connect?refresh=1`,
      return_url: `${BACKEND_URL}/api/stripe/connect/complete?account=${encodeURIComponent(
        stripeAccountId
      )}&email=${encodeURIComponent(normalizedEmail)}`,
      type: "account_onboarding",
    });

    return res.json({
      ok: true,
      url: accountLink.url,
      stripeAccountId,
    });
  } catch (err) {
    console.error("Erreur Stripe Connect start :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur démarrage Stripe Connect",
    });
  }
});

app.get("/api/stripe/connect/complete", async (req, res) => {
  try {
    const { account, email } = req.query;

    if (!account || !email) {
      return res.status(400).send("Paramètres Stripe Connect manquants");
    }

    const stripeAccountId = String(account).trim();
    const normalizedEmail = normalizeEmail(email);

    const stripeAccount = await stripe.accounts.retrieve(stripeAccountId);

    await supabase
      .from("havena_users")
      .update({
        stripe_account_id: stripeAccountId,
      })
      .eq("email", normalizedEmail);

    await supabase
      .from("logements")
      .update({
        stripe_account_id: stripeAccountId,
      })
      .eq("hebergeur_email", normalizedEmail);

    return res.redirect(
      `${FRONTEND_URL}/hebergeur/stripe-connect/success?account=${encodeURIComponent(
        stripeAccountId
      )}&charges_enabled=${stripeAccount.charges_enabled ? "1" : "0"}&details_submitted=${
        stripeAccount.details_submitted ? "1" : "0"
      }`
    );
  } catch (err) {
    console.error("Erreur Stripe Connect complete :", err);
    return res.redirect(`${FRONTEND_URL}/hebergeur/stripe-connect?error=1`);
  }
});

app.get("/api/stripe/connect/status", async (req, res) => {
  try {
    const { hebergeurEmail } = req.query;

    if (!hebergeurEmail || !String(hebergeurEmail).trim()) {
      return res.status(400).json({
        ok: false,
        message: "Email hébergeur manquant",
      });
    }

    const normalizedEmail = normalizeEmail(hebergeurEmail);

    const { data: user, error } = await supabase
      .from("havena_users")
      .select("id, email, stripe_account_id")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture statut Stripe",
        error: error.message,
      });
    }

    if (!user || !user.stripe_account_id) {
      return res.json({
        ok: true,
        connected: false,
        stripe_account_id: null,
      });
    }

    const stripeAccount = await stripe.accounts.retrieve(user.stripe_account_id);

    return res.json({
      ok: true,
      connected: true,
      stripe_account_id: user.stripe_account_id,
      charges_enabled: !!stripeAccount.charges_enabled,
      details_submitted: !!stripeAccount.details_submitted,
      payouts_enabled: !!stripeAccount.payouts_enabled,
    });
  } catch (err) {
    console.error("Erreur Stripe Connect status :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur statut Stripe Connect",
    });
  }
});

app.post("/api/stripe/create-checkout-session", async (req, res) => {
  try {
    const { reservationId, logementId } = req.body;

    if (!reservationId || !logementId) {
      return res.status(400).json({
        ok: false,
        message: "Données Stripe manquantes : réservation et logement.",
      });
    }

    const { data: reservation, error: reservationError } = await supabase
      .from("reservations")
      .select("*")
      .eq("id", reservationId)
      .maybeSingle();

    if (reservationError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture réservation.",
        error: reservationError.message,
      });
    }

    if (!reservation) {
      return res.status(404).json({
        ok: false,
        message: "Réservation introuvable.",
      });
    }

    const { data: logement, error: logementError } = await supabase
      .from("logements")
      .select("*")
      .eq("id", Number(logementId))
      .maybeSingle();

    if (logementError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture logement.",
        error: logementError.message,
      });
    }

    if (!logement) {
      return res.status(404).json({
        ok: false,
        message: "Logement introuvable.",
      });
    }

    if (!logement.stripe_account_id) {
      return res.status(400).json({
        ok: false,
        message: "Ce logement n’a pas de compte Stripe connecté.",
      });
    }

    // Stripe encaisse uniquement l'acompte calculé côté backend
    const acompteNumber = toMoneyNumber(reservation.acompte);

    if (!acompteNumber || acompteNumber <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Acompte invalide ou manquant pour cette réservation.",
      });
    }

    const unitAmount = Math.round(acompteNumber * 100);

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: reservation.email,
      metadata: {
        reservationId: String(reservationId),
        logementId: String(logementId),
        type: "havena_reservation_acompte",
      },
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: `Acompte réservation HAVENA - ${
                logement.titre || "Logement"
              }`,
              description:
                `Dates : ${reservation.dates || ""} | ` +
                `Prix total : ${reservation.montant || ""} | ` +
                `Acompte payé maintenant : ${reservation.acompte || ""}`,
            },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      payment_intent_data: {
        transfer_data: {
          destination: logement.stripe_account_id,
        },
      },
      success_url: `${FRONTEND_URL}/reservation/success`,
      cancel_url: `${FRONTEND_URL}/reservation/cancel`,
    });

    return res.json({
  ok: true,
  url: session.url,
  reservationId,
  logementId,
  acompte_a_payer: reservation.acompte,
  montant_total: reservation.montant,
  message: "Veuillez procéder au paiement de votre acompte.",
});
  } catch (err) {
    console.error("Erreur création checkout Stripe acompte :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur Stripe acompte",
      error: err.message,
    });
  }
});

/* ===============================
   MESSAGERIE HAVENA SANS PAIEMENT 3 €
=============================== */

app.get("/api/message-unlocks/check", async (req, res) => {
  try {
    const { employerEmail, candidateId } = req.query;

    if (!employerEmail || !candidateId) {
      return res.status(400).json({
        ok: false,
        unlocked: false,
        message: "Données manquantes",
      });
    }

    const normalizedEmployerEmail = normalizeEmail(employerEmail);
    const normalizedCandidateId = Number(candidateId);

    if (!normalizedEmployerEmail || !normalizedCandidateId) {
      return res.status(400).json({
        ok: false,
        unlocked: false,
        message: "Email employeur ou candidat invalide",
      });
    }

    const { data: employer, error: employerError } = await supabase
      .from("havena_users")
      .select("id, email, role, email_confirmed")
      .eq("email", normalizedEmployerEmail)
      .maybeSingle();

    if (employerError) {
      return res.status(500).json({
        ok: false,
        unlocked: false,
        message: "Erreur vérification employeur",
        error: employerError.message,
      });
    }

    if (!employer || employer.role !== "employeur") {
      return res.status(403).json({
        ok: false,
        unlocked: false,
        message: "Accès réservé aux employeurs HAVENA.",
      });
    }

    if (!employer.email_confirmed) {
      return res.status(403).json({
        ok: false,
        unlocked: false,
        message: "Adresse email employeur non confirmée.",
      });
    }

    return res.json({
      ok: true,
      unlocked: true,
      message: "Messagerie HAVENA autorisée.",
    });
  } catch (err) {
    console.error("Erreur vérification messagerie :", err);

    return res.status(500).json({
      ok: false,
      unlocked: false,
      message: "Erreur serveur vérification messagerie",
      error: err.message,
    });
  }
});

/* ===============================
   RÉSERVATIONS
=============================== */

app.post("/api/reservations", async (req, res) => {
  try {
    const {
      logementId,
      logement_id,
      prenom,
      nom,
      email,
      telephone,
      ville,
      type,
      date_debut,
      date_fin,
      dates,
      voyageurs,
      role,
      message,
    } = req.body;

    const finalLogementId = logementId || logement_id;

    if (!prenom || !nom || !email || !finalLogementId) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants : prénom, nom, email et logement.",
      });
    }

    const { data: logement, error: logementError } = await supabase
      .from("logements")
      .select("*")
      .eq("id", Number(finalLogementId))
      .maybeSingle();

    if (logementError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture logement",
        error: logementError.message,
      });
    }

    if (!logement) {
      return res.status(404).json({
        ok: false,
        message: "Logement introuvable.",
      });
    }

    let finalDateDebut = date_debut || "";
    let finalDateFin = date_fin || "";

    if ((!finalDateDebut || !finalDateFin) && dates) {
      const parts = String(dates)
        .split(/au|à|-|→/i)
        .map((part) => part.trim())
        .filter(Boolean);

      finalDateDebut = finalDateDebut || parts[0] || "";
      finalDateFin = finalDateFin || parts[1] || "";
    }

    if (!finalDateDebut || !finalDateFin) {
      return res.status(400).json({
        ok: false,
        message: "Dates de réservation manquantes.",
      });
    }

    const calcul = calculateReservationAmounts({
      prixParNuit: logement.prix_par_nuit,
      acomptePourcentage: logement.acompte_pourcentage || 20,
      dateDebut: finalDateDebut,
      dateFin: finalDateFin,
    });

    if (!calcul.nuits || calcul.nuits <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Dates invalides : la date de fin doit être après la date de début.",
      });
    }

    if (!calcul.prix_par_nuit || calcul.prix_par_nuit <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Prix par nuit invalide ou manquant pour ce logement.",
      });
    }

    const datesTexte = `${finalDateDebut} au ${finalDateFin}`;

    const reservation = {
      prenom,
      nom,
      email: normalizeEmail(email),
      telephone: telephone || "",
      ville: ville || logement.ville || "",
      type: type || logement.type || "",
      dates: datesTexte,
      voyageurs: voyageurs || "",
      montant: `${calcul.montant_total} €`,
      acompte: `${calcul.acompte} €`,
      role: role || "",
      message:
        `${message || ""}\n\n` +
        `--- Calcul automatique HAVENA ---\n` +
        `Logement ID : ${finalLogementId}\n` +
        `Logement : ${logement.titre || ""}\n` +
        `Prix par nuit : ${calcul.prix_par_nuit} €\n` +
        `Nombre de nuits : ${calcul.nuits}\n` +
        `Prix total : ${calcul.montant_total} €\n` +
        `Acompte (${calcul.acompte_pourcentage}%) : ${calcul.acompte} €\n` +
        `Solde restant : ${calcul.solde_restant} €`,
      payment_status: "pending",
      confirmation_envoyee_client: false,
      confirmation_envoyee_hebergeur: false,
      statut: "en attente de paiement acompte",
      created_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from("reservations")
      .insert([reservation])
      .select();

    if (error) {
      console.error("Erreur Supabase réservation :", error);
      return res.status(500).json({
        ok: false,
        message: "Erreur lors de l’enregistrement Supabase",
        error: error.message,
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Réservation enregistrée avec calcul automatique",
      reservation: data[0],
      calcul,
      logement: {
        id: logement.id,
        titre: logement.titre,
        ville: logement.ville,
        type: logement.type,
        hebergeur_email: logement.hebergeur_email,
      },
    });
  } catch (err) {
    console.error("Erreur serveur réservation :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur réservation",
      error: err.message,
    });
  }
});

app.get("/api/reservations", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("reservations")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Erreur lecture Supabase réservations :", error);

      return res.status(500).json({
        ok: false,
        message: "Erreur lors de la lecture des réservations",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      total: data.length,
      reservations: data,
    });
  } catch (err) {
    console.error("Erreur serveur lecture réservations :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.get("/api/reservations/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("reservations")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      return res.status(404).json({
        ok: false,
        message: "Réservation introuvable",
      });
    }

    return res.json({
      ok: true,
      reservation: data,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.post("/api/reservations/:id/send-confirmations", async (req, res) => {
  try {
    const { id } = req.params;

    const { data: reservation, error } = await supabase
      .from("reservations")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !reservation) {
      return res.status(404).json({
        ok: false,
        message: "Réservation introuvable",
      });
    }

    if (!reservation.email) {
      return res.status(400).json({
        ok: false,
        message: "Email client manquant",
      });
    }

    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: reservation.email,
      subject: "Confirmation de votre réservation HAVENA",
      text:
        `Bonjour ${reservation.prenom || ""},\n\n` +
        `Votre réservation HAVENA a bien été reçue.\n` +
        `Ville : ${reservation.ville || ""}\n` +
        `Type : ${reservation.type || ""}\n` +
        `Dates : ${reservation.dates || ""}\n` +
        `Acompte : ${reservation.acompte || ""}\n\n` +
        `Merci,\nHAVENA`,
    });

    await supabase
      .from("reservations")
      .update({ confirmation_envoyee_client: true })
      .eq("id", id);

    return res.json({
      ok: true,
      message: "Confirmation client envoyée",
    });
  } catch (err) {
    console.error("Erreur envoi confirmation :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur envoi email",
    });
  }
});

/* ===============================
   LOGEMENTS
=============================== */

app.post("/api/logements", upload.array("images", 10), async (req, res) => {
  try {
   const {
  titre,
  type,
  ville,
  adresse,
  surface,
  chambres,
  couchages,
  prix_par_nuit,
  acompte_pourcentage,
  reduction,
  animaux_acceptes,
  fumeur_accepte,
  equipements,
  description,
  statut,
  jardin,
  parking,
  wifi,
  hebergeur_email,
  hebergeur_nom,
  disponibilites,
  telephone,
  nombre_animaux_max,
  types_animaux,
  restrictions_animaux,
  latitude,
  longitude,
} = req.body;

    if (!titre || !type || !ville) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

  
    

    const normalizedHebergeurEmail = normalizeEmail(hebergeur_email);
const hebergeurSubscriptionActive = await isProfessionalSubscriptionActive(normalizedHebergeurEmail) ;

if ( !hebergeurSubscriptionActive) {
  return res.status(403).json({
OK : false,
    message: "Veuillez vous abonner à HAVENA Professionnel avant de publier un logement ou créer une banderole.",
  });
}


   let image_url = "";
let image_urls = [];

if (req.files && req.files.length > 0) {
  const mimeToExt = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/avif": "avif",
    "image/svg+xml": "svg",
  };

  for (const image of req.files) {
    const safeExt =
      mimeToExt[image.mimetype] ||
      String(image.originalname || "").split(".").pop()?.toLowerCase() ||
      "jpg";

    const fileName = `logement_${Date.now()}_${Math.random()
      .toString(36)
      .substring(2, 8)}.${safeExt}`;

    const { data: uploadData, error: uploadError } =
      await supabase.storage
        .from("logements")
        .upload(fileName, image.buffer, {
          contentType: image.mimetype,
          upsert: false,
        });

    if (uploadError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur upload image",
        error: uploadError.message,
      });
    }

    const uploadedPath = uploadData?.path || fileName;

    const { data: publicUrlData } = supabase.storage
      .from("logements")
      .getPublicUrl(uploadedPath);

    if (publicUrlData?.publicUrl) {
      image_urls.push(publicUrlData.publicUrl);
    }
  }

  image_url = image_urls[0] || "";
}

    let stripeAccountId = "";

    if (normalizedHebergeurEmail) {
      const { data: hebergeurUser } = await supabase
        .from("havena_users")
        .select("stripe_account_id")
        .eq("email", normalizedHebergeurEmail)
        .maybeSingle();

      stripeAccountId = hebergeurUser?.stripe_account_id || "";
    }

    const logement = {
      titre,
      type,
      ville,
      adresse: adresse || "",
      surface: surface || "",
      chambres: chambres || "",
      couchages: couchages || "",
      animaux_acceptes: animaux_acceptes || "",
      fumeur_accepte: fumeur_accepte || "",
      equipements: equipements || "",
      description: description || "",
      image_url,
      statut: statut || "Disponible",
      jardin: jardin || "",
      parking: parking || "",
      wifi: wifi || "",
      hebergeur_email: normalizedHebergeurEmail,
      hebergeur_nom: hebergeur_nom || "",
      disponibilites: disponibilites || "",
      telephone: telephone || "",
      stripe_account_id: stripeAccountId,
      prix_par_nuit: prix_par_nuit || null,
acompte_pourcentage: acompte_pourcentage || 20,
images: image_urls,
latitude: latitude || null,
longitude: longitude || null,
    };

    const { data, error } = await supabase
      .from("logements")
      .insert([logement])
      .select();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur enregistrement logement",
        error: error.message,
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Logement enregistré",
      logement: data[0],
    });
  } catch (err) {
    console.error("Erreur serveur création logement :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.get("/api/logements/:id/disponibilites", async (req, res) => {
  try {
    const logementId = req.params.id;

    const { data, error } = await supabase
      .from("logement_disponibilites")
      .select("*")
      .eq("logement_id", logementId)
      .order("date_debut", { ascending: true });

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur chargement disponibilités",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      disponibilites: data || [],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur disponibilités",
      error: err.message,
    });
  }
});

app.post("/api/logements/:id/disponibilites", async (req, res) => {
  try {
    const logementId = req.params.id;

    const {
      hebergeur_email,
      date_debut,
      date_fin,
      statut = "disponible",
      type_periode = "manuel",
      note = "",
    } = req.body || {};

    if (!logementId || !hebergeur_email || !date_debut || !date_fin) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const { data, error } = await supabase
      .from("logement_disponibilites")
      .insert([
        {
          logement_id: logementId,
          hebergeur_email,
          date_debut,
          date_fin,
          statut,
          type_periode,
          note,
        },
      ])
      .select()
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur ajout disponibilité",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      disponibilite: data,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur ajout disponibilité",
      error: err.message,
    });
  }
});
// ===============================
// HAVENA - OFFRES EMPLOI ADZUNA
// ===============================

const ADZUNA_COUNTRIES = {
  // PAYS OK ADZUNA
  france: "fr",
  allemagne: "de",
  italie: "it",
  paysbas: "nl",
  "pays-bas": "nl",
  australie: "au",
  suisse: "ch",
  etatsunis: "us",
  "etats-unis": "us",
  "états-unis": "us",
  "nouvelle-zelande": "nz",
  "nouvelle-zélande": "nz",
  bresil: "br",
  "brésil": "br",
  pologne: "pl",
  afriquedusud: "za",
  "afrique-du-sud": "za",
  canada: "ca",
  inde: "in",
  singapour: "sg",

  // PAYS NON DISPONIBLES VIA ADZUNA POUR L’INSTANT
  espagne: null,
  belgique: null,
  portugal: null,
  royaumeuni: null,
  "royaume-uni": null,
  luxembourg: null,
  danemark: null,
  norvege: null,
  "norvège": null,
  grece: null,
  "grèce": null,
  irlande: null,
  finlande: null,
  bulgarie: null,
  suede: null,
  "suède": null,
  ukraine: null,
  roumanie: null,
  turquie: null,
  autriche: null,

  // AUTRES PAYS À COMPLÉTER PLUS TARD AVEC AUTRES API
  maroc: null,
  tunisie: null,
  algerie: null,
  "algérie": null,
  senegal: null,
  "sénégal": null,
  "cote-divoire": null,
  "côte-divoire": null,
  "côte-d’ivoire": null,
  japon: null,
  chine: null,
  vietnam: null,
  philippines: null,
  "arabie-saoudite": null,
  "polynesie-francaise": null,
  "polynésie-française": null,
  "wallis-et-futuna": null,
  "nouvelle-caledonie": null,
  "nouvelle-calédonie": null,
  argentine: null,
  chili: null,
  colombie: null,
  "coree-du-sud": null,
  "corée-du-sud": null,
  indonesie: null,
  "indonésie": null,
  thailande: null,
  "thaïlande": null,
  "emirats-arabes-unis": null,
  "émirats-arabes-unis": null,
};


function normalizeHavenaCountry(value = "") {
  return String(value)
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[’']/g, "")
    .replace(/\s+/g, "-");
}

function detectContractType(title = "", description = "") {
  const text = `${title} ${description}`.toLowerCase();

  if (
    text.includes("saisonnier") ||
    text.includes("travail saisonnier") ||
    text.includes("seasonal") ||
    text.includes("temporada") ||
    text.includes("stagionale") ||
    text.includes("saisonarbeit")
  ) {
    return "Saisonnier";
  }

  if (text.includes("cdi") || text.includes("permanent")) {
    return "CDI";
  }

  if (
    text.includes("cdd") ||
    text.includes("fixed term") ||
    text.includes("temporary") ||
    text.includes("temporaire")
  ) {
    return "CDD";
  }

  if (
    text.includes("stage") ||
    text.includes("internship") ||
    text.includes("prácticas") ||
    text.includes("praktikum")
  ) {
    return "Stage";
  }

  if (
    text.includes("alternance") ||
    text.includes("apprenticeship") ||
    text.includes("apprentissage")
  ) {
    return "Alternance";
  }

  if (
    text.includes("part time") ||
    text.includes("temps partiel") ||
    text.includes("teilzeit")
  ) {
    return "Temps partiel";
  }

  return "Non précisé";
}

app.get("/api/jobs/adzuna", async (req, res) => {
  try {
    const appId = process.env.ADZUNA_APP_ID;
    const appKey = process.env.ADZUNA_APP_KEY;

    if (!appId || !appKey) {
      return res.status(500).json({
        ok: false,
        message: "Clés Adzuna manquantes dans les variables Render.",
      });
    }

    const rawCountry = req.query.country || "france";
    const normalizedCountry = normalizeHavenaCountry(rawCountry);
    const adzunaCountryCode = ADZUNA_COUNTRIES[normalizedCountry];

    if (!adzunaCountryCode) {
      return res.json({
        ok: true,
        source: "adzuna",
        country: rawCountry,
        supported: false,
        offers: [],
        message:
          "Ce pays n’est pas encore disponible via Adzuna. Il faudra ajouter une autre API emploi pour ce pays.",
      });
    }

    const page = Number(req.query.page || 1);
    const what = req.query.what || "";
    const resultsPerPage = Number(req.query.limit || 20);

   const params = new URLSearchParams();

params.append("app_id", String(appId).trim());
params.append("app_key", String(appKey).trim());
params.append("results_per_page", String(resultsPerPage));

if (what) {
  params.append("what", String(what).trim());
}

const url = `http://api.adzuna.com/v1/api/jobs/${adzunaCountryCode}/search/${page}?${params.toString()}`;

console.log("ADZUNA COUNTRY:", adzunaCountryCode);
console.log("ADZUNA URL:", url.replace(String(appKey).trim(), "HIDDEN_KEY"));

    const response = await fetch(url);

    if (!response.ok) {
      const errorText = await response.text();

      return res.status(response.status).json({
        ok: false,
        message: "Erreur API Adzuna.",
        details: errorText,
      });
    }

    const data = await response.json();

    const offers = (data.results || []).map((job) => ({
      id: job.id,
      title: job.title || "Offre sans titre",
      company: job.company?.display_name || "Entreprise non précisée",
      location: job.location?.display_name || "Lieu non précisé",
      country: rawCountry,
      contract_type: detectContractType(job.title, job.description),
      salary_min: job.salary_min || null,
      salary_max: job.salary_max || null,
      description: job.description || "",
      created: job.created || null,
      redirect_url: job.redirect_url,
      source: "Adzuna",
    }));

    return res.json({
      ok: true,
      source: "adzuna",
      country: rawCountry,
      supported: true,
      count: data.count || offers.length,
      offers,
    });
  } catch (error) {
    console.error("Erreur /api/jobs/adzuna :", error);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur pendant la récupération des offres.",
    });
  }
});
const JOOBLE_COUNTRY_NAMES = {
  espagne: "Spain",
  belgique: "Belgium",
  "royaume-uni": "United Kingdom",
  royaumeuni: "United Kingdom",
  norvege: "Norway",
  "norvège": "Norway",
  suede: "Sweden",
  "suède": "Sweden",
  ukraine: "Ukraine",
  roumanie: "Romania",
  turquie: "Turkey",
  maroc: "Morocco",
  senegal: "Senegal",
  "sénégal": "Senegal",
  "cote-divoire": "Ivory Coast",
  "côte-divoire": "Ivory Coast",
  "côte-d’ivoire": "Ivory Coast",
  mexique: "Mexico",
  chili: "Chile",
  colombie: "Colombia",
  argentine: "Argentina",
  japon: "Japan",
  chine: "China",
  vietnam: "Vietnam",
  philippines: "Philippines",
  "arabie-saoudite": "Saudi Arabia",
  "polynesie-francaise": "French Polynesia",
  "polynésie-française": "French Polynesia",
  portugal: "Portugal",
  luxembourg: "Luxembourg",
  irlande: "Ireland",
  danemark: "Denmark",
  finlande: "Finland",
  bulgarie: "Bulgaria",
  grece: "Greece",
  "grèce": "Greece",
  tunisie: "Tunisia",
  algerie: "Algeria",
  "algérie": "Algeria",
  "coree-du-sud": "South Korea",
  "corée-du-sud": "South Korea",
  indonesie: "Indonesia",
  "indonésie": "Indonesia",
  thailande: "Thailand",
  "thaïlande": "Thailand",
  "emirats-arabes-unis": "United Arab Emirates",
  "émirats-arabes-unis": "United Arab Emirates",
  "wallis-et-futuna": "Wallis and Futuna",
  "nouvelle-caledonie": "New Caledonia",
  "nouvelle-calédonie": "New Caledonia",
};

app.get("/api/jobs/jooble", async (req, res) => {
  try {
    const apiKey = process.env.JOOBLE_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        ok: false,
        error: "JOOBLE_API_KEY manquante dans les variables d'environnement.",
      });
    }

    const rawCountry = String(req.query.country || "").trim();
const normalizedCountry = normalizeHavenaCountry(rawCountry);
const country = JOOBLE_COUNTRY_NAMES[normalizedCountry] || rawCountry;
    const keywords = String(req.query.what || "seasonal summer job").trim();
    const location = String(req.query.location || "").trim();

    const joobleUrl = `https://jooble.org/api/${apiKey}`;

    const response = await fetch(joobleUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        keywords,
        location: location || country,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        ok: false,
        source: "jooble",
        error: "Erreur API Jooble",
        details: data,
      });
    }

    const JOOBLE_LOCATION_FILTERS = {
  Spain: ["spain", "espagne", "madrid", "barcelona", "barcelone", "valencia", "sevilla", "malaga"],
  Belgium: ["belgium", "belgique", "brussels", "bruxelles", "antwerp", "anvers"],
  "United Kingdom": ["united kingdom", "uk", "england", "scotland", "wales", "london", "manchester", "birmingham"],
  Norway: ["norway", "norvège", "oslo", "bergen", "trondheim"],
  Sweden: ["sweden", "suède", "stockholm", "gothenburg", "malmö"],
  Ukraine: ["ukraine", "kyiv", "kiev", "lviv", "odessa"],
  Romania: ["romania", "roumanie", "bucharest", "bucarest", "cluj"],
  Turkey: ["turkey", "turquie", "istanbul", "ankara", "antalya"],
  Morocco: ["morocco", "maroc", "casablanca", "marrakech", "rabat", "agadir", "tanger"],
  Senegal: ["senegal", "sénégal", "dakar"],
  "Ivory Coast": ["ivory coast", "côte d’ivoire", "cote d'ivoire", "abidjan"],
  Mexico: ["mexico", "mexique", "mexico city", "cancun", "guadalajara"],
  Chile: ["chile", "chili", "santiago", "valparaiso"],
  Colombia: ["colombia", "colombie", "bogota", "medellin", "cartagena"],
  Argentina: ["argentina", "argentine", "buenos aires", "cordoba"],
  Japan: ["japan", "japon", "tokyo", "osaka", "kyoto"],
  China: ["china", "chine", "beijing", "pekin", "shanghai", "guangzhou"],
  Vietnam: ["vietnam", "hanoi", "ho chi minh"],
  Philippines: ["philippines", "manila", "cebu"],
  "Saudi Arabia": ["saudi arabia", "arabie saoudite", "riyadh", "jeddah"],
  "French Polynesia": ["french polynesia", "polynésie française", "polynesie francaise", "tahiti", "papeete"],
  Portugal: ["portugal", "lisbon", "lisbonne", "porto", "algarve"],
  Luxembourg: ["luxembourg"],
  Ireland: ["ireland", "irlande", "dublin", "cork", "galway"],
  Denmark: ["denmark", "danemark", "copenhagen", "copenhague"],
  Finland: ["finland", "finlande", "helsinki"],
  Bulgaria: ["bulgaria", "bulgarie", "sofia", "varna"],
  Greece: ["greece", "grèce", "grece", "athens", "athènes", "crete", "crète"],
  Tunisia: ["tunisia", "tunisie", "tunis", "djerba"],
  Algeria: ["algeria", "algérie", "algerie", "algiers", "alger", "oran"],
  "South Korea": ["south korea", "corée du sud", "coree du sud", "seoul", "busan"],
  Indonesia: ["indonesia", "indonésie", "indonesie", "jakarta", "bali"],
  Thailand: ["thailand", "thaïlande", "thailande", "bangkok", "phuket"],
  "United Arab Emirates": ["united arab emirates", "uae", "émirats arabes unis", "emirats arabes unis", "dubai", "abu dhabi"],
  "Wallis and Futuna": ["futuna", "wallis and futuna", "wallis-et-futuna"],
  "New Caledonia": ["new caledonia", "noumea", "nouméa", "nouvelle-calédonie", "nouvelle-caledonie"],
};

const rawJobs = Array.isArray(data.jobs) ? data.jobs : [];

const allowedLocations = JOOBLE_LOCATION_FILTERS[country];

const filteredJobs = allowedLocations
  ? rawJobs.filter((job) => {
      const locationText = String(job.location || "").toLowerCase();

      return allowedLocations.some((term) =>
        locationText.includes(term.toLowerCase())
      );
    })
  : rawJobs;

const offers = filteredJobs.map((job) => ({
  id: job.id || job.link || `${job.title}-${job.company}`,
  title: job.title || "Offre saisonnière",
  company: job.company || "Entreprise",
  location: job.location || country || "Localisation non précisée",
  description: job.snippet || job.description || "",
  salary: job.salary || "",
  contract_type: "Saisonnier / job d’été",
  created: job.updated || job.date || null,
  redirect_url: job.link || "",
  source: "Jooble",
}));


    return res.json({
      ok: true,
      source: "jooble",
      country,
      what: keywords,
    count: offers.length,
      offers,
    });
  } catch (error) {
    console.error("Erreur Jooble:", error);
    return res.status(500).json({
      ok: false,
      source: "jooble",
      error: "Erreur serveur Jooble",
      details: error.message,
    });
  }
});

app.delete("/api/logements/disponibilites/:disponibiliteId", async (req, res) => {
  try {
    const disponibiliteId = req.params.disponibiliteId;

    const { error } = await supabase
      .from("logement_disponibilites")
      .delete()
      .eq("id", disponibiliteId);

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur suppression disponibilité",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Disponibilité supprimée",
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur suppression disponibilité",
      error: err.message,
    });
  }
});

app.get("/api/logements", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("logements")
      .select("*")
      .order("id", { ascending: false });

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture logements",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      logements: data || [],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.delete("/api/logements/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const requesterEmail = normalizeEmail(
      req.query.email ||
        req.query.userEmail ||
        req.headers["x-user-email"] ||
        req.body?.email ||
        req.body?.userEmail ||
        req.body?.requesterEmail ||
        ""
    );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID logement manquant.",
      });
    }

    if (!requesterEmail) {
      return res.status(401).json({
        ok: false,
        message: "Utilisateur non identifié. Suppression refusée.",
      });
    }

    const { data: logement, error: readError } = await supabase
      .from("logements")
      .select("id, hebergeur_email")
      .eq("id", id)
      .maybeSingle();

    if (readError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture logement avant suppression.",
        error: readError.message,
      });
    }

    if (!logement) {
      return res.status(404).json({
        ok: false,
        message: "Logement introuvable.",
      });
    }

    const ownerEmail = normalizeEmail(logement.hebergeur_email);
    const isAdmin = requesterEmail === "fasterame@gmail.com";
    const isOwner = ownerEmail && ownerEmail === requesterEmail;

    if (!isAdmin && !isOwner) {
      return res.status(403).json({
        ok: false,
        message: "Suppression refusée : ce logement ne vous appartient pas.",
      });
    }

    const { error } = await supabase
      .from("logements")
      .delete()
      .eq("id", id);

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur suppression logement",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Logement supprimé",
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
      error: err.message,
    });
  }
});


app.put("/api/logements/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const {
      disponibilites,
      titre,
      type,
      ville,
      adresse,
      surface,
      chambres,
      couchages,
      prix,
      prix_par_nuit,
      acompte_pourcentage,
      animaux_acceptes,
      fumeur_accepte,
      equipements,
      description,
      statut,
      jardin,
      parking,
      wifi,
      telephone,
      hebergeur_email,
      hebergeur_nom,
      latitude,
      longitude,
    } = req.body;

    const requesterEmail = normalizeEmail(
      req.query.email ||
        req.query.userEmail ||
        req.headers["x-user-email"] ||
        req.body?.email ||
        req.body?.userEmail ||
        req.body?.requesterEmail ||
        hebergeur_email ||
        ""
    );

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID logement manquant.",
      });
    }

    if (!requesterEmail) {
      return res.status(401).json({
        ok: false,
        message: "Utilisateur non identifié. Modification refusée.",
      });
    }

    const { data: existingLogement, error: readError } = await supabase
      .from("logements")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (readError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture logement avant modification.",
        error: readError.message,
      });
    }

    if (!existingLogement) {
      return res.status(404).json({
        ok: false,
        message: "Logement introuvable.",
      });
    }

    const ownerEmail = normalizeEmail(existingLogement.hebergeur_email);
    const isAdmin = requesterEmail === "fasterame@gmail.com";
    const isOwner = ownerEmail && ownerEmail === requesterEmail;

    if (!isAdmin && !isOwner) {
      return res.status(403).json({
        ok: false,
        message: "Modification refusée : ce logement ne vous appartient pas.",
      });
    }

    const subscriptionEmail = isAdmin ? ownerEmail : requesterEmail;
    const hebergeurSubscriptionActive = isAdmin
      ? true
      : await isProfessionalSubscriptionActive(subscriptionEmail);

    if (!hebergeurSubscriptionActive) {
      return res.status(403).json({
        ok: false,
        message:
          "Veuillez vous abonner à HAVENA Professionnel avant de modifier ou publier un logement.",
      });
    }

    const finalPrixParNuit =
      prix_par_nuit !== undefined && prix_par_nuit !== null
        ? prix_par_nuit
        : prix !== undefined && prix !== null
        ? prix
        : existingLogement.prix_par_nuit;

    const updatePayload = {
      titre: titre ?? existingLogement.titre,
      type: type ?? existingLogement.type,
      ville: ville ?? existingLogement.ville,
      adresse: adresse ?? existingLogement.adresse ?? "",
      surface: surface ?? existingLogement.surface ?? "",
      chambres: chambres ?? existingLogement.chambres ?? "",
      couchages: couchages ?? existingLogement.couchages ?? "",
      prix_par_nuit: finalPrixParNuit ?? null,
      acompte_pourcentage:
        acompte_pourcentage ?? existingLogement.acompte_pourcentage ?? 20,
      animaux_acceptes:
        animaux_acceptes ?? existingLogement.animaux_acceptes ?? "",
      fumeur_accepte: fumeur_accepte ?? existingLogement.fumeur_accepte ?? "",
      equipements: equipements ?? existingLogement.equipements ?? "",
      description: description ?? existingLogement.description ?? "",
      statut: statut ?? existingLogement.statut ?? "Disponible",
      jardin: jardin ?? existingLogement.jardin ?? "",
      parking: parking ?? existingLogement.parking ?? "",
      wifi: wifi ?? existingLogement.wifi ?? "",
      disponibilites: disponibilites ?? existingLogement.disponibilites ?? "",
      telephone: telephone ?? existingLogement.telephone ?? "",
      hebergeur_nom: hebergeur_nom ?? existingLogement.hebergeur_nom ?? "",
      hebergeur_email: existingLogement.hebergeur_email,
      latitude: latitude ?? existingLogement.latitude ?? null,
      longitude: longitude ?? existingLogement.longitude ?? null,
    };

    const { data, error } = await supabase
      .from("logements")
      .update(updatePayload)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur mise à jour logement",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Logement mis à jour",
      logement: data,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur modification logement",
      error: err.message,
    });
  }
});


/* ===============================
   OFFRES EMPLOI HAVENA
=============================== */

app.post("/api/offres-emploi", async (req, res) => {
  try {
    const {
      titre,
      ville,
      contrat,
      periode,
      salaire,
      profil,
      description,
      statut,
      employeur_email,
    } = req.body;

    if (!titre || !ville || !contrat) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const publicOffreFields = [
      titre,
      ville,
      contrat,
      periode,
      salaire,
      profil,
      description,
      statut,
    ];

    if (publicOffreFields.some((field) => containsForbiddenContactInfo(field))) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    const offre = {
      titre,
      ville,
      contrat,
      periode: periode || "",
      salaire: salaire || "",
      profil: profil || "",
      description: description || "",
      statut: statut || "Offre active",
      employeur_email: employeur_email ? normalizeEmail(employeur_email) : "",
    };

    const { data, error } = await supabase
      .from("offres_emploi")
      .insert([offre])
      .select();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur enregistrement offre",
        error: error.message,
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Offre enregistrée",
      offre: data[0],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.get("/api/offres-emploi", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("offres_emploi")
      .select("*")
      .order("id", { ascending: false });

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture offres",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      offres: data || [],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.put("/api/offres-emploi/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID offre invalide",
      });
    }

    const {
      titre,
      ville,
      contrat,
      periode,
      salaire,
      profil,
      description,
      statut,
    } = req.body;

    if (!titre || !ville || !contrat) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const publicOffreUpdateFields = [
      titre,
      ville,
      contrat,
      periode,
      salaire,
      profil,
      description,
      statut,
    ];

    if (
      publicOffreUpdateFields.some((field) => containsForbiddenContactInfo(field))
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    const { data, error } = await supabase
      .from("offres_emploi")
      .update({
        titre,
        ville,
        contrat,
        periode: periode || "",
        salaire: salaire || "",
        profil: profil || "",
        description: description || "",
        statut: statut || "Offre active",
      })
      .eq("id", id)
      .select();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur modification offre",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Offre modifiée",
      offre: data?.[0] || null,
    });
  } catch (err) {
    console.error("Erreur serveur modification offre :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

app.delete("/api/offres-emploi/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID offre invalide",
      });
    }

    const { error } = await supabase
      .from("offres_emploi")
      .delete()
      .eq("id", id);

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur suppression offre",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Offre supprimée",
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

/* ===============================
   CANDIDATURES EMPLOI HAVENA
=============================== */

app.post("/api/candidatures-emploi", async (req, res) => {
  try {
    const {
      offre_id,
      offre_titre,
      ville,
      contrat,
      periode,
      salaire,
      candidat_email,
      candidat_nom,
      candidat_prenom,
      cv_experience,
      message,
    } = req.body;

    let employeurEmail = "";

    if (!offre_titre || !ville || !contrat) {
      return res.status(400).json({
        ok: false,
        message: "Informations de l’offre manquantes",
      });
    }

    const publicCandidatureFields = [cv_experience, message];

    if (
      publicCandidatureFields.some((field) => containsForbiddenContactInfo(field))
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    if (offre_id) {
      const { data: offreData, error: offreError } = await supabase
        .from("offres_emploi")
        .select("*")
        .eq("id", Number(offre_id))
        .maybeSingle();

      if (offreError) {
        return res.status(500).json({
          ok: false,
          message: "Erreur lecture offre emploi",
          error: offreError.message,
        });
      }

      if (offreData?.employeur_email) {
        employeurEmail = normalizeEmail(offreData.employeur_email);
      }
    }

    if (!employeurEmail) {
      return res.status(400).json({
        ok: false,
        message:
          "Email employeur introuvable pour cette offre. Impossible d’envoyer la candidature.",
      });
    }

    const candidature = {
      offre_id: offre_id || null,
      offre_titre,
      ville,
      contrat,
      periode: periode || "",
      salaire: salaire || "",
      candidat_email: candidat_email || "",
      candidat_nom: candidat_nom || "",
      candidat_prenom: candidat_prenom || "",
      cv_experience: cv_experience || "",
      message: message || "",
      employeur_email: employeurEmail,
      statut: "nouvelle",
      created_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from("candidatures_emploi")
      .insert([candidature])
      .select()
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur enregistrement candidature",
        error: error.message,
      });
    }

    try {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: employeurEmail,
        subject: "Nouvelle candidature reçue - HAVENA",
        text:
          `Bonjour,\n\n` +
          `Vous avez reçu une nouvelle candidature sur HAVENA.\n\n` +
          `Offre : ${offre_titre}\n` +
          `Ville : ${ville}\n` +
          `Contrat : ${contrat}\n` +
          `Période : ${periode || ""}\n` +
          `Salaire : ${salaire || ""}\n\n` +
          `Candidat : ${candidat_prenom || ""} ${candidat_nom || ""}\n` +
          `Email candidat : ${candidat_email || ""}\n\n` +
          `CV / expérience :\n${cv_experience || ""}\n\n` +
          `Message :\n${message || ""}\n\n` +
          `HAVENA`,
      });
    } catch (mailError) {
      console.error("Erreur email employeur candidature :", mailError);

      return res.status(500).json({
        ok: false,
        message:
          "Candidature enregistrée, mais erreur lors de l’envoi email employeur.",
        candidature: data,
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Candidature envoyée à l’employeur",
      candidature: data,
    });
  } catch (err) {
    console.error("Erreur serveur candidature emploi :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur candidature emploi",
      error: err.message,
    });
  }
});

app.post("/api/messages/check", async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || !String(message).trim()) {
      return res.status(400).json({
        ok: false,
        message: "Message vide",
      });
    }

    if (containsForbiddenContactInfo(message)) {
      return res.status(400).json({
        ok: false,
        message:
          "Message bloqué : numéros, emails, liens externes et contacts hors HAVENA interdits.",
      });
    }

    return res.json({
      ok: true,
      message: "Message autorisé",
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
    });
  }
});

/* ===============================
   SAISONNIERS / CANDIDATS
=============================== */

app.get("/api/saisonniers", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("havena_users")
      .select(
        `
        id,
        first_name,
        last_name,
        role,
        poste_recherche,
        mois_disponible,
        periode_disponible,
        niveau_etudes,
        diplomes,
        formation,
        experiences,
        competences,
        langues,
        permis,
        mobilite,
        type_contrat_recherche,
        secteur_recherche,
        presentation,
        created_at
      `
      )
      .eq("role", "saisonnier")
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture saisonniers",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      saisonniers: data || [],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur saisonniers",
      error: err.message,
    });
  }
});

app.get("/api/candidats", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("havena_users")
      .select(
        `
        id,
        first_name,
        last_name,
        email,
        phone,
        contact_email,
        role,
        poste_recherche,
        mois_disponible,
        periode_disponible,
        niveau_etudes,
        diplomes,
        formation,
        experiences,
        competences,
        langues,
        permis,
        mobilite,
        type_contrat_recherche,
        secteur_recherche,
        presentation,
        created_at
      `
      )
      .in("role", ["saisonnier", "etudiant"])
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture candidats",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      candidats: data || [],
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur candidats",
      error: err.message,
    });
  }
});

app.put("/api/candidats/profil", async (req, res) => {
  try {
    const {
      email,
      poste_recherche,
      mois_disponible,
      periode_disponible,
      niveau_etudes,
      diplomes,
      formation,
      experiences,
      competences,
      langues,
      permis,
      mobilite,
      type_contrat_recherche,
      secteur_recherche,
      presentation,
    } = req.body;

    if (!email) {
      return res.status(400).json({
        ok: false,
        message: "Email utilisateur manquant",
      });
    }

    const normalizedEmail = normalizeEmail(email);

    const publicCandidateProfileFields = [
      poste_recherche,
      mois_disponible,
      periode_disponible,
      niveau_etudes,
      diplomes,
      formation,
      experiences,
      competences,
      langues,
      permis,
      mobilite,
      type_contrat_recherche,
      secteur_recherche,
      presentation,
    ];

    if (
      publicCandidateProfileFields.some((field) => containsForbiddenContactInfo(field))
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    const updatePayload = {
      poste_recherche: poste_recherche || null,
      mois_disponible: mois_disponible || null,
      periode_disponible: periode_disponible || null,
      niveau_etudes: niveau_etudes || null,
      diplomes: diplomes || null,
      formation: formation || null,
      experiences: experiences || null,
      competences: competences || null,
      langues: langues || null,
      permis: permis || null,
      mobilite: mobilite || null,
      type_contrat_recherche: type_contrat_recherche || null,
      secteur_recherche: secteur_recherche || null,
      presentation: presentation || null,
    };

    const { data, error } = await supabase
      .from("havena_users")
      .update(updatePayload)
      .eq("email", normalizedEmail)
      .in("role", ["saisonnier", "etudiant"])
      .select(
        `
        id,
        first_name,
        last_name,
        email,
        role,
        poste_recherche,
        mois_disponible,
        periode_disponible,
        niveau_etudes,
        diplomes,
        formation,
        experiences,
        competences,
        langues,
        permis,
        mobilite,
        type_contrat_recherche,
        secteur_recherche,
        presentation,
        created_at
      `
      )
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur mise à jour profil candidat",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Profil candidat mis à jour",
      candidat: data,
    });
  } catch (err) {
    console.error("Erreur serveur mise à jour profil candidat :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur mise à jour profil candidat",
      error: err.message,
    });
  }
});

/* ===============================
   BANDEROLES PUBLICITAIRES HAVENA
=============================== */

app.get("/api/partner-ads/active", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("partner_ads")
      .select("*")
      .eq("is_active", true)
      .limit(20);

    if (error) {
      console.error("Erreur lecture publicités actives :", error);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture publicités actives.",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      ads: data || [],
    });
  } catch (err) {
    console.error("Erreur serveur publicités actives :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur publicités actives.",
      error: err.message,
    });
  }
});
app.get("/api/host-ad-banners/active", async (req, res) => {
  try {
    const { data: banners, error } = await supabase
      .from("host_ad_banners")
      .select("*")
      .eq("status", "published")
      .limit(20);

    if (error) {
      console.error("Erreur lecture banderoles hébergeurs :", error);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture banderoles hébergeurs.",
        error: error.message,
      });
    }

    const bannerIds = (banners || []).map((banner) => banner.id);

    let photos = [];

    if (bannerIds.length > 0) {
      const { data: photosData, error: photosError } = await supabase
        .from("host_ad_banner_photos")
        .select("*")
        .in("banner_id", bannerIds);

      if (photosError) {
        console.error("Erreur lecture photos banderoles :", photosError);
      } else {
        photos = photosData || [];
      }
    }

    const photosByBanner = {};

    photos.forEach((photo) => {
      if (!photosByBanner[photo.banner_id]) {
        photosByBanner[photo.banner_id] = [];
      }

      photosByBanner[photo.banner_id].push(photo);
    });

    const result = (banners || []).map((banner) => ({
      ...banner,
      photos: photosByBanner[banner.id] || [],
    }));

    return res.json({
      ok: true,
      banners: result,
    });
  } catch (err) {
    console.error("Erreur serveur banderoles hébergeurs :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur banderoles hébergeurs.",
      error: err.message,
    });
  }
});


app.get("/api/partner-ads/me", async (req, res) => {
  try {
    const ownerEmail = normalizeEmail(req.query.email);
    const isAdminOwner = ownerEmail === "fasterame@gmail.com";

    if (!ownerEmail) {
      return res.status(400).json({
        ok: false,
        message: "Email manquant.",
      });
    }

    const subscriptionActive = isAdminOwner
      ? true
      : await isProfessionalSubscriptionActive(ownerEmail);

    const { data, error } = await supabase
      .from("partner_ads")
      .select("*")
      .eq("owner_email", ownerEmail)
      .order("updated_at", { ascending: false })
      .limit(1);

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture banderole.",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      subscription_active: subscriptionActive,
      ad: data?.[0] || null,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur banderole.",
      error: err.message,
    });
  }
});

app.post("/api/partner-ads/upsert", async (req, res) => {
  try {
    const {
      owner_email,
      owner_role,
      business_name,
      city,
      title,
      description,
      promotion,
      logo_url,
      image_urls,
      music_key,
      link_url,
      is_active,
    } = req.body;

    const ownerEmail = normalizeEmail(owner_email);
    const ownerRole = String(owner_role || "").trim().toLowerCase();
    const isAdminOwner = ownerEmail === "fasterame@gmail.com";

    if (!ownerEmail) {
      return res.status(400).json({
        ok: false,
        message: "Email propriétaire manquant.",
      });
    }

    const subscriptionActive = isAdminOwner
      ? true
      : await isProfessionalSubscriptionActive(ownerEmail);

    if (!subscriptionActive && !isAdminOwner) {
      return res.status(403).json({
        ok: false,
        message:
          "Abonnement professionnel HAVENA requis pour créer ou afficher une banderole.",
      });
    }

    const publicAdFields = [
      business_name,
      city,
      title,
      description,
      promotion,
      link_url,
    ];

    if (publicAdFields.some((field) => containsForbiddenContactInfo(field))) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites dans la publicité. Utilisez uniquement un lien ou une fiche HAVENA autorisée.",
      });
    }

    const safeImageUrls = Array.isArray(image_urls) ? image_urls : [];

    const payload = {
      owner_email: ownerEmail,
      owner_role: ownerRole || "",
      business_name: business_name || "",
      city: city || "",
      title: title || "",
      description: description || "",
      promotion: promotion || "",
      logo_url: logo_url || "",
      image_urls: safeImageUrls,
      music_key: music_key || "",
      link_url: link_url || "",
      is_active: isAdminOwner ? true : !!is_active && subscriptionActive,
      updated_at: new Date().toISOString(),
    };

    const { data: existingAds, error: readError } = await supabase
      .from("partner_ads")
      .select("id")
      .eq("owner_email", ownerEmail)
      .order("updated_at", { ascending: false })
      .limit(1);

    if (readError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture publicité existante.",
        error: readError.message,
      });
    }

    let result;

    if (existingAds && existingAds.length > 0) {
      const { data, error } = await supabase
        .from("partner_ads")
        .update(payload)
        .eq("id", existingAds[0].id)
        .select()
        .single();

      if (error) {
        return res.status(500).json({
          ok: false,
          message: "Erreur modification banderole.",
          error: error.message,
        });
      }

      result = data;
    } else {
      const { data, error } = await supabase
        .from("partner_ads")
        .insert([
          {
            ...payload,
            views_count: 0,
            clicks_count: 0,
            created_at: new Date().toISOString(),
          },
        ])
        .select()
        .single();

      if (error) {
        return res.status(500).json({
          ok: false,
          message: "Erreur création banderole.",
          error: error.message,
        });
      }

      result = data;
    }

    return res.json({
      ok: true,
      message: "Banderole enregistrée.",
      ad: result,
    });
  } catch (error) {
    console.error("Erreur serveur /api/partner-ads/upsert :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur pendant l’enregistrement de la banderole.",
      error: error.message,
    });
  }
});

app.post("/api/partner-ads/:id/view", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID publicité manquant.",
      });
    }

    const { data: ad, error: readError } = await supabase
      .from("partner_ads")
      .select("id, views_count, is_active, owner_email")
      .eq("id", id)
      .eq("is_active", true)
      .single();

    if (readError || !ad) {
      return res.status(404).json({
        ok: false,
        message: "Publicité active introuvable.",
      });
    }

    const ownerEmail = normalizeEmail(ad.owner_email);
    const isAdminOwner = ownerEmail === "fasterame@gmail.com";

    if (!isAdminOwner) {
      const subscriptionActive = await isProfessionalSubscriptionActive(ownerEmail);

      if (!subscriptionActive) {
        await deactivateAdsForEmail(ownerEmail);

        return res.status(403).json({
          ok: false,
          message: "Abonnement expiré. Publicité désactivée.",
        });
      }
    }

    const { error: updateError } = await supabase
      .from("partner_ads")
      .update({
        views_count: Number(ad.views_count || 0) + 1,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);

    if (updateError) {
      console.error("Erreur compteur vue publicité :", updateError);
      return res.status(500).json({
        ok: false,
        message: "Impossible de compter la vue.",
      });
    }

    return res.json({
      ok: true,
      message: "Vue enregistrée.",
    });
  } catch (error) {
    console.error("Erreur serveur /api/partner-ads/:id/view :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur pendant le comptage de vue.",
    });
  }
});

app.post("/api/partner-ads/:id/click", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "ID publicité manquant.",
      });
    }

    const { data: ad, error: readError } = await supabase
      .from("partner_ads")
      .select("id, clicks_count, is_active, owner_email")
      .eq("id", id)
      .eq("is_active", true)
      .single();

    if (readError || !ad) {
      return res.status(404).json({
        ok: false,
        message: "Publicité active introuvable.",
      });
    }

    const ownerEmail = normalizeEmail(ad.owner_email);
    const isAdminOwner = ownerEmail === "fasterame@gmail.com";

    if (!isAdminOwner) {
      const subscriptionActive = await isProfessionalSubscriptionActive(ownerEmail);

      if (!subscriptionActive) {
        await deactivateAdsForEmail(ownerEmail);

        return res.status(403).json({
          ok: false,
          message: "Abonnement expiré. Publicité désactivée.",
        });
      }
    }

    const { error: updateError } = await supabase
      .from("partner_ads")
      .update({
        clicks_count: Number(ad.clicks_count || 0) + 1,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);

    if (updateError) {
      console.error("Erreur compteur clic publicité :", updateError);
      return res.status(500).json({
        ok: false,
        message: "Impossible de compter le clic.",
      });
    }

    return res.json({
      ok: true,
      message: "Clic enregistré.",
    });
  } catch (error) {
    console.error("Erreur serveur /api/partner-ads/:id/click :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur pendant le comptage du clic.",
    });
  }
});


/* ===============================
   FRANCE TRAVAIL - OFFRES PAR PAYS
=============================== */

const FRANCE_TRAVAIL_TOKEN_URL =
  "https://entreprise.francetravail.fr/connexion/oauth2/access_token?realm=%2Fpartenaire";

const FRANCE_TRAVAIL_OFFRES_URL =
  "https://api.francetravail.io/partenaire/offresdemploi/v2/offres/search";

let franceTravailTokenCache = {
  token: null,
  expiresAt: 0,
};

async function getFranceTravailToken() {
  const now = Date.now();

  if (
    franceTravailTokenCache.token &&
    franceTravailTokenCache.expiresAt > now + 60000
  ) {
    return franceTravailTokenCache.token;
  }

  const clientId = String(process.env.FRANCE_TRAVAIL_CLIENT_ID || "").trim();
  const clientSecret = String(process.env.FRANCE_TRAVAIL_CLIENT_SECRET || "").trim();

  if (!clientId || !clientSecret) {
    throw new Error("Variables France Travail manquantes.");
  }

  const body = new URLSearchParams();

  body.append("grant_type", "client_credentials");
  body.append("client_id", clientId);
  body.append("client_secret", clientSecret);

  const scope = String(
    process.env.FRANCE_TRAVAIL_SCOPE || "api_offresdemploiv2 o2dsoffre"
  ).trim();

  body.append("scope", scope);

  const response = await fetch(FRANCE_TRAVAIL_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    console.error("Erreur token France Travail :", data);
    throw new Error("Impossible d'obtenir le token France Travail.");
  }

  franceTravailTokenCache = {
    token: data.access_token,
    expiresAt: now + (data.expires_in || 1500) * 1000,
  };

  return data.access_token;
}

app.get("/api/offres-emploi/pays/:pays", async (req, res) => {
  try {
    const pays = String(req.params.pays || "").trim().toLowerCase();

    if (!pays) {
      return res.status(400).json({
        ok: false,
        message: "Pays manquant.",
      });
    }

    if (pays !== "france") {
      return res.json({
        ok: true,
        source: "havena",
        pays,
        offres: [],
        message:
          "Ce pays est prêt côté HAVENA, mais son API emploi officielle n’est pas encore branchée.",
      });
    }

    const token = await getFranceTravailToken();

    const response = await fetch(`${FRANCE_TRAVAIL_OFFRES_URL}?range=0-19`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Erreur API France Travail :", data);

      return res.status(response.status).json({
        ok: false,
        error: "Erreur API France Travail.",
        details: data,
      });
    }

    const offres = (data.resultats || []).map((offre) => ({
      id: offre.id,
      titre: offre.intitule || "Offre d’emploi",
      entreprise:
        offre.entreprise?.nom ||
        offre.entreprise?.nomEntreprise ||
        "Entreprise à confirmer",
      ville:
        offre.lieuTravail?.libelle ||
        offre.lieuTravail?.commune ||
        "France",
      pays: "France",
      contrat: offre.typeContrat || offre.natureContrat || "Contrat à confirmer",
      salaire:
        offre.salaire?.libelle ||
        offre.salaire?.commentaire ||
        "Salaire à confirmer",
      description:
        offre.description ||
        "Description de l’offre à consulter auprès de France Travail.",
      url:
        offre.origineOffre?.urlOrigine ||
        `https://candidat.francetravail.fr/offres/recherche/detail/${offre.id}`,
      source: "France Travail",
    }));

    return res.json({
      ok: true,
      source: "France Travail",
      pays: "france",
      offres,
    });
  } catch (error) {
    console.error("Erreur route /api/offres-emploi/pays/:pays :", error);

    return res.status(500).json({
      ok: false,
      error: "Erreur serveur pendant le chargement des offres par pays.",
      details: error.message,
    });
  }
});
/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Promotions officielles actives
=============================== */

app.get("/api/partner-promotions/active", async (req, res) => {
  try {
    const nowIso = new Date().toISOString();

    const { data: promotions, error: promotionsError } = await supabase
      .from("partner_promotions")
      .select("*")
      .eq("is_active", true)
      .or(`end_date.is.null,end_date.gte.${nowIso}`)
      .order("updated_at", { ascending: false });

    if (promotionsError) {
      console.error("Erreur lecture promotions partenaires :", promotionsError);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture promotions partenaires.",
        error: promotionsError.message,
      });
    }

    const { data: rules, error: rulesError } = await supabase
      .from("partner_promotion_rules")
      .select("*")
      .eq("is_enabled", true)
      .eq("promotions_allowed", true)
      .eq("official_resources_only", true);

    if (rulesError) {
      console.error("Erreur lecture règles promotions :", rulesError);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture règles promotions partenaires.",
        error: rulesError.message,
      });
    }

    const rulesByPartnerKey = new Map(
      (rules || []).map((rule) => [String(rule.partner_key || "").trim(), rule])
    );

    const safePromotions = (promotions || [])
      .filter((promotion) => {
        const partnerKey = String(promotion.partner_key || "").trim();
        const rule = rulesByPartnerKey.get(partnerKey);

        if (!rule) return false;

        if (promotion.promo_code && !rule.promo_codes_allowed) {
          return false;
        }

        return true;
      })
      .map((promotion) => ({
        id: promotion.id,
        network: promotion.network,
        partner_name: promotion.partner_name,
        partner_key: promotion.partner_key,
        category: promotion.category,
        title: promotion.title,
        description: promotion.description,
        promo_code: promotion.promo_code || "",
        affiliate_link: promotion.affiliate_link,
        image_url: promotion.image_url || "",
        start_date: promotion.start_date,
        end_date: promotion.end_date,
      }));

    return res.json({
      ok: true,
      total: safePromotions.length,
      promotions: safePromotions,
    });
  } catch (error) {
    console.error("Erreur serveur /api/partner-promotions/active :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur promotions partenaires.",
      error: error.message,
    });
  }
});
/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Moteur sécurisé d'enregistrement
=============================== */

async function getPartnerPromotionRulesMap() {
  const { data, error } = await supabase
    .from("partner_promotion_rules")
    .select("*")
    .eq("is_enabled", true)
    .eq("promotions_allowed", true)
    .eq("official_resources_only", true);

  if (error) {
    console.error("Erreur lecture règles promotions partenaires :", error);
    throw new Error("Impossible de lire les règles promotions partenaires.");
  }

  return new Map(
    (data || []).map((rule) => [String(rule.partner_key || "").trim(), rule])
  );
}

function cleanPromotionText(value = "") {
  return String(value || "").trim();
}

function cleanPromotionDate(value) {
  if (!value) return null;

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

async function upsertOfficialPartnerPromotion(promotion, rulesMap) {
  const network = cleanPromotionText(promotion.network);
  const partnerKey = cleanPromotionText(promotion.partner_key);
  const partnerName = cleanPromotionText(promotion.partner_name);
  const sourceId = cleanPromotionText(promotion.source_id);
  const title = cleanPromotionText(promotion.title);
  const affiliateLink = cleanPromotionText(promotion.affiliate_link);

  if (!network || !partnerKey || !partnerName || !sourceId || !title || !affiliateLink) {
    return {
      ok: false,
      skipped: true,
      reason: "Promotion incomplète.",
    };
  }

  const rule = rulesMap.get(partnerKey);

  if (!rule) {
    return {
      ok: false,
      skipped: true,
      reason: "Partenaire non autorisé dans partner_promotion_rules.",
    };
  }

  let promoCode = cleanPromotionText(promotion.promo_code);

  if (promoCode && !rule.promo_codes_allowed) {
    promoCode = "";
  }

  const payload = {
    network,
    partner_name: partnerName,
    partner_key: partnerKey,
    category: cleanPromotionText(promotion.category || rule.category || ""),
    title,
    description: cleanPromotionText(promotion.description),
    promo_code: promoCode,
    affiliate_link: affiliateLink,
    image_url: cleanPromotionText(promotion.image_url),
    start_date: cleanPromotionDate(promotion.start_date),
    end_date: cleanPromotionDate(promotion.end_date),
    source_id: sourceId,
    source_payload: promotion.source_payload || {},
    is_active: true,
    updated_at: new Date().toISOString(),
  };

  const { data: existingPromotion, error: readError } = await supabase
    .from("partner_promotions")
    .select("id")
    .eq("network", network)
    .eq("source_id", sourceId)
    .maybeSingle();

  if (readError) {
    console.error("Erreur recherche promotion existante :", readError);
    throw new Error("Erreur recherche promotion existante.");
  }

  if (existingPromotion?.id) {
    const { data, error } = await supabase
      .from("partner_promotions")
      .update(payload)
      .eq("id", existingPromotion.id)
      .select()
      .single();

    if (error) {
      console.error("Erreur mise à jour promotion partenaire :", error);
      throw new Error("Erreur mise à jour promotion partenaire.");
    }

    return {
      ok: true,
      action: "updated",
      promotion: data,
    };
  }

  const { data, error } = await supabase
    .from("partner_promotions")
    .insert([
      {
        ...payload,
        created_at: new Date().toISOString(),
      },
    ])
    .select()
    .single();

  if (error) {
    console.error("Erreur insertion promotion partenaire :", error);
    throw new Error("Erreur insertion promotion partenaire.");
  }

  return {
    ok: true,
    action: "inserted",
    promotion: data,
  };
}
/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Connecteur Awin officiel
=============================== */

function normalizePartnerSearchText(value = "") {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function findRuleForNetworkPartner(rulesMap, network, advertiserName = "") {
  const cleanNetwork = normalizePartnerSearchText(network);
  const cleanAdvertiserName = normalizePartnerSearchText(advertiserName);

  if (!cleanAdvertiserName) return null;

  for (const rule of rulesMap.values()) {
    const ruleNetwork = normalizePartnerSearchText(rule.network);
    const ruleName = normalizePartnerSearchText(rule.partner_name);

    if (ruleNetwork !== cleanNetwork) continue;

    if (
      cleanAdvertiserName === ruleName ||
      cleanAdvertiserName.includes(ruleName) ||
      ruleName.includes(cleanAdvertiserName)
    ) {
      return rule;
    }
  }

  return null;
}

function extractAwinPromotionsFromResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.promotions)) return data.promotions;
  if (Array.isArray(data?.offers)) return data.offers;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.results)) return data.results;
  return [];
}

async function syncAwinPartnerPromotions(rulesMap) {
  const awinToken = String(process.env.AWIN_API_TOKEN || "").trim();
  const awinPublisherId = String(process.env.AWIN_PUBLISHER_ID || "").trim();

  if (!awinToken || !awinPublisherId) {
    throw new Error("Variables Awin manquantes : AWIN_API_TOKEN ou AWIN_PUBLISHER_ID.");
  }

  const endpoint = `https://api.awin.com/publisher/${encodeURIComponent(
    awinPublisherId
  )}/promotions?accessToken=${encodeURIComponent(awinToken)}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: awinToken,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      filters: {
        membership: "joined",
        status: "active",
        type: "all",
      },
      pagination: {
        page: 1,
        pageSize: 200,
      },
    }),
  });

  const responseText = await response.text();

  let data = null;
  try {
    data = responseText ? JSON.parse(responseText) : null;
  } catch (error) {
    data = null;
  }

  if (!response.ok) {
    console.error("Erreur API Awin promotions :", response.status, responseText);
    throw new Error(`Erreur API Awin promotions : ${response.status}`);
  }

  const awinPromotions = extractAwinPromotionsFromResponse(data);

  const results = {
    network: "Awin",
    received: awinPromotions.length,
    inserted: 0,
    updated: 0,
    skipped: 0,
  };

  for (const awinPromotion of awinPromotions) {
    const advertiserName =
      awinPromotion?.advertiser?.name ||
      awinPromotion?.advertiser_name ||
      awinPromotion?.advertiserName ||
      awinPromotion?.merchant_name ||
      awinPromotion?.merchantName ||
      awinPromotion?.brand ||
      awinPromotion?.program ||
      awinPromotion?.programName ||
      awinPromotion?.name ||
      "";

    const rule = findRuleForNetworkPartner(rulesMap, "Awin", advertiserName);

    if (!rule) {
      results.skipped += 1;
      continue;
    }

    const promoTitle =
      awinPromotion?.title ||
      awinPromotion?.promotion_title ||
      awinPromotion?.promotionTitle ||
      awinPromotion?.name ||
      awinPromotion?.description ||
      "Promotion officielle Awin";

    const promoDescription =
      awinPromotion?.description ||
      awinPromotion?.summary ||
      awinPromotion?.details ||
      awinPromotion?.terms ||
      promoTitle ||
      "Ressource officielle disponible via Awin.";

    const promoCode =
      awinPromotion?.voucher?.code ||
      awinPromotion?.voucherCode ||
      awinPromotion?.promo_code ||
      awinPromotion?.promoCode ||
      awinPromotion?.code ||
      "";

    const affiliateLink =
      awinPromotion?.url ||
      awinPromotion?.tracking_url ||
      awinPromotion?.trackingUrl ||
      awinPromotion?.urlTracking ||
      awinPromotion?.trackingLink ||
      awinPromotion?.affiliate_url ||
      awinPromotion?.affiliateUrl ||
      awinPromotion?.click_url ||
      awinPromotion?.clickUrl ||
      awinPromotion?.link ||
      awinPromotion?.deeplink ||
      "";

    if (!affiliateLink) {
      results.skipped += 1;
      continue;
    }

    const sourceId =
      awinPromotion?.id ||
      awinPromotion?.promotionId ||
      awinPromotion?.promotion_id ||
      awinPromotion?.offerId ||
      awinPromotion?.offer_id ||
      `${rule.partner_key}-${promoTitle}-${promoCode || affiliateLink}`;

    const saved = await upsertOfficialPartnerPromotion(
      {
        network: "Awin",
        partner_name: rule.partner_name,
        partner_key: rule.partner_key,
        category: rule.category || "",
        title: promoTitle,
        description: promoDescription,
        promo_code: promoCode,
        affiliate_link: affiliateLink,
        image_url:
          awinPromotion?.image_url ||
          awinPromotion?.imageUrl ||
          awinPromotion?.advertiser?.logoUrl ||
          "",
        start_date:
          awinPromotion?.startDate ||
          awinPromotion?.start_date ||
          awinPromotion?.startsAt ||
          null,
        end_date:
          awinPromotion?.endDate ||
          awinPromotion?.end_date ||
          awinPromotion?.endsAt ||
          null,
        source_id: String(sourceId),
        source_payload: awinPromotion,
      },
      rulesMap
    );

    if (saved?.action === "inserted") {
      results.inserted += 1;
    } else if (saved?.action === "updated") {
      results.updated += 1;
    } else {
      results.skipped += 1;
    }
  }

  return results;
}

/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Synchronisation officielle sécurisée
=============================== */
function normalizePromotionText(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function isRealPartnerPromotion(promo) {
  const title = String(promo?.title || "");
  const description = String(promo?.description || "");
  const promoCode = String(promo?.promo_code || "");

  const sourcePayload =
    typeof promo?.source_payload === "string"
      ? promo.source_payload
      : JSON.stringify(promo?.source_payload || {});

  const rawText = `${title} ${description} ${promoCode} ${sourcePayload}`;

  const fullText = rawText
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");

  const sourcePayloadObject =
    promo?.source_payload && typeof promo.source_payload === "object"
      ? promo.source_payload
      : {};

  const promotionType = String(
    sourcePayloadObject?.promotionType ||
      sourcePayloadObject?.type ||
      ""
  )
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");

  const hasPromoCode = promoCode.trim().length > 0;

  const hasOfficialPromoType =
    promotionType.includes("coupon") ||
    promotionType.includes("voucher") ||
    promotionType.includes("sale") ||
    promotionType.includes("sale link") ||
    promotionType.includes("discount") ||
    promotionType.includes("promotion") ||
    promotionType.includes("promo");

  const hasPercentDiscount = /\b\d{1,3}\s?%/.test(fullText);

  const hasMoneyDiscount =
    /(\$|€|£|usd|eur|gbp|cad|aud|chf|¥|￥|円|r\$)\s?\d+/i.test(rawText) ||
    /\d+\s?(\$|€|£|usd|eur|gbp|cad|aud|chf|¥|￥|円|r\$)/i.test(rawText);

  const worldwidePromoKeywords = [
    // Français
    "offre", "offres", "offre speciale", "offres speciales", "offre exclusive",
    "offres exclusives", "promotion", "promo", "code promo", "remise",
    "reduction", "rabais", "bon plan", "soldes",

    // Anglais
    "special offer", "special offers", "sale", "sale link", "deal", "deals",
    "discount", "coupon", "voucher", "promo code", "save", "savings", "off",
    "cashback", "limited time", "valid until", "expires",

    // Espagnol
    "oferta", "ofertas", "descuento", "promocion", "promociones",
    "codigo promocional", "cupon", "hasta el", "valido hasta", "rebaja",
    "rebajas", "ahorra", "ahorro",

    // Italien
    "offerta", "offerte", "sconto", "promozione", "codice promo",
    "coupon", "fino al", "risparmia", "saldi",

    // Portugais
    "oferta", "ofertas", "desconto", "promocao", "promocoes",
    "cupom", "codigo promocional", "ate", "economize",

    // Allemand
    "rabatt", "gutschein", "angebot", "angebote", "aktion",
    "sonderangebot", "ersparnis", "sparen", "bis zum",

    // Néerlandais
    "korting", "aanbieding", "aanbiedingen", "coupon", "actie",
    "bespaar", "geldig tot",

    // Polonais
    "rabat", "znizka", "zniżka", "kupon", "promocja", "oferta",
    "wazne do", "ważne do",

    // Turc
    "indirim", "kupon", "promosyon", "kampanya", "firsat", "fırsat",

    // Russe / Ukrainien
    "скидка", "акция", "купон", "промокод", "предложение",
    "знижка", "акція", "купон", "промокод",

    // Arabe
    "خصم", "عرض", "عروض", "قسيمة", "كوبون", "رمز ترويجي", "تخفيض",

    // Chinois
    "优惠", "折扣", "促销", "优惠券", "特价", "满减", "限时",

    // Japonais
    "割引", "クーポン", "セール", "キャンペーン", "特典", "期間限定",

    // Coréen
    "할인", "쿠폰", "프로모션", "특가", "이벤트",

    // Thaï / Vietnamien / Indonésien
    "ส่วนลด", "คูปอง", "โปรโมชั่น",
    "giảm giá", "mã giảm giá", "khuyến mãi",
    "diskon", "kode promo", "promo", "penawaran"
  ];

  const hasWorldwidePromoKeyword = worldwidePromoKeywords.some((keyword) =>
    fullText.includes(
      keyword
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
    )
  );

  const dateLimitKeywords = [
    "valid until", "expires", "expire", "until", "limited time",
    "jusqu", "valable jusqu", "offre valable",
    "hasta el", "valido hasta",
    "fino al", "valida fino",
    "bis zum", "gilt bis",
    "geldig tot",
    "wazne do", "ważne do",
    "期限", "有效期", "限时",
    "期間限定",
    "لغاية", "حتى"
  ];

  const hasDateLimit = dateLimitKeywords.some((keyword) =>
    fullText.includes(
      keyword
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
    )
  );

  const travelOfferContextKeywords = [
    "book", "booking", "flight", "flights", "hotel", "hotels", "car rental",
    "travel", "trip", "stay", "destination",
    "reserve", "reservation", "vol", "vols", "hotel", "sejour", "séjour",
    "location", "vacances", "voyage",
    "vuela", "destino", "viaje", "reserva", "alojamiento",
    "flug", "reise", "hotel", "mietwagen",
    "volo", "viaggio", "soggiorno",
    "voo", "viagem", "estadia",
    "航空", "酒店", "旅行", "予約",
    "항공", "호텔", "여행",
    "رحلة", "فندق", "سفر"
  ];

  const hasTravelOfferContext = travelOfferContextKeywords.some((keyword) =>
    fullText.includes(
      keyword
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
    )
  );

  const simpleResourceKeywords = [
    "homepage", "home page", "home ",
    "logo", "generic", "test",
    "banner_", "new logo",
    "car rental homepage"
  ];

  const looksLikeSimpleResource = simpleResourceKeywords.some((keyword) =>
    fullText.includes(keyword)
  );

  if (hasPromoCode) {
    return true;
  }

  if (hasOfficialPromoType) {
    return true;
  }

  if (hasPercentDiscount) {
    return true;
  }

  if (hasMoneyDiscount && hasWorldwidePromoKeyword) {
    return true;
  }

  if (hasWorldwidePromoKeyword && !looksLikeSimpleResource) {
    return true;
  }

  if (hasDateLimit && hasTravelOfferContext) {
    return true;
  }

  return false;
}

function getPromotionPercentValue(promo) {
  const fullText = normalizePromotionText(
    `${promo.title || ""} ${promo.description || ""} ${promo.promo_code || ""}`
  );

  const match = fullText.match(/(^|\D)([1-9][0-9]?|100)\s?%/);
  return match ? `${match[2]}%` : "";
}

function dedupePartnerPromotions(promotions) {
  const seen = new Set();

  return (promotions || []).filter((promo) => {
    const partnerName = normalizePromotionText(promo.partner_name);
    const promoCode = normalizePromotionText(promo.promo_code);
    const percentValue = getPromotionPercentValue(promo);
    const category = normalizePromotionText(
      Array.isArray(promo.categories) ? promo.categories.join(" ") : promo.category
    );

    const key = [
      partnerName,
      promoCode || percentValue || normalizePromotionText(promo.title),
      category,
    ].join("|");

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}


app.get("/api/partner-promotions", async (req, res) => {
  try {
    const nowIso = new Date().toISOString();

    const { data, error } = await supabase
      .from("partner_promotions")
      .select("*")
      .eq("is_active", true)
      .or(`end_date.is.null,end_date.gte.${nowIso}`)
      .order("updated_at", { ascending: false })
      .limit(1000);

    if (error) {
      console.error("Erreur lecture promotions partenaires :", error);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture promotions partenaires.",
        error: error.message,
      });
    }

const realPromotions = dedupePartnerPromotions(
  (data || []).filter(isRealPartnerPromotion)
);

return res.json({
  ok: true,
  promotions: realPromotions,
  total_received: data?.length || 0,
  total_displayed: realPromotions.length,
});


  } catch (error) {
    console.error("Erreur serveur promotions partenaires :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur promotions partenaires.",
      error: error.message,
    });
  }
});

app.post("/api/partner-promotions/sync", async (req, res) => {
  try {
    const syncSecret = String(process.env.PARTNER_PROMOTIONS_SYNC_SECRET || "").trim();
    const incomingSecret = String(
      req.headers["x-havena-sync-secret"] || req.body?.syncSecret || ""
    ).trim();

    if (!syncSecret || incomingSecret !== syncSecret) {
      return res.status(403).json({
        ok: false,
        message: "Accès refusé. Synchronisation non autorisée.",
      });
    }

    const rulesMap = await getPartnerPromotionRulesMap();

const results = {};

try {
  results.awin = await syncAwinPartnerPromotions(rulesMap);
} catch (error) {
  console.error("Erreur sync Awin :", error);
  results.awin = {
    ok: false,
    error: error.message,
  };
}

try {
  results.cj = await syncCjPartnerPromotions(rulesMap);
} catch (error) {
  console.error("Erreur sync CJ :", error);
  results.cj = {
    ok: false,
    error: error.message,
  };
}

try {
  results.travelpayouts = await syncTravelpayoutsPartnerPromotions(rulesMap);
} catch (error) {
  console.error("Erreur sync Travelpayouts :", error);
  results.travelpayouts = {
    ok: false,
    error: error.message,
  };
}

return res.json({
  ok: true,
  message: "Synchronisation promotions partenaires terminée.",
  results,
});

  } catch (error) {
    console.error("Erreur synchronisation promotions partenaires :", error);
    return res.status(500).json({
      ok: false,
      message: "Erreur synchronisation promotions partenaires.",
      error: error.message,
    });
  }
});
/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Connecteur CJ officiel
=============================== */

function extractCjLinksFromResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.links)) return data.links;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.results)) return data.results;
  if (Array.isArray(data?.["link-search"]?.links)) return data["link-search"].links;
  return [];
}
function getXmlValue(xml, tagName) {
  const match = xml.match(new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "i"));
  return match ? match[1].replace(/<!\\[CDATA\\[|\\]\\]>/g, "").trim() : "";
}

function extractCjLinksFromXml(xml) {
  if (!xml || typeof xml !== "string") {
    return [];
  }

  const linkBlocks = xml.match(/<link>[\s\S]*?<\/link>/gi) || [];


  return linkBlocks.map((block) => ({
    advertiserName: getXmlValue(block, "advertiser-name"),
    advertiserId: getXmlValue(block, "advertiser-id"),
    category: getXmlValue(block, "category"),
    linkName: getXmlValue(block, "link-name"),
    description: getXmlValue(block, "description"),
    linkType: getXmlValue(block, "link-type"),
    promotionType: getXmlValue(block, "promotion-type"),
    promotionStartDate: getXmlValue(block, "promotion-start-date"),
    promotionEndDate: getXmlValue(block, "promotion-end-date"),
    couponCode: getXmlValue(block, "coupon-code"),
    clickUrl: getXmlValue(block, "clickUrl"),
    destination: getXmlValue(block, "destination"),
  }));
}
function shouldSkipGenericCjPromotion(link) {
  const title = String(
    link?.linkName ||
    link?.name ||
    link?.title ||
    ""
  ).toLowerCase();

  const description = String(link?.description || "").toLowerCase();
  const promotionType = String(link?.promotionType || "").toLowerCase();
  const destination = String(link?.destination || "").toLowerCase();
  const clickUrl = String(link?.clickUrl || "").toLowerCase();

  const text = `${title} ${description} ${promotionType} ${destination} ${clickUrl}`;

  const genericTerms = [
    "generic",
    "home",
    "homepage",
    "banner",
    "logo",
    "text link",
    "leaderboard",
    "skyscraper",
    "728x90",
    "300x600",
    "300x250",
    "160x600",
    "468x60",
    "125x125",
    "120x600",
    "970x90",
    "320x50",
  ];

  const realOfferTerms = [
    "offer",
    "offers",
    "special",
    "deal",
    "deals",
    "discount",
    "sale",
    "saving",
    "savings",
    "save",
    "promo",
    "promotion",
    "coupon",
    "voucher",
    "summer",
    "holiday",
    "vacation",
    "flight",
    "hotel",
    "car rental",
    "cruise",
    "offre",
    "offres",
    "spécial",
    "special",
    "réduction",
    "reduction",
    "remise",
    "vacances",
    "vol",
    "hôtel",
    "hotel",
  ];

  const hasGenericTerm = genericTerms.some((term) => text.includes(term));
  const hasRealOfferTerm = realOfferTerms.some((term) => text.includes(term));
  const hasBannerSize = /\b\d{2,4}x\d{2,4}\b/.test(text);

  if (title.includes("generic")) {
    return true;
  }

  if (hasBannerSize && !hasRealOfferTerm) {
    return true;
  }

  if (hasGenericTerm && !hasRealOfferTerm) {
    return true;
  }

  return false;
}

async function syncCjPartnerPromotions(rulesMap) {
  const cjToken = String(process.env.CJ_API_TOKEN || "").trim();
const cjWebsiteId = String(process.env.CJ_WEBSITE_ID || "").trim();
  if (!cjToken) {
    throw new Error("Variable CJ manquante : CJ_API_TOKEN.");
  }
if (!cjWebsiteId) {
  throw new Error("Variable CJ manquante : CJ_WEBSITE_ID.");
}

const cjLinks = [];

for (let pageNumber = 1; pageNumber <= 10; pageNumber += 1) {
  const params = new URLSearchParams();
  params.append("website-id", cjWebsiteId);
  params.append("advertiser-ids", "joined");
  params.append("records-per-page", "100");
  params.append("page-number", String(pageNumber));

  const endpoint = `https://link-search.api.cj.com/v2/link-search?${params.toString()}`;

  const response = await fetch(endpoint, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${cjToken}`,
      Accept: "application/xml",
    },
  });

  const responseText = await response.text();

  let data = null;
  try {
    data = responseText ? JSON.parse(responseText) : null;
  } catch (error) {
    data = null;
  }

  if (!response.ok) {
    console.error("Erreur CJ détaillée :", {
      status: response.status,
      statusText: response.statusText,
      endpoint,
      responseText,
      pageNumber,
    });
    throw new Error(
      `Erreur API CJ Link Search : ${response.status} ${response.statusText} - ${responseText}`
    );
  }

  const pageLinksFromXml = extractCjLinksFromXml(responseText);
  const pageLinks =
    pageLinksFromXml.length > 0
      ? pageLinksFromXml
      : extractCjLinksFromResponse(data);

  if (!pageLinks.length) {
    break;
  }

  cjLinks.push(...pageLinks);

  if (pageLinks.length < 100) {
    break;
  }
}



  const results = {
    network: "CJ",
    received: cjLinks.length,
    inserted: 0,
    updated: 0,
    skipped: 0,
  };

  for (const cjLink of cjLinks) {
    const advertiserName =
      cjLink?.advertiserName ||
      cjLink?.advertiser_name ||
      cjLink?.advertiser ||
      cjLink?.advertiserNameText ||
      "";

    const rule = findRuleForNetworkPartner(rulesMap, "CJ", advertiserName);

    if (!rule) {
      results.skipped += 1;
      continue;
    }
if (shouldSkipGenericCjPromotion(cjLink)) {
      const skippedLinkName =
        cjLink?.linkName ||
        cjLink?.link_name ||
        cjLink?.name ||
        cjLink?.description ||
        "";

      console.log("Promotion CJ générique ignorée et désactivée :", {
        advertiserName,
        linkName: skippedLinkName,
      });

      if (skippedLinkName) {
        await supabase
          .from("partner_promotions")
          .update({
            is_active: false,
            updated_at: new Date().toISOString(),
          })
          .eq("network", "CJ")
          .eq("partner_key", rule.partner_key)
          .eq("title", skippedLinkName);
      }

      results.skipped += 1;
      continue;
    }


    const linkName =
      cjLink?.linkName ||
      cjLink?.link_name ||
      cjLink?.name ||
      cjLink?.title ||
      "Offre officielle CJ";

    const destinationUrl =
      cjLink?.clickUrl ||
      cjLink?.click_url ||
      cjLink?.trackingUrl ||
      cjLink?.tracking_url ||
      cjLink?.url ||
      "";

    if (!destinationUrl) {
      results.skipped += 1;
      continue;
    }

    const promotionType =
      cjLink?.promotionType ||
      cjLink?.promotion_type ||
      cjLink?.linkType ||
      cjLink?.link_type ||
      "";

    const descriptionParts = [
      cjLink?.description || "",
      promotionType ? `Type : ${promotionType}` : "",
    ].filter(Boolean);

    const saved = await upsertOfficialPartnerPromotion(
      {
        network: "CJ",
        partner_name: rule.partner_name,
        partner_key: rule.partner_key,
        category: rule.category || "",
        title: linkName,
        description:
          descriptionParts.join(" - ") ||
          "Ressource officielle disponible via CJ.",
       promo_code:
  cjLink?.couponCode ||
  cjLink?.coupon_code ||
  "",
        affiliate_link: destinationUrl,
        image_url: cjLink?.imageUrl || cjLink?.image_url || "",
        start_date: cjLink?.startDate || cjLink?.start_date || null,
        end_date: cjLink?.endDate || cjLink?.end_date || null,
        source_id:
          cjLink?.linkId
            ? String(cjLink.linkId)
            : cjLink?.link_id
            ? String(cjLink.link_id)
            : `${rule.partner_key}-${linkName}`,
        source_payload: cjLink,
      },
      rulesMap
    );

    if (saved?.action === "inserted") {
      results.inserted += 1;
    } else if (saved?.action === "updated") {
      results.updated += 1;
    } else {
      results.skipped += 1;
    }
  }

  return results;
}
/* ===============================
   PROMOTIONS PARTENAIRES HAVENA
   Connecteur Travelpayouts officiel
=============================== */

function buildTravelpayoutsAffiliateLink(rawUrl = "") {
  const marker = String(process.env.TRAVELPAYOUTS_MARKER || "").trim();
  const cleanUrl = String(rawUrl || "").trim();

  if (!marker || !cleanUrl) {
    return cleanUrl;
  }

  if (cleanUrl.includes("marker=")) {
    return cleanUrl;
  }

  const encodedUrl = encodeURIComponent(cleanUrl);

  return `https://tp.media/r?marker=${encodeURIComponent(
    marker
  )}&u=${encodedUrl}`;
}

function extractTravelpayoutsPromotionsFromResponse(data) {
  
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.data)) return data.data;
  if (Array.isArray(data?.promotions)) return data.promotions;
  if (Array.isArray(data?.offers)) return data.offers;
  if (Array.isArray(data?.results)) return data.results;
  return [];
}

async function syncTravelpayoutsPartnerPromotions(rulesMap) {
  const travelpayoutsToken = String(process.env.TRAVELPAYOUTS_API_TOKEN || "").trim();

  if (!travelpayoutsToken) {
    throw new Error("Variable Travelpayouts manquante : TRAVELPAYOUTS_API_TOKEN.");
  }

  const officialTravelpayoutsPromotions = [
    {
      partner_name: "Klook",
      title: "Code promo Klook officiel",
      description: "Code promo Travelpayouts officiel fourni pour Klook.",
      promo_code: "TPKLOOKTA5",
      affiliate_link: "https://klook.tpx.lt/92J1Use4",
      image_url: "",
      category: "activites",
      source_payload: {
        origin: "official_travelpayouts_promotion",
        verified_by_admin: true,
        note: "Promotion officielle Travelpayouts validée pour HAVENA.",
      },
    },
  ];

  const results = {
    network: "Travelpayouts",
    received: officialTravelpayoutsPromotions.length,
    inserted: 0,
    updated: 0,
    skipped: 0,
  };

  for (const travelPromotion of officialTravelpayoutsPromotions) {
    const partnerName = travelPromotion.partner_name || "";
    const rule = findRuleForNetworkPartner(rulesMap, "Travelpayouts", partnerName);

    if (!rule) {
      results.skipped += 1;
      continue;
    }

    const promoTitle = travelPromotion.title || "Promotion officielle Travelpayouts";
    const promoDescription =
      travelPromotion.description || "Ressource officielle disponible via Travelpayouts.";
    const promoCode = travelPromotion.promo_code || "";
    const affiliateLink = travelPromotion.affiliate_link || "";

    if (!affiliateLink) {
      results.skipped += 1;
      continue;
    }

    const sourceId = `${rule.partner_key}-${promoCode || promoTitle}`;

    const saved = await upsertOfficialPartnerPromotion(
      {
        network: "Travelpayouts",
        partner_name: rule.partner_name,
        partner_key: rule.partner_key,
        category: rule.category || travelPromotion.category || "voyage",
        title: promoTitle,
        description: promoDescription,
        promo_code: promoCode,
        affiliate_link: affiliateLink,
        image_url: travelPromotion.image_url || "",
        start_date: null,
        end_date: null,
        source_id: String(sourceId),
        source_payload: travelPromotion,
      },
      rulesMap
    );

    if (saved?.action === "inserted") {
      results.inserted += 1;
    } else if (saved?.action === "updated") {
      results.updated += 1;
    } else {
      results.skipped += 1;
    }
  }

  return {
    ok: true,
    ...results,
  };
}


const PORT = process.env.PORT || 5055;
// ===============================
// DOCUMENTS HAVENA
// Upload + lecture documents
// Étudiants / saisonniers / employeurs / hébergeurs
// ===============================

app.post("/api/documents/upload", upload.single("file"), async (req, res) => {
  try {
    const { userEmail, userRole, category, owner } = req.body;

    if (!userEmail) {
      return res.status(400).json({ error: "Email utilisateur manquant." });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Aucun fichier reçu." });
    }

    const allowedRoles = ["etudiant", "saisonnier", "employeur", "hebergeur"];

    const cleanRole = allowedRoles.includes(userRole)
      ? userRole
      : "etudiant";

    const allowedMimeTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      return res.status(400).json({
        error: "Format non autorisé. Formats acceptés : PDF, JPG, PNG, DOC, DOCX.",
      });
    }

    const safeEmail = userEmail
      .toLowerCase()
      .replace(/[^a-zA-Z0-9@._-]/g, "_");

    const safeFileName = req.file.originalname
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-zA-Z0-9._-]/g, "_");

    const filePath = `${cleanRole}/${safeEmail}/${Date.now()}-${safeFileName}`;

    const { error: uploadError } = await supabase.storage
      .from("documents")
      .upload(filePath, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false,
      });

    if (uploadError) {
      console.error("Erreur upload Supabase documents:", uploadError);
      return res.status(500).json({ error: "Erreur upload du document." });
    }

    const { data, error: insertError } = await supabase
      .from("documents")
      .insert([
        {
          user_email: userEmail,
          user_role: cleanRole,
          name: req.file.originalname,
          category: category || "Document ajouté",
          owner: owner || "Vous",
          status: "Sécurisé",
          file_path: filePath,
          mime_type: req.file.mimetype,
          size_bytes: req.file.size,
        },
      ])
      .select()
      .single();

    if (insertError) {
      console.error("Erreur insertion document:", insertError);
      return res.status(500).json({ error: "Erreur enregistrement document." });
    }

    return res.json({
      success: true,
      document: data,
    });
  } catch (error) {
    console.error("Erreur /api/documents/upload:", error);
    return res.status(500).json({ error: "Erreur serveur document." });
  }
});

app.get("/api/documents", async (req, res) => {
  try {
    const userEmail = req.query.userEmail;
    const userRole = req.query.userRole;

    if (!userEmail) {
      return res.status(400).json({ error: "Email utilisateur manquant." });
    }

    let query = supabase
      .from("documents")
      .select("*")
      .eq("user_email", userEmail)
      .order("created_at", { ascending: false });

    if (userRole) {
      query = query.eq("user_role", userRole);
    }

    const { data, error } = await query;

    if (error) {
      console.error("Erreur lecture documents:", error);
      return res.status(500).json({ error: "Erreur lecture documents." });
    }

    return res.json({
      success: true,
      documents: data || [],
    });
  } catch (error) {
    console.error("Erreur /api/documents:", error);
    return res.status(500).json({ error: "Erreur serveur documents." });
  }
});
// ===============================
// OUVERTURE SÉCURISÉE DOCUMENT HAVENA
// Génère un lien temporaire Supabase Storage
// ===============================

app.get("/api/documents/open/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        success: false,
        error: "ID document manquant.",
      });
    }

    const { data: documentData, error: documentError } = await supabase
      .from("documents")
      .select("id, name, file_path")
      .eq("id", id)
      .single();

    if (documentError || !documentData) {
      console.error("Document introuvable:", documentError);
      return res.status(404).json({
        success: false,
        error: "Document introuvable.",
      });
    }

    const { data: signedData, error: signedError } = await supabase.storage
      .from("documents")
      .createSignedUrl(documentData.file_path, 60 * 5);

    if (signedError || !signedData?.signedUrl) {
      console.error("Erreur lien signé document:", signedError);
      return res.status(500).json({
        success: false,
        error: "Impossible d’ouvrir le document.",
      });
    }

    return res.json({
      success: true,
      name: documentData.name,
      url: signedData.signedUrl,
    });
  } catch (error) {
    console.error("Erreur /api/documents/open/:id:", error);
    return res.status(500).json({
      success: false,
      error: "Erreur serveur ouverture document.",
    });
  }
});

app.post("/api/admin/send-contact-profile-reminders", async (req, res) => {
  try {
    const secret = req.headers["x-cron-secret"];

    if (!process.env.CONTACT_REMINDER_SECRET) {
      return res.status(500).json({
        ok: false,
        message: "CONTACT_REMINDER_SECRET manquant dans les variables Render.",
      });
    }

    if (secret !== process.env.CONTACT_REMINDER_SECRET) {
      return res.status(401).json({
        ok: false,
        message: "Accès refusé.",
      });
    }

    const { data: users, error } = await supabase
      .from("havena_users")
      .select(
        "id, email, role, phone, contact_email, contact_profile_completed, contact_reminder_sent_at"
      );

    if (error) {
      throw error;
    }

    const allowedRoles = [
      "employeur",
      "recruteur",
      "candidat",
      "saisonnier",
      "etudiant",
    ];

    const normalizeRole = (role) =>
      String(role || "")
        .trim()
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "");

    const contactsToRemind = (users || []).filter((user) => {
      const role = normalizeRole(user.role);
      const email = String(user.email || "").trim();
      const phone = String(user.phone || "").trim();
      const contactEmail = String(user.contact_email || "").trim();

      return (
        email &&
        allowedRoles.includes(role) &&
        (!phone || !contactEmail) &&
        !user.contact_reminder_sent_at
      );
    });

    let sentCount = 0;

    for (const user of contactsToRemind) {
      const profileUrl = "https://www.havena1.fr/profil";

      await transporter.sendMail({
        from: process.env.MAIL_FROM || process.env.MAIL_USER,
        to: user.email,
        subject: "Complétez vos coordonnées sur HAVENA",
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #24124D;">
            <h2>Votre profil HAVENA est presque complet</h2>

            <p>Bonjour,</p>

            <p>
              Afin de faciliter les échanges entre candidats, employeurs et recruteurs,
              nous vous invitons à compléter vos coordonnées sur HAVENA.
            </p>

            <p>
              Merci d’ajouter votre <strong>numéro de téléphone</strong> et votre
              <strong>email de contact</strong> dans votre profil.
            </p>

            <p>
              <a href="${profileUrl}" style="display:inline-block;padding:12px 18px;background:#6C4CF1;color:white;text-decoration:none;border-radius:999px;font-weight:bold;">
                Compléter mon profil
              </a>
            </p>

            <p>
              À très bientôt,<br/>
              L’équipe HAVENA
            </p>
          </div>
        `,
      });

      await supabase
        .from("havena_users")
        .update({
          contact_reminder_sent_at: new Date().toISOString(),
        })
        .eq("id", user.id);

      sentCount += 1;
    }

    return res.json({
      ok: true,
      message: "Emails de rappel envoyés.",
      sent: sentCount,
    });
  } catch (error) {
    console.error("Erreur envoi rappels coordonnées :", error);

    return res.status(500).json({
      ok: false,
      message: "Erreur lors de l’envoi des rappels coordonnées.",
      error: error.message,
    });
  }
});
/* ======================================================
   HAVENA MASTER GUIDE - MOTEUR DE RECHERCHE VOLS
====================================================== */

async function havenaResolveAirportCode(value) {
  const search = String(value || "").trim();

  if (!search) {
    throw new Error("Ville ou aéroport manquant.");
  }
const searchNormalise = search
  .toLowerCase()
  .normalize("NFD")
  .replace(/[\u0300-\u036f]/g, "");

if (searchNormalise === "paris") {
  return "CDG,ORY";
}

if (searchNormalise === "noumea") {
  return "NOU";
}
  // Si l'utilisateur saisit déjà CDG, NOU, LHR...
  if (/^[A-Za-z]{3}$/.test(search)) {
    return search.toUpperCase();
  }

  const url = new URL(
    "https://autocomplete.travelpayouts.com/places2"
  );

  url.searchParams.set("term", search);
  url.searchParams.set("locale", "fr");
  url.searchParams.append("types[]", "city");
  url.searchParams.append("types[]", "airport");

  const response = await fetch(url.toString());

  if (!response.ok) {
    throw new Error(
      `Impossible de trouver l'aéroport pour ${search}.`
    );
  }

  const locations = await response.json();

  if (!Array.isArray(locations) || locations.length === 0) {
    throw new Error(
      `Aucun aéroport trouvé pour ${search}.`
    );
  }

  // On privilégie le code ville.
  // Exemple : Paris = PAR, Londres = LON
  const city =
    locations.find(
      (location) =>
        location.type === "city" &&
        location.code
    ) ||
    locations.find(
      (location) =>
        location.city_code
    ) ||
    locations.find(
      (location) =>
        location.code
    );

  const code =
    city?.type === "city"
      ? city.code
      : city?.city_code || city?.code;

  if (!code) {
    throw new Error(
      `Code aéroport introuvable pour ${search}.`
    );
  }

  return String(code).toUpperCase();
}


/* ------------------------------------------------------
   CONNECTEUR VOLS N°1
   GOOGLE FLIGHTS VIA SERPAPI
------------------------------------------------------ */

async function havenaSearchFlightsSerpApi({
  departureCode,
  destinationCode,
  dateAller,
  dateRetour,
  adultes,
  enfants,
}) {
  const apiKey = String(
    process.env.SERPAPI_API_KEY || ""
  ).trim();

  if (!apiKey) {
    return {
      source: "serpapi_google_flights",
      available: false,
      error: "SERPAPI_API_KEY manquante",
      results: [],
    };
  }

  const url = new URL(
    "https://serpapi.com/search.json"
  );

  url.searchParams.set(
    "engine",
    "google_flights"
  );

  url.searchParams.set(
    "departure_id",
    departureCode
  );

  url.searchParams.set(
    "arrival_id",
    destinationCode
  );

  url.searchParams.set(
    "outbound_date",
    dateAller
  );

  if (dateRetour) {
    url.searchParams.set(
      "return_date",
      dateRetour
    );

    url.searchParams.set(
      "type",
      "1"
    );
  } else {
    url.searchParams.set(
      "type",
      "2"
    );
  }

  url.searchParams.set(
    "adults",
    String(Math.max(1, Number(adultes) || 1))
  );

  url.searchParams.set(
    "children",
    String(Math.max(0, Number(enfants) || 0))
  );

  url.searchParams.set(
    "currency",
    "EUR"
  );

  url.searchParams.set(
    "hl",
    "fr"
  );

  url.searchParams.set(
    "gl",
    "fr"
  );

  // Prix les moins chers en premier
  url.searchParams.set(
    "sort_by",
    "2"
  );

  // Force une recherche récente
  url.searchParams.set(
    "no_cache",
    "true"
  );

  url.searchParams.set(
    "api_key",
    apiKey
  );

  const response = await fetch(
    url.toString()
  );

  if (!response.ok) {
    const details = await response.text();

    console.error(
      "Erreur SerpApi Google Flights :",
      response.status,
      details
    );

    return {
      source: "serpapi_google_flights",
      available: false,
      error: `Erreur source vols ${response.status}`,
      results: [],
    };
  }

  const data = await response.json();

  const rawFlights = [
    ...(Array.isArray(data.best_flights)
      ? data.best_flights
      : []),

    ...(Array.isArray(data.other_flights)
      ? data.other_flights
      : []),
  ];

  const results = rawFlights
    .map((offer, index) => {
      const segments =
        Array.isArray(offer.flights)
          ? offer.flights
          : [];

      if (segments.length === 0) {
        return null;
      }

      const firstFlight = segments[0];

      const lastFlight =
        segments[segments.length - 1];

      const airlines = [
        ...new Set(
          segments
            .map((flight) => flight.airline)
            .filter(Boolean)
        ),
      ];

      const price = Number(offer.price);

      if (!Number.isFinite(price)) {
        return null;
      }

      return {
        id: `serpapi-${index}-${price}`,

        source:
          "Google Flights / SerpApi",

        airlines,

        airline:
          airlines.join(" + ") ||
          "Compagnie aérienne",

        airlineLogo:
          offer.airline_logo ||
          firstFlight?.airline_logo ||
          "",

        price,

        currency: "EUR",

        totalDurationMinutes:
          Number(offer.total_duration) || null,

        stops:
          Array.isArray(offer.layovers)
            ? offer.layovers.length
            : Math.max(
                segments.length - 1,
                0
              ),

        departureAirport:
          firstFlight?.departure_airport?.id ||
          departureCode,

        departureAirportName:
          firstFlight?.departure_airport?.name ||
          "",

        departureTime:
          firstFlight?.departure_airport?.time ||
          "",

        arrivalAirport:
          lastFlight?.arrival_airport?.id ||
          destinationCode,

        arrivalAirportName:
          lastFlight?.arrival_airport?.name ||
          "",

        arrivalTime:
          lastFlight?.arrival_airport?.time ||
          "",

        flightNumbers:
          segments
            .map(
              (flight) =>
                flight.flight_number
            )
            .filter(Boolean),

        layovers:
          Array.isArray(offer.layovers)
            ? offer.layovers
            : [],

        type:
          offer.type || "",

        departureToken:
          offer.departure_token || "",

        checkedAt:
          new Date().toISOString(),
      };
    })
    .filter(Boolean);

  return {
    source: "serpapi_google_flights",
    available: true,
    error: null,
    results,
  };
}


/* ------------------------------------------------------
   ORCHESTRATEUR HAVENA VOLS
------------------------------------------------------ */

async function havenaRunFlightSources(search) {
  const sources = [
    havenaSearchFlightsSerpApi(search),

    /*
      PLUS TARD, ON AJOUTERA ICI :

      havenaSearchAirFrance(search),
      havenaSearchIberia(search),
      havenaSearchQatar(search),
      havenaSearchSingapore(search),
      etc.

      uniquement lorsque le partenaire
      autorise cette récupération.
    */
  ];

  const settled =
    await Promise.allSettled(sources);

  const results = [];

  const sourceStatus = [];

  settled.forEach((sourceResult) => {
    if (
      sourceResult.status === "fulfilled"
    ) {
      const source =
        sourceResult.value;

      sourceStatus.push({
        source: source.source,
        available:
          source.available,
        error:
          source.error || null,
        resultCount:
          source.results?.length || 0,
      });

      if (
        Array.isArray(source.results)
      ) {
        results.push(
          ...source.results
        );
      }
    } else {
      sourceStatus.push({
        source: "unknown",
        available: false,
        error:
          sourceResult.reason?.message ||
          "Source indisponible",
        resultCount: 0,
      });
    }
  });

  // On classe tous les partenaires
  // du moins cher au plus cher.
  results.sort(
    (a, b) =>
      Number(a.price) -
      Number(b.price)
  );

  return {
    results,
    sources: sourceStatus,
  };
}


/* ------------------------------------------------------
   ROUTE HAVENA MASTER GUIDE - VOLS
------------------------------------------------------ */

app.post(
 "/api/travel/search-flights-serpapi",
  async (req, res) => {
    try {
      const {
        depart,
        destination,
        dateAller,
        dateRetour,
        adultes = 1,
        enfants = 0,
      } = req.body || {};

      if (
        !depart ||
        !destination ||
        !dateAller
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            message:
              "Départ, destination et date aller sont obligatoires.",
          });
      }

      const [
        departureCode,
        destinationCode,
      ] = await Promise.all([
        havenaResolveAirportCode(
          depart
        ),
        havenaResolveAirportCode(
          destination
        ),
      ]);

      const search = {
        departureCode,
        destinationCode,
        dateAller,
        dateRetour:
          dateRetour || "",
        adultes:
          Math.max(
            1,
            Number(adultes) || 1
          ),
        enfants:
          Math.max(
            0,
            Number(enfants) || 0
          ),
      };

      console.log(
        "HAVENA MASTER GUIDE - recherche vols :",
        search
      );

      const {
        results,
        sources,
      } =
        await havenaRunFlightSources(
          search
        );

      return res.json({
        ok: true,

        search: {
          depart,
          departureCode,
          destination,
          destinationCode,
          dateAller,
          dateRetour:
            dateRetour || "",
          adultes:
            search.adultes,
          enfants:
            search.enfants,
        },

        resultCount:
          results.length,

        results,

        sources,

        checkedAt:
          new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        "Erreur HAVENA MASTER GUIDE vols :",
        error
      );

      return res
        .status(500)
        .json({
          ok: false,
          message:
            error?.message ||
            "Erreur moteur vols HAVENA.",
        });
    }
  }
);
/* ======================================================
   HAVENA MASTER GUIDE - ROUTE RECHERCHE VOLS
====================================================== */



app.post("/api/travel/search-flights", async (req, res) => {
  try {
    const {
      depart,
      destination,
      dateAller,
      dateRetour,
      adultes = 1,
      enfants = 0,
    } = req.body || {};

    if (!depart || !destination || !dateAller) {
      return res.status(400).json({
        ok: false,
        message:
          "Départ, destination et date aller sont obligatoires.",
      });
    }

    const recherche = {
      depart: String(depart).trim(),
      destination: String(destination).trim(),
      dateAller: String(dateAller).trim(),
      dateRetour: String(dateRetour || "").trim(),
      adultes: Math.max(1, Number(adultes) || 1),
      enfants: Math.max(0, Number(enfants) || 0),
    };

    console.log(
      "HAVENA MASTER GUIDE - recherche vols :",
      recherche
    );

   const resultat = await rechercherVolsHAVENA(
  SOURCES_VOLS_HAVENA,
  recherche
);

    return res.json(resultat);
  } catch (error) {
    console.error(
      "Erreur moteur vols HAVENA :",
      error
    );

    return res.status(500).json({
      ok: false,
      message:
        error?.message ||
        "Erreur pendant la recherche de vols.",
    });
  }
});
app.listen(PORT, () => {
  console.log(`HAVENA server lancé sur le port ${PORT}`);
});