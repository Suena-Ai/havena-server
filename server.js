const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const crypto = require("crypto");
const supabase = require("./supabase");
const Stripe = require("stripe");
const transporter = require("./mailer");
const multer = require("multer");
const bcrypt = require("bcryptjs");

dotenv.config();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const FRONTEND_URL = "https://www.havena1.fr";
const BACKEND_URL = "https://havena-server.onrender.com";

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

          if (reservation?.email) {
            try {
              await transporter.sendMail({
                from: process.env.MAIL_USER,
                to: reservation.email,
                subject: "Paiement confirmé - Réservation HAVENA",
                text:
                  `Bonjour ${reservation.prenom || ""},\n\n` +
                  `Votre paiement a bien été confirmé.\n` +
                  `Logement : ${logement?.titre || "Logement réservé"}\n` +
                  `Ville : ${reservation.ville || logement?.ville || ""}\n` +
                  `Type : ${reservation.type || logement?.type || ""}\n` +
                  `Dates : ${reservation.dates || ""}\n` +
                  `Acompte payé : ${reservation.acompte || ""}\n\n` +
                  `Merci,\nHAVENA`,
              });

              await supabase
                .from("reservations")
                .update({ confirmation_envoyee_client: true })
                .eq("id", reservationId);
            } catch (mailError) {
              console.error("Erreur mail confirmation client :", mailError);
            }
          }

          if (logement?.hebergeur_email) {
            try {
              await transporter.sendMail({
                from: process.env.MAIL_USER,
                to: logement.hebergeur_email,
                subject: "Nouvelle réservation confirmée - HAVENA",
                text:
                  `Bonjour ${logement.hebergeur_nom || "Hébergeur"},\n\n` +
                  `Une réservation a été confirmée pour votre logement.\n` +
                  `Logement : ${logement.titre || ""}\n` +
                  `Client : ${reservation?.prenom || ""} ${reservation?.nom || ""}\n` +
                  `Email client : ${reservation?.email || ""}\n` +
                  `Dates : ${reservation?.dates || ""}\n` +
                  `Acompte payé : ${reservation?.acompte || ""}\n\n` +
                  `HAVENA`,
              });

              await supabase
                .from("reservations")
                .update({ confirmation_envoyee_hebergeur: true })
                .eq("id", reservationId);
            } catch (mailError) {
              console.error("Erreur mail confirmation hébergeur :", mailError);
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
    } = req.body;

    if (!firstName || !lastName || !email || !password || !role) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedRole = String(role).trim().toLowerCase();

    const allowedRoles = ["saisonnier", "etudiant", "employeur", "hebergeur"];

    if (!allowedRoles.includes(normalizedRole)) {
      return res.status(400).json({
        ok: false,
        message: "Rôle invalide",
      });
    }

    const { data: existingUser, error: existingError } = await supabase
      .from("havena_users")
      .select("id, email, role")
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
      if (existingUser.role !== normalizedRole) {
        return res.status(409).json({
          ok: false,
          message: "Cette adresse email est déjà utilisée avec un autre profil.",
        });
      }

      return res.status(409).json({
        ok: false,
        message:
          "Cette adresse email est déjà utilisée pour ce profil. Veuillez vous connecter.",
      });
    }

    const requiredCandidateFields = [
      poste_recherche,
      mois_disponible,
      periode_disponible,
      niveau_etudes,
      experiences,
      competences,
      langues,
      mobilite,
      type_contrat_recherche,
      secteur_recherche,
      presentation,
    ];

    if (
      (normalizedRole === "saisonnier" || normalizedRole === "etudiant") &&
      requiredCandidateFields.some((field) => !String(field || "").trim())
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Pour créer un compte candidat HAVENA, veuillez compléter les informations essentielles de votre profil : poste recherché, disponibilité, expérience, compétences, langues, mobilité, type de contrat, secteur recherché et présentation.",
      });
    }

    const publicRegisterCandidateFields = [
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
      (normalizedRole === "saisonnier" || normalizedRole === "etudiant") &&
      publicRegisterCandidateFields.some((field) => containsForbiddenContactInfo(field))
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    const hashedPassword = await bcrypt.hash(String(password), 12);

    const newUser = {
      first_name: String(firstName).trim(),
      last_name: String(lastName).trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: normalizedRole,
      email_confirmed: false,
      created_at: new Date().toISOString(),
      ...(normalizedRole === "saisonnier" || normalizedRole === "etudiant"
        ? {
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
          }
        : {}),
    };

    const { data, error } = await supabase
      .from("havena_users")
      .insert([newUser])
      .select(
        `
        id,
        first_name,
        last_name,
        email,
        role,
        email_confirmed,
        stripe_account_id,
        created_at
      `
      )
      .single();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur création utilisateur",
        error: error.message,
      });
    }

    const confirmToken = buildEmailConfirmToken(normalizedEmail);
    const confirmLink = `${FRONTEND_URL}/confirm-email?token=${encodeURIComponent(
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
      console.error("Erreur envoi email confirmation :", mailError);
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

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedRole = String(role).trim().toLowerCase();

    const { data: user, error } = await supabase
      .from("havena_users")
      .select(
        `
        id,
        email,
        password,
        role,
        first_name,
        last_name,
        email_confirmed,
        stripe_account_id
      `
      )
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

    if (user.role !== normalizedRole) {
      return res.status(403).json({
        ok: false,
        message: `Cette adresse email est déjà liée au profil "${user.role}".`,
      });
    }

    if (!user.email_confirmed) {
      return res.status(403).json({
        ok: false,
        message:
          "Veuillez confirmer votre adresse email avant de vous connecter. Un lien de confirmation vous a été envoyé par email.",
      });
    }

    const storedPassword = String(user.password || "");
    const incomingPassword = String(password || "");

    let passwordIsValid = false;

    if (storedPassword.startsWith("$2a$") || storedPassword.startsWith("$2b$")) {
      passwordIsValid = await bcrypt.compare(incomingPassword, storedPassword);
    } else {
      passwordIsValid = storedPassword === incomingPassword;

      if (passwordIsValid) {
        const hashedPassword = await bcrypt.hash(incomingPassword, 12);

        await supabase
          .from("havena_users")
          .update({ password: hashedPassword })
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
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
        email_confirmed: user.email_confirmed,
        stripe_account_id: user.stripe_account_id || "",
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
    const { montant, prenom, nom, email, reservationId, logementId } = req.body;

    if (!montant || !prenom || !nom || !email || !reservationId || !logementId) {
      return res.status(400).json({
        ok: false,
        message: "Données Stripe manquantes",
      });
    }

    const montantNumber = Number(String(montant).replace(/[^\d]/g, ""));

    if (!montantNumber || montantNumber <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Montant invalide",
      });
    }

    const { data: logement, error: logementError } = await supabase
      .from("logements")
      .select("*")
      .eq("id", Number(logementId))
      .single();

    if (logementError || !logement) {
      return res.status(404).json({
        ok: false,
        message: "Logement introuvable",
      });
    }

    if (!logement.stripe_account_id) {
      return res.status(400).json({
        ok: false,
        message: "Ce logement n’a pas de compte Stripe connecté.",
      });
    }

    const unitAmount = montantNumber * 100;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: email,
      metadata: {
        reservationId: String(reservationId),
        logementId: String(logementId),
      },
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: `Réservation HAVENA - ${logement.titre || `${prenom} ${nom}`}`,
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
      applicationFeeAmount: 0,
      commission: "0%",
    });
  } catch (err) {
    console.error("Erreur création checkout Stripe :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur Stripe",
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
      prenom,
      nom,
      email,
      telephone,
      ville,
      type,
      dates,
      voyageurs,
      montant,
      acompte,
      role,
      message,
    } = req.body;

    if (!prenom || !nom || !email) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const reservation = {
      prenom,
      nom,
      email,
      telephone: telephone || "",
      ville: ville || "",
      type: type || "",
      dates: dates || "",
      voyageurs: voyageurs || "",
      montant: montant || "",
      acompte: acompte || "",
      role: role || "",
      message: message || "",
      payment_status: "pending",
      confirmation_envoyee_client: false,
      confirmation_envoyee_hebergeur: false,
      statut: "reçue",
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
      message: "Réservation enregistrée",
      reservation: data[0],
    });
  } catch (err) {
    console.error("Erreur serveur réservation :", err);

    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
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

app.post("/api/logements", upload.single("image"), async (req, res) => {
  try {
    const {
      titre,
      type,
      ville,
      adresse,
      surface,
      chambres,
      couchages,
      prix,
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
    } = req.body;

    if (!titre || !type || !ville) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    const publicLogementFields = [
      titre,
      type,
      ville,
      adresse,
      surface,
      chambres,
      couchages,
      prix,
      animaux_acceptes,
      fumeur_accepte,
      equipements,
      description,
      statut,
      jardin,
      parking,
      wifi,
      disponibilites,
    ];

    if (publicLogementFields.some((field) => containsForbiddenContactInfo(field))) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    if (telephone && containsForbiddenContactInfo(telephone)) {
      return res.status(400).json({
        ok: false,
        message:
          "Le téléphone ne doit pas être publié dans une annonce. Le contact doit passer par la messagerie HAVENA.",
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

    if (req.file) {
      const mimeToExt = {
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "image/gif": "gif",
        "image/avif": "avif",
        "image/svg+xml": "svg",
      };

      const safeExt =
        mimeToExt[req.file.mimetype] ||
        String(req.file.originalname || "").split(".").pop()?.toLowerCase() ||
        "jpg";

      const fileName = `logement_${Date.now()}.${safeExt}`;

      const { data: uploadData, error: uploadError } = await supabase.storage
        .from("logements")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
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

      image_url = publicUrlData?.publicUrl || "";
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
      prix: prix || "",
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

    const { error } = await supabase.from("logements").delete().eq("id", id);

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
      animaux_acceptes,
      fumeur_accepte,
      equipements,
      description,
      statut,
      jardin,
      parking,
      wifi,
      telephone,
    } = req.body;

    const publicLogementUpdateFields = [
      titre,
      type,
      ville,
      adresse,
      surface,
      chambres,
      couchages,
      prix,
      animaux_acceptes,
      fumeur_accepte,
      equipements,
      description,
      statut,
      jardin,
      parking,
      wifi,
      disponibilites,
    ];

    if (
      publicLogementUpdateFields.some((field) => containsForbiddenContactInfo(field))
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Coordonnées directes interdites. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    if (telephone && containsForbiddenContactInfo(telephone)) {
      return res.status(400).json({
        ok: false,
        message:
          "Le téléphone ne doit pas être publié dans une annonce. Le contact doit passer par la messagerie HAVENA.",
      });
    }

    const { data, error } = await supabase
      .from("logements")
      .update({
        disponibilites: disponibilites || "",
      })
      .eq("id", id)
      .select();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur mise à jour logement",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      message: "Disponibilités mises à jour",
      logement: data?.[0] || null,
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
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
      .order("updated_at", { ascending: false })
      .limit(20);

    if (error) {
      console.error("Erreur lecture publicités actives :", error);
      return res.status(500).json({
        ok: false,
        message: "Erreur lecture publicités actives.",
        error: error.message,
      });
    }

    const ads = [];

    for (const ad of data || []) {
      const ownerEmail = normalizeEmail(ad.owner_email);
      const isAdminOwner = ownerEmail === "fasterame@gmail.com";

      if (isAdminOwner) {
        ads.push(ad);
        continue;
      }

      const subscriptionActive = await isProfessionalSubscriptionActive(ownerEmail);

      if (subscriptionActive) {
        ads.push(ad);
      }
    }

    return res.json({
      ok: true,
      ads,
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
  const title = normalizePromotionText(promo.title);
  const description = normalizePromotionText(promo.description);
  const promoCode = normalizePromotionText(promo.promo_code);
  const partnerName = normalizePromotionText(promo.partner_name);

  const fullText = `${title} ${description} ${promoCode} ${partnerName}`;

  const hasPromoCode =
    promoCode &&
    promoCode !== "empty" &&
    promoCode !== "null" &&
    promoCode !== "undefined";

  const hasPercentDiscount = /(^|\D)([1-9][0-9]?|100)\s?%/.test(fullText);

  const hasStrongPromoKeyword =
    fullText.includes("discount") ||
    fullText.includes("off") ||
    fullText.includes("coupon") ||
    fullText.includes("voucher") ||
    fullText.includes("promo code") ||
    fullText.includes("code promo") ||
    fullText.includes("rabatt") ||
    fullText.includes("gutschein") ||
    fullText.includes("reduction") ||
    fullText.includes("remise") ||
    fullText.includes("descuento") ||
    fullText.includes("sconto") ||
    fullText.includes("promocao") ||
    fullText.includes("promocion");

  const hasClearSpecialOffer =
    fullText.includes("special offer") ||
    fullText.includes("offre speciale") ||
    fullText.includes("offre spéciale") ||
    fullText.includes("sale") ||
    fullText.includes("deal");

  const isOnlyHotelDescription =
    title.startsWith("neue hotel") ||
    title.includes("new hotel") ||
    title.includes("nouvel hotel") ||
    title.includes("nouvel hôtel");

  if (isOnlyHotelDescription && !hasPromoCode && !(hasPercentDiscount && hasStrongPromoKeyword)) {
    return false;
  }

  if (hasPromoCode) {
    return true;
  }

  if (hasPercentDiscount && hasStrongPromoKeyword) {
    return true;
  }

  if (hasClearSpecialOffer && hasStrongPromoKeyword) {
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
      .limit(200);

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
async function syncCjPartnerPromotions(rulesMap) {
  const cjToken = String(process.env.CJ_API_TOKEN || "").trim();
const cjWebsiteId = String(process.env.CJ_WEBSITE_ID || "").trim();
  if (!cjToken) {
    throw new Error("Variable CJ manquante : CJ_API_TOKEN.");
  }
if (!cjWebsiteId) {
  throw new Error("Variable CJ manquante : CJ_WEBSITE_ID.");
}

const params = new URLSearchParams();
params.append("website-id", cjWebsiteId);
params.append("advertiser-ids", "joined");
params.append("records-per-page", "100");
params.append("page-number", "1");

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
  });

  throw new Error(
    `Erreur API CJ Link Search : ${response.status} ${response.statusText} - ${responseText}`
  );
}

const cjLinksFromXml = extractCjLinksFromXml(responseText);
const cjLinks =
  cjLinksFromXml.length > 0
    ? cjLinksFromXml
    : extractCjLinksFromResponse(data);


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
        promo_code: "",
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

app.listen(PORT, () => {
  console.log(`HAVENA server lancé sur le port ${PORT}`);
});