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
    return new RegExp(`(^|\\s|[.,;:!?()\\-])${escapedWord}(\\s|$|[.,;:!?()\\-])`, "i").test(value);
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
  const normalizedEmail = String(email || "").trim().toLowerCase();
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

    const normalizedEmail = String(email || "").trim().toLowerCase();

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
  const normalizedEmail = String(email || "").trim().toLowerCase();
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

    const normalizedEmail = String(email || "").trim().toLowerCase();

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
        const reservationId = session?.metadata?.reservationId;
        const logementId = session?.metadata?.logementId;
        const unlockType = session?.metadata?.type;
        const unlockId = session?.metadata?.unlockId;

        if (unlockType === "message_unlock" && unlockId) {
          await supabase
            .from("message_unlocks")
            .update({
              payment_status: "paid",
              unlocked_at: new Date().toISOString(),
              stripe_session_id: session.id,
            })
            .eq("id", unlockId);

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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "HAVENA server opérationnel",
  });
});

/* =========================
   AUTH HAVENA
   1 EMAIL = 1 SEUL ROLE
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

    const normalizedEmail = String(email).trim().toLowerCase();
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
      publicRegisterCandidateFields.some((field) =>
        containsForbiddenContactInfo(field)
      )
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
      .select(`
        id,
        first_name,
        last_name,
        email,
        role,
        email_confirmed,
        stripe_account_id,
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

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedRole = String(role).trim().toLowerCase();

    const { data: user, error } = await supabase
      .from("havena_users")
      .select(`
        id,
        email,
        password,
        role,
        first_name,
        last_name,
        email_confirmed,
        stripe_account_id
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

    const normalizedEmail = String(email || "").trim().toLowerCase();

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
    const normalizedEmail = String(email || "").trim().toLowerCase();

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

    const normalizedEmail = String(email || "").trim().toLowerCase();
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
   STRIPE CONNECT HEBERGEUR
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

    const normalizedEmail = String(hebergeurEmail).trim().toLowerCase();

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
    const normalizedEmail = String(email).trim().toLowerCase();

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

    const normalizedEmail = String(hebergeurEmail).trim().toLowerCase();

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

    if (
      !montant ||
      !prenom ||
      !nom ||
      !email ||
      !reservationId ||
      !logementId
    ) {
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
    const applicationFeeAmount = Math.round(unitAmount * 0.06);

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
              name: `Réservation HAVENA - ${
                logement.titre || `${prenom} ${nom}`
              }`,
            },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      payment_intent_data: {
        application_fee_amount: applicationFeeAmount,
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
      applicationFeeAmount,
    });
  } catch (err) {
    console.error("Erreur création checkout Stripe :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur Stripe",
    });
  }
});

// ===============================
// STRIPE - DÉBLOCAGE MESSAGERIE CANDIDAT 3€
// ===============================

app.post("/api/stripe/create-message-unlock-session", async (req, res) => {
  try {
    const { employerEmail, candidateId } = req.body;

    if (!employerEmail || !candidateId) {
      return res.status(400).json({
        ok: false,
        message: "Données manquantes pour débloquer la messagerie",
      });
    }

    const normalizedEmployerEmail = String(employerEmail).trim().toLowerCase();
    const normalizedCandidateId = Number(candidateId);

    if (!normalizedEmployerEmail || !normalizedCandidateId) {
      return res.status(400).json({
        ok: false,
        message: "Email employeur ou candidat invalide",
      });
    }

    const { data: existingUnlock, error: existingError } = await supabase
      .from("message_unlocks")
      .select("*")
      .eq("employer_email", normalizedEmployerEmail)
      .eq("candidate_id", normalizedCandidateId)
      .eq("payment_status", "paid")
      .maybeSingle();

    if (existingError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur vérification déblocage",
        error: existingError.message,
      });
    }

    if (existingUnlock) {
      return res.json({
        ok: true,
        alreadyUnlocked: true,
        message: "Messagerie déjà débloquée pour ce candidat",
      });
    }

    const { data: pendingUnlock, error: insertError } = await supabase
      .from("message_unlocks")
      .insert([
        {
          employer_email: normalizedEmployerEmail,
          candidate_id: normalizedCandidateId,
          amount_cents: 300,
          payment_status: "pending",
        },
      ])
      .select()
      .single();

    if (insertError) {
      return res.status(500).json({
        ok: false,
        message: "Erreur création déblocage messagerie",
        error: insertError.message,
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: normalizedEmployerEmail,
      metadata: {
        type: "message_unlock",
        unlockId: String(pendingUnlock.id),
        employerEmail: normalizedEmployerEmail,
        candidateId: String(normalizedCandidateId),
      },
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: "Déblocage messagerie candidat HAVENA",
              description: "Ouverture de la messagerie interne avec un candidat",
            },
            unit_amount: 300,
          },
          quantity: 1,
        },
      ],
      success_url: `${
        process.env.STRIPE_SUCCESS_URL || FRONTEND_URL
      }/candidats/${normalizedCandidateId}?message_unlocked=success`,
      cancel_url: `${
        process.env.STRIPE_CANCEL_URL || FRONTEND_URL
      }/candidats/${normalizedCandidateId}?message_unlocked=cancel`,
    });

    await supabase
      .from("message_unlocks")
      .update({
        stripe_session_id: session.id,
      })
      .eq("id", pendingUnlock.id);

    return res.json({
      ok: true,
      url: session.url,
    });
  } catch (err) {
    console.error("Erreur création session déblocage messagerie :", err);
    return res.status(500).json({
      ok: false,
      message: "Erreur Stripe déblocage messagerie",
      error: err.message,
    });
  }
});

// ===============================
// VÉRIFIER SI LA MESSAGERIE EST DÉBLOQUÉE
// ===============================

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

    const normalizedEmployerEmail = String(employerEmail).trim().toLowerCase();
    const normalizedCandidateId = Number(candidateId);

    const { data, error } = await supabase
      .from("message_unlocks")
      .select("*")
      .eq("employer_email", normalizedEmployerEmail)
      .eq("candidate_id", normalizedCandidateId)
      .eq("payment_status", "paid")
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        unlocked: false,
        message: "Erreur vérification messagerie",
        error: error.message,
      });
    }

    return res.json({
      ok: true,
      unlocked: !!data,
    });
  } catch (err) {
    console.error("Erreur vérification déblocage messagerie :", err);
    return res.status(500).json({
      ok: false,
      unlocked: false,
      message: "Erreur serveur vérification messagerie",
      error: err.message,
    });
  }
});

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

    console.log("Nouvelle réservation HAVENA :", data);

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

    if (
      publicLogementFields.some((field) => containsForbiddenContactInfo(field))
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

    const normalizedHebergeurEmail = String(hebergeur_email || "")
      .trim()
      .toLowerCase();

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

// ===============================
// DISPONIBILITÉS LOGEMENTS HAVENA
// ===============================

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
      publicLogementUpdateFields.some((field) =>
        containsForbiddenContactInfo(field)
      )
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
      employeur_email: employeur_email
        ? String(employeur_email).trim().toLowerCase()
        : "",
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
      publicOffreUpdateFields.some((field) =>
        containsForbiddenContactInfo(field)
      )
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

// ===============================
// CANDIDATURES EMPLOI HAVENA
// ===============================

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
      publicCandidatureFields.some((field) =>
        containsForbiddenContactInfo(field)
      )
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
        employeurEmail = String(offreData.employeur_email)
          .trim()
          .toLowerCase();
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

const PORT = process.env.PORT || 5055;

// ===============================
// SAISONNIERS HAVENA
// ===============================

app.get("/api/saisonniers", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("havena_users")
      .select(`
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
      `)
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

// ===============================
// CANDIDATS HAVENA
// Saisonniers + étudiants
// ===============================

app.get("/api/candidats", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("havena_users")
      .select(`
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
      `)
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

// ===============================
// MISE À JOUR PROFIL CANDIDAT HAVENA
// Saisonnier / Étudiant
// ===============================

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

    const normalizedEmail = String(email).trim().toLowerCase();

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
      publicCandidateProfileFields.some((field) =>
        containsForbiddenContactInfo(field)
      )
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
      .select(`
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
      `)
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

app.listen(PORT, () => {
  console.log(`HAVENA server lancé sur le port ${PORT}`);
});