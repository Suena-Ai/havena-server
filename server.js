const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const supabase = require("./supabase");
const Stripe = require("stripe");
const transporter = require("./mailer");
const multer = require("multer");

dotenv.config();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const FRONTEND_URL = "https://havena-front.onrender.com";

function containsForbiddenContactInfo(text = "") {
  const value = String(text || "").toLowerCase().trim();
  const phoneRegex =
    /(?:\+?\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?)?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}/i;
  const emailRegex =
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/i;
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
  const hasForbiddenWord = forbiddenWords.some((word) => value.includes(word));
  return (
    phoneRegex.test(text) ||
    emailRegex.test(text) ||
    linkRegex.test(text) ||
    hasForbiddenWord
  );
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
    const { firstName, lastName, email, password, role } = req.body;

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
      .select("*")
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

    const newUser = {
      first_name: String(firstName).trim(),
      last_name: String(lastName).trim(),
      email: normalizedEmail,
      password: String(password),
      role: normalizedRole,
      email_confirmed: false,
      created_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from("havena_users")
      .insert([newUser])
      .select();

    if (error) {
      return res.status(500).json({
        ok: false,
        message: "Erreur création utilisateur",
        error: error.message,
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Compte créé",
      user: data[0],
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
      .select("*")
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

    if (String(user.password) !== String(password)) {
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
      .select("*")
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

      await supabase
        .from("logements")
        .update({
          stripe_account_id: stripeAccountId,
        })
        .eq("hebergeur_email", normalizedEmail);
    }

    const accountLink = await stripe.accountLinks.create({
      account: stripeAccountId,
      refresh_url: `${FRONTEND_URL}/hebergeur/stripe-connect?refresh=1`,
      return_url: `https://havena-server.onrender.com/api/stripe/connect/complete?account=${encodeURIComponent(
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
      .select("*")
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
              name: `Réservation HAVENA - ${logement.titre || `${prenom} ${nom}`}`,
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
      success_url: "https://havena-front.onrender.com/reservation/success",
      cancel_url: "https://havena-front.onrender.com/reservation/cancel",
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
      stripe_account_id,
    } = req.body;

    if (!titre || !type || !ville) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
      });
    }

    let image_url = "";

    if (req.file) {
      const fileExt = req.file.originalname.split(".").pop();
      const fileName = `logement_${Date.now()}.${fileExt}`;

      const { error: uploadError } = await supabase.storage
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

      const { data: publicUrlData } = supabase.storage
        .from("logements")
        .getPublicUrl(fileName);

      image_url = publicUrlData.publicUrl;
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
      hebergeur_email: hebergeur_email || "",
      hebergeur_nom: hebergeur_nom || "",
      disponibilites: disponibilites || "",
      telephone: telephone || "",
      stripe_account_id: stripe_account_id || "",
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
    return res.status(500).json({
      ok: false,
      message: "Erreur serveur",
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
    });
  }
});

app.put("/api/logements/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { disponibilites } = req.body;

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
    } = req.body;

    if (!titre || !ville || !contrat) {
      return res.status(400).json({
        ok: false,
        message: "Champs obligatoires manquants",
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

app.listen(PORT, () => {
  console.log(`HAVENA server lancé sur le port ${PORT}`);
});
