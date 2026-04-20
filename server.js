const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const supabase = require("./supabase");
const Stripe = require("stripe");
const transporter = require("./mailer");

dotenv.config();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "HAVENA server opérationnel",
  });
});

app.post("/api/stripe/create-checkout-session", async (req, res) => {
  try {
    const { montant, prenom, nom, email, reservationId } = req.body;

    if (!montant || !prenom || !nom || !email) {
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

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      customer_email: email,
      metadata: {
        reservationId: String(reservationId || ""),
      },
      line_items: [
        {
          price_data: {
            currency: "eur",
            product_data: {
              name: `Réservation HAVENA - ${prenom} ${nom}`,
            },
            unit_amount: montantNumber * 100,
          },
          quantity: 1,
        },
      ],
      success_url: "http://localhost:3000/reservation/success",
      cancel_url: "http://localhost:3000/reservation/cancel",
    });

    return res.json({
      ok: true,
      url: session.url,
      reservationId,
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

const PORT = process.env.PORT || 5055;

app.listen(PORT, () => {
  console.log(`HAVENA server lancé sur le port ${PORT}`);
});
