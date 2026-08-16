const SOVRN_MERCHANTS_URL =
  "https://viglink.io/merchants/rates/summaries";

async function getSovrnApprovedMerchants({
  category = "TV",
  page = 1,
  pageSize = 1000,
} = {}) {
  const secretKey = process.env.SOVRN_SECRET_KEY;
  const campaignId = process.env.SOVRN_CAMPAIGN_ID;

  if (!secretKey) {
    throw new Error("SOVRN_SECRET_KEY manquante");
  }

  if (!campaignId) {
    throw new Error("SOVRN_CAMPAIGN_ID manquant");
  }

  const response = await fetch(
    `${SOVRN_MERCHANTS_URL}?campaignId=${encodeURIComponent(campaignId)}`,
    {
      method: "POST",

      headers: {
        Authorization: `secret ${secretKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },

      body: JSON.stringify({
        filters: [
          {
            type: "CATEGORY",
            values: [category],
          },
        ],
        page,
        pageSize,
      }),
    }
  );

  const text = await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(
      `Erreur Sovrn ${response.status} : ${
        typeof data === "string" ? data : JSON.stringify(data)
      }`
    );
  }

  return data;
}

module.exports = {
  getSovrnApprovedMerchants,
};