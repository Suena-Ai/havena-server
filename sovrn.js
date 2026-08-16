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
async function findSovrnMerchantByName(name) {
  const secretKey =
    process.env.SOVRN_SECRET_KEY;

  const campaignId =
    process.env.SOVRN_CAMPAIGN_ID;

  if (!secretKey) {
    throw new Error(
      "SOVRN_SECRET_KEY manquante"
    );
  }

  if (!campaignId) {
    throw new Error(
      "SOVRN_CAMPAIGN_ID manquant"
    );
  }

  const response = await fetch(
    `${SOVRN_MERCHANTS_URL}?campaignId=${encodeURIComponent(
      campaignId
    )}`,
    {
      method: "POST",

      headers: {
        Authorization:
          `secret ${secretKey}`,

        "Content-Type":
          "application/json",

        Accept:
          "application/json",
      },

      body: JSON.stringify({
        filters: [
          {
            type: "NAME",
            values: [name],
          },
        ],

        page: 1,
        pageSize: 50,
      }),
    }
  );

  const text =
    await response.text();

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(
      `Erreur Sovrn ${response.status}: ${
        typeof data === "string"
          ? data
          : JSON.stringify(data)
      }`
    );
  }

  return Array.isArray(data?.results)
    ? data.results
    : [];
}
async function optimizeSovrnLink(
  destinationUrl,
  geo = "FR"
) {
  const apiKey = String(
    process.env.SOVRN_API_KEY || ""
  ).trim();

  if (!apiKey || !destinationUrl) {
    return {
      affiliatable: false,
      optimized: destinationUrl || "",
    };
  }

  const url = new URL(
    "https://api.viglink.com/api/link/"
  );

  url.searchParams.set(
    "out",
    destinationUrl
  );

  url.searchParams.set(
    "key",
    apiKey
  );

  url.searchParams.set(
    "optimize",
    "true"
  );

  url.searchParams.set(
    "format",
    "json"
  );

  url.searchParams.set(
    "geo",
    geo
  );

  const response =
    await fetch(url.toString());

  if (!response.ok) {
    return {
      affiliatable: false,
      optimized: destinationUrl,
    };
  }

  const data =
    await response.json();

  return {
    affiliatable:
      data?.affiliatable === true,

    optimized:
      data?.optimized ||
      destinationUrl,

    eepc:
      data?.eepc ?? null,
  };
}
module.exports = {
  getSovrnApprovedMerchants,
};