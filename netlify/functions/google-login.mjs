
import { GoogleAuth } from "google-auth-library";
import admin from "firebase-admin";

const corsHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "https://linkshear.netlify.app",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

export default async (request) => {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }

  if (request.method !== "POST") {
    return Response.json(
      { error: "Method not allowed" },
      { status: 405, headers: corsHeaders }
    );
  }

  try {
    const { credential } = await request.json();

    if (!credential || typeof credential !== "string") {
      return Response.json(
        { error: "Google credential is required" },
        { status: 400, headers: corsHeaders }
      );
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const serviceAccountJson =
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

    if (!clientId || !serviceAccountJson) {
      throw new Error("Server environment is not configured");
    }

    const googleAuth = new GoogleAuth({
      credentials: JSON.parse(serviceAccountJson)
    });

    const ticket = await new (await import("google-auth-library"))
      .OAuth2Client(clientId)
      .verifyIdToken({
        idToken: credential,
        audience: clientId
      });

    const payload = ticket.getPayload();

    if (!payload?.sub || !payload.email || !payload.email_verified) {
      return Response.json(
        { error: "Google account could not be verified" },
        { status: 401, headers: corsHeaders }
      );
    }

    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(
          JSON.parse(serviceAccountJson)
        )
      });
    }

    const uid = `google_${payload.sub}`;

    try {
      await admin.auth().getUser(uid);
    } catch (error) {
      if (error.code !== "auth/user-not-found") throw error;

      await admin.auth().createUser({
        uid,
        email: payload.email,
        emailVerified: true,
        displayName: payload.name || "",
        photoURL: payload.picture || ""
      });
    }

    const token = await admin.auth().createCustomToken(uid);

    return Response.json(
      { token },
      { status: 200, headers: corsHeaders }
    );
  } catch (error) {
    console.error("Google login failed:", error.message);

    return Response.json(
      { error: "Google sign-in failed. Check server settings." },
      { status: 500, headers: corsHeaders }
    );
  }
};

export const config = {
  path: "/.netlify/functions/google-login"
};
