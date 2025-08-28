// import { env } from "cloudflare:workers";
import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { Octokit } from "octokit";
import type { Props, ExtendedEnv } from "../types";
import {
	clientIdAlreadyApproved,
	parseRedirectApproval,
	renderApprovalDialog,
	fetchUpstreamAuthToken,
	getUpstreamAuthorizeUrl,
} from "./oauth-utils";
const app = new Hono<{ Bindings: ExtendedEnv }>();

app.get("/authorize", async (c) => {
	console.log("Environment variables:", {
		GITHUB_CLIENT_ID: (c.env as any).GITHUB_CLIENT_ID,
		GITHUB_CLIENT_SECRET: (c.env as any).GITHUB_CLIENT_SECRET,
		COOKIE_ENCRYPTION_KEY: (c.env as any).COOKIE_ENCRYPTION_KEY,
		OAUTH_KV: !!c.env.OAUTH_KV
	});
	
	try {
		console.log("Parsing OAuth request...");
		const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
		console.log("OAuth request parsed:", oauthReqInfo);
		
		const { clientId } = oauthReqInfo;
		if (!clientId) {
			console.log("No clientId found, returning 400");
			return c.text("Invalid request", 400);
		}
		
		console.log("Checking if client already approved...");
		if (
			await clientIdAlreadyApproved(c.req.raw, oauthReqInfo.clientId, (c.env as any).COOKIE_ENCRYPTION_KEY)
		) {
			console.log("Client already approved, redirecting to GitHub");
			return redirectToGithub(c.req.raw, oauthReqInfo, c.env, {});
		}
		
		console.log("Rendering approval dialog");
		return renderApprovalDialog(c.req.raw, {
			client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
			server: {
				description: "This is a demo MCP Remote Server using GitHub for authentication.",
				logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
				name: "Cloudflare GitHub MCP Server",
			},
			state: { oauthReqInfo },
		});
	} catch (error) {
		console.error("Error in /authorize:", error);
		return c.text(`Internal error: ${error.message}`, 500);
	}
});

app.post("/authorize", async (c) => {
	// Validates form submission, extracts state, and generates Set-Cookie headers to skip approval dialog next time
	const { state, headers } = await parseRedirectApproval(c.req.raw, (c.env as any).COOKIE_ENCRYPTION_KEY);
	if (!state.oauthReqInfo) {
		return c.text("Invalid request", 400);
	}

	return redirectToGithub(c.req.raw, state.oauthReqInfo, c.env, headers);
});

async function redirectToGithub(
	request: Request,
	oauthReqInfo: AuthRequest,
	env: Env,
	headers: Record<string, string> = {},
  ) {
	return new Response(null, {
	  headers: {
		...headers,
		location: getUpstreamAuthorizeUrl({
		  client_id: (env as any).GITHUB_CLIENT_ID,
		  redirect_uri: new URL("/callback", request.url).href, // Dynamic based on request hostname
		  scope: "read:user",
		  state: btoa(JSON.stringify(oauthReqInfo)),
		  upstream_url: "https://github.com/login/oauth/authorize",
		}),
	  },
	  status: 302,
	});
  }

/**
 * OAuth Callback Endpoint
 *
 * This route handles the callback from GitHub after user authentication.
 * It exchanges the temporary code for an access token, then stores some
 * user metadata & the auth token as part of the 'props' on the token passed
 * down to the client. It ends by redirecting the client back to _its_ callback URL
 */
app.get("/callback", async (c) => {
	// Get the oauthReqInfo from the state parameter
	let oauthReqInfo: AuthRequest;
	try {
	  oauthReqInfo = JSON.parse(atob(c.req.query("state") as string)) as AuthRequest;
	  console.log("Decoded oauthReqInfo:", JSON.stringify(oauthReqInfo)); // Optional log
	} catch (e) {
	  console.error("State decoding error:", e);
	  return c.text("Invalid state parameter", 400);
	}
  
	if (!oauthReqInfo.clientId) {
	  return c.text("Invalid state: missing clientId", 400);
	}
  
	// Log the received code and redirect_uri for debugging (optional)
	const code = c.req.query("code");
	console.log("Received code from GitHub:", code);
	const dynamicRedirectUri = new URL("/callback", c.req.url).href;
	console.log("Using redirect_uri for token exchange:", dynamicRedirectUri);
  
	// Exchange the code for an access token
	const [accessToken, errResponse] = await fetchUpstreamAuthToken({
	  client_id: (c.env as any).GITHUB_CLIENT_ID,
	  client_secret: (c.env as any).GITHUB_CLIENT_SECRET,
	  code: code,
	  redirect_uri: dynamicRedirectUri, // Dynamic based on request hostname
	  upstream_url: "https://github.com/login/oauth/access_token",
	});
	if (errResponse) {
	  const errorText = await errResponse.text();
	  console.error("Token exchange error:", errResponse.status, errorText);
	  return new Response(errorText, { status: errResponse.status });
	}
  
	// Fetch the user info from GitHub
	const user = await new Octokit({ auth: accessToken }).rest.users.getAuthenticated();
	const { login, name, email } = user.data;
  
	// Complete the authorization with OAuthProvider (this generates the provider code and redirectTo)
	const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
	  metadata: {
		label: name,
	  },
	  props: {
		accessToken,
		email,
		login,
		name,
	  } as Props,
	  request: oauthReqInfo,
	  scope: oauthReqInfo.scope,
	  userId: login,
	});
  
	console.log("Redirecting to client:", redirectTo); // Optional log
	return Response.redirect(redirectTo);
  });

export { app as GitHubHandler };
