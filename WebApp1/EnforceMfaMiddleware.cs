using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Middleware that ensures that requests to protected resources are only forwarded if a user who needs to use 2fa has set it up correctly.
/// </summary>
public class EnforceMfaMiddleware
{
	private readonly RequestDelegate _next;
	private const string s_mfaSetupPath = "/Identity/Account/Manage/EnableAuthenticator";

	public EnforceMfaMiddleware(RequestDelegate next)
	{
		_next = next;
	}

	public async Task Invoke(HttpContext context)
	{
		var endpoint = context.GetEndpoint();
		var isProtected = endpoint?.Metadata.GetMetadata<AuthorizeAttribute>() != null;

		if (isProtected)
		{
			var userAuthenticated = context.User?.Identity is not null && context.User.Identity.IsAuthenticated;
			var pathAllowed = IsPathProtectedButAllowed(context.Request.Path);
			if (userAuthenticated && !pathAllowed)
			{
				var mfaRequired = context!.User!.HasClaim("enforceMfa", "true");
				var mfaUsed = context!.User!.HasClaim("amr", "mfa");

				if (mfaRequired && !mfaUsed)
				{
					context.Response.Redirect(s_mfaSetupPath);
					return;
				}
			}
		}

		await _next(context);
	}

	private static bool IsPathProtectedButAllowed(string path)
	{
		return path == s_mfaSetupPath || path == "/Identity/Account/Logout";
    }
}