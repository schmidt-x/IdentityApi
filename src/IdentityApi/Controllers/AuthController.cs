using System;
using System.Threading;
using System.Threading.Tasks;
using IdentityApi.Contracts.DTOs;
using IdentityApi.Filters;
using IdentityApi.Responses;
using IdentityApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApi.Controllers;

[Consumes("application/json")]
[Produces("application/json")]
[ApiController, Route("api/[controller]")]
[AllowAnonymous]
public class AuthController : ControllerBase
{
	private readonly IAuthService _authService;
	private readonly IEmailService _emailService;

	public AuthController(IAuthService authService, IEmailService emailService)
	{
		_authService = authService;
		_emailService = emailService;
	}
	
	
	/// <summary>
	/// Sends a verification code to email
	/// </summary>
	/// <response code="200">Verification code is sent and the session id is retured in cookie</response>
	/// <response code="400">Email address is already taken or invalid</response>
	[HttpPost("session")]
	[ProducesResponseType(typeof(SessionSuccessResponse), 200)]
	[ProducesResponseType(typeof(FailResponse), 400)]
	public async Task<IActionResult> CreateSession(EmailRegistration emailRegistration, CancellationToken ct)
	{
		var sessionResult = await _authService.CreateSessionAsync(emailRegistration.Email, ct);
		
		if (!sessionResult.Succeeded)
			return BadRequest(new FailResponse { Errors = sessionResult.Errors });
		
		_emailService.Send(emailRegistration.Email, sessionResult.VerificationCode); // TODO return errors if any
		
		Response.Cookies.Append(
			"session_id",
			sessionResult.Id, // should I convert it into Base64?
			new()
			{
				Secure = true,
				HttpOnly = true,
				Expires = DateTimeOffset.UtcNow.AddMinutes(5)
			}
		);
		
		return Ok(new SessionSuccessResponse
		{
			Message = "Verification code is sent to your email"
		});
	}
	
	/// <summary>
	/// Verifies an email
	/// </summary>
	/// <response code="200">Email address is successfully verified</response>
	/// <response code="400">Vefirication code is wrong</response>
	[HttpPost("verification")]
	[ServiceFilter(typeof(SessionCookieActionFilter))]
	[ProducesResponseType(typeof(SessionSuccessResponse), 200)]
	[ProducesResponseType(typeof(FailResponse), 400)]
	public IActionResult VerifyEmail(CodeVerification codeVerification)
	{
		var id = (string) HttpContext.Items["sessionId"]!;
		
		var sessionResult = _authService.VerifyEmail(id, codeVerification.Code);
		
		if (!sessionResult.Succeeded)
		{
			return BadRequest(new FailResponse { Errors = sessionResult.Errors});
		}
		
		return Ok(new SessionSuccessResponse
		{
			Message = "Email address has successfully been verified"
		});
	}
	
	/// <summary>
	/// Registers a user
	/// </summary>
	/// <response code="200">User is successfully registered</response>
	/// <response code="400">Username is already taken or validation failed</response>
	[HttpPost("registration")]
	[ServiceFilter(typeof(SessionCookieActionFilter))]
	[ProducesResponseType(typeof(AuthSuccessResponse), 200)]
	[ProducesResponseType(typeof(FailResponse), 400)]
	public async Task<IActionResult> Register(UserRegistration userRegistration, CancellationToken ct)
	{
		var id = (string) HttpContext.Items["sessionId"]!;
		
		var authenticationResult = await _authService.RegisterAsync(id, userRegistration, ct);
		
		if (!authenticationResult.Succeeded)
		{
			return BadRequest(new FailResponse { Errors = authenticationResult.Errors });
		}
		
		var tokens = await _authService.GenerateTokensAsync(authenticationResult.User, ct);
		
		Response.Cookies.Delete("session_id");
		
		return Ok(new AuthSuccessResponse
		{
			Message = "You have successfully registered",
			AccessToken = tokens.AccessToken,
			RefreshToken = tokens.RefreshToken
		});
	}
	
	/// <summary>
	/// Logs in a user
	/// </summary>
	/// <response code="200">User is logged in</response>
	/// <response code="400">Validation failed</response>
	/// <response code="401">User's login/password are wrong</response>
	[HttpPost("login")]
	[ProducesResponseType(typeof(AuthSuccessResponse), 200)]
	[ProducesResponseType(typeof(FailResponse), 400)]
	[ProducesResponseType(typeof(FailResponse), 401)]
	public async Task<IActionResult> Login(UserLogin userLogin, CancellationToken ct)
	{
		var authenticationResult = await _authService.AuthenticateAsync(userLogin, ct);
		
		if (!authenticationResult.Succeeded)
		{
			return Unauthorized(new FailResponse { Errors = authenticationResult.Errors });
		}
		
		var tokens = await _authService.GenerateTokensAsync(authenticationResult.User, ct);
		
		return Ok(new AuthSuccessResponse
		{
			Message = "You have successfully logged in",
			AccessToken = tokens.AccessToken,
			RefreshToken = tokens.RefreshToken
		});
	} 
	
	/// <summary>
	/// Refreshes the tokens
	/// </summary>
	/// <response code="200">Tokens are refreshed</response>
	/// <response code="400">Tokens are missing</response>
	/// <response code="401">Tokens are invalid</response>
	[HttpPost("refresh")]
	[ProducesResponseType(typeof(AuthSuccessResponse), 200)]
	[ProducesResponseType(typeof(FailResponse), 400)]
	[ProducesResponseType(typeof(FailResponse), 401)]
	public async Task<IActionResult> RefreshToken(TokenRefreshing tokensRequest, CancellationToken ct)
	{
		var validationResult = await _authService.ValidateTokensAsync(tokensRequest, ct);
		
		if (!validationResult.Succeeded)
		{
			return Unauthorized(new FailResponse { Errors = validationResult.Errors });
		}
		
		var tokens = await _authService.GenerateTokensAsync(validationResult.User, ct);
		
		return Ok(new AuthSuccessResponse
		{
			Message = "You have successfully refreshed the tokens",
			AccessToken = tokens.AccessToken,
			RefreshToken = tokens.RefreshToken
		});
	}
}