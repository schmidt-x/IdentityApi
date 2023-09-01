﻿using System.Collections.Generic;
using IdentityApi.Domain.Models;

namespace IdentityApi.Results;

public class AuthResult
{
	public UserClaims Claims { get; set; } = default!;
	public bool Succeeded { get; set; }
	public Dictionary<string, IEnumerable<string>>? Errors { get; set; }
}