﻿using System;

namespace IdentityApi.Domain.Models;

public class UserProfile
{
	public string Username { get; set; } = default!;
	public string Email { get; set; } = default!;
	public DateTime CreatedAt { get; set; }
	public DateTime UpdatedAt { get; set; }
	public string Role { get; set; } = default!;
}