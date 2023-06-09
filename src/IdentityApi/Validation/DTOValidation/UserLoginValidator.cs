﻿using FluentValidation;
using IdentityApi.Contracts.DTOs;

namespace IdentityApi.Validation.DTOValidation;

public class UserLoginValidator : AbstractValidator<UserLogin>
{
	public UserLoginValidator()
	{
		RuleFor(u => u.Login)
			.NotEmpty().WithMessage("Username is required");
			
		RuleFor(u => u.Password)
			.NotEmpty().WithMessage("Password is required");
	}
}