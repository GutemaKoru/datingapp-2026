using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(AppDbContext context) : BaseController
{
    [HttpPost("register")]
    public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => x.Email == registerDto.Email);
        if (user != null) return BadRequest("Email Taken");

        //Hash Password
        using var hmac = new HMACSHA512();
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password));

        //Map from domain to dto
        var userDto = new AppUser
        {
            DisplayName = registerDto.DisplayName,
            Email = registerDto.Email,
            PasswordHash = computedHash,
            PasswordSalt = hmac.Key
        };

        context.Users.Add(userDto);
        await context.SaveChangesAsync();

        return userDto;
    }
}
