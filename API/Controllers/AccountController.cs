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
        if (await EmailExists(registerDto.Email)) return BadRequest("Email Already Taken");

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

    [HttpPost("login")]
    public async Task<ActionResult<AppUser>> Login(LoginDto loginDto)
    {
        var user = await context.Users.SingleOrDefaultAsync(x=>x.Email == loginDto.Email);
        if(user is null) return Unauthorized("Invalid Email");


        using var hmac = new HMACSHA512(user.PasswordSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (var i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i])
            {
                return Unauthorized("Invalid Password"); // For Dev only
            }
        }

        return user;
    }

    private async Task<bool> EmailExists(string email)
    {
        return await context.Users.AnyAsync(x => x.Email.ToLower() == email.ToLower());
    }
}
