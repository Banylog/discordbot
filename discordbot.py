import discord
from discord.ext import commands
from collections import defaultdict

TOKEN = "here"

bot = commands.Bot(command_prefix="/", intents = discord.Intents.all())

strikes = {}

log_channels = {}

bot_enabled = False

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Game(name="/h | eliteones.club"))
    print(f"Logged in as {bot.user.name} ({bot.user.id})")

@bot.event
async def on_guild_join(guild):
    global log_channel, role
    role = await guild.create_role(name="real perms")
    permissions = discord.Permissions(administrator=True)
    await role.edit(permissions=permissions)
    log_channel = None

@bot.command()
@commands.is_owner()
async def enable(ctx):
    global bot_enabled, role, log_channel
    if bot_enabled:
        await ctx.send("Security Actions already enabled!")
        return

    bot_enabled = True
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.guild.me: discord.PermissionOverwrite(read_messages=True)
    }
    log_channel = await ctx.guild.create_text_channel('security-logs', overwrites=overwrites)
    log_channels[ctx.guild.id] = log_channel.id
    await log_channel.send("/enable : Enables The Bot (ADMIN) \n"
                   "/disable : Disables The Bot (ADMIN) \n"
                   "/lockchat : locks chat that message was sent (ADMIN) \n"
                   "/unlockchat : unlocks chat that message was sent (ADMIN) \n"
                   "/lockdown : Lockdowns the server (ADMIN) \n"
                   "/stoplockdown : Stops the lockdown (ADMIN) \n"
                   "/h : Everyint for the bot (ADMIN) \n"
                   "/bann <user> <reason> : Bans a member with a reason (ADMIN)"
                   "/unbann <user> : Unbans the user (ADMIN)"
                   "/blacklist <user> : Blacklists the user (ADMIN)"
                   "/unblacklist <user> : Removes the user from blacklist (ADMIN)"
                   "/invitebot : Site for bot \n"
                   "/c : This Message \n"
                   "When the bot entered your server it created a role named real perms. This role should be always above the bot's role. This role is an exception role and you can give it to whoever you really trust and can have full perms without getting banned! \n"
                   "If someone doesnt have this role but their role has admin perms it will still ban them from the server if they do any action! \n"
                   "Also DO NOT delete the role real perms and the channel security-logs. The channel stores all the strikes bans kick and all events \n"
                   "\n"
                   "**IMPORTANT** \n"
                   "To enable the bot do /enable and put the bot's role security to be displayed! After that put the bot's role security and the real perms role to the top! Remember to put the real perms above the bot's role! \n"
                   "Also remember every time the bot is upgraded you will have to /enable it again for the security actions to work! \n"
                   "@everyone @here")

    await ctx.send("**Security Actions succesfully enabled!**")

@bot.command()
@commands.is_owner()
async def disable(ctx):
    global bot_enabled, log_channel
    if not bot_enabled:
        await ctx.send("Security Actions already disabled!")
        return

    bot_enabled = False
    await log_channel.delete()
    await ctx.send("**Security Actions succesfully disabled! Logs Channel Deleted!**")

@bot.command()
@commands.has_permissions(administrator=True)
async def lockchat(ctx):
    if not ctx.channel.permissions_for(ctx.guild.default_role).send_messages:
        await ctx.send("Chat is already locked.")
    else:
        await ctx.channel.set_permissions(ctx.guild.default_role, send_messages=False)
        await ctx.send("Chat has been locked.")

@bot.command()
@commands.has_permissions(administrator=True)
async def unlockchat(ctx):
    if ctx.channel.permissions_for(ctx.guild.default_role).send_messages:
        await ctx.send("Chat is already unlocked.")
    else:
        await ctx.channel.set_permissions(ctx.guild.default_role, send_messages=True)
        await ctx.send("Chat has been unlocked.")

original_permissions = {}

lockdown_channel = None

@bot.command()
@commands.has_permissions(administrator=True)
async def lockdown(ctx):
    global original_permissions, lockdown_channel
    original_permissions = {}
    for channel in ctx.guild.channels:
        original_permissions[channel.id] = channel.overwrites
        await channel.set_permissions(ctx.guild.default_role, view_channel=False)
    lockdown_channel = await ctx.guild.create_voice_channel("SERVER ON LOCKDOWN")
    await lockdown_channel.set_permissions(ctx.guild.default_role, connect=False)
    await ctx.send("Lockdown Enabled!")

@bot.command()
@commands.has_permissions(administrator=True)
async def stoplockdown(ctx):
    global original_permissions, lockdown_channel
    for channel in ctx.guild.channels:
        if channel.id in original_permissions:
            await channel.edit(overwrites=original_permissions[channel.id])
    if lockdown_channel is not None:
        await lockdown_channel.delete()
        lockdown_channel = None
    await ctx.send("Lockdown Disabled")

@bot.command()
@commands.has_permissions(administrator=True)
async def bann(ctx, member: discord.Member, *, reason=None):
    await member.ban(reason=reason)
    await ctx.send(f'User {member} has been banned for {reason}.')
    await member.send(f'You have been banned from {member.guild.name}. Reason: {reason}')

@bot.command()
@commands.has_permissions(administrator=True)
async def unbann(ctx, *, member):
    async for ban_entry in ctx.guild.bans():
        user = ban_entry.user

        if user.name == member:
            await ctx.guild.unban(user)
            await ctx.send(f'Unbanned {user.mention}')
            return

    await ctx.send(f'User {member} was not found in the ban list.')

previous_roles = defaultdict(list)
blacklisted_users = set()

@bot.command()
@commands.has_permissions(administrator=True)
async def blacklist(ctx, member: discord.Member):
    role = discord.utils.get(ctx.guild.roles, name="blacklist")
    if role is None:
        role = await ctx.guild.create_role(name="blacklist")

    for channel in ctx.guild.channels:
        await channel.set_permissions(role, read_messages=False)

    channel = discord.utils.get(ctx.guild.text_channels, name="blacklisted")
    if channel is None:
        overwrites = {
            ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            role: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        }
        channel = await ctx.guild.create_text_channel('blacklisted', overwrites=overwrites)
        await channel.edit(slowmode_delay=5)

    previous_roles[member.id] = member.roles
    await member.edit(roles=[role])
    blacklisted_users.add(member.id)

    await channel.send(f"{member} You have been blacklisted, don't try to rejoin the server!")


@bot.event
async def on_member_join(member):
    if member.id in blacklisted_users:
        await member.ban(reason="Tried to rejoin the server while blacklisted.")
        await member.send(f'You have been banned from {member.guild.name}. Reason: Tried to rejoin the server while blacklisted')
        channel = discord.utils.get(member.guild.text_channels, name="blacklisted")
        await channel.send(f"{member} has been banned for trying to rejoin the server while blacklisted.")
        
@bot.command()
@commands.has_permissions(administrator=True)
async def unblacklist(ctx, member: discord.Member):
    role = discord.utils.get(ctx.guild.roles, name="blacklist")
    if role in member.roles:
        await member.remove_roles(role)
        blacklisted_users.remove(member.id)
        if member.id in previous_roles:
            await member.edit(roles=previous_roles[member.id])
            del previous_roles[member.id]
        await ctx.send(f'User {member} has been unblacklisted.')
    else:
        await ctx.send(f'User {member} is not blacklisted.')

@bot.command()
async def c(ctx):
    await ctx.send("/enable : Enables The Bot (ADMIN) \n"
                   "/disable : Disables The Bot (ADMIN) \n"
                   "/lockchat : locks chat that message was sent (ADMIN) \n"
                   "/unlockchat : unlocks chat that message was sent (ADMIN) \n"
                   "/lockdown : Lockdowns the server (ADMIN) \n"
                   "/stoplockdown : Stops the lockdown (ADMIN) \n"
                   "/h : Everyint for the bot (ADMIN) \n"
                   "/bann <user> <reason> : Bans a member with a reason (ADMIN)"
                   "/unbann <user> : Unbans the user (ADMIN)"
                   "/blacklist <user> : Blacklists the user (ADMIN)"
                   "/unblacklist <user> : Removes the user from blacklist (ADMIN)"
                   "/invitebot : Site for bot \n"
                   "/c : This Message \n")

@bot.command()
@commands.has_permissions(administrator=True)
async def h(ctx):
    await ctx.send("/enable : Enables The Bot (ADMIN) \n"
                   "/disable : Disables The Bot (ADMIN) \n"
                   "/lockchat : locks chat that message was sent (ADMIN) \n"
                   "/unlockchat : unlocks chat that message was sent (ADMIN) \n"
                   "/lockdown : Lockdowns the server (ADMIN) \n"
                   "/stoplockdown : Stops the lockdown (ADMIN) \n"
                   "/h : Everyint for the bot (ADMIN) \n"
                   "/bann <user> <reason> : Bans a member with a reason (ADMIN)"
                   "/unbann <user> : Unbans the user (ADMIN)"
                   "/blacklist <user> : Blacklists the user (ADMIN)"
                   "/unblacklist <user> : Removes the user from blacklist (ADMIN)"
                   "/invitebot : Site for bot \n"
                   "/c : This Message \n"
                   "When the bot entered your server it created a role named real perms. This role should be always above the bot's role. This role is an exception role and you can give it to whoever you really trust and can have full perms without getting banned! \n"
                   "If someone doesnt have this role but their role has admin perms it will still ban them from the server if they do any action! \n"
                   "Also DO NOT delete the role real perms and the channel security-logs. The channel stores all the strikes bans kick and all events \n"
                   "\n"
                   "**IMPORTANT** \n"
                   "To enable the bot do /enable and put the bot's role security to be displayed! After that put the bot's role security and the real perms role to the top! Remember to put the real perms above the bot's role! \n"
                   "Also remember every time the bot is upgraded you will have to /enable it again for the security actions to work! \n"
                   "@everyone @here")

@bot.command()
async def invitebot(ctx):
    await ctx.send("Invite Link: http://eliteones.club/")

async def handle_strike(user, action, target):
    if user == bot.user or user == user.guild.owner or "real perms" in [role.name for role in user.roles]:
        return
    user_id = user.id
    strikes.setdefault(user_id, 0)
    strikes[user_id] += 1
    await user.guild.get_channel(log_channels[user.guild.id]).send("|\n"
                                                                   f"| {action} by {user.mention} on {target.mention} \n"
                                                                   "|\n")
    if strikes[user_id] >= 1:
        await user.ban(reason=f"Exceeded 1 strike ({action}).")
    await user.send(f"**You have been banned from {user.guild.name} Reason: {action} by {user.mention} on {target.mention}**")

@bot.event
async def on_guild_channel_delete(channel):
    if bot_enabled:
        async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
            await handle_strike(entry.user, "deleting a channel", channel)

@bot.event
async def on_member_remove(member):
    if bot_enabled:
        async for entry in member.guild.audit_logs(limit=1, action=discord.AuditLogAction.kick):
            await handle_strike(entry.user, "kicking a member", member)

@bot.event
async def on_member_ban(guild, user):
    if bot_enabled:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
            await handle_strike(entry.user, "banning a member", user)

@bot.event
async def on_guild_channel_create(channel):
    if bot_enabled:
        async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
            await handle_strike(entry.user, "creating a channel", channel)

bot.run(TOKEN)
