---------
-- Redirect handler for OAuth 2.0 grant authorization code.

local config  = require 'ngx-oauth.config'
local Cookies = require 'ngx-oauth.Cookies'
local either  = require 'ngx-oauth.either'
local httpc   = require 'ngx-oauth.http_client'
local nginx   = require 'ngx-oauth.nginx'
local oauth   = require 'ngx-oauth.oauth2'
local util    = require 'ngx-oauth.util'

local log     = nginx.log
local par     = util.partial
local hasAccess = util.hasAccess
local conf, err = config.load()
if err then
  return nginx.fail(500, "OAuth proxy error: %s", err)
end
local function failResponse(...)
  local args1 = {...}
  return ngx.redirect(oauth.authorization_url(conf), 303)
end

local fail_with_oaas_error = par(failResponse, 503, "Authorization server error: %s")
local get_or_fail = par(either, fail_with_oaas_error, util.id)


local cookies = Cookies(conf)
local err_code = nginx.get_uri_arg('error')
local auth_code = nginx.get_uri_arg('code')

log.debug('processing request from authorization server')
if err_code then
  return nginx.fail(403, err_code)

elseif auth_code then
  log.debug("requesting token for auth code: %s", auth_code)

  local token = get_or_fail(oauth.request_token('authorization_code', conf, auth_code))
  cookies.add_token(token)

  local user = get_or_fail(httpc.get_for_json(conf.userinfo_url, token.access_token))
  cookies.add_username(user.id)
  -- log.info("user: %s, conf: users (%s) - guilds (%s)", user.username, conf.allowed_users, conf.allowed_guilds)
  if not hasAccess(conf, user, guilds) then
    log.err("unauthorized user %s (%s)", user.username, user.id)
    cookies.clear_all()
    return nginx.fail(401, "unauthorized user/guild")
  end
  log.info("authorized user '%s', redirecting to: %s", user.username, conf.success_uri)
  return ngx.redirect(conf.success_uri, 303)

else
  return nginx.fail(400, "Missing query parameter 'code' or 'error'.")
end
