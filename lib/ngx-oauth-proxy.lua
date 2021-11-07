---------
-- Proxy script for OAuth 2.0.

local config  = require 'ngx-oauth.config'
local Cookies = require 'ngx-oauth.Cookies'
local either  = require 'ngx-oauth.either'
local nginx   = require 'ngx-oauth.nginx'
local oauth   = require 'ngx-oauth.oauth2'
local util = require 'ngx-oauth.util'

local log    = nginx.log

local function write_auth_header (access_token)
  ngx.req.set_header('Authorization', 'Bearer '..access_token)
end


local conf, errs = config.load()
if errs then
  return nginx.fail(500, 'OAuth proxy error: %s', errs)
end

local cookies = Cookies(conf)
local access_token = cookies.get_access_token()

-- Cookie with access token found; set Authorization header and we're done.
if access_token then
  if not util.hasAccess(conf, { id = cookies.get_username() }) then
    cookies.clear_all()
    ngx.redirect(oauth.authorization_url(conf), 303)
  else
    write_auth_header(access_token)
  end

-- Cookie with refresh token found; refresh token and set Authorization header.
elseif cookies.get_refresh_token() then
  log.info('refreshing token for user: %s', cookies.get_username())

  either (
    function(err)
      nginx.fail(503, 'Authorization server error: %s', err)
    end,
    function(token)
      cookies.add_token(token)
      write_auth_header(token.access_token)
    end,
    oauth.request_token('refresh_token', conf, cookies.get_refresh_token())
  )
  if not util.hasAccess(conf, { id = cookies.get_username() }) then
    cookies.clear_all()
    return ngx.redirect(oauth.authorization_url(conf), 303)
  end

-- Neither access token nor refresh token found; bad luck, return HTTP 401.
else
  ngx.redirect(oauth.authorization_url(conf), 303)
  -- ngx.header['WWW-Authenticate'] = 'Bearer error="unauthorized"'
  -- nginx.fail(401, 'No access token provided.')
end
