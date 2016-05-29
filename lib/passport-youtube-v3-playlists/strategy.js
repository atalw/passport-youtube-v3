/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2').Strategy
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * Youtube authentication strategy authenticates requests using the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
  options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';
  options.scope = options.scope || ['https://www.googleapis.com/auth/youtube'];

  OAuth2Strategy.call(this, options, verify);
  this.name = 'youtube';
  this._profileURL = options.profileURL || 'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true';
  this._channelURL = options.channelURL || 'https://www.googleapis.com/youtube/v3/playlists?part=snippet&maxResults=50&channelId=';
  this._playlistURL = options.playlistURL || 'https://www.googleapis.com/youtube/v3/playlistItems?part=snippet&maxResults=50&playlistId=';
  this._authorizationParams = options.authorizationParams;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Youtube.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `youtube`
 *   - `id`               the user's Google Plus user ID
 *   - `username`         the user's Youtube username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - 'picture'          the user's profile picture url
 *   - 'playlists'        list of the user's playlists
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
	// get profile info using url
	var url = this._profileURL;
	// get list of playlists (channel info) using curl
	var curl = this._channelURL;
	// get playlistsItems using purl
	var purl = this._playlistURL;

	var oauth2 = this._oauth2;

	oauth2.getProtectedResource(url, accessToken, function (err, body, res) {

		if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
		try {
			var json = JSON.parse(body);
			var youtubeProfile = json.items && json.items.length && json.items[0];
			var profile = { provider: 'youtube' };

			if (youtubeProfile) {
				profile.id = youtubeProfile.id;
				profile.displayName = youtubeProfile.snippet.title;
				profile.picture = youtubeProfile.snippet.thumbnails.default.url;
			}
			profile._raw = body;
			profile._json = json;

			// update url with channel id
			curl += profile.id;
			// get request for playlist id's
			oauth2.getProtectedResource(curl, accessToken, function (err, body, res) {
				if (err) { return done(new InternalOAuthError('failed to fetch user playlists', err)); }
				try {
					var jsonp = JSON.parse(body);
					profile.playlists = jsonp.items;
					var ps = profile.playlists;
					var index = 0;

					ps.forEach(function(playlist){
						var tempPurl = purl;
						tempPurl += playlist.id;
						// request playlistItems for each playlist
						oauth2.getProtectedResource(tempPurl, accessToken, function (err, body, res) {
							if (err) { return done(new InternalOAuthError('failed to fetch playlistItems', err)); }
							try {
								var jsonp = JSON.parse(body);
								profile.playlists[index].data = jsonp;
								++index;
								// if index has crossed last playlist - send done
								if (!profile.playlists[index]) {
									done(null, profile);
								}
							} catch(e) {
								done(e);
							}
						});
					});
				} catch(e) {
					done(e);
				}
			});
		} catch(e) {
			done(e);
		}
	});
}

Strategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'username':    'username',
    'displayName': 'name',
    'name':       ['last_name', 'first_name'],
	'url':         'url'
  };

  var fields = [];

  profileFields.forEach(function(f) {
    if (typeof map[f] === 'undefined') return;

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
}


Strategy.prototype.authorizationParams = function(options) {
  return options && options.authorizationParams || this._authorizationParams || {
    access_type : 'offline',
    approval_prompt: 'force'
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
