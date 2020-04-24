const assert = require('assert');
const openid = require('openid-client');

function _httpOption(target, option) {
    let httpOptions = option && option.httpOptions && typeof option.httpOptions === 'object' ? option.httpOptions : undefined;
    if (httpOptions) target[openid.custom.http_options] = (options) => {
        return {...options, ...httpOptions};
    }
}

class openidSchema {
    normalizeOptions(option) {
        assert(option);
        assert(option.client_id && typeof option.client_id === 'string');
        assert(option.client_secret && typeof option.client_secret === 'string');
        assert(option.redirect_uris && Array.isArray(option.redirect_uris));

        option.state = option.state !== undefined ? !!option.state : false;
        option.openidClientMetadata = option.openidClientMetadata || {};
        option.openidJwks = typeof option.openidJwks === 'object' ? option.openidJwks : undefined;

        option.csrfStateMechanism = option.csrfStateMechanism !== undefined ? !!option.csrfStateMechanism : true;
        if (option.csrfStateMechanism) option.csrfStateKey =
            option.csrfStateKey && typeof option.csrfStateKey === 'string' ? option.csrfStateKey : 'knock-knock-openid-schema-state';
        option.csrfStateNoSignedCookie = !!option.csrfStateNoSignedCookie;
        option.oauthMode = option.oauthMode !== undefined ? !!option.oauthMode : false;
        option.retriveUserInfo = option.userInfo !== undefined ? !!option.userInfo : false;
        option.refineToken = typeof option.refineToken === 'function' ? option.refineToken :
            (claim, userInfo) => {
                return {...claim, ...userInfo}
            };

        return option;
    }

    constructor(option) {
        assert(option.issuer);
        let issuer;
        if (option.issuer instanceof openid.Issuer) {
            issuer = option.issuer
        } else {
            _httpOption(openid.Issuer, option);
            issuer = new openid.Issuer(option.issuer);
        }
        option = this.normalizeOptions(option);
        this._genSchema(issuer, option);
        this.name = 'openid/oauth login';
    }

    static async discovery(url, option) {
        assert(url && typeof url === 'string');

        _httpOption(openid.Issuer, option);
        const issuer = await openid.Issuer.discover(url);
        return new this({issuer, ...option});
    }


    _genSchema(issuer, option) {
        if (!(issuer instanceof openid.Issuer))
            throw SyntaxError(`no issuer instance or don't call this function directly.`);


        _httpOption(issuer, option);
        _httpOption(issuer.Client, option);


        //create client
        const client = new issuer.Client({
                client_id: option.client_id,
                client_secret: option.client_secret,
                redirect_uris: option.redirect_uris,
                response_types: ['code'],
                // ...option.openidClientMetadata
            },
            option.openidJwks);

        _httpOption(client, option);

        this.oauthLogin = async function (req, res) {
            let state;
            if (option.csrfStateMechanism) {
                state = openid.generators.state();
                res.cookie(option.csrfStateKey, state, {httpOnly: true, signed: !option.csrfStateNoSignedCookie});
            }

            //must return user id object
            let oauthUrl = client.authorizationUrl({
                //'openid email'
                scope: option.scope,
                state: state
            });

            res.redirect(oauthUrl);
        };

        this.knockLogin = this.oauthCallback = async function (req, res) {
            const params = client.callbackParams(req);
            let state;
            if (option.csrfStateMechanism) {
                state = !option.csrfStateNoSignedCookie ? req.signedCookies[option.csrfStateKey] : req.cookies[option.csrfStateKey];
                assert(state);
            }

            let callback = option.oauthMode ? client.oauthCallback : client.callback;
            callback = callback.bind(client);

            let tokenSet = await callback(option.redirect_uris[0], params,
                {state}
            );
            let tokenClaims;
            try {
                tokenClaims = tokenSet.claims();
            } catch (e) {
            }

            let userinfoResponse = option.retriveUserInfo ? await client.userinfo(tokenSet.access_token) : {};
            assert(tokenClaims || userinfoResponse);

            req.user = option.refineToken(tokenClaims, userinfoResponse);
        }
    }

}

module.exports = openidSchema;

